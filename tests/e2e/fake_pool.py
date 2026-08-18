#!/usr/bin/env python3
"""Selector-based deterministic SV1 backend that requires PROXY protocol v2."""

import json
import os
import selectors
import socket
import struct


BACKEND_NAME = os.environ.get("BACKEND_NAME", "unknown")
RESPONSE_PADDING_BYTES = int(os.environ.get("RESPONSE_PADDING_BYTES", "0"))
STALL_AFTER_REQUESTS = int(os.environ.get("STALL_AFTER_REQUESTS", "0"))
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3333
HEALTH_LISTEN_PORT = 7777
LISTEN_BACKLOG = 65_535
PROXY_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
READ_BYTES = 65_536
MAXIMUM_HTTP_REQUEST_BYTES = 4_096
STRATUM_LISTENER = object()
HEALTH_LISTENER = object()
RESPONSE_PADDING = "x" * RESPONSE_PADDING_BYTES
STALLED_CONNECTIONS: dict[int, "ConnectionState"] = {}
# Every mining.submit nonce this backend has accepted. A solo pool wins on exactly one of these, so
# the resilience suite asserts the set is complete rather than merely large.
ACCEPTED_SUBMIT_NONCES: set[str] = set()

if RESPONSE_PADDING_BYTES < 0 or RESPONSE_PADDING_BYTES > 1_048_576:
    raise ValueError("RESPONSE_PADDING_BYTES must be between 0 and 1048576")
if STALL_AFTER_REQUESTS < 0:
    raise ValueError("STALL_AFTER_REQUESTS must be non-negative")


class ConnectionState:
    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self.input = bytearray()
        self.output = bytearray()
        self.proxy_payload_bytes: int | None = None
        self.source = "unspecified"
        self.proxy_complete = False
        self.requests_processed = 0
        self.reads_stalled = False


class HealthConnectionState:
    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self.input = bytearray()
        self.output = bytearray()


def parse_proxy_header(state: ConnectionState) -> None:
    if state.proxy_payload_bytes is None:
        if len(state.input) < 16:
            return
        if state.input[:12] != PROXY_SIGNATURE or state.input[12] != 0x21:
            raise ValueError("missing PROXY v2 header")
        state.proxy_payload_bytes = struct.unpack("!H", state.input[14:16])[0]
    total = 16 + state.proxy_payload_bytes
    if len(state.input) < total:
        return
    family = state.input[13] >> 4
    payload = state.input[16:total]
    if family == 1 and len(payload) >= 12:
        state.source = socket.inet_ntop(socket.AF_INET, payload[:4])
    elif family == 2 and len(payload) >= 36:
        state.source = socket.inet_ntop(socket.AF_INET6, payload[:16])
    del state.input[:total]
    state.proxy_complete = True


def process_requests(state: ConnectionState) -> None:
    if not state.proxy_complete:
        parse_proxy_header(state)
    if not state.proxy_complete:
        return
    while True:
        newline = state.input.find(b"\n")
        if newline < 0:
            return
        request = json.loads(state.input[:newline])
        del state.input[: newline + 1]
        if request.get("method") == "mining.submit":
            params = request.get("params")
            if isinstance(params, list) and len(params) >= 5:
                ACCEPTED_SUBMIT_NONCES.add(str(params[4]))
        response = {
            "id": request.get("id"),
            "result": {"backend": BACKEND_NAME, "source": state.source},
            "error": None,
        }
        if RESPONSE_PADDING:
            response["result"]["padding"] = RESPONSE_PADDING
        state.output.extend(json.dumps(response, separators=(",", ":")).encode() + b"\n")
        state.requests_processed += 1
        if STALL_AFTER_REQUESTS and state.requests_processed >= STALL_AFTER_REQUESTS:
            state.reads_stalled = True
            return


def close_connection(selector: selectors.BaseSelector, state: ConnectionState) -> None:
    descriptor = state.connection.fileno()
    try:
        selector.unregister(state.connection)
    except KeyError:
        pass
    STALLED_CONNECTIONS.pop(descriptor, None)
    state.connection.close()


def service_connection(
    selector: selectors.BaseSelector, state: ConnectionState, mask: int
) -> None:
    try:
        if mask & selectors.EVENT_READ and not state.reads_stalled:
            received = state.connection.recv(READ_BYTES)
            if not received:
                close_connection(selector, state)
                return
            state.input.extend(received)
            process_requests(state)
        if mask & selectors.EVENT_WRITE and state.output:
            sent = state.connection.send(state.output)
            del state.output[:sent]
        if state.reads_stalled and not state.output:
            selector.unregister(state.connection)
            STALLED_CONNECTIONS[state.connection.fileno()] = state
            return
        events = selectors.EVENT_WRITE if state.reads_stalled else selectors.EVENT_READ
        if state.output:
            events |= selectors.EVENT_WRITE
        selector.modify(state.connection, events, state)
    except (ConnectionError, json.JSONDecodeError, OSError, ValueError):
        close_connection(selector, state)


def accept_connections(
    selector: selectors.BaseSelector,
    server: socket.socket,
    health: bool = False,
) -> None:
    while True:
        try:
            connection, _ = server.accept()
        except BlockingIOError:
            return
        connection.setblocking(False)
        state = HealthConnectionState(connection) if health else ConnectionState(connection)
        selector.register(connection, selectors.EVENT_READ, state)


def service_health_connection(
    selector: selectors.BaseSelector,
    state: HealthConnectionState,
    mask: int,
) -> None:
    try:
        if mask & selectors.EVENT_READ:
            received = state.connection.recv(READ_BYTES)
            if not received:
                close_connection(selector, state)
                return
            state.input.extend(received)
            if len(state.input) > MAXIMUM_HTTP_REQUEST_BYTES:
                close_connection(selector, state)
                return
            if b"\r\n\r\n" in state.input:
                if state.input.startswith(b"GET /submits HTTP/1."):
                    status = b"200 OK"
                    body = ("\n".join(sorted(ACCEPTED_SUBMIT_NONCES)) + "\n").encode()
                elif state.input.startswith(b"GET /health HTTP/1."):
                    status = b"200 OK"
                    body = b"ok\n"
                else:
                    status = b"404 Not Found"
                    body = b"not found\n"
                state.output.extend(
                    b"HTTP/1.1 "
                    + status
                    + b"\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
        if mask & selectors.EVENT_WRITE and state.output:
            sent = state.connection.send(state.output)
            del state.output[:sent]
            if not state.output:
                close_connection(selector, state)
                return
        events = selectors.EVENT_WRITE if state.output else selectors.EVENT_READ
        selector.modify(state.connection, events, state)
    except (ConnectionError, OSError):
        close_connection(selector, state)


def make_listener(port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, port))
    server.listen(LISTEN_BACKLOG)
    server.setblocking(False)
    return server


def main() -> None:
    with selectors.DefaultSelector() as selector:
        with make_listener(LISTEN_PORT) as server, make_listener(
            HEALTH_LISTEN_PORT
        ) as health_server:
            selector.register(server, selectors.EVENT_READ, STRATUM_LISTENER)
            selector.register(health_server, selectors.EVENT_READ, HEALTH_LISTENER)
            while True:
                for key, mask in selector.select():
                    if key.data is STRATUM_LISTENER:
                        accept_connections(selector, server)
                    elif key.data is HEALTH_LISTENER:
                        accept_connections(selector, health_server, health=True)
                    elif isinstance(key.data, HealthConnectionState):
                        service_health_connection(selector, key.data, mask)
                    else:
                        service_connection(selector, key.data, mask)


if __name__ == "__main__":
    main()
