#!/usr/bin/env python3
"""Dependency-free protocol driver for the real load balancer stack."""

import concurrent.futures
import hashlib
import json
import math
import os
import platform
import random
import selectors
import socket
import ssl
import sys
import time
import urllib.request

HOST = os.environ.get("LB_HOST", "pool-lb")
PORT = int(os.environ.get("LB_PORT", "3333"))
USE_TLS = os.environ.get("LB_TLS", "0") == "1"
TIMEOUT_SECONDS = 5
API_URL = os.environ.get("LB_API_URL", "http://pool-lb:7778/metrics")
TLS_RELOAD_TIMEOUT_SECONDS = 30
TLS_RELOAD_SUCCESS_METRIC = (
    'pool_lb_tls_certificate_reloads_total{result="success"}'
)
BENCHMARK_SCENARIOS = {
    "idle",
    "relay",
    "reconnect",
    "malformed",
    "stalled-client",
    "stalled-upstream",
}
BACKPRESSURE_SCENARIOS = {"stalled-client", "stalled-upstream"}
BENCHMARK_METRICS = (
    "pool_lb_connections_accepted_total",
    "pool_lb_connections_closed_total",
    "pool_lb_connections_rejected_protocol_total",
    "pool_lb_connections_rejected_rate_total",
    "pool_lb_connections_rejected_global_rate_total",
    "pool_lb_connections_rejected_tls_total",
    "pool_lb_connections_rejected_no_backend_total",
    "pool_lb_connections_rejected_queue_limit_total",
    "pool_lb_client_bytes_total",
    "pool_lb_upstream_bytes_total",
    "pool_lb_queued_bytes",
    "pool_lb_queued_bytes_limit",
    "pool_lb_queued_bytes_high_water",
)
MAXIMUM_SCHEDULE_BURST = 1_024
BACKPRESSURE_METRICS_INTERVAL_SECONDS = 0.05
BACKPRESSURE_RECEIVE_BUFFER_BYTES = 1_024

TLS_CLIENT_CONTEXT: ssl.SSLContext | None = None
if USE_TLS:
    TLS_CLIENT_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    TLS_CLIENT_CONTEXT.check_hostname = False
    TLS_CLIENT_CONTEXT.verify_mode = ssl.CERT_NONE


class BenchmarkSession:
    def __init__(self, connection: socket.socket, started_ns: int) -> None:
        self.connection = connection
        self.started_ns = started_ns
        self.input = bytearray()
        self.output = bytearray()
        self.initial_pending: set[int] = set()
        self.pending: dict[int, int] = {}
        self.ready = False
        self.error = ""
        self.closed = False


class StalledWriteState:
    def __init__(
        self,
        session: BenchmarkSession,
        payload: bytes,
        operations: int,
        pressure_bytes_per_operation: int,
    ) -> None:
        self.session = session
        self.payload = payload
        self.operations_remaining = operations
        self.pressure_bytes_per_operation = pressure_bytes_per_operation
        self.offset = 0
        self.generator_bytes_sent = 0
        self.operations_sent = 0
        self.pressure_bytes_offered = 0


class LatencySamples:
    def __init__(self, maximum: int, seed: int) -> None:
        self.maximum = maximum
        self.values: list[int] = []
        self.seen = 0
        self.random = random.Random(seed)

    def add(self, value_ns: int) -> None:
        self.seen += 1
        if len(self.values) < self.maximum:
            self.values.append(value_ns)
            return
        replacement = self.random.randrange(self.seen)
        if replacement < self.maximum:
            self.values[replacement] = value_ns


def connect() -> socket.socket:
    connection = socket.create_connection((HOST, PORT), timeout=TIMEOUT_SECONDS)
    if TLS_CLIENT_CONTEXT is None:
        return connection
    try:
        return TLS_CLIENT_CONTEXT.wrap_socket(connection, server_hostname=HOST)
    except (OSError, ValueError):
        connection.close()
        raise


def expect_backend(expected: str) -> None:
    with connect() as connection:
        request = {"id": 1, "method": "mining.subscribe", "params": ["e2e/1.0"]}
        connection.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        response = json.loads(connection.makefile("rb").readline())
        actual = response["result"]["backend"]
        source = response["result"]["source"]
        if actual != expected:
            raise AssertionError(f"expected backend {expected}, got {actual}")
        if source in ("", "unspecified"):
            raise AssertionError("backend did not receive the client address through PROXY v2")
        transport = "SV1/TLS" if USE_TLS else "SV1"
        print(f"ok: {transport} relayed to {actual}; PROXY v2 source={source}")


def invalid_rejected() -> None:
    with connect() as connection:
        connection.sendall(b"GET / HTTP/1.1\r\nHost: scanner\r\n\r\n")
        connection.settimeout(TIMEOUT_SECONDS)
        received = connection.recv(1)
        if received:
            raise AssertionError("scanner payload received an upstream response")
        print("ok: non-SV1 scanner payload was closed at the edge")


def oversized_rejected() -> None:
    with connect() as connection:
        request = {
            "id": 1,
            "method": "mining.subscribe",
            "params": ["x" * 20_000],
        }
        connection.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        connection.settimeout(TIMEOUT_SECONDS)
        received = connection.recv(1)
        if received:
            raise AssertionError("oversized SV1 line received an upstream response")
        print("ok: oversized SV1 line was closed at the edge")


def certificate_fingerprint() -> None:
    if not USE_TLS:
        raise AssertionError("certificate fingerprint requires LB_TLS=1")
    with connect() as connection:
        certificate = connection.getpeercert(binary_form=True)
        if not certificate:
            raise AssertionError("TLS peer did not provide a certificate")
        print(hashlib.sha256(certificate).hexdigest())


def successful_tls_reload_count() -> int:
    with urllib.request.urlopen(API_URL, timeout=TIMEOUT_SECONDS) as response:
        metrics = response.read().decode()
    for line in metrics.splitlines():
        if line.startswith(TLS_RELOAD_SUCCESS_METRIC + " "):
            return int(float(line.removeprefix(TLS_RELOAD_SUCCESS_METRIC + " ")))
    raise AssertionError("successful TLS reload metric is missing")


def wait_for_successful_tls_reload(previous_count: int) -> None:
    deadline = time.monotonic() + TLS_RELOAD_TIMEOUT_SECONDS
    last_error = ""
    while time.monotonic() < deadline:
        try:
            if successful_tls_reload_count() > previous_count:
                return
        except (AssertionError, OSError) as error:
            last_error = str(error)
        time.sleep(0.1)
    detail = f": {last_error}" if last_error else ""
    raise AssertionError(
        f"timed out waiting for a TLS reload after generation {previous_count}{detail}"
    )


def persistent_tls_session() -> None:
    if not USE_TLS:
        raise AssertionError("persistent TLS session requires LB_TLS=1")
    with connect() as connection:
        with connection.makefile("rb") as responses:
            subscribe = {
                "id": 1,
                "method": "mining.subscribe",
                "params": ["e2e/rotation"],
            }
            connection.sendall(
                json.dumps(subscribe, separators=(",", ":")).encode() + b"\n"
            )
            first_line = responses.readline()
            if not first_line:
                raise AssertionError("persistent TLS session closed during initialization")
            first_response = json.loads(first_line)
            if first_response["result"]["backend"] != "primary":
                raise AssertionError("persistent TLS session reached the wrong backend")

            reload_generation = successful_tls_reload_count()
            print("ok: persistent TLS session established", flush=True)

            wait_for_successful_tls_reload(reload_generation)
            authorize = {
                "id": 2,
                "method": "mining.authorize",
                "params": ["e2e.worker", "x"],
            }
            connection.sendall(
                json.dumps(authorize, separators=(",", ":")).encode() + b"\n"
            )
            second_line = responses.readline()
            if not second_line:
                raise AssertionError(
                    "persistent TLS session closed after certificate rotation"
                )
            second_response = json.loads(second_line)
            if (
                second_response["id"] != 2
                or second_response["result"]["backend"] != "primary"
            ):
                raise AssertionError(
                    "persistent TLS session failed after certificate rotation"
                )
            print("ok: established TLS session survived certificate rotation", flush=True)


def metric_value(metrics: str, name: str) -> int:
    prefix = name + " "
    for line in metrics.splitlines():
        if line.startswith(prefix):
            return int(float(line.removeprefix(prefix)))
    raise AssertionError(f"metric not found: {name}")


def environment_integer(name: str, default: int, minimum: int = 0) -> int:
    text = os.environ.get(name, str(default))
    try:
        value = int(text)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def environment_number(name: str, default: float, minimum: float = 0.0) -> float:
    text = os.environ.get(name, str(default))
    try:
        value = float(text)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error
    if not math.isfinite(value) or value < minimum:
        raise ValueError(f"{name} must be finite and at least {minimum}")
    return value


def encoded_request(request_id: int, method: str, params: list[object]) -> bytes:
    request = {"id": request_id, "method": method, "params": params}
    return json.dumps(request, separators=(",", ":")).encode() + b"\n"


def percentile(values: list[int], percentage: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(0, math.ceil((percentage / 100.0) * len(ordered)) - 1)
    return ordered[rank] / 1_000_000.0


def latency_summary(samples: LatencySamples) -> dict[str, float | int | None]:
    values = samples.values
    return {
        "observations": samples.seen,
        "samples": len(values),
        "samples_discarded": samples.seen - len(values),
        "minimum_ms": min(values) / 1_000_000.0 if values else None,
        "p50_ms": percentile(values, 50.0),
        "p95_ms": percentile(values, 95.0),
        "p99_ms": percentile(values, 99.0),
        "maximum_ms": max(values) / 1_000_000.0 if values else None,
    }


def scrape_metrics() -> tuple[dict[str, float], str]:
    if not API_URL:
        return {}, "disabled"
    try:
        with urllib.request.urlopen(API_URL, timeout=TIMEOUT_SECONDS) as response:
            body = response.read().decode()
    except (OSError, UnicodeError) as error:
        return {}, str(error)

    values: dict[str, float] = {}
    family_totals = {
        "pool_lb_backend_connection_attempts_total": 0.0,
        "pool_lb_backend_connection_errors_total": 0.0,
    }
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            name, value_text = line.rsplit(" ", 1)
            value = float(value_text)
        except ValueError:
            continue
        for metric in BENCHMARK_METRICS:
            if name == metric:
                values[metric] = value
        for family in family_totals:
            if name == family or name.startswith(family + "{"):
                family_totals[family] += value
    values.update(family_totals)
    return values, ""


def metric_delta(before: dict[str, float], after: dict[str, float]) -> dict[str, float]:
    return {
        name: after[name] - before.get(name, 0.0)
        for name in sorted(after)
        if name in before
    }


def close_benchmark_session(
    selector: selectors.BaseSelector,
    session: BenchmarkSession,
    error: str = "",
) -> None:
    if session.closed:
        return
    if error and not session.error:
        session.error = error
    try:
        selector.unregister(session.connection)
    except KeyError:
        pass
    session.connection.close()
    session.closed = True


def refresh_benchmark_interest(
    selector: selectors.BaseSelector, session: BenchmarkSession
) -> None:
    if session.closed:
        return
    events = selectors.EVENT_READ
    if session.output:
        events |= selectors.EVENT_WRITE
    selector.modify(session.connection, events, session)


def service_benchmark_session(
    selector: selectors.BaseSelector,
    session: BenchmarkSession,
    mask: int,
    connection_latencies: LatencySamples,
    message_latencies: LatencySamples,
    completion_deadline_ns: int | None = None,
) -> int:
    completions_before_deadline = 0
    try:
        if mask & selectors.EVENT_WRITE and session.output:
            try:
                sent = session.connection.send(session.output)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                sent = 0
            if sent > 0:
                del session.output[:sent]

        if mask & selectors.EVENT_READ:
            try:
                received = session.connection.recv(65_536)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                received = None
            if received == b"":
                close_benchmark_session(selector, session, "connection closed")
                return completions_before_deadline
            if received:
                session.input.extend(received)

        while True:
            newline = session.input.find(b"\n")
            if newline < 0:
                break
            line = bytes(session.input[:newline])
            del session.input[: newline + 1]
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                close_benchmark_session(selector, session, "backend returned invalid JSON")
                return completions_before_deadline
            response_id = response.get("id") if isinstance(response, dict) else None
            if response_id in session.initial_pending:
                session.initial_pending.remove(response_id)
                if not session.initial_pending and not session.ready:
                    session.ready = True
                    connection_latencies.add(time.perf_counter_ns() - session.started_ns)
            elif response_id in session.pending:
                sent_ns = session.pending.pop(response_id)
                message_latencies.add(time.perf_counter_ns() - sent_ns)
                if (
                    completion_deadline_ns is not None
                    and time.monotonic_ns() <= completion_deadline_ns
                ):
                    completions_before_deadline += 1

        refresh_benchmark_interest(selector, session)
    except (ConnectionError, OSError, ValueError) as error:
        close_benchmark_session(selector, session, str(error))
    return completions_before_deadline


def establish_benchmark_sessions(
    connection_count: int,
    ramp_per_second: float,
    ready_timeout_seconds: float,
    maximum_samples: int,
    connect_workers: int,
) -> tuple[
    selectors.BaseSelector,
    list[BenchmarkSession],
    LatencySamples,
    LatencySamples,
    float,
    float,
    float,
    list[str],
]:
    selector = selectors.DefaultSelector()
    sessions: list[BenchmarkSession] = []
    transport_latencies = LatencySamples(maximum_samples, 0x7A4A5)
    connection_latencies = LatencySamples(maximum_samples, 0xC011EC7)
    message_latencies = LatencySamples(1, 0x51A7)
    errors: list[str] = []
    ramp_started = time.monotonic()
    schedule_elapsed = 0.0
    transport_elapsed = 0.0
    next_connection_index = 0
    pending_connections: dict[
        concurrent.futures.Future[tuple[int, int, socket.socket, int]], int
    ] = {}

    def establish_transport(connection_index: int) -> tuple[int, int, socket.socket, int]:
        started_ns = time.perf_counter_ns()
        connection = connect()
        elapsed_ns = time.perf_counter_ns() - started_ns
        return connection_index, started_ns, connection, elapsed_ns

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=connect_workers,
        thread_name_prefix="qualification-connect",
    ) as executor:
        while next_connection_index < connection_count or pending_connections:
            now = time.monotonic()
            while (
                next_connection_index < connection_count
                and len(pending_connections) < connect_workers
                and now >= ramp_started + next_connection_index / ramp_per_second
            ):
                connection_index = next_connection_index
                future = executor.submit(establish_transport, connection_index)
                pending_connections[future] = connection_index
                next_connection_index += 1
                if next_connection_index == connection_count:
                    schedule_elapsed = time.monotonic() - ramp_started
                if connection_index and connection_index % 1_000 == 0:
                    print(
                        f"progress: scheduled {connection_index} sessions",
                        file=sys.stderr,
                        flush=True,
                    )
                now = time.monotonic()

            completed = [future for future in pending_connections if future.done()]
            for future in completed:
                connection_index = pending_connections.pop(future)
                connection: socket.socket | None = None
                try:
                    (
                        _,
                        started_ns,
                        connection,
                        transport_elapsed_ns,
                    ) = future.result()
                    transport_latencies.add(transport_elapsed_ns)
                    connection.setblocking(False)
                    session = BenchmarkSession(connection, started_ns)
                    subscribe_id = connection_index * 2 + 1
                    authorize_id = subscribe_id + 1
                    session.initial_pending.update((subscribe_id, authorize_id))
                    session.output.extend(
                        encoded_request(
                            subscribe_id,
                            "mining.subscribe",
                            ["qualification/1.0"],
                        )
                    )
                    session.output.extend(
                        encoded_request(
                            authorize_id,
                            "mining.authorize",
                            ["qualification.worker", "x"],
                        )
                    )
                    selector.register(
                        connection,
                        selectors.EVENT_READ | selectors.EVENT_WRITE,
                        session,
                    )
                    sessions.append(session)
                except (ConnectionError, KeyError, OSError, ValueError, ssl.SSLError) as error:
                    if connection is not None:
                        connection.close()
                    if len(errors) < 20:
                        errors.append(f"connection {connection_index}: {error}")

            if next_connection_index == connection_count and not pending_connections:
                break
            if next_connection_index < connection_count and len(pending_connections) < connect_workers:
                next_due = ramp_started + next_connection_index / ramp_per_second
                timeout = min(max(next_due - time.monotonic(), 0.0), 0.05)
            else:
                timeout = 0.01
            for key, mask in selector.select(timeout=timeout):
                service_benchmark_session(
                    selector,
                    key.data,
                    mask,
                    connection_latencies,
                    message_latencies,
                )

    transport_elapsed = time.monotonic() - ramp_started
    ready_deadline = time.monotonic() + ready_timeout_seconds
    while time.monotonic() < ready_deadline:
        pending = [session for session in sessions if not session.ready and not session.closed]
        if not pending:
            break
        for key, mask in selector.select(timeout=0.25):
            service_benchmark_session(
                selector,
                key.data,
                mask,
                connection_latencies,
                message_latencies,
            )

    for session in sessions:
        if not session.ready and not session.closed:
            close_benchmark_session(selector, session, "initial responses timed out")
        if session.error and len(errors) < 20:
            errors.append(session.error)
    ready_elapsed = time.monotonic() - ramp_started
    return (
        selector,
        sessions,
        transport_latencies,
        connection_latencies,
        schedule_elapsed,
        transport_elapsed,
        ready_elapsed,
        errors,
    )


def select_available_session(
    sessions: list[BenchmarkSession],
    start_index: int,
    maximum_pending: int,
) -> tuple[BenchmarkSession | None, int]:
    for offset in range(len(sessions)):
        index = (start_index + offset) % len(sessions)
        session = sessions[index]
        if not session.closed and len(session.pending) < maximum_pending:
            return session, (index + 1) % len(sessions)
    return None, start_index


def run_relay_benchmark(
    selector: selectors.BaseSelector,
    sessions: list[BenchmarkSession],
    duration_seconds: float,
    rate_per_second: float,
    drain_seconds: float,
    maximum_pending: int,
    maximum_samples: int,
    connection_latencies: LatencySamples,
) -> dict[str, object]:
    ready_sessions = [session for session in sessions if session.ready and not session.closed]
    message_latencies = LatencySamples(maximum_samples, 0x5A17)
    if not ready_sessions:
        return {
            "messages_offered": 0,
            "messages_scheduled": 0,
            "messages_completed": 0,
            "messages_completed_in_window": 0,
            "messages_completed_after_window": 0,
            "messages_not_scheduled": 0,
            "messages_pending": 0,
            "response_rate_per_second": 0.0,
            "in_window_response_rate_per_second": 0.0,
            "drained_response_rate_per_second": 0.0,
            "total_response_rate_per_second": 0.0,
            "measurement_elapsed_seconds": 0.0,
            "post_window_elapsed_seconds": 0.0,
            "total_elapsed_seconds": 0.0,
            "latency": latency_summary(message_latencies),
        }

    started_ns = time.monotonic_ns()
    started = started_ns / 1_000_000_000
    completion_deadline_ns = started_ns + int(duration_seconds * 1_000_000_000)
    deadline = completion_deadline_ns / 1_000_000_000
    interval = 1.0 / rate_per_second
    next_message = started
    next_request_id = 1_000_000
    next_session_index = 0
    offered = 0
    scheduled = 0
    not_scheduled = 0
    completed_in_window = 0

    while time.monotonic() < deadline:
        now = time.monotonic()
        due_count = 0
        if now >= next_message:
            due_count = min(
                int((now - next_message) / interval) + 1,
                MAXIMUM_SCHEDULE_BURST,
            )
        for _ in range(due_count):
            offered += 1
            session, next_session_index = select_available_session(
                ready_sessions, next_session_index, maximum_pending
            )
            if session is None:
                not_scheduled += 1
            else:
                request_id = next_request_id
                next_request_id += 1
                session.pending[request_id] = time.perf_counter_ns()
                session.output.extend(
                    encoded_request(
                        request_id,
                        "mining.submit",
                        [
                            "qualification.worker",
                            "job",
                            "00000000",
                            "00000000",
                            "00000000",
                        ],
                    )
                )
                refresh_benchmark_interest(selector, session)
                scheduled += 1
            next_message += interval

        now = time.monotonic()
        wait_seconds = min(
            max(next_message - now, 0.0),
            max(deadline - now, 0.0),
            0.05,
        )
        for key, mask in selector.select(timeout=wait_seconds):
            completed_in_window += service_benchmark_session(
                selector,
                key.data,
                mask,
                connection_latencies,
                message_latencies,
                completion_deadline_ns,
            )

    measurement_elapsed = time.monotonic() - started
    drain_deadline = time.monotonic() + drain_seconds
    while time.monotonic() < drain_deadline:
        pending = sum(len(session.pending) for session in ready_sessions)
        queued = sum(len(session.output) for session in ready_sessions)
        if pending == 0 and queued == 0:
            break
        for key, mask in selector.select(timeout=0.05):
            completed_in_window += service_benchmark_session(
                selector,
                key.data,
                mask,
                connection_latencies,
                message_latencies,
                completion_deadline_ns,
            )

    pending = sum(len(session.pending) for session in ready_sessions)
    total_elapsed = time.monotonic() - started
    post_window_elapsed = max(total_elapsed - duration_seconds, 0.0)
    completed_total = message_latencies.seen
    completed_after_window = completed_total - completed_in_window
    in_window_response_rate = completed_in_window / duration_seconds
    drained_response_rate = (
        completed_total / total_elapsed if total_elapsed > 0.0 else 0.0
    )
    return {
        "messages_offered": offered,
        "messages_scheduled": scheduled,
        "messages_completed": completed_total,
        "messages_completed_in_window": completed_in_window,
        "messages_completed_after_window": completed_after_window,
        "messages_not_scheduled": not_scheduled,
        "messages_pending": pending,
        "response_rate_per_second": in_window_response_rate,
        "in_window_response_rate_per_second": in_window_response_rate,
        "drained_response_rate_per_second": drained_response_rate,
        "total_response_rate_per_second": drained_response_rate,
        "measurement_elapsed_seconds": measurement_elapsed,
        "post_window_elapsed_seconds": post_window_elapsed,
        "total_elapsed_seconds": total_elapsed,
        "latency": latency_summary(message_latencies),
    }


def run_idle_benchmark(
    selector: selectors.BaseSelector,
    sessions: list[BenchmarkSession],
    duration_seconds: float,
    connection_latencies: LatencySamples,
) -> dict[str, object]:
    message_latencies = LatencySamples(1, 0x1D1E)
    deadline = time.monotonic() + duration_seconds
    while time.monotonic() < deadline:
        timeout = min(deadline - time.monotonic(), 0.25)
        for key, mask in selector.select(timeout=max(timeout, 0.0)):
            service_benchmark_session(
                selector,
                key.data,
                mask,
                connection_latencies,
                message_latencies,
            )
    alive = sum(session.ready and not session.closed for session in sessions)
    return {"sessions_alive_after_hold": alive}


def run_stalled_benchmark(
    selector: selectors.BaseSelector,
    sessions: list[BenchmarkSession],
    scenario: str,
    duration_seconds: float,
    drain_seconds: float,
    bytes_per_session: int,
    response_padding_bytes: int,
    before_metrics: dict[str, float],
) -> dict[str, object]:
    ready_sessions = [session for session in sessions if session.ready and not session.closed]
    if scenario == "stalled-client":
        payload = encoded_request(
            2_000_000,
            "mining.submit",
            ["qualification.worker", "job", "00000000", "00000000", "00000000"],
        )
        pressure_bytes_per_operation = max(response_padding_bytes, 1)
        direction = "upstream_to_client"
    else:
        payload = encoded_request(
            2_000_000,
            "mining.submit",
            ["x" * 512, "x" * 512, "x" * 512, "x" * 512, "x" * 512],
        )
        pressure_bytes_per_operation = len(payload)
        direction = "client_to_upstream"
    operations_per_session = math.ceil(bytes_per_session / pressure_bytes_per_operation)

    writers: list[StalledWriteState] = []
    setup_errors: list[str] = []
    for session in ready_sessions:
        try:
            selector.unregister(session.connection)
            if scenario == "stalled-client":
                session.connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_RCVBUF,
                    BACKPRESSURE_RECEIVE_BUFFER_BYTES,
                )
            writer = StalledWriteState(
                session,
                payload,
                operations_per_session,
                pressure_bytes_per_operation,
            )
            selector.register(session.connection, selectors.EVENT_WRITE, writer)
            writers.append(writer)
        except (KeyError, OSError, ValueError) as error:
            if len(setup_errors) < 20:
                setup_errors.append(str(error))
            close_benchmark_session(selector, session)

    queue_rejections_before = before_metrics.get(
        "pool_lb_connections_rejected_queue_limit_total", 0.0
    )
    queued_bytes_before = before_metrics.get("pool_lb_queued_bytes", 0.0)
    queue_high_water_before = before_metrics.get("pool_lb_queued_bytes_high_water", 0.0)
    queue_rejections_observed = queue_rejections_before
    queued_bytes_observed = queued_bytes_before
    maximum_queued_bytes_observed = queued_bytes_before
    queue_high_water_observed = queue_high_water_before
    metric_errors: list[str] = []
    connections_closed = 0
    started = time.monotonic()
    deadline = started + duration_seconds
    next_metrics = started

    while time.monotonic() < deadline:
        now = time.monotonic()
        timeout = min(max(next_metrics - now, 0.0), 0.05)
        for key, _ in selector.select(timeout=timeout):
            writer = key.data
            if not isinstance(writer, StalledWriteState):
                continue
            try:
                sent = writer.session.connection.send(writer.payload[writer.offset :])
                if sent == 0:
                    continue
                writer.generator_bytes_sent += sent
                writer.offset += sent
                if writer.offset == len(writer.payload):
                    writer.offset = 0
                    writer.operations_remaining -= 1
                    writer.operations_sent += 1
                    writer.pressure_bytes_offered += writer.pressure_bytes_per_operation
                    if writer.operations_remaining == 0:
                        selector.unregister(writer.session.connection)
            except ssl.SSLWantReadError:
                selector.modify(
                    writer.session.connection,
                    selectors.EVENT_READ | selectors.EVENT_WRITE,
                    writer,
                )
            except (BlockingIOError, ssl.SSLWantWriteError):
                pass
            except (ConnectionError, OSError, ValueError):
                connections_closed += 1
                close_benchmark_session(selector, writer.session)

        now = time.monotonic()
        if now >= next_metrics:
            observed, metrics_error = scrape_metrics()
            if metrics_error and metrics_error not in metric_errors and len(metric_errors) < 20:
                metric_errors.append(metrics_error)
            queue_rejections_observed = observed.get(
                "pool_lb_connections_rejected_queue_limit_total",
                queue_rejections_observed,
            )
            queued_bytes_observed = observed.get(
                "pool_lb_queued_bytes", queued_bytes_observed
            )
            maximum_queued_bytes_observed = max(
                maximum_queued_bytes_observed, queued_bytes_observed
            )
            queue_high_water_observed = observed.get(
                "pool_lb_queued_bytes_high_water", queue_high_water_observed
            )
            next_metrics = now + BACKPRESSURE_METRICS_INTERVAL_SECONDS
            if queue_rejections_observed > queue_rejections_before:
                break

    elapsed = time.monotonic() - started
    for writer in writers:
        close_benchmark_session(selector, writer.session)

    drain_completed = False
    drain_deadline = time.monotonic() + drain_seconds
    while time.monotonic() < drain_deadline:
        observed, metrics_error = scrape_metrics()
        if metrics_error and metrics_error not in metric_errors and len(metric_errors) < 20:
            metric_errors.append(metrics_error)
        queue_rejections_observed = observed.get(
            "pool_lb_connections_rejected_queue_limit_total", queue_rejections_observed
        )
        queued_bytes_observed = observed.get("pool_lb_queued_bytes", queued_bytes_observed)
        maximum_queued_bytes_observed = max(
            maximum_queued_bytes_observed, queued_bytes_observed
        )
        queue_high_water_observed = observed.get(
            "pool_lb_queued_bytes_high_water", queue_high_water_observed
        )
        if not metrics_error and queued_bytes_observed <= queued_bytes_before:
            drain_completed = True
            break
        time.sleep(BACKPRESSURE_METRICS_INTERVAL_SECONDS)

    return {
        "direction": direction,
        "sessions_started": len(writers),
        "target_pressure_bytes_per_session": bytes_per_session,
        "operations_per_session": operations_per_session,
        "operations_sent": sum(writer.operations_sent for writer in writers),
        "generator_bytes_sent": sum(writer.generator_bytes_sent for writer in writers),
        "pressure_bytes_offered": sum(
            writer.pressure_bytes_offered for writer in writers
        ),
        "connections_closed_while_sending": connections_closed,
        "elapsed_seconds": elapsed,
        "queue": {
            "rejections_before": queue_rejections_before,
            "rejections_observed": queue_rejections_observed,
            "rejections_observed_delta": (
                queue_rejections_observed - queue_rejections_before
            ),
            "bytes_before": queued_bytes_before,
            "bytes_after_close": queued_bytes_observed,
            "maximum_bytes_observed": maximum_queued_bytes_observed,
            "high_water_before": queue_high_water_before,
            "high_water_observed": queue_high_water_observed,
            "high_water_observed_increase": (
                queue_high_water_observed - queue_high_water_before
            ),
            "drained_to_baseline": drain_completed,
        },
        "setup_errors": setup_errors,
        "metrics_errors": metric_errors,
    }


def receive_line(connection: socket.socket) -> bytes:
    received = bytearray()
    while len(received) <= 65_536:
        chunk = connection.recv(4_096)
        if not chunk:
            return bytes(received)
        received.extend(chunk)
        newline = received.find(b"\n")
        if newline >= 0:
            return bytes(received[:newline])
    raise AssertionError("response line exceeded 65536 bytes")


def run_churn_benchmark(
    scenario: str,
    duration_seconds: float,
    rate_per_second: float,
    maximum_samples: int,
    connect_workers: int,
) -> dict[str, object]:
    latencies = LatencySamples(maximum_samples, 0xC4A7)
    started = time.monotonic()
    deadline = started + duration_seconds
    operations_offered = int(math.ceil(duration_seconds * rate_per_second))
    operations_scheduled = 0
    completed = 0
    errors: list[str] = []
    last_schedule_elapsed = 0.0
    pending: dict[concurrent.futures.Future[int], int] = {}

    def run_operation(operation_id: int) -> int:
        operation_started = time.perf_counter_ns()
        with connect() as connection:
            if scenario == "reconnect":
                connection.sendall(
                    encoded_request(
                        operation_id,
                        "mining.subscribe",
                        ["qualification/churn"],
                    )
                )
                response = json.loads(receive_line(connection))
                if response.get("id") != operation_id:
                    raise AssertionError("subscription response id did not match")
            else:
                connection.sendall(b"GET / HTTP/1.1\r\nHost: scanner\r\n\r\n")
                try:
                    received = connection.recv(1)
                except ConnectionResetError:
                    received = b""
                if received:
                    raise AssertionError("malformed request received an edge response")
        return time.perf_counter_ns() - operation_started

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=connect_workers,
        thread_name_prefix="qualification-churn",
    ) as executor:
        while time.monotonic() < deadline or pending:
            now = time.monotonic()
            while (
                now < deadline
                and operations_scheduled < operations_offered
                and len(pending) < connect_workers
                and now >= started + operations_scheduled / rate_per_second
            ):
                operation_id = operations_scheduled + 1
                pending[executor.submit(run_operation, operation_id)] = operation_id
                operations_scheduled += 1
                last_schedule_elapsed = time.monotonic() - started
                now = time.monotonic()

            completed_futures = [future for future in pending if future.done()]
            for future in completed_futures:
                operation_id = pending.pop(future)
                try:
                    latencies.add(future.result())
                    completed += 1
                except (
                    AssertionError,
                    ConnectionError,
                    json.JSONDecodeError,
                    OSError,
                    ValueError,
                ) as error:
                    if len(errors) < 20:
                        errors.append(f"operation {operation_id}: {error}")

            now = time.monotonic()
            if now >= deadline and not pending:
                break
            if (
                now < deadline
                and operations_scheduled < operations_offered
                and len(pending) < connect_workers
            ):
                next_due = started + operations_scheduled / rate_per_second
                sleep_seconds = min(max(next_due - now, 0.0), 0.01)
            else:
                sleep_seconds = 0.001
            if sleep_seconds > 0.0:
                time.sleep(sleep_seconds)

    elapsed = time.monotonic() - started
    operations_not_scheduled = operations_offered - operations_scheduled
    return {
        "operations_offered": operations_offered,
        "operations_scheduled": operations_scheduled,
        "operations_not_scheduled": operations_not_scheduled,
        "operations_attempted": operations_scheduled,
        "operations_completed": completed,
        "operation_failures": operations_scheduled - completed,
        "operation_rate_per_second": completed / elapsed if elapsed > 0.0 else 0.0,
        "schedule_rate_per_second": (
            operations_scheduled / duration_seconds if duration_seconds > 0.0 else 0.0
        ),
        "last_schedule_elapsed_seconds": last_schedule_elapsed,
        "elapsed_seconds": elapsed,
        "establishment_model": "paced_bounded_blocking_worker_pool",
        "connect_workers": connect_workers,
        "latency": latency_summary(latencies),
        "errors": errors,
    }


def qualification_benchmark() -> bool:
    scenario = os.environ.get("BENCH_SCENARIO", "relay")
    if scenario not in BENCHMARK_SCENARIOS:
        raise ValueError(
            "BENCH_SCENARIO must be idle, relay, reconnect, malformed, "
            "stalled-client, or stalled-upstream"
        )
    connection_count = environment_integer("BENCH_CONNECTIONS", 1_000, 1)
    duration_seconds = environment_number("BENCH_DURATION_SECONDS", 30.0, 0.1)
    ramp_per_second = environment_number("BENCH_RAMP_PER_SECOND", 500.0, 0.1)
    rate_per_second = environment_number("BENCH_RATE_PER_SECOND", 1_000.0, 0.1)
    ready_timeout_seconds = environment_number("BENCH_READY_TIMEOUT_SECONDS", 60.0, 1.0)
    drain_seconds = environment_number("BENCH_DRAIN_SECONDS", 10.0, 0.1)
    minimum_rate_ratio = environment_number("BENCH_MINIMUM_RATE_RATIO", 0.90, 0.0)
    if minimum_rate_ratio > 1.0:
        raise ValueError("BENCH_MINIMUM_RATE_RATIO must not exceed 1.0")
    maximum_pending = environment_integer("BENCH_MAX_PENDING_PER_CONNECTION", 4, 1)
    maximum_samples = environment_integer("BENCH_MAX_LATENCY_SAMPLES", 1_000_000, 1)
    connect_workers = environment_integer("BENCH_CONNECT_WORKERS", 16, 1)
    if connect_workers > 256:
        raise ValueError("BENCH_CONNECT_WORKERS must not exceed 256")
    stalled_bytes_per_session = environment_integer(
        "BENCH_STALLED_BYTES_PER_SESSION", 8_388_608, 1
    )
    response_padding_bytes = environment_integer(
        "BENCH_RESPONSE_PADDING_BYTES", 0, 0
    )
    expected_queue_limit_bytes = environment_integer(
        "BENCH_QUEUE_LIMIT_BYTES", 0, 0
    )
    if scenario == "stalled-client" and response_padding_bytes == 0:
        raise ValueError("BENCH_RESPONSE_PADDING_BYTES must be positive for stalled-client")
    if scenario in BACKPRESSURE_SCENARIOS and expected_queue_limit_bytes == 0:
        raise ValueError("BENCH_QUEUE_LIMIT_BYTES must be positive for stalled-peer scenarios")
    require_metrics = os.environ.get("BENCH_REQUIRE_METRICS", "0") == "1"
    if scenario in BACKPRESSURE_SCENARIOS:
        require_metrics = True
    generator_id = os.environ.get("BENCH_GENERATOR_ID", platform.node() or "unknown")

    before_metrics, before_metrics_error = scrape_metrics()
    wall_started = time.time()
    result: dict[str, object] = {
        "schema_version": 1,
        "scenario": scenario,
        "transport": "tls" if USE_TLS else "plain",
        "target": {"host": HOST, "port": PORT, "metrics_url": API_URL},
        "generator": {
            "id": generator_id,
            "hostname": platform.node(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
            "model": "one process and one network namespace",
            "connection_establishment_model": "bounded concurrent blocking worker pool",
            "connection_workers": connect_workers,
        },
        "parameters": {
            "connections": connection_count,
            "duration_seconds": duration_seconds,
            "ramp_per_second": ramp_per_second,
            "rate_per_second": rate_per_second,
            "ready_timeout_seconds": ready_timeout_seconds,
            "drain_seconds": drain_seconds,
            "minimum_rate_ratio": minimum_rate_ratio,
            "maximum_pending_per_connection": maximum_pending,
            "maximum_latency_samples": maximum_samples,
            "connect_workers": connect_workers,
            "stalled_bytes_per_session": stalled_bytes_per_session,
            "response_padding_bytes": response_padding_bytes,
            "expected_queue_limit_bytes": expected_queue_limit_bytes,
        },
        "started_unix_seconds": wall_started,
    }

    passed = True
    errors: list[str] = []
    if scenario in {"idle", "relay", *BACKPRESSURE_SCENARIOS}:
        (
            selector,
            sessions,
            transport_latencies,
            connection_latencies,
            schedule_elapsed,
            transport_elapsed,
            ready_elapsed,
            setup_errors,
        ) = (
            establish_benchmark_sessions(
                connection_count,
                ramp_per_second,
                ready_timeout_seconds,
                maximum_samples,
                connect_workers,
            )
        )
        errors.extend(setup_errors)
        ready_sessions = sum(session.ready and not session.closed for session in sessions)
        connection_result: dict[str, object] = {
            "attempted": connection_count,
            "established": ready_sessions,
            "failed": connection_count - ready_sessions,
            "ramp_schedule_elapsed_seconds": schedule_elapsed,
            "transport_elapsed_seconds": transport_elapsed,
            "ready_elapsed_seconds": ready_elapsed,
            "establishment_rate_per_second": (
                ready_sessions / ready_elapsed if ready_elapsed > 0.0 else 0.0
            ),
            "transport_connect_rate_per_second": (
                len(sessions) / transport_elapsed if transport_elapsed > 0.0 else 0.0
            ),
            "ramp_schedule_rate_per_second": (
                connection_count / schedule_elapsed if schedule_elapsed > 0.0 else 0.0
            ),
            "transport_latency": latency_summary(transport_latencies),
            "ready_latency": latency_summary(connection_latencies),
            "establishment_model": "bounded_blocking_worker_pool",
            "connect_workers": connect_workers,
        }
        if USE_TLS:
            connection_result["tls_handshakes_completed"] = len(sessions)
            connection_result["tls_handshakes_per_second"] = connection_result[
                "transport_connect_rate_per_second"
            ]
        result["connections"] = connection_result
        if (
            connection_count > 1
            and float(connection_result["establishment_rate_per_second"])
            < ramp_per_second * minimum_rate_ratio
        ):
            passed = False
            errors.append(
                "connection ramp missed its offered rate; the generator's bounded connect/TLS "
                "worker cohort may be saturated, so increase BENCH_CONNECT_WORKERS safely or "
                "repeat with multiple independently addressed generators before attributing "
                "the shortfall to the load balancer"
            )
        try:
            if scenario == "relay":
                traffic = run_relay_benchmark(
                    selector,
                    sessions,
                    duration_seconds,
                    rate_per_second,
                    drain_seconds,
                    maximum_pending,
                    maximum_samples,
                    connection_latencies,
                )
                result["traffic"] = traffic
                completed = int(traffic["messages_completed"])
                scheduled = int(traffic["messages_scheduled"])
                achieved_rate = float(traffic["in_window_response_rate_per_second"])
                not_scheduled = int(traffic["messages_not_scheduled"])
                if (
                    completed != scheduled
                    or not_scheduled != 0
                    or achieved_rate < rate_per_second * minimum_rate_ratio
                ):
                    passed = False
            elif scenario == "idle":
                hold = run_idle_benchmark(
                    selector,
                    sessions,
                    duration_seconds,
                    connection_latencies,
                )
                result["hold"] = hold
                if int(hold["sessions_alive_after_hold"]) != ready_sessions:
                    passed = False
            else:
                backpressure = run_stalled_benchmark(
                    selector,
                    sessions,
                    scenario,
                    duration_seconds,
                    drain_seconds,
                    stalled_bytes_per_session,
                    response_padding_bytes,
                    before_metrics,
                )
                result["backpressure"] = backpressure
                errors.extend(backpressure["setup_errors"])
                if backpressure["metrics_errors"]:
                    errors.append("metrics scrape failed during stalled-peer scenario")
                if not bool(backpressure["queue"]["drained_to_baseline"]):
                    passed = False
        finally:
            runtime_failures = sum(bool(session.error) for session in sessions)
            connection_result["failed_during_measurement"] = runtime_failures
            if runtime_failures != 0:
                passed = False
            for session in sessions:
                if session.error and len(errors) < 20 and session.error not in errors:
                    errors.append(session.error)
                close_benchmark_session(selector, session)
            selector.close()
        if ready_sessions != connection_count:
            passed = False
    else:
        churn = run_churn_benchmark(
            scenario,
            duration_seconds,
            rate_per_second,
            maximum_samples,
            connect_workers,
        )
        result["churn"] = churn
        errors.extend(churn["errors"])
        if int(churn["operation_failures"]) != 0:
            passed = False
        if int(churn["operations_not_scheduled"]) != 0:
            passed = False
            errors.append(
                "churn generator missed its offered schedule; the bounded connect/TLS worker "
                "cohort may be saturated, so increase BENCH_CONNECT_WORKERS safely or use "
                "multiple independently addressed generators"
            )
        if float(churn["operation_rate_per_second"]) < rate_per_second * minimum_rate_ratio:
            passed = False
            errors.append(
                "completed churn rate missed the offered rate; inspect operation latency and "
                "generator worker saturation before attributing the shortfall to the load balancer"
            )

    after_metrics, after_metrics_error = scrape_metrics()
    result["metrics"] = {
        "before": before_metrics,
        "after": after_metrics,
        "delta": metric_delta(before_metrics, after_metrics),
        "before_error": before_metrics_error,
        "after_error": after_metrics_error,
    }
    if require_metrics and (before_metrics_error or after_metrics_error):
        passed = False
        errors.append("required Prometheus scrape failed")
    if scenario in BACKPRESSURE_SCENARIOS:
        queue_rejection_delta = after_metrics.get(
            "pool_lb_connections_rejected_queue_limit_total", 0.0
        ) - before_metrics.get("pool_lb_connections_rejected_queue_limit_total", 0.0)
        queue_high_water_before = before_metrics.get(
            "pool_lb_queued_bytes_high_water", 0.0
        )
        queue_high_water_after = after_metrics.get(
            "pool_lb_queued_bytes_high_water", 0.0
        )
        queue_limit_after = after_metrics.get(
            "pool_lb_queued_bytes_limit", float(expected_queue_limit_bytes)
        )
        queue_high_water_ceiling = max(queue_high_water_before, queue_limit_after)
        queue_bytes_after = after_metrics.get("pool_lb_queued_bytes", math.inf)
        queue_bytes_before = before_metrics.get("pool_lb_queued_bytes", 0.0)
        queue_validation = {
            "rejections_delta": queue_rejection_delta,
            "high_water_before": queue_high_water_before,
            "high_water_after": queue_high_water_after,
            "high_water_increase": queue_high_water_after - queue_high_water_before,
            "high_water_ceiling": queue_high_water_ceiling,
            "limit_after": queue_limit_after,
            "bytes_before": queue_bytes_before,
            "bytes_after": queue_bytes_after,
        }
        result["backpressure"]["queue_validation"] = queue_validation
        if queue_rejection_delta < 1.0:
            passed = False
            errors.append("stalled-peer traffic did not exercise the process queue limit")
        if queue_high_water_after > queue_high_water_ceiling:
            passed = False
            errors.append(
                "queued-byte high water increased beyond the larger of its lifetime baseline "
                "and the configured process limit"
            )
        if queue_bytes_after > queue_bytes_before:
            passed = False
            errors.append("queued bytes did not return to the pre-test baseline")
    result["errors"] = errors
    result["finished_unix_seconds"] = time.time()
    result["passed"] = passed
    print(json.dumps(result, separators=(",", ":"), sort_keys=True), flush=True)
    return passed


def load(connection_count: int) -> None:
    request = b'{"id":1,"method":"mining.subscribe","params":["scale/1.0"]}\n'
    connections: list[socket.socket] = []
    selector = selectors.DefaultSelector()
    responses: dict[int, bytearray] = {}
    deadline = time.monotonic() + max(30, connection_count / 100)
    try:
        for connection_index in range(connection_count):
            connection = connect()
            connection.sendall(request)
            connection.setblocking(False)
            connections.append(connection)
            responses[connection.fileno()] = bytearray()
            selector.register(connection, selectors.EVENT_READ)
            if connection_index and connection_index % 1_000 == 0:
                print(f"progress: opened {connection_index} sessions", flush=True)

        remaining = connection_count
        while remaining > 0 and time.monotonic() < deadline:
            for key, _ in selector.select(timeout=1):
                connection = key.fileobj
                buffer = responses[connection.fileno()]
                received = connection.recv(4096)
                if not received:
                    raise AssertionError("load session closed before a response")
                buffer.extend(received)
                newline = buffer.find(b"\n")
                if newline < 0:
                    continue
                response = json.loads(buffer[:newline])
                if response["result"]["backend"] != "primary":
                    raise AssertionError("load session reached the wrong backend")
                selector.unregister(connection)
                remaining -= 1
        if remaining:
            raise AssertionError(f"timed out waiting for {remaining} load responses")

        with urllib.request.urlopen(API_URL, timeout=TIMEOUT_SECONDS) as response:
            metrics = response.read().decode()
        active = metric_value(metrics, "pool_lb_connections_active")
        workers = metric_value(metrics, "pool_lb_io_workers")
        if active < connection_count:
            raise AssertionError(f"expected {connection_count} active sessions, metric has {active}")
        if workers <= 0 or workers >= connection_count:
            raise AssertionError(f"invalid fixed reactor count {workers}")
        print(
            f"ok: {connection_count} concurrent SV1 sessions on {workers} reactor workers",
            flush=True,
        )
    finally:
        selector.close()
        for connection in connections:
            connection.close()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: tester.py expect-primary|expect-secondary|invalid-rejected|"
            "oversized-rejected|certificate-fingerprint|persistent-tls-session|"
            "benchmark|load-N"
        )
    command = sys.argv[1]
    if command == "expect-primary":
        expect_backend("primary")
    elif command == "expect-secondary":
        expect_backend("secondary")
    elif command == "invalid-rejected":
        invalid_rejected()
    elif command == "oversized-rejected":
        oversized_rejected()
    elif command == "certificate-fingerprint":
        certificate_fingerprint()
    elif command == "persistent-tls-session":
        persistent_tls_session()
    elif command == "benchmark":
        try:
            return 0 if qualification_benchmark() else 1
        except Exception as error:
            failure = {
                "schema_version": 1,
                "scenario": os.environ.get("BENCH_SCENARIO", "unknown"),
                "transport": "tls" if USE_TLS else "plain",
                "passed": False,
                "fatal_error": str(error),
            }
            print(json.dumps(failure, separators=(",", ":"), sort_keys=True), flush=True)
            return 1
    elif command.startswith("load-"):
        load(int(command.removeprefix("load-")))
    else:
        raise SystemExit(f"unknown command: {command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
