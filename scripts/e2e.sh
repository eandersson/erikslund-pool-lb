#!/usr/bin/env bash
# E2E: real SV1/SV1-TLS edge, protocol rejection, primary failure, fallback, and recovery.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f tests/e2e/docker-compose.yml)
persistent_output=""
tls_reload_wait_seconds=30

cleanup() {
  if [[ -n "$persistent_output" ]]; then
    rm -f "$persistent_output"
  fi
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
failure() {
  echo "E2E failed: $*" >&2
  "${COMPOSE[@]}" logs --no-log-prefix pool-lb | tail -n 40 >&2 || true
  exit 1
}
trap cleanup EXIT

tester() {
  "${COMPOSE[@]}" run --rm --no-deps tester "$@" || failure "tester $*"
}

tls_tester() {
  "${COMPOSE[@]}" run --rm --no-deps -e LB_PORT=3334 -e LB_TLS=1 tester "$@" \
    || failure "TLS tester $*"
}

tls_reload_metric() {
  local result="$1"
  curl -fsS --max-time 2 http://127.0.0.1:17778/metrics 2>/dev/null \
    | awk -v expected="pool_lb_tls_certificate_reloads_total{result=\"${result}\"}" \
      '$1 == expected {print int($2)}'
}

wait_for_tls_reload_increment() {
  local result="$1"
  local previous_count="$2"
  local deadline=$((SECONDS + tls_reload_wait_seconds))
  local current_count=""
  while ((SECONDS < deadline)); do
    current_count=$(tls_reload_metric "$result" || true)
    if [[ "$current_count" =~ ^[0-9]+$ ]] && ((current_count > previous_count)); then
      return
    fi
    sleep 0.1
  done
  failure "timed out waiting for ${result} TLS reload after generation ${previous_count}"
}

echo "==> Starting the real load balancer, TLS generator, and fake pools"
"${COMPOSE[@]}" build tester
"${COMPOSE[@]}" up -d --build certs pool-primary pool-secondary pool-lb
sleep 4

echo "==> Plain SV1 and edge rejection"
tester expect-primary
tester invalid-rejected
tester oversized-rejected

echo "==> TLS-terminated SV1"
tls_tester expect-primary

echo "==> TLS certificate rotation preserves established sessions"
initial_fingerprint=$(tls_tester certificate-fingerprint | tail -n 1)
initial_tls_metrics=$(curl -fsS --max-time 5 http://127.0.0.1:17778/metrics) \
  || failure "GET /metrics before TLS rotation"
initial_expiry=$(awk '$1 == "pool_lb_tls_certificate_expiry_timestamp_seconds{listener=\"sv1-tls\"}" {print $2}' \
  <<<"$initial_tls_metrics")
[[ -n "$initial_expiry" ]] || failure "TLS certificate expiry metric missing"
initial_reload_success=$(awk \
  '$1 == "pool_lb_tls_certificate_reloads_total{result=\"success\"}" {print int($2)}' \
  <<<"$initial_tls_metrics")
initial_reload_failure=$(awk \
  '$1 == "pool_lb_tls_certificate_reloads_total{result=\"failure\"}" {print int($2)}' \
  <<<"$initial_tls_metrics")
[[ "$initial_reload_success" =~ ^[0-9]+$ ]] \
  || failure "successful TLS reload metric missing before rotation"
[[ "$initial_reload_failure" =~ ^[0-9]+$ ]] \
  || failure "failed TLS reload metric missing before rotation"
current_time=$(date +%s)
minimum_expected_lifetime_seconds=82800
maximum_expected_lifetime_seconds=90000
[[ "$initial_expiry" -ge $((current_time + minimum_expected_lifetime_seconds)) ]] \
  || failure "initial TLS certificate expiry is unexpectedly near"
[[ "$initial_expiry" -le $((current_time + maximum_expected_lifetime_seconds)) ]] \
  || failure "initial TLS certificate expiry is unexpectedly far away"
persistent_output=$(mktemp)
"${COMPOSE[@]}" run --rm --no-deps -e LB_PORT=3334 -e LB_TLS=1 \
  tester persistent-tls-session >"$persistent_output" 2>&1 &
persistent_tls_tester=$!
session_ready=false
for _ in {1..120}; do
  if grep -q '^ok: persistent TLS session established$' "$persistent_output"; then
    session_ready=true
    break
  fi
  if ! kill -0 "$persistent_tls_tester" 2>/dev/null; then
    cat "$persistent_output" >&2
    failure "persistent TLS tester exited before establishing a session"
  fi
  sleep 0.25
done
if [[ "$session_ready" != true ]]; then
  cat "$persistent_output" >&2
  failure "persistent TLS session did not become active"
fi

"${COMPOSE[@]}" run --rm --no-deps --entrypoint sh certs -c \
  'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tls/key.pem.next >/dev/null 2>&1 && mv /tls/key.pem.next /tls/key.pem' \
  || failure "write mismatched TLS key"
"${COMPOSE[@]}" kill --signal SIGHUP pool-lb >/dev/null
wait_for_tls_reload_increment failure "$initial_reload_failure"
failed_reload_fingerprint=$(tls_tester certificate-fingerprint | tail -n 1)
[[ "$failed_reload_fingerprint" == "$initial_fingerprint" ]] \
  || failure "failed TLS reload replaced the active certificate"
failed_reload_expiry=$(curl -fsS --max-time 5 http://127.0.0.1:17778/metrics \
  | awk '$1 == "pool_lb_tls_certificate_expiry_timestamp_seconds{listener=\"sv1-tls\"}" {print $2}')
[[ "$failed_reload_expiry" == "$initial_expiry" ]] \
  || failure "failed TLS reload replaced the active certificate expiry"
if ! kill -0 "$persistent_tls_tester" 2>/dev/null; then
  cat "$persistent_output" >&2
  failure "established TLS session closed during failed certificate reload"
fi

"${COMPOSE[@]}" run --rm --no-deps --entrypoint sh certs -c \
  'openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 -subj /CN=pool-lb-reloaded -addext subjectAltName=DNS:pool-lb -keyout /tls/key.pem.next -out /tls/cert.pem.next >/dev/null 2>&1 && mv /tls/key.pem.next /tls/key.pem && mv /tls/cert.pem.next /tls/cert.pem' \
  || failure "rotate TLS certificate"
"${COMPOSE[@]}" kill --signal SIGHUP pool-lb >/dev/null
wait_for_tls_reload_increment success "$initial_reload_success"
reloaded_fingerprint=$(tls_tester certificate-fingerprint | tail -n 1)
[[ "$reloaded_fingerprint" != "$initial_fingerprint" ]] \
  || failure "successful TLS reload kept the old certificate"
if ! wait "$persistent_tls_tester"; then
  cat "$persistent_output" >&2
  failure "established TLS session did not survive rotation"
fi
cat "$persistent_output"

reload_metrics=$(curl -fsS --max-time 5 http://127.0.0.1:17778/metrics) \
  || failure "GET /metrics after TLS rotation"
reload_success=$(awk \
  '$1 == "pool_lb_tls_certificate_reloads_total{result=\"success\"}" {print int($2)}' \
  <<<"$reload_metrics")
reload_failure=$(awk \
  '$1 == "pool_lb_tls_certificate_reloads_total{result=\"failure\"}" {print int($2)}' \
  <<<"$reload_metrics")
[[ "$reload_success" -eq $((initial_reload_success + 1)) ]] \
  || failure "successful TLS reload metric did not increase exactly once"
[[ "$reload_failure" -eq $((initial_reload_failure + 1)) ]] \
  || failure "failed TLS reload metric did not increase exactly once"
reloaded_expiry=$(awk '$1 == "pool_lb_tls_certificate_expiry_timestamp_seconds{listener=\"sv1-tls\"}" {print $2}' \
  <<<"$reload_metrics")
[[ "$reloaded_expiry" -gt "$initial_expiry" ]] \
  || failure "successful TLS reload did not update the certificate expiry"

echo "==> Operational endpoints"
status=$(curl -fsS --max-time 5 http://127.0.0.1:17778/) || failure "GET /"
metrics=$(curl -fsS --max-time 5 http://127.0.0.1:17778/metrics) || failure "GET /metrics"
"${COMPOSE[@]}" exec -T pool-lb erikslund-pool-lb --health-check 127.0.0.1:7778 \
  || failure "native health probe"
grep -q "TLS CERTIFICATE EXPIRING" <<<"$status" \
  || failure "status page certificate warning missing"
grep -q 'TLS sv1-tls certificate</td><td class="warn">expires ' <<<"$status" \
  || failure "status page TLS certificate expiry missing"
grep -q "pool_lb_connections_rejected_protocol_total 2" <<<"$metrics" \
  || failure "protocol rejection metric missing"
grep -q 'pool_lb_backend_up{pool="primary",backend="pool-primary"} 1' <<<"$metrics" \
  || failure "primary health metric missing"
grep -q 'pool_lb_backend_connection_attempts_total' <<<"$metrics" \
  || failure "backend attempt metric missing"

echo "==> Primary loss routes new sessions to the secondary pool"
"${COMPOSE[@]}" stop pool-primary
sleep 4
tester expect-secondary

echo "==> Primary recovery reclaims new sessions"
"${COMPOSE[@]}" start pool-primary
sleep 4
tester expect-primary

echo "==> E2E PASSED"
