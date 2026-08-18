#!/usr/bin/env bash
# E2E: no valid share is lost under legitimate adversity.
#
# Every scenario below is something a real mining site does to itself - a satellite link, a lossy
# rural uplink, a miner that reads its socket lazily, a whole farm reconnecting after a switch
# reboot. None of them is abuse, so none of them may cost a share. On a solo pool one submit is the
# block, so the pass condition is that the pool received EVERY nonce a miner sent, not most of them.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f tests/e2e/docker-compose.yml)
FAILURES=0

# Distinguishes the three outcomes that matter. A scenario that never ran must never be reported as
# a share-loss result, and an impairment the kernel refused must never be reported as a pass.
run_scenario() {
  local name="$1"
  shift
  local output status
  output=$("$@" 2>&1)
  status=$?
  echo "$output"
  if [ "$status" -eq 0 ] && grep -q '"passed":true' <<<"$output"; then
    echo "    PASS ${name}"
    return 0
  fi
  if [ "$status" -eq 2 ] || grep -q "IMPAIRMENT UNAVAILABLE" <<<"$output"; then
    echo "    UNAVAILABLE ${name}: this kernel has no netem; the scenario proved nothing" >&2
  elif grep -q '"passed":false' <<<"$output"; then
    echo "    FAIL ${name}: shares were lost" >&2
  else
    echo "    ERROR ${name}: the scenario did not run to completion" >&2
  fi
  FAILURES=$((FAILURES + 1))
  return 1
}

cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

# name | netem qdisc arguments | miners | submits each | lazy reader
SCENARIOS=(
  "baseline||8|25|0"
  "satellite-600ms|delay 300ms 40ms distribution normal|6|20|0"
  "lossy-uplink|loss 5%|6|20|0"
  "congested-lte|delay 120ms 60ms distribution normal loss 3% reorder 5% 50%|6|20|0"
  "duplicating-nat|duplicate 2% corrupt 0.1%|6|20|0"
  "lazy-miner|delay 40ms|6|20|1"
)

echo "==> Starting stack"
"${COMPOSE[@]}" up -d --build certs pool-primary pool-secondary pool-lb
"${COMPOSE[@]}" build tester tester-impaired
sleep 4

for scenario in "${SCENARIOS[@]}"; do
  IFS='|' read -r name netem miners submits slow_read <<<"$scenario"
  echo "==> ${name}${netem:+ (netem: ${netem})}"
  E2E_NETEM="$netem" E2E_SCENARIO="$name" E2E_MINERS="$miners" \
    E2E_SUBMITS="$submits" E2E_SLOW_READ="$slow_read" \
    run_scenario "$name" "${COMPOSE[@]}" run --rm --no-deps tester-impaired share-integrity || true
done

echo "==> Reconnect storm: a whole site returning after a switch reboot"
run_scenario reconnect-storm "${COMPOSE[@]}" run --rm --no-deps \
  -e E2E_SCENARIO=reconnect-storm -e E2E_MINERS=64 -e E2E_SUBMITS=4 \
  -e E2E_TIMEOUT_SECONDS=20 tester share-integrity || true

echo "==> Edge counters"
metrics=$(curl -fsS --max-time 5 http://127.0.0.1:17778/metrics)
for counter in \
  pool_lb_connections_rejected_protocol_total \
  pool_lb_connections_rejected_traffic_rate_total \
  pool_lb_connections_rejected_queue_limit_total \
  pool_lb_connections_rejected_ip_limit_total \
  pool_lb_connections_rejected_rate_total; do
  value=$(awk -v name="$counter" '$1 == name {print $2}' <<<"$metrics")
  # A legitimate miner must never be counted as abuse. Anything non-zero here means the edge
  # decided one of the scenarios above was hostile.
  if [ -n "$value" ] && [ "${value%.*}" -ne 0 ]; then
    echo "    FAIL ${counter} = ${value}: legitimate traffic was classified as abuse" >&2
    FAILURES=$((FAILURES + 1))
  else
    echo "    ok ${counter} = ${value:-0}"
  fi
done

if [ "$FAILURES" -ne 0 ]; then
  echo "==> RESILIENCE FAILED (${FAILURES} scenario(s))" >&2
  "${COMPOSE[@]}" logs --no-log-prefix pool-lb | tail -n 40 >&2 || true
  exit 1
fi
echo "==> RESILIENCE PASSED: no share lost in any legitimate scenario"
