#!/usr/bin/env bash
# Hold thousands of real proxied SV1 sessions through the release service and selector backend.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f tests/e2e/docker-compose.yml)
CONNECTIONS="${STRESS_CONNECTIONS:-5000}"
RESULT_DIR="${STRESS_RESULT_DIR:-}"

capture_artifacts() {
  local -a container_ids
  if [[ -z "$RESULT_DIR" ]]; then
    return
  fi
  mkdir -p "$RESULT_DIR"
  {
    echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "connections=$CONNECTIONS"
    uname -a
    docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}'
  } >"$RESULT_DIR/environment.txt" 2>&1 || true
  "${COMPOSE[@]}" config >"$RESULT_DIR/compose.yml" 2>&1 || true
  "${COMPOSE[@]}" ps -a >"$RESULT_DIR/compose-ps.txt" 2>&1 || true
  "${COMPOSE[@]}" logs --no-color --no-log-prefix \
    >"$RESULT_DIR/services.log" 2>&1 || true
  curl -fsS --max-time 5 http://127.0.0.1:17778/metrics \
    >"$RESULT_DIR/metrics.prom" 2>"$RESULT_DIR/metrics-error.log" || true
  mapfile -t container_ids < <("${COMPOSE[@]}" ps -aq)
  if [[ "${#container_ids[@]}" -gt 0 ]]; then
    docker stats --no-stream \
      --format '{{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.PIDs}}' \
      "${container_ids[@]}" >"$RESULT_DIR/resources.tsv" 2>&1 || true
  fi
}
cleanup() {
  local status=$?
  trap - EXIT
  capture_artifacts
  if [[ -n "$RESULT_DIR" ]]; then
    echo "$status" >"$RESULT_DIR/exit-code"
  fi
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  exit "$status"
}
failure() {
  echo "Stress test failed: $*" >&2
  "${COMPOSE[@]}" logs --no-log-prefix pool-lb pool-primary | tail -n 80 >&2 || true
  exit 1
}
trap cleanup EXIT

echo "==> Starting stack for ${CONNECTIONS} concurrent SV1 sessions"
"${COMPOSE[@]}" build tester
"${COMPOSE[@]}" up -d --build certs pool-primary pool-secondary pool-lb
sleep 4

"${COMPOSE[@]}" run --rm --no-deps tester "load-${CONNECTIONS}" \
  || failure "${CONNECTIONS} concurrent sessions"

echo "==> STRESS PASSED (${CONNECTIONS} concurrent sessions)"
