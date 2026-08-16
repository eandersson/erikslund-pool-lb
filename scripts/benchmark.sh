#!/usr/bin/env bash
# Parameterized qualification harness; results describe this generator and topology only.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f tests/e2e/docker-compose.yml)
SCENARIO="${BENCH_SCENARIO:-relay}"
if [[ "$SCENARIO" == "stalled-client" || "$SCENARIO" == "stalled-upstream" ]]; then
  DEFAULT_CONNECTIONS=4
  DEFAULT_RAMP_PER_SECOND=50
else
  DEFAULT_CONNECTIONS=1000
  DEFAULT_RAMP_PER_SECOND=500
fi
CONNECTIONS="${BENCH_CONNECTIONS:-$DEFAULT_CONNECTIONS}"
DURATION_SECONDS="${BENCH_DURATION_SECONDS:-30}"
RAMP_PER_SECOND="${BENCH_RAMP_PER_SECOND:-$DEFAULT_RAMP_PER_SECOND}"
RATE_PER_SECOND="${BENCH_RATE_PER_SECOND:-1000}"
TLS="${BENCH_TLS:-0}"
MANAGE_STACK="${BENCH_MANAGE_STACK:-1}"
RESULT_DIR="${BENCH_RESULT_DIR:-benchmark-results/$(date -u +%Y%m%dT%H%M%SZ)}"
RESOURCE_INTERVAL_SECONDS="${BENCH_RESOURCE_INTERVAL_SECONDS:-1}"
BACKEND_TUPLES="${BENCH_BACKEND_TUPLES:-1}"
UPSTREAM_SOURCE_ADDRESSES="${BENCH_UPSTREAM_SOURCE_ADDRESSES:-1}"
GENERATOR_SOURCES="${BENCH_GENERATOR_SOURCES:-1}"
GENERATOR_ID="${BENCH_GENERATOR_ID:-generator-1}"
STALLED_BYTES_PER_SESSION="${BENCH_STALLED_BYTES_PER_SESSION:-8388608}"
RESPONSE_PADDING_BYTES="${BENCH_RESPONSE_PADDING_BYTES:-0}"
QUEUE_LIMIT_BYTES="${BENCH_QUEUE_LIMIT_BYTES:-0}"
sampler_pid=""

usage() {
  cat <<'EOF'
Run a measured SV1 qualification scenario through the real release load balancer.

Configuration is through environment variables:
  BENCH_SCENARIO                 idle | relay | reconnect | malformed | stalled-client |
                                 stalled-upstream (default relay)
  BENCH_CONNECTIONS              concurrent sessions for idle/relay (default 1000)
  BENCH_DURATION_SECONDS         measured hold/traffic duration (default 30)
  BENCH_RAMP_PER_SECOND          offered session establishment rate (default 500)
  BENCH_RATE_PER_SECOND          relay messages or churn operations per second (default 1000)
  BENCH_TLS                      0 for SV1, 1 for SV1/TLS (default 0)
  BENCH_RESULT_DIR               artifact directory (default benchmark-results/<UTC>)
  BENCH_MANAGE_STACK             1 for the hermetic stack, 0 for an external target
  BENCH_TARGET_HOST              external target visible inside the tester container
  BENCH_TARGET_PORT              external target port
  BENCH_TARGET_API_URL           external Prometheus URL visible inside the tester container
  BENCH_DOCKER_NETWORK           external tester Docker network (default host)
  BENCH_BACKEND_TUPLES           distinct upstream destination IP:port pairs for preflight
  BENCH_UPSTREAM_SOURCE_ADDRESSES distinct load-balancer source IPs for preflight
  BENCH_GENERATOR_SOURCES        independently addressed generator namespaces for preflight
  BENCH_CONNECT_WORKERS          bounded concurrent connect/TLS worker cohort (default 16)
  BENCH_STALLED_BYTES_PER_SESSION bounded bytes offered toward each stalled direction
  BENCH_RESPONSE_PADDING_BYTES    controlled-backend response padding for external stalled-client
  BENCH_QUEUE_LIMIT_BYTES        expected process queue cap (required for external stalled tests)

The managed hermetic stack is deliberately capped at 20,000 sessions and is not 100k evidence.
Use independently addressed generator namespaces or hosts and enough upstream four-tuples for
deployment qualification; keep one result JSON per generator.
EOF
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "$name must be a positive integer, got: $value" >&2
    exit 2
  fi
}

require_positive_number() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] ||
      ! awk -v value="$value" 'BEGIN { exit !(value > 0) }'; then
    echo "$name must be a positive number, got: $value" >&2
    exit 2
  fi
}

stop_sampler() {
  if [[ -n "$sampler_pid" ]]; then
    kill "$sampler_pid" >/dev/null 2>&1 || true
    wait "$sampler_pid" >/dev/null 2>&1 || true
    sampler_pid=""
  fi
}

cleanup() {
  stop_sampler
  if [[ "$MANAGE_STACK" == "1" ]]; then
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  fi
}

collect_managed_logs() {
  "${COMPOSE[@]}" logs --no-color --no-log-prefix pool-lb pool-primary pool-secondary \
    >"$RESULT_DIR/services.log" 2>&1 || true
}

sample_managed_resources() {
  local -a container_ids
  mapfile -t container_ids < <(
    "${COMPOSE[@]}" ps -q pool-lb pool-primary pool-secondary
  )
  printf 'timestamp_utc\tcontainer_id\tname\tcpu\tmemory\tnetwork_io\tpids\n'
  if [[ "${#container_ids[@]}" -eq 0 ]]; then
    return
  fi
  while true; do
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    docker stats --no-stream \
      --format "${timestamp}\t{{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.PIDs}}" \
      "${container_ids[@]}" || true
    sleep "$RESOURCE_INTERVAL_SECONDS"
  done
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi
if [[ ! "$SCENARIO" =~ ^(idle|relay|reconnect|malformed|stalled-client|stalled-upstream)$ ]]; then
  echo "BENCH_SCENARIO must be idle, relay, reconnect, malformed, stalled-client, or stalled-upstream" >&2
  exit 2
fi
if [[ "$TLS" != "0" && "$TLS" != "1" ]]; then
  echo "BENCH_TLS must be 0 or 1" >&2
  exit 2
fi
if [[ "$MANAGE_STACK" != "0" && "$MANAGE_STACK" != "1" ]]; then
  echo "BENCH_MANAGE_STACK must be 0 or 1" >&2
  exit 2
fi
if [[ "$MANAGE_STACK" == "0" && -z "${BENCH_TARGET_HOST:-}" ]]; then
  echo "BENCH_TARGET_HOST is required when BENCH_MANAGE_STACK=0" >&2
  exit 2
fi
require_positive_integer BENCH_CONNECTIONS "$CONNECTIONS"
require_positive_number BENCH_DURATION_SECONDS "$DURATION_SECONDS"
require_positive_number BENCH_RAMP_PER_SECOND "$RAMP_PER_SECOND"
require_positive_number BENCH_RATE_PER_SECOND "$RATE_PER_SECOND"
require_positive_number BENCH_RESOURCE_INTERVAL_SECONDS "$RESOURCE_INTERVAL_SECONDS"
require_positive_integer BENCH_BACKEND_TUPLES "$BACKEND_TUPLES"
require_positive_integer BENCH_UPSTREAM_SOURCE_ADDRESSES "$UPSTREAM_SOURCE_ADDRESSES"
require_positive_integer BENCH_GENERATOR_SOURCES "$GENERATOR_SOURCES"
require_positive_integer BENCH_STALLED_BYTES_PER_SESSION "$STALLED_BYTES_PER_SESSION"
if [[ "$MANAGE_STACK" == "1" && "$CONNECTIONS" -gt 20000 ]]; then
  echo "The managed fixture is capped at 20,000 sessions; use an external qualification topology." >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
RESULT_DIR=$(cd "$RESULT_DIR" && pwd -P)
trap cleanup EXIT

target_host="${BENCH_TARGET_HOST:-pool-lb}"
if [[ -n "${BENCH_TARGET_PORT:-}" ]]; then
  target_port="$BENCH_TARGET_PORT"
elif [[ "$TLS" == "1" ]]; then
  target_port=3334
else
  target_port=3333
fi
target_api_url="${BENCH_TARGET_API_URL:-}"
require_metrics="${BENCH_REQUIRE_METRICS:-0}"

if [[ "$SCENARIO" == "stalled-client" || "$SCENARIO" == "stalled-upstream" ]]; then
  if [[ "$MANAGE_STACK" == "1" ]]; then
    export E2E_POOL_LB_CONFIG=./pool-lb.backpressure.yml
    QUEUE_LIMIT_BYTES=65536
    if [[ "$SCENARIO" == "stalled-client" ]]; then
      export E2E_RESPONSE_PADDING_BYTES=16384
      export E2E_STALL_AFTER_REQUESTS=0
      RESPONSE_PADDING_BYTES=16384
    else
      export E2E_RESPONSE_PADDING_BYTES=0
      export E2E_STALL_AFTER_REQUESTS=2
      RESPONSE_PADDING_BYTES=0
    fi
  else
    require_positive_integer BENCH_QUEUE_LIMIT_BYTES "$QUEUE_LIMIT_BYTES"
    if [[ -z "$target_api_url" ]]; then
      echo "BENCH_TARGET_API_URL is required for external stalled-peer scenarios" >&2
      exit 2
    fi
    if [[ "$SCENARIO" == "stalled-client" ]]; then
      require_positive_integer BENCH_RESPONSE_PADDING_BYTES "$RESPONSE_PADDING_BYTES"
    fi
  fi
  require_metrics=1
else
  export E2E_POOL_LB_CONFIG=./pool-lb.yml
  export E2E_RESPONSE_PADDING_BYTES=0
  export E2E_STALL_AFTER_REQUESTS=0
fi

{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "scenario=$SCENARIO"
  echo "connections=$CONNECTIONS"
  echo "duration_seconds=$DURATION_SECONDS"
  echo "ramp_per_second=$RAMP_PER_SECOND"
  echo "rate_per_second=$RATE_PER_SECOND"
  echo "tls=$TLS"
  echo "managed_stack=$MANAGE_STACK"
  echo "generator_id=$GENERATOR_ID"
  echo "connect_workers=${BENCH_CONNECT_WORKERS:-16}"
  echo "stalled_bytes_per_session=$STALLED_BYTES_PER_SESSION"
  echo "response_padding_bytes=$RESPONSE_PADDING_BYTES"
  echo "expected_queue_limit_bytes=$QUEUE_LIMIT_BYTES"
  uname -a
  docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}'
} >"$RESULT_DIR/environment.txt" 2>&1

if [[ "$MANAGE_STACK" == "1" ]]; then
  echo "==> Starting the hermetic release stack"
  "${COMPOSE[@]}" build tester
  "${COMPOSE[@]}" up -d --build certs pool-primary pool-secondary pool-lb
  "${COMPOSE[@]}" config >"$RESULT_DIR/compose.yml"
  cp "tests/e2e/${E2E_POOL_LB_CONFIG#./}" "$RESULT_DIR/pool-lb.yml"

  ready=false
  for _ in {1..120}; do
    if curl -fsS --max-time 2 http://127.0.0.1:17778/healthz >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 0.5
  done
  if [[ "$ready" != "true" ]]; then
    collect_managed_logs
    echo "Managed stack did not become ready" >&2
    exit 1
  fi
  if [[ "$TLS" == "1" ]]; then
    target_port=3334
  else
    target_port=3333
  fi
  target_api_url="http://pool-lb:7778/metrics"
  require_metrics=1
  curl -fsS --max-time 5 http://127.0.0.1:17778/metrics \
    >"$RESULT_DIR/metrics-before.prom" || true

  preflight_pid_args=()
  container_id=$("${COMPOSE[@]}" ps -q pool-lb)
  if [[ -n "$container_id" ]]; then
    candidate_pid=$(docker inspect --format '{{.State.Pid}}' "$container_id" 2>/dev/null || true)
    if [[ -n "$candidate_pid" && -r "/proc/$candidate_pid/limits" ]]; then
      preflight_pid_args=(--pid "$candidate_pid")
    fi
  fi
  set +e
  bash scripts/capacity-preflight.sh --max-connections "$CONNECTIONS" \
    --backend-tuples "$BACKEND_TUPLES" \
    --upstream-source-addresses "$UPSTREAM_SOURCE_ADDRESSES" \
    --generator-sources "$GENERATOR_SOURCES" "${preflight_pid_args[@]}" \
    >"$RESULT_DIR/preflight.json" 2>"$RESULT_DIR/preflight.log"
  preflight_status=$?
  set -e
  echo "$preflight_status" >"$RESULT_DIR/preflight.exit-code"

  sample_managed_resources >"$RESULT_DIR/resources.tsv" 2>&1 &
  sampler_pid=$!
else
  echo "==> Building the dependency-free generator for external target $target_host:$target_port"
  docker build -f tests/e2e/Dockerfile.tester -t erikslund-pool-lb-tester .
fi

tester_environment=(
  -e "LB_HOST=$target_host"
  -e "LB_PORT=$target_port"
  -e "LB_TLS=$TLS"
  -e "LB_API_URL=$target_api_url"
  -e "BENCH_SCENARIO=$SCENARIO"
  -e "BENCH_CONNECTIONS=$CONNECTIONS"
  -e "BENCH_DURATION_SECONDS=$DURATION_SECONDS"
  -e "BENCH_RAMP_PER_SECOND=$RAMP_PER_SECOND"
  -e "BENCH_RATE_PER_SECOND=$RATE_PER_SECOND"
  -e "BENCH_GENERATOR_ID=$GENERATOR_ID"
  -e "BENCH_REQUIRE_METRICS=$require_metrics"
  -e "BENCH_READY_TIMEOUT_SECONDS=${BENCH_READY_TIMEOUT_SECONDS:-60}"
  -e "BENCH_DRAIN_SECONDS=${BENCH_DRAIN_SECONDS:-10}"
  -e "BENCH_MINIMUM_RATE_RATIO=${BENCH_MINIMUM_RATE_RATIO:-0.90}"
  -e "BENCH_MAX_PENDING_PER_CONNECTION=${BENCH_MAX_PENDING_PER_CONNECTION:-4}"
  -e "BENCH_MAX_LATENCY_SAMPLES=${BENCH_MAX_LATENCY_SAMPLES:-1000000}"
  -e "BENCH_CONNECT_WORKERS=${BENCH_CONNECT_WORKERS:-16}"
  -e "BENCH_STALLED_BYTES_PER_SESSION=$STALLED_BYTES_PER_SESSION"
  -e "BENCH_RESPONSE_PADDING_BYTES=$RESPONSE_PADDING_BYTES"
  -e "BENCH_QUEUE_LIMIT_BYTES=$QUEUE_LIMIT_BYTES"
)

echo "==> Running $SCENARIO qualification ($CONNECTIONS sessions, ${DURATION_SECONDS}s, TLS=$TLS)"
set +e
if [[ "$MANAGE_STACK" == "1" ]]; then
  "${COMPOSE[@]}" run --rm --no-deps "${tester_environment[@]}" tester benchmark \
    >"$RESULT_DIR/generator.stdout.log" 2>"$RESULT_DIR/generator.stderr.log"
  benchmark_status=$?
else
  docker run --rm --network "${BENCH_DOCKER_NETWORK:-host}" \
    "${tester_environment[@]}" erikslund-pool-lb-tester benchmark \
    >"$RESULT_DIR/generator.stdout.log" 2>"$RESULT_DIR/generator.stderr.log"
  benchmark_status=$?
fi
set -e
stop_sampler

if [[ -s "$RESULT_DIR/generator.stdout.log" ]]; then
  tail -n 1 "$RESULT_DIR/generator.stdout.log" >"$RESULT_DIR/result.json"
else
  printf '{"schema_version":1,"passed":false,"fatal_error":"generator produced no result"}\n' \
    >"$RESULT_DIR/result.json"
  benchmark_status=1
fi

if [[ "$MANAGE_STACK" == "1" ]]; then
  curl -fsS --max-time 5 http://127.0.0.1:17778/metrics \
    >"$RESULT_DIR/metrics-after.prom" || true
  set +e
  bash scripts/capacity-preflight.sh --max-connections "$CONNECTIONS" \
    --backend-tuples "$BACKEND_TUPLES" \
    --upstream-source-addresses "$UPSTREAM_SOURCE_ADDRESSES" \
    --generator-sources "$GENERATOR_SOURCES" "${preflight_pid_args[@]}" \
    >"$RESULT_DIR/postflight.json" 2>"$RESULT_DIR/postflight.log"
  postflight_status=$?
  set -e
  echo "$postflight_status" >"$RESULT_DIR/postflight.exit-code"
  collect_managed_logs
fi
echo "$benchmark_status" >"$RESULT_DIR/benchmark.exit-code"

if [[ "$benchmark_status" -ne 0 ]]; then
  echo "==> QUALIFICATION FAILED; artifacts: $RESULT_DIR" >&2
  tail -n 40 "$RESULT_DIR/generator.stderr.log" >&2 || true
  exit "$benchmark_status"
fi
echo "==> QUALIFICATION PASSED for this generator/topology only"
echo "    artifacts: $RESULT_DIR"
