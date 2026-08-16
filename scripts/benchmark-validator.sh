#!/usr/bin/env bash
# Build and run the standalone SV1 validator throughput benchmark with GCC 16.2.
set -euo pipefail
cd "$(dirname "$0")/.."

ITERATIONS="${1:-5000000}"
IMAGE="erikslund-pool-lb-build"
if [[ ! "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: $0 [positive-iteration-count]" >&2
  exit 2
fi

docker build -f docker/Dockerfile -t "$IMAGE" .
docker run --rm -v "$PWD:/src:ro" "$IMAGE" bash -lc '
  g++ -std=c++26 -O3 -DNDEBUG -I/src/src \
    /src/benchmarks/validator_benchmark.cpp /src/src/stratum/validator.cpp \
    -Wl,--no-as-needed -lmimalloc -Wl,--as-needed -o /tmp/validator-benchmark
  /tmp/validator-benchmark '"$ITERATIONS"'
'
