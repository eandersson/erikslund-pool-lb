#!/usr/bin/env bash
# Build the release binary with the authoritative GCC 16.2 container toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -f docker/Dockerfile -t erikslund-pool-lb-build .
docker run --rm \
  -v "$PWD:/src:ro" \
  -v erikslund_pool_lb_build:/build \
  erikslund-pool-lb-build \
  bash -lc 'cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DNATIVE_ARCH=OFF && cmake --build /build -j"$(nproc)"'

