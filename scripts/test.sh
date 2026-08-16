#!/usr/bin/env bash
# Build and run doctest through CTest inside the GCC 16.2 toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -f docker/Dockerfile -t erikslund-pool-lb-build .
docker run --rm \
  -v "$PWD:/src:ro" \
  -v erikslund_pool_lb_test_build:/build \
  erikslund-pool-lb-build \
  bash -lc 'cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Debug -DNATIVE_ARCH=OFF && cmake --build /build -j"$(nproc)" && ctest --test-dir /build --output-on-failure'

