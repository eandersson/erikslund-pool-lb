#!/usr/bin/env bash
# Run both independent static-analysis gates in the project toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -f docker/Dockerfile -t erikslund-pool-lb-build .
docker run --rm \
  -v "$PWD:/src:ro" \
  -v erikslund-pool-lb-tidy-build:/build \
  --entrypoint /usr/local/bin/clang-tidy.sh \
  erikslund-pool-lb-build
docker run --rm \
  -v "$PWD:/src:ro" \
  --entrypoint /usr/local/bin/cppcheck.sh \
  erikslund-pool-lb-build
