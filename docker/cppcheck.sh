#!/usr/bin/env bash
# Independent cppcheck gate for warning, performance, and portability findings.
set -uo pipefail

cd /src
echo "==> $(cppcheck --version) on src/ (warning,performance,portability; exhaustive)"

cppcheck \
    --enable=warning,performance,portability \
    --check-level=exhaustive \
    --std=c++20 \
    --language=c++ \
    --inline-suppr \
    --suppress=missingInclude \
    --suppress=missingIncludeSystem \
    --suppress=normalCheckLevelMaxBranches \
    --error-exitcode=1 \
    --quiet \
    src/
status=$?

if [ "$status" -eq 0 ]; then
    echo "==> OK: cppcheck clean"
else
    echo "==> FAIL: cppcheck reported findings (exit $status)"
fi
exit "$status"
