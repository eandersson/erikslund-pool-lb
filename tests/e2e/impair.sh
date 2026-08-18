#!/usr/bin/env bash
# Apply a netem impairment to this container's interface, then run the tester through it.
# E2E_NETEM carries the qdisc arguments, for example "delay 300ms 40ms distribution normal loss 5%".
set -euo pipefail

if [ -n "${E2E_NETEM:-}" ]; then
  # A missing sch_netem module must fail the scenario loudly. Silently running an impairment
  # suite without impairment would report a pass that proves nothing.
  if ! tc qdisc replace dev eth0 root netem ${E2E_NETEM}; then
    echo "IMPAIRMENT UNAVAILABLE: kernel rejected 'netem ${E2E_NETEM}'" >&2
    exit 2
  fi
  echo "impairment active: ${E2E_NETEM}" >&2
fi

exec python3 /usr/local/bin/tester "$@"
