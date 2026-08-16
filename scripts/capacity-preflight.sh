#!/usr/bin/env bash
# Read-only Linux capacity preflight for a planned pool-lb session count and topology.
set -euo pipefail

MAX_CONNECTIONS=100000
DESCRIPTOR_HEADROOM=4096
BACKEND_TUPLES=1
UPSTREAM_SOURCE_ADDRESSES=1
GENERATOR_SOURCES=1
TARGET_PID="$$"

usage() {
  cat <<'EOF'
Usage: capacity-preflight.sh [options]

Read-only checks against the current Linux host/cgroup:
  --max-connections N             planned simultaneous miner sessions (default 100000)
  --descriptor-headroom N         non-session descriptor reserve (default 4096)
  --backend-tuples N              distinct upstream destination IP:port pairs (default 1)
  --upstream-source-addresses N   load-balancer source IPs used for upstream connects (default 1)
  --generator-sources N           independently addressed generator namespaces/IPs (default 1)
  --pid PID                       process whose limits/cgroup are inspected (default this shell)

The script never changes limits, cgroups, sysctls, or network configuration. JSON is written to
stdout and a short verdict to stderr. Exit status 1 means the observed FD or TCP tuple capacity is
insufficient. Unknown/unavailable host data is reported as a warning rather than invented.
EOF
}

require_nonnegative_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer, got: $value" >&2
    exit 2
  fi
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  require_nonnegative_integer "$name" "$value"
  if [[ "$value" -eq 0 ]]; then
    echo "$name must be greater than zero" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-connections)
      MAX_CONNECTIONS="${2:-}"
      shift 2
      ;;
    --descriptor-headroom)
      DESCRIPTOR_HEADROOM="${2:-}"
      shift 2
      ;;
    --backend-tuples)
      BACKEND_TUPLES="${2:-}"
      shift 2
      ;;
    --upstream-source-addresses)
      UPSTREAM_SOURCE_ADDRESSES="${2:-}"
      shift 2
      ;;
    --generator-sources)
      GENERATOR_SOURCES="${2:-}"
      shift 2
      ;;
    --pid)
      TARGET_PID="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_positive_integer --max-connections "$MAX_CONNECTIONS"
require_nonnegative_integer --descriptor-headroom "$DESCRIPTOR_HEADROOM"
require_positive_integer --backend-tuples "$BACKEND_TUPLES"
require_positive_integer --upstream-source-addresses "$UPSTREAM_SOURCE_ADDRESSES"
require_positive_integer --generator-sources "$GENERATOR_SOURCES"
require_positive_integer --pid "$TARGET_PID"

failures=()
warnings=()

json_escape() {
  local value="$1"
  value=${value//\/\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

json_array() {
  local first=true
  local value
  printf '['
  for value in "$@"; do
    if [[ "$first" == "true" ]]; then
      first=false
    else
      printf ','
    fi
    printf '"%s"' "$(json_escape "$value")"
  done
  printf ']'
}

read_value() {
  local path="$1"
  if [[ -r "$path" ]]; then
    tr -d '\n' <"$path"
  fi
}

limit_is_sufficient() {
  local value="$1"
  local required="$2"
  [[ "$value" == "unlimited" ]] ||
    { [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -ge "$required" ]]; }
}

count_reserved_ports() {
  local reserved="$1"
  local start="$2"
  local end="$3"
  awk -v reserved="$reserved" -v range_start="$start" -v range_end="$end" '
    BEGIN {
      count = split(reserved, entries, ",")
      for (entry_index = 1; entry_index <= count; ++entry_index) {
        if (entries[entry_index] == "")
          continue
        part_count = split(entries[entry_index], bounds, "-")
        low = bounds[1] + 0
        high = part_count == 2 ? bounds[2] + 0 : low
        if (low < range_start)
          low = range_start
        if (high > range_end)
          high = range_end
        for (port = low; port <= high; ++port)
          seen[port] = 1
      }
      print length(seen)
    }
  '
}

count_cpu_set() {
  local cpu_set="$1"
  awk -v cpu_set="$cpu_set" '
    BEGIN {
      total = 0
      count = split(cpu_set, entries, ",")
      for (entry_index = 1; entry_index <= count; ++entry_index) {
        if (entries[entry_index] == "")
          continue
        part_count = split(entries[entry_index], bounds, "-")
        total += part_count == 2 ? bounds[2] - bounds[1] + 1 : 1
      }
      print total
    }
  '
}

sockstat_value() {
  local path="$1"
  local section="$2"
  local field="$3"
  if [[ -r "$path" ]]; then
    awk -v section="$section" -v field="$field" '
      $1 == section {
        for (field_index = 2; field_index < NF; ++field_index) {
          if ($field_index == field) {
            print $(field_index + 1)
            exit
          }
        }
      }
    ' "$path"
  fi
}

protocol_counter() {
  local path="$1"
  local section="$2"
  local counter="$3"
  if [[ -r "$path" ]]; then
    awk -v section="$section" -v counter="$counter" '
      $1 == section && !header_seen {
        for (column = 2; column <= NF; ++column)
          columns[$column] = column
        header_seen = 1
        next
      }
      $1 == section && header_seen {
        if (counter in columns)
          print $(columns[counter])
        exit
      }
    ' "$path"
  fi
}

read_lines() {
  local path="$1"
  if [[ -r "$path" ]]; then
    awk '{ if (NR > 1) printf "; "; printf "%s", $0 } END { if (NR) print "" }' "$path"
  fi
}

required_descriptors=$((MAX_CONNECTIONS * 2 + DESCRIPTOR_HEADROOM))
limits_file="/proc/$TARGET_PID/limits"
nofile_soft="unknown"
nofile_hard="unknown"
if [[ -r "$limits_file" ]]; then
  nofile_soft=$(awk '$1 == "Max" && $2 == "open" && $3 == "files" { print $4; exit }' \
    "$limits_file")
  nofile_hard=$(awk '$1 == "Max" && $2 == "open" && $3 == "files" { print $5; exit }' \
    "$limits_file")
fi
host_file_max=$(read_value /proc/sys/fs/file-max)
host_file_allocated="null"
host_file_unused="null"
host_file_available="null"
if [[ -r /proc/sys/fs/file-nr ]]; then
  read -r host_file_allocated host_file_unused host_file_max_observed \
    </proc/sys/fs/file-nr
  if [[ "$host_file_allocated" =~ ^[0-9]+$ && "$host_file_max_observed" =~ ^[0-9]+$ ]]; then
    host_file_available=$((host_file_max_observed - host_file_allocated))
  else
    host_file_allocated="null"
    host_file_unused="null"
    host_file_available="null"
  fi
fi
target_fd_count="null"
target_fd_path="/proc/$TARGET_PID/fd"
if [[ -d "$target_fd_path" && -r "$target_fd_path" ]]; then
  target_fd_count=0
  for descriptor in "$target_fd_path"/*; do
    if [[ -e "$descriptor" || -L "$descriptor" ]]; then
      ((target_fd_count += 1))
    fi
  done
else
  warnings+=("could not count open descriptors for target PID")
fi

target_status_file="/proc/$TARGET_PID/status"
target_vm_rss_kib="null"
target_threads="null"
target_voluntary_context_switches="null"
target_nonvoluntary_context_switches="null"
if [[ -r "$target_status_file" ]]; then
  target_vm_rss_kib=$(awk '$1 == "VmRSS:" { print $2; exit }' "$target_status_file")
  target_threads=$(awk '$1 == "Threads:" { print $2; exit }' "$target_status_file")
  target_voluntary_context_switches=$(
    awk '$1 == "voluntary_ctxt_switches:" { print $2; exit }' "$target_status_file"
  )
  target_nonvoluntary_context_switches=$(
    awk '$1 == "nonvoluntary_ctxt_switches:" { print $2; exit }' "$target_status_file"
  )
  target_vm_rss_kib=${target_vm_rss_kib:-null}
  target_threads=${target_threads:-null}
  target_voluntary_context_switches=${target_voluntary_context_switches:-null}
  target_nonvoluntary_context_switches=${target_nonvoluntary_context_switches:-null}
else
  warnings+=("could not read process status for target PID")
fi
fd_sufficient="null"
if [[ "$nofile_soft" != "unknown" && "$nofile_hard" != "unknown" ]]; then
  fd_sufficient=true
  if ! limit_is_sufficient "$nofile_soft" "$required_descriptors"; then
    failures+=("RLIMIT_NOFILE soft limit is below the required descriptor count")
    fd_sufficient=false
  fi
  if ! limit_is_sufficient "$nofile_hard" "$required_descriptors"; then
    failures+=("RLIMIT_NOFILE hard limit is below the required descriptor count")
    fd_sufficient=false
  fi
else
  warnings+=("could not read RLIMIT_NOFILE for target PID")
fi
if [[ "$host_file_max" =~ ^[0-9]+$ ]] && [[ "$host_file_max" -lt "$required_descriptors" ]]; then
  failures+=("host fs.file-max is below the required descriptor count")
  fd_sufficient=false
elif [[ -z "$host_file_max" ]]; then
  host_file_max="unknown"
  warnings+=("could not read host fs.file-max")
fi
if [[ "$host_file_available" =~ ^[0-9]+$ && "$target_fd_count" =~ ^[0-9]+$ ]]; then
  additional_descriptors=$((required_descriptors - target_fd_count))
  if [[ "$additional_descriptors" -lt 0 ]]; then
    additional_descriptors=0
  fi
  if [[ "$host_file_available" -lt "$additional_descriptors" ]]; then
    failures+=("host-wide available file handles cannot cover the additional descriptor count")
    fd_sufficient=false
  fi
fi

ephemeral_start="unknown"
ephemeral_end="unknown"
reserved_ports_raw=$(read_value /proc/sys/net/ipv4/ip_local_reserved_ports)
if [[ -r /proc/sys/net/ipv4/ip_local_port_range ]]; then
  read -r ephemeral_start ephemeral_end </proc/sys/net/ipv4/ip_local_port_range
fi
reserved_port_count=0
usable_ports=0
upstream_capacity=0
generator_capacity=0
required_backend_tuples=0
required_generator_sources=0
topology_sufficient="null"
if [[ "$ephemeral_start" =~ ^[0-9]+$ && "$ephemeral_end" =~ ^[0-9]+$ ]] &&
    [[ "$ephemeral_end" -ge "$ephemeral_start" ]]; then
  reserved_port_count=$(count_reserved_ports "$reserved_ports_raw" \
    "$ephemeral_start" "$ephemeral_end")
  usable_ports=$((ephemeral_end - ephemeral_start + 1 - reserved_port_count))
  if [[ "$usable_ports" -gt 0 ]]; then
    capacity_per_backend_set=$((usable_ports * UPSTREAM_SOURCE_ADDRESSES))
    required_backend_tuples=$(((MAX_CONNECTIONS + capacity_per_backend_set - 1) /
      capacity_per_backend_set))
    required_generator_sources=$(((MAX_CONNECTIONS + usable_ports - 1) / usable_ports))
    upstream_capacity=$((usable_ports * UPSTREAM_SOURCE_ADDRESSES * BACKEND_TUPLES))
    generator_capacity=$((usable_ports * GENERATOR_SOURCES))
    topology_sufficient=true
    if [[ "$upstream_capacity" -lt "$MAX_CONNECTIONS" ]]; then
      failures+=("configured upstream source/destination tuple count cannot hold the planned sessions")
      topology_sufficient=false
    fi
    if [[ "$generator_capacity" -lt "$MAX_CONNECTIONS" ]]; then
      failures+=("generator source-address count cannot open the planned simultaneous sessions")
      topology_sufficient=false
    fi
  else
    failures+=("ephemeral port range has no usable ports")
    topology_sufficient=false
  fi
else
  warnings+=("could not read the ephemeral port range")
fi

somaxconn=$(read_value /proc/sys/net/core/somaxconn)
tcp_max_syn_backlog=$(read_value /proc/sys/net/ipv4/tcp_max_syn_backlog)
conntrack_count=$(read_value /proc/sys/net/netfilter/nf_conntrack_count)
conntrack_max=$(read_value /proc/sys/net/netfilter/nf_conntrack_max)
somaxconn=${somaxconn:-unknown}
tcp_max_syn_backlog=${tcp_max_syn_backlog:-unknown}
conntrack_count=${conntrack_count:-unknown}
conntrack_max=${conntrack_max:-unknown}

sockstat_raw=$(read_lines /proc/net/sockstat)
sockstat6_raw=$(read_lines /proc/net/sockstat6)
sockstat_raw=${sockstat_raw:-unknown}
sockstat6_raw=${sockstat6_raw:-unknown}
sockets_used=$(sockstat_value /proc/net/sockstat "sockets:" used)
tcp_inuse=$(sockstat_value /proc/net/sockstat "TCP:" inuse)
tcp_orphan=$(sockstat_value /proc/net/sockstat "TCP:" orphan)
tcp_time_wait=$(sockstat_value /proc/net/sockstat "TCP:" tw)
tcp_allocated=$(sockstat_value /proc/net/sockstat "TCP:" alloc)
tcp_memory_pages=$(sockstat_value /proc/net/sockstat "TCP:" mem)
tcp6_inuse=$(sockstat_value /proc/net/sockstat6 "TCP6:" inuse)
sockets_used=${sockets_used:-null}
tcp_inuse=${tcp_inuse:-null}
tcp_orphan=${tcp_orphan:-null}
tcp_time_wait=${tcp_time_wait:-null}
tcp_allocated=${tcp_allocated:-null}
tcp_memory_pages=${tcp_memory_pages:-null}
tcp6_inuse=${tcp6_inuse:-null}

tcp_active_opens=$(protocol_counter /proc/net/snmp "Tcp:" ActiveOpens)
tcp_passive_opens=$(protocol_counter /proc/net/snmp "Tcp:" PassiveOpens)
tcp_current_established=$(protocol_counter /proc/net/snmp "Tcp:" CurrEstab)
tcp_in_segments=$(protocol_counter /proc/net/snmp "Tcp:" InSegs)
tcp_out_segments=$(protocol_counter /proc/net/snmp "Tcp:" OutSegs)
tcp_retransmitted_segments=$(protocol_counter /proc/net/snmp "Tcp:" RetransSegs)
tcp_fast_retransmits=$(protocol_counter /proc/net/netstat "TcpExt:" TCPFastRetrans)
tcp_slow_start_retransmits=$(
  protocol_counter /proc/net/netstat "TcpExt:" TCPSlowStartRetrans
)
tcp_timeouts=$(protocol_counter /proc/net/netstat "TcpExt:" TCPTimeouts)
tcp_lost_retransmits=$(protocol_counter /proc/net/netstat "TcpExt:" TCPLostRetransmit)
tcp_retransmit_failures=$(protocol_counter /proc/net/netstat "TcpExt:" TCPRetransFail)
tcp_active_opens=${tcp_active_opens:-null}
tcp_passive_opens=${tcp_passive_opens:-null}
tcp_current_established=${tcp_current_established:-null}
tcp_in_segments=${tcp_in_segments:-null}
tcp_out_segments=${tcp_out_segments:-null}
tcp_retransmitted_segments=${tcp_retransmitted_segments:-null}
tcp_fast_retransmits=${tcp_fast_retransmits:-null}
tcp_slow_start_retransmits=${tcp_slow_start_retransmits:-null}
tcp_timeouts=${tcp_timeouts:-null}
tcp_lost_retransmits=${tcp_lost_retransmits:-null}
tcp_retransmit_failures=${tcp_retransmit_failures:-null}

cgroup_path="unknown"
cpu_max="unknown"
cpu_quota_cores="null"
cpuset_effective="unknown"
cpuset_cpu_count="null"
memory_max="unknown"
memory_current="unknown"
cpu_usage_usec=0
cpu_user_usec=0
cpu_system_usec=0
cpu_nr_periods=0
cpu_nr_throttled=0
cpu_throttled_usec=0
memory_events_low=0
memory_events_high=0
memory_events_max=0
memory_events_oom=0
memory_events_oom_kill=0
memory_events_oom_group_kill=0
if [[ -r "/proc/$TARGET_PID/cgroup" ]]; then
  cgroup_relative=$(awk -F: '$1 == "0" { print $3; exit }' "/proc/$TARGET_PID/cgroup")
  if [[ -n "$cgroup_relative" && -d "/sys/fs/cgroup$cgroup_relative" ]]; then
    cgroup_path="$cgroup_relative"
    cgroup_root="/sys/fs/cgroup$cgroup_relative"
    cpu_max=$(read_value "$cgroup_root/cpu.max")
    cpu_max=${cpu_max:-unknown}
    if [[ "$cpu_max" != "unknown" ]]; then
      read -r cpu_quota cpu_period <<<"$cpu_max"
      if [[ "$cpu_quota" != "max" && "$cpu_quota" =~ ^[0-9]+$ &&
          "$cpu_period" =~ ^[0-9]+$ && "$cpu_period" -gt 0 ]]; then
        cpu_quota_cores=$(awk -v quota="$cpu_quota" -v period="$cpu_period" \
          'BEGIN { printf "%.3f", quota / period }')
      fi
    fi
    cpuset_effective=$(read_value "$cgroup_root/cpuset.cpus.effective")
    if [[ -z "$cpuset_effective" ]]; then
      cpuset_effective=$(read_value "$cgroup_root/cpuset.cpus")
    fi
    cpuset_effective=${cpuset_effective:-unknown}
    if [[ "$cpuset_effective" != "unknown" ]]; then
      cpuset_cpu_count=$(count_cpu_set "$cpuset_effective")
    fi
    memory_max=$(read_value "$cgroup_root/memory.max")
    memory_max=${memory_max:-unknown}
    memory_current=$(read_value "$cgroup_root/memory.current")
    memory_current=${memory_current:-unknown}
    if [[ -r "$cgroup_root/cpu.stat" ]]; then
      cpu_usage_usec=$(awk '$1 == "usage_usec" { print $2 }' "$cgroup_root/cpu.stat")
      cpu_user_usec=$(awk '$1 == "user_usec" { print $2 }' "$cgroup_root/cpu.stat")
      cpu_system_usec=$(awk '$1 == "system_usec" { print $2 }' "$cgroup_root/cpu.stat")
      cpu_nr_periods=$(awk '$1 == "nr_periods" { print $2 }' "$cgroup_root/cpu.stat")
      cpu_nr_throttled=$(awk '$1 == "nr_throttled" { print $2 }' "$cgroup_root/cpu.stat")
      cpu_throttled_usec=$(awk '$1 == "throttled_usec" { print $2 }' "$cgroup_root/cpu.stat")
      cpu_usage_usec=${cpu_usage_usec:-0}
      cpu_user_usec=${cpu_user_usec:-0}
      cpu_system_usec=${cpu_system_usec:-0}
      cpu_nr_periods=${cpu_nr_periods:-0}
      cpu_nr_throttled=${cpu_nr_throttled:-0}
      cpu_throttled_usec=${cpu_throttled_usec:-0}
    fi
    if [[ -r "$cgroup_root/memory.events" ]]; then
      memory_events_low=$(awk '$1 == "low" { print $2 }' "$cgroup_root/memory.events")
      memory_events_high=$(awk '$1 == "high" { print $2 }' "$cgroup_root/memory.events")
      memory_events_max=$(awk '$1 == "max" { print $2 }' "$cgroup_root/memory.events")
      memory_events_oom=$(awk '$1 == "oom" { print $2 }' "$cgroup_root/memory.events")
      memory_events_oom_kill=$(awk '$1 == "oom_kill" { print $2 }' "$cgroup_root/memory.events")
      memory_events_oom_group_kill=$(
        awk '$1 == "oom_group_kill" { print $2 }' "$cgroup_root/memory.events"
      )
      memory_events_low=${memory_events_low:-0}
      memory_events_high=${memory_events_high:-0}
      memory_events_max=${memory_events_max:-0}
      memory_events_oom=${memory_events_oom:-0}
      memory_events_oom_kill=${memory_events_oom_kill:-0}
      memory_events_oom_group_kill=${memory_events_oom_group_kill:-0}
      if [[ "$memory_events_oom_kill" -gt 0 ]]; then
        warnings+=("target cgroup reports prior OOM kills; compare counters before and after a run")
      fi
    fi
  else
    warnings+=("cgroup v2 path is unavailable for the target PID")
  fi
else
  warnings+=("could not read cgroup membership for target PID")
fi

passed=true
if [[ "${#failures[@]}" -ne 0 ]]; then
  passed=false
fi

cat <<EOF
{
  "schema_version": 1,
  "passed": $passed,
  "target": {"pid": $TARGET_PID, "max_connections": $MAX_CONNECTIONS},
  "process": {
    "open_file_descriptors": $target_fd_count,
    "vm_rss_kib": $target_vm_rss_kib,
    "threads": $target_threads,
    "voluntary_context_switches": $target_voluntary_context_switches,
    "nonvoluntary_context_switches": $target_nonvoluntary_context_switches
  },
  "file_descriptors": {
    "required": $required_descriptors,
    "headroom": $DESCRIPTOR_HEADROOM,
    "soft_limit": "$(json_escape "$nofile_soft")",
    "hard_limit": "$(json_escape "$nofile_hard")",
    "host_file_max": "$(json_escape "$host_file_max")",
    "host_file_allocated": $host_file_allocated,
    "host_file_unused": $host_file_unused,
    "host_file_available": $host_file_available,
    "sufficient": $fd_sufficient
  },
  "tcp_ports": {
    "range_start": "$(json_escape "$ephemeral_start")",
    "range_end": "$(json_escape "$ephemeral_end")",
    "reserved": "$(json_escape "$reserved_ports_raw")",
    "reserved_in_range": $reserved_port_count,
    "usable_per_source_destination_tuple": $usable_ports,
    "backend_destination_tuples": $BACKEND_TUPLES,
    "upstream_source_addresses": $UPSTREAM_SOURCE_ADDRESSES,
    "upstream_capacity": $upstream_capacity,
    "required_backend_destination_tuples": $required_backend_tuples,
    "generator_sources": $GENERATOR_SOURCES,
    "generator_capacity": $generator_capacity,
    "required_generator_sources": $required_generator_sources,
    "sufficient": $topology_sufficient
  },
  "cgroup": {
    "path": "$(json_escape "$cgroup_path")",
    "cpu_max": "$(json_escape "$cpu_max")",
    "cpu_quota_cores": $cpu_quota_cores,
    "cpuset_cpus_effective": "$(json_escape "$cpuset_effective")",
    "cpuset_cpu_count": $cpuset_cpu_count,
    "cpu_stat": {
      "usage_usec": $cpu_usage_usec,
      "user_usec": $cpu_user_usec,
      "system_usec": $cpu_system_usec,
      "nr_periods": $cpu_nr_periods,
      "nr_throttled": $cpu_nr_throttled,
      "throttled_usec": $cpu_throttled_usec
    },
    "memory_max": "$(json_escape "$memory_max")",
    "memory_current": "$(json_escape "$memory_current")",
    "memory_events": {
      "low": $memory_events_low,
      "high": $memory_events_high,
      "max": $memory_events_max,
      "oom": $memory_events_oom,
      "oom_kill": $memory_events_oom_kill,
      "oom_group_kill": $memory_events_oom_group_kill
    }
  },
  "kernel": {
    "somaxconn": "$(json_escape "$somaxconn")",
    "tcp_max_syn_backlog": "$(json_escape "$tcp_max_syn_backlog")",
    "nf_conntrack_count": "$(json_escape "$conntrack_count")",
    "nf_conntrack_max": "$(json_escape "$conntrack_max")",
    "sockstat": {
      "raw": "$(json_escape "$sockstat_raw")",
      "sockets_used": $sockets_used,
      "tcp_inuse": $tcp_inuse,
      "tcp_orphan": $tcp_orphan,
      "tcp_time_wait": $tcp_time_wait,
      "tcp_allocated": $tcp_allocated,
      "tcp_memory_pages": $tcp_memory_pages
    },
    "sockstat6": {
      "raw": "$(json_escape "$sockstat6_raw")",
      "tcp6_inuse": $tcp6_inuse
    },
    "tcp_counters": {
      "active_opens": $tcp_active_opens,
      "passive_opens": $tcp_passive_opens,
      "current_established": $tcp_current_established,
      "in_segments": $tcp_in_segments,
      "out_segments": $tcp_out_segments,
      "retransmitted_segments": $tcp_retransmitted_segments,
      "fast_retransmits": $tcp_fast_retransmits,
      "slow_start_retransmits": $tcp_slow_start_retransmits,
      "timeouts": $tcp_timeouts,
      "lost_retransmits": $tcp_lost_retransmits,
      "retransmit_failures": $tcp_retransmit_failures
    }
  },
  "failures": $(json_array "${failures[@]}"),
  "warnings": $(json_array "${warnings[@]}")
}
EOF

if [[ "$passed" == "true" ]]; then
  echo "capacity preflight: PASS for observed FD and TCP tuple limits" >&2
  exit 0
fi
echo "capacity preflight: FAIL (${#failures[@]} blocking finding(s))" >&2
for failure in "${failures[@]}"; do
  echo "  - $failure" >&2
done
exit 1
