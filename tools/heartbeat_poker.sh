#!/bin/bash
#
# Sticky Honey Bun heartbeat poker.
#
# Periodically issues a SELECT against a designated heartbeat row on one or
# more PostgreSQL endpoints. The read trips honey_bun's output function,
# which emits a heartbeat-tagged log entry. The alert processor treats absence of
# these as a deadman trigger.
#
# Intended for RDS replicas (where bgworkers don't run) and read replicas in
# general. The self-hosted bgworker is sufficient where it can run.
#
# Setup once per cluster (writer):
#   CREATE TABLE shb_heartbeat (id int PRIMARY KEY, honey honey_bun);
#   INSERT INTO shb_heartbeat
#     VALUES (1, 'sticky_honey_bun.heartbeat.external_poker');
#
# Then run this script targeting each replica you want to deadman-watch.

set -euo pipefail

INTERVAL_SECONDS="${SHB_POKER_INTERVAL:-60}"
QUERY="${SHB_POKER_QUERY:-SELECT honey FROM shb_heartbeat WHERE id = 1}"

usage() {
    cat >&2 <<EOF
Usage: $0 [dsn...]

Reads a designated heartbeat row on a fixed interval to keep
sticky_honey_bun deadman alerters alive.

Targets:
  Pass one or more DSNs as arguments, or rely on libpq env vars
  (PGHOST, PGPORT, PGUSER, PGDATABASE, ...). With multiple DSNs the
  script pokes each one per tick.

Environment:
  SHB_POKER_INTERVAL  seconds between pokes (default: 60)
  SHB_POKER_QUERY     SQL to execute (default: read row 1 of shb_heartbeat)

The script logs success/failure to stderr for its own monitoring. It does
not interpret or filter alerts — its only job is to keep the heartbeat
stream alive on hosts that cannot self-tickle.
EOF
    exit 2
}

if [ $# -eq 0 ] && [ -z "${PGHOST:-}" ]; then
    usage
fi

shutdown() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) poker: shutting down" >&2
    exit 0
}
trap shutdown SIGTERM SIGINT

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
    targets=("")  # rely on libpq env
fi

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) poker: starting, ${#targets[@]} target(s), interval=${INTERVAL_SECONDS}s" >&2

while true; do
    for target in "${targets[@]}"; do
        if [ -n "$target" ]; then
            args=("-d" "$target")
            label="$target"
        else
            args=()
            label="${PGHOST:-default}"
        fi
        if psql -X -A -t -v ON_ERROR_STOP=1 "${args[@]}" -c "$QUERY" >/dev/null 2>&1; then
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) poker: ok $label" >&2
        else
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) poker: FAIL $label" >&2
        fi
    done
    sleep "$INTERVAL_SECONDS"
done
