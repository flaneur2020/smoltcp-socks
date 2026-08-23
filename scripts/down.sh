#!/usr/bin/env bash
#
# Tear down the smoltcp-socks forwarder started by scripts/up.sh.
#
# Sends SIGINT (so the binary shuts down cleanly via its [MAIN]/[ENGINE]
# markers), waits up to a few seconds, then force-kills if hung. Removes the
# /32 host route it installed. The utun itself is destroyed automatically when
# the owning process exits (macOS utuns cannot be `ifconfig destroy`d by hand).
#
# Run as:    sudo scripts/down.sh

set -euo pipefail

PIDFILE="/tmp/smoltcp-socks.pid"
DEVFILE="/tmp/smoltcp-socks.utun"

DST="${DST:-172.66.0.227}"

GRACE_TIMEOUT=6   # seconds to wait for a clean SIGINT shutdown

c_grn() { [ -t 2 ] && printf '\033[32m%s\033[0m' "$1" || printf '%s' "$1"; }
c_ylw() { [ -t 2 ] && printf '\033[33m%s\033[0m' "$1" || printf '%s' "$1"; }
c_red() { [ -t 2 ] && printf '\033[31m%s\033[0m' "$1" || printf '%s' "$1"; }

note() { printf '%s %s\n' "$(c_ylw '…')" "$*" >&2; }
ok()   { printf '%s %s\n' "$(c_grn '✓')" "$*" >&2; }

if [ ! -f "$PIDFILE" ]; then
    note "no pidfile at $PIDFILE — nothing to stop"
    exit 0
fi
PID=$(cat "$PIDFILE" 2>/dev/null || true)
DEVNAME=$(cat "$DEVFILE" 2>/dev/null || true)

# Allow running without root: we can still remove the route only as root, but
# killing a root-owned process also needs root. Warn and try anyway.
if [ "$(id -u)" -ne 0 ]; then
    printf '%s not root — signal/route cleanup may fail; re-run with sudo\n' "$(c_red '!')" >&2
fi

# Forward SIGINT (clean shutdown), then wait. macOS `kill` and the process
# being root make `wait`/exit-code unreliable, so we fall back to SIGKILL,
# mirroring the verify script's approach.
if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
    note "sending SIGINT to pid $PID"
    kill -INT "$PID" 2>/dev/null || true
    gone=0
    for _ in $(seq 1 $((GRACE_TIMEOUT * 4))); do
        kill -0 "$PID" 2>/dev/null || { gone=1; break; }
        sleep 0.25
    done
    if [ "$gone" -ne 1 ]; then
        note "still alive after ${GRACE_TIMEOUT}s — sending SIGKILL"
        kill -KILL "$PID" 2>/dev/null || true
    fi
    ok "stopped pid $PID"
elif [ -n "${PID:-}" ]; then
    ok "pid $PID not running (already gone)"
fi

# Best-effort route removal. up.sh installs an unscoped
# `-host $DST -interface $DEVNAME` route; remove it. Try a couple of forms in
# case the interface is already gone (the process may have exited first).
if [ -n "${DEVNAME:-}" ]; then
    route delete -host "$DST" -interface "$DEVNAME" >/dev/null 2>&1 \
        || route delete -host "$DST" >/dev/null 2>&1 || true
    ok "removed host route for $DST (if present)"
fi

# The utun is torn down by the kernel when the owning process exits; no manual
# `ifconfig destroy` (and macOS rejects one for utuns). Confirm it's gone.
if [ -n "${DEVNAME:-}" ] && ifconfig "$DEVNAME" >/dev/null 2>&1; then
    note "interface $DEVNAME still present — it will vanish once the process fully exits"
fi

rm -f "$PIDFILE" "$DEVFILE"
ok "cleanup complete"
