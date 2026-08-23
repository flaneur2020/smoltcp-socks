#!/usr/bin/env bash
#
# Bring up the smoltcp-socks forwarder for a single destination on macOS.
#
# Captures all traffic addressed to $DST (default 172.66.0.227) by:
#   1. building + launching smoltcp-socks, which creates a utun device,
#   2. configuring the utun with a point-to-point address,
#   3. installing a /32 host route for $DST that pins it to the utun.
#
# The forwarder terminates TCP connections to *any* (ip, port) seen on the
# utun — it observes the first SYN to each destination port via smoltcp's raw
# socket, lazily creates a listener, and relays the connection through $PROXY
# (default socks5://127.0.0.1:7890). The proxy forwards to a *remote* upstream,
# so its own dial never targets $DST directly — no proxy-route exclusion is
# needed (and none would be correct here).
#
# State (PID + utun name) is written to /tmp so scripts/down.sh can tear it all
# down. Run as:    sudo scripts/up.sh        (TUN creation needs root)

set -euo pipefail

# --- tunables (override via environment) -----------------------------------
DST="${DST:-172.66.0.227}"                       # destination to capture
PROXY="${PROXY:-socks5://127.0.0.1:7890}"        # upstream SOCKS5 proxy
TUN_ADDR="${TUN_ADDR:-198.18.0.1/30}"            # point-to-point addr on the utun
TUN_REMOTE="${TUN_REMOTE:-198.18.0.2}"           # far end of the /30 (addressed at the utun)
MTU="${MTU:-1500}"                               # utun MTU
LOG_LEVEL="${LOG_LEVEL:-info}"                   # trace|debug|info|warn|error
UTUN="${UTUN:-}"                                 # e.g. utun9; empty ⇒ kernel picks

# The gateway the kernel uses for $DST is the far end of the utun's /30 — used
# for the point-to-point address config below. NOTE: the host route itself uses
# `-interface $DEV` (not a gateway): macOS `-ifscope` routes are scoped and
# ignored by unscoped lookups (i.e. by real traffic and `route get`), so they do
# NOT capture traffic into the utun. A `-interface` route on a point-to-point
# link sends packets for $DST straight out the utun, and an unscoped lookup
# (real apps, `route get`) honors it.
TUN_GW="$TUN_REMOTE"

# --- state files -----------------------------------------------------------
PIDFILE="/tmp/smoltcp-socks.pid"
DEVFILE="/tmp/smoltcp-socks.utun"
LOGFILE="${LOGFILE:-/tmp/smoltcp-socks.log}"

c_red() { [ -t 2 ] && printf '\033[31m%s\033[0m' "$1" || printf '%s' "$1"; }
c_grn() { [ -t 2 ] && printf '\033[32m%s\033[0m' "$1" || printf '%s' "$1"; }
c_ylw() { [ -t 2 ] && printf '\033[33m%s\033[0m' "$1" || printf '%s' "$1"; }

die() { printf '%s: %s\n' "$(c_red 'error')" "$*" >&2; exit 1; }
# (note: $* joins args with IFS — a space by default — so multi-arg die works.)

# --- preflight -------------------------------------------------------------
[ "$(uname -s)" = "Darwin" ] || die "this script targets macOS (got $(uname -s))"
[ "$(id -u)" -eq 0 ] || die "must run as root (TUN creation needs privileges) — try: sudo $0 $*"

# Refuse to start if a previous instance is still running.
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    die "another instance appears to be running (pid $(cat "$PIDFILE")); run scripts/down.sh first"
fi

# Resolve the repo root from this script's location, then locate the binary
# (prefer release, fall back to debug). Build as the invoking user so target/
# doesn't end up root-owned.
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN=""
for cand in "$REPO_DIR/target/release/smoltcp-socks" \
            "$REPO_DIR/target/debug/smoltcp-socks"; do
    [ -x "$cand" ] && BIN="$cand" && break
done

if [ -z "$BIN" ]; then
    printf '%s building smoltcp-socks (as %s)…\n' "$(c_ylw '…')" "${SUDO_USER:-$USER}" >&2
    # Build as the invoking user so target/ ownership stays clean.
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" --preserve-env=HOME cargo build --release --manifest-path "$REPO_DIR/Cargo.toml" >&2
    else
        cargo build --release --manifest-path "$REPO_DIR/Cargo.toml" >&2
    fi
    BIN="$REPO_DIR/target/release/smoltcp-socks"
fi
[ -x "$BIN" ] || die "binary not found after build"

# --- launch ----------------------------------------------------------------
# Build the --device spec. Empty UTUN ⇒ `utun://` (kernel picks a free unit).
if [ -n "$UTUN" ]; then
    case "$UTUN" in
        utun*) DEVICE="utun://$UTUN" ;;
        *) die "UTUN must look like `utun9` (got \`$UTUN\`)" ;;
    esac
else
    DEVICE="utun://"
fi

printf '%s launching %s\n' "$(c_ylw '…')" "$BIN $DEVICE --proxy $PROXY" >&2
# Detach into its own session so it survives this script's exit, logging to
# $LOGFILE. The utun is owned by this process and dies with it.
RUST_LOG="$LOG_LEVEL" nohup "$BIN" \
    --device "$DEVICE" \
    --proxy "$PROXY" \
    --mtu "$MTU" \
    --log-level "$LOG_LEVEL" \
    >"$LOGFILE" 2>&1 &
PID=$!
echo "$PID" >"$PIDFILE"

# Wait for the `[TUN] opened <name>` log line, capturing the real utun name
# (the kernel assigns it when DEVICE is `utun://`).
DEVNAME=""
for _ in $(seq 1 40); do
    if [ ! -d "/proc/$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
        cat "$LOGFILE" >&2
        rm -f "$PIDFILE"
        die "smoltcp-socks exited during startup — see $LOGFILE above"
    fi
    # `|| true` + no pipefail here: grep returns 1 (no match yet) on early
    # iterations, and under `set -o pipefail` that would abort the script
    # before the log line ever appears.
    line=$( { grep -E '\[TUN\] opened [A-Za-z0-9]+' "$LOGFILE" 2>/dev/null || true; } | tail -n1)
    if [ -n "$line" ]; then
        DEVNAME=$(printf '%s' "$line" | sed -E 's/.*\[TUN\] opened ([A-Za-z0-9]+).*/\1/')
        break
    fi
    sleep 0.25
done
[ -n "$DEVNAME" ] || { cat "$LOGFILE" >&2; rm -f "$PIDFILE"; die "did not see the TUN-open log line in $LOGFILE"; }
echo "$DEVNAME" >"$DEVFILE"

# --- configure the utun ----------------------------------------------------
# Assign the point-to-point address and bring the interface up. macOS utuns
# start IFF_UP; this sets the address. `set +e` around these so we can report
# the EXACT failing command (the generic `|| die` swallowed the real error).
set +e
ifconfig "$DEVNAME" inet "$TUN_ADDR" "$TUN_REMOTE" up
if [ $? -ne 0 ]; then
    die "ifconfig $DEVNAME inet $TUN_ADDR $TUN_REMOTE up failed" \
        "(is another process holding $DEVNAME? check: ps aux | grep smoltcp-socks)"
fi

# /32 host route for $DST, pointed at the utun. On a point-to-point link the
# `-interface $DEV` form (per `man route`) keeps the route valid and — crucially
# — is an UNSCOPED route, so real app traffic and `route get $DST` honor it.
# (The `-ifscope` form is scoped: it's ignored by unscoped lookups, so it would
# NOT actually capture traffic into the utun — `route get` would still say en0.)
# A host route is more specific than any broader default/prefix, so it wins for
# $DST regardless of the default route. No exclusion route: the proxy dials a
# *remote* upstream (not $DST itself), so its egress takes the normal default
# route and never re-enters the utun.
route add -host "$DST" -interface "$DEVNAME" >/dev/null
if [ $? -ne 0 ]; then
    # A stale host route from a crashed previous run may already claim $DST;
    # delete it (best-effort, any form) then re-add.
    route delete -host "$DST" >/dev/null 2>&1 || true
    route delete -host "$DST" -interface "$DEVNAME" >/dev/null 2>&1 || true
    route add -host "$DST" -interface "$DEVNAME" >/dev/null \
        || die "route add -host $DST -interface $DEVNAME failed" \
               "(existing route? check: netstat -rn | grep $DST)"
fi
set -e

# --- done ------------------------------------------------------------------
printf '%s forwarding %s → %s via %s (pid %s, %s)\n' \
    "$(c_grn '✓')" "$DST" "$PROXY" "$DEVNAME" "$PID" "$LOGFILE"
printf '    %s  %s\n' "$(c_grn '✓')" "utun $DEVNAME configured $TUN_ADDR ↔ $TUN_REMOTE"
printf '    %s  %s\n' "$(c_grn '✓')" "host route: $DST → $DEVNAME (-interface)"
printf '    stop with: scripts/down.sh\n'
