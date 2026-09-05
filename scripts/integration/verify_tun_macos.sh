#!/usr/bin/env bash
#
# Integration verification of the platform TUN open path on macOS.
#
# What this checks (the work wired in src/runtime.rs `open_tun`):
#   1. `--device utun://`        → kernel picks a free utunN; it shows up in
#                                  `ifconfig`; the real name is logged.
#   2. `--device utun://utun9`   → explicit unit is honored (utun9 created).
#   3. `--device utun:// --mtu 1400` → the --mtu flag is threaded through to
#                                  the device (logged as `mtu 1400`).
#   4. `--device tun://tun0`     → fails fast with the clear macOS error
#                                  instead of the crate's opaque `InvalidName`.
#   5. Each run shuts down cleanly on SIGINT (exit 0).
#
# What this does NOT check: a data-path round trip through the real TUN.
# That needs a route into the utun plus the SOCKS5 egress to leave the box (the
# proxy forwards to a remote upstream, so its own dial must not loop back into
# the TUN). The mocked-TUN e2e test (`tests/tun_e2e.rs`) covers the
# data path, including the wildcard-port listening; this script
# covers the real platform open path. The end-to-end forwarding path through a
# real utun is driven by `scripts/up.sh` / `scripts/down.sh`.
#
# Requirements: macOS, sudo (TUN creation needs root), a SOCKS5 proxy already
# listening on $SOCKS_PORT (default 7890). The binary is built as the normal
# user first, then run under sudo so `target/` doesn't end up root-owned.

set -u

BIN="${TARGET_DIR:-target/debug}/smoltcp-socks"
SOCKS_PORT="${SOCKS_PORT:-7890}"
PROXY="socks5://127.0.0.1:${SOCKS_PORT}"

STARTUP_TIMEOUT=10   # seconds to wait for a TUN-open log line
GRACE_TIMEOUT=5      # seconds to wait for clean shutdown after SIGINT

# Colors (disabled if stdout isn't a tty).
if [ -t 1 ]; then
    G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[0m'
else
    G=''; R=''; Y=''; D=''
fi

passed=0
failed=0
tmpdir=$(mktemp -d -t smoltcp-socks-verify)
trap 'rm -rf "$tmpdir"' EXIT

note()  { printf '%s\n' "${Y}… $*${D}"; }
pass()  { printf '%s\n' "${G}✓ PASS${D}: $*"; passed=$((passed+1)); }
fail()  { printf '%s\n' "${R}✗ FAIL${D}: $*"; failed=$((failed+1)); }

# Wait up to $STARTUP_TIMEOUT s for `grep -E "$1"` to match in file `$2`.
wait_for_log() {
    local pattern="$1" file="$2"
    local i
    for ((i=0; i<STARTUP_TIMEOUT*4; i++)); do
        if grep -Eq "$pattern" "$file"; then return 0; fi
        sleep 0.25
    done
    return 1
}

# Warm the sudo timestamp (cached ~5 min on macOS). Called again before each
# graceful_stop so the credential never lapses mid-run. Without this, a `sudo
# -n` that fires after the cache expires fails with "a password is required"
# and the SIGINT is never delivered.
sudo_warm() { sudo -v >/dev/null 2>&1 || sudo -n true 2>/dev/null; }

# Start the binary under sudo, log to $1, args rest. Echoes the PID of the
# *nested* root child (captured via $!), which `sudo` forwards signals to.
start_bg() {
    local log="$1"; shift
    sudo_warm
    sudo -E "$BIN" "$@" >"$log" 2>&1 &
    echo $!
}

# Liveness check that goes through sudo: the child is root, so a plain
# `kill -0` from the non-root shell gets EPERM (indistinguishable from "gone").
proc_alive() {
    sudo kill -0 "$1" 2>/dev/null
}

# Forward SIGINT (sudo forwards it to the child) and wait up to $GRACE_TIMEOUT
# for the process to exit. The exit *code* is an unreliable signal here: `$!`
# is `sudo`'s PID, and sudo's own exit after forwarding a signal is not
# reliably 0. So a "clean shutdown" is verified two ways:
#   (a) the process is gone within the grace window, and
#   (b) the log shows the binary's own shutdown markers
#       (`[MAIN] received interrupt` + `[ENGINE] stopped`).
# `graceful_stop` takes the log file as a second arg for that check.
graceful_stop() {
    local pid="$1" log="$2"
    sudo_warm
    sudo kill -INT "$pid" 2>/dev/null
    local i
    for ((i=0; i<GRACE_TIMEOUT*4; i++)); do
        proc_alive "$pid" || break
        sleep 0.25
    done
    if proc_alive "$pid"; then
        sudo kill -KILL "$pid" 2>/dev/null   # hung — force it
        wait "$pid" 2>/dev/null
        return 1
    fi
    wait "$pid" 2>/dev/null
    # The process exited; now check it logged a clean (non-forced) shutdown.
    grep -Eq '\[MAIN\] received interrupt' "$log" \
        && grep -Eq '\[ENGINE\] stopped' "$log"
}

# ─── preflight ─────────────────────────────────────────────────────────────

note "building smoltcp-socks (as the normal user)…"
if ! cargo build --bin smoltcp-socks 2>"$tmpdir/build.log"; then
    fail "cargo build"
    cat "$tmpdir/build.log"
    exit 1
fi
[ -x "$BIN" ] || { fail "binary not found at $BIN"; exit 1; }

note "checking SOCKS5 proxy on 127.0.0.1:${SOCKS_PORT}…"
if ! nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null; then
    fail "no listener on 127.0.0.1:${SOCKS_PORT} (set SOCKS_PORT / start your proxy)"
    exit 1
fi
pass "proxy reachable"

note "probing sudo (will prompt once if needed)…"
sudo_warm || { fail "sudo is required for TUN creation"; exit 1; }
pass "sudo ready"

# ─── case 1: kernel-picked utun ────────────────────────────────────────────

note "case 1: --device utun:// (kernel picks a free utunN)"
log="$tmpdir/c1.log"
pid=$(start_bg "$log" --device utun:// --proxy "$PROXY")
if wait_for_log '\[TUN\] opened utun[0-9]+ \(mtu 1500\)' "$log"; then
    name=$(grep -Eo 'opened utun[0-9]+' "$log" | head -1 | awk '{print $2}')
    if ifconfig "$name" >/dev/null 2>&1; then
        pass "kernel picked $name and it is present in ifconfig"
    else
        fail "$name logged but not found in ifconfig"
    fi
else
    fail "did not log a kernel-picked utun name"
    tail -n 20 "$log"
fi
if graceful_stop "$pid" "$log" >/dev/null 2>&1; then
    pass "clean SIGINT shutdown"
else
    fail "did not shut down cleanly on SIGINT"
    echo "    alive_now=$(proc_alive "$pid" && echo yes || echo no)"
    echo "    interrupt_marker=$(grep -c 'received interrupt' "$log" 2>/dev/null)  engine_stopped_marker=$(grep -c 'ENGINE.stopped' "$log" 2>/dev/null)"
    echo "    --- last 12 log lines ---"
    tail -n 12 "$log" | sed 's/^/    /'
fi

# ─── case 2: explicit utun unit ────────────────────────────────────────────

note "case 2: --device utun://utun9 (explicit unit)"
log="$tmpdir/c2.log"
pid=$(start_bg "$log" --device utun://utun9 --proxy "$PROXY")
if wait_for_log '\[TUN\] opened utun9 \(mtu 1500\)' "$log"; then
    if ifconfig utun9 >/dev/null 2>&1; then
        pass "utun9 created and present in ifconfig"
    else
        fail "utun9 logged but not found in ifconfig"
    fi
else
    fail "did not log 'opened utun9 (mtu 1500)'"
    tail -n 20 "$log"
fi
graceful_stop "$pid" "$log" >/dev/null 2>&1 && pass "clean SIGINT shutdown" \
    || { fail "did not shut down cleanly on SIGINT"
         echo "    alive_now=$(proc_alive "$pid" && echo yes || echo no)"
         echo "    interrupt_marker=$(grep -c 'received interrupt' "$log" 2>/dev/null)  engine_stopped_marker=$(grep -c 'ENGINE.stopped' "$log" 2>/dev/null)"
         echo "    --- last 12 log lines ---"
         tail -n 12 "$log" | sed 's/^/    /'; }

# ─── case 3: MTU threading ─────────────────────────────────────────────

note "case 3: --device utun:// --mtu 1400 (MTU reaches the device)"
log="$tmpdir/c3.log"
pid=$(start_bg "$log" --device utun:// --proxy "$PROXY" --mtu 1400)
if wait_for_log '\[TUN\] opened utun[0-9]+ \(mtu 1400\)' "$log"; then
    pass "device opened with mtu 1400 (--mtu flag is wired through)"
else
    fail "did not log mtu 1400"
    tail -n 20 "$log"
fi
graceful_stop "$pid" "$log" >/dev/null 2>&1 && pass "clean SIGINT shutdown" \
    || { fail "did not shut down cleanly on SIGINT"
         echo "    alive_now=$(proc_alive "$pid" && echo yes || echo no)"
         echo "    interrupt_marker=$(grep -c 'received interrupt' "$log" 2>/dev/null)  engine_stopped_marker=$(grep -c 'ENGINE.stopped' "$log" 2>/dev/null)"
         echo "    --- last 12 log lines ---"
         tail -n 12 "$log" | sed 's/^/    /'; }

# ─── case 4: clear error for a non-utun name on macOS ──────────────────────

note "case 4: --device tun://tun0 (must fail fast with a clear error)"
log="$tmpdir/c4.log"
# No root needed for the failure (name parsing happens before any syscall),
# but run under sudo anyway for uniform log capture.
pid=$(start_bg "$log" --device tun://tun0 --proxy "$PROXY")
if wait_for_log 'macOS requires a utun name' "$log" \
   && grep -Eq "got \`tun0\`" "$log"; then
    pass "rejected tun0 with the clear macOS utun-name error"
else
    fail "did not produce the expected clear error for tun://tun0"
    tail -n 20 "$log"
fi
graceful_stop "$pid" >/dev/null 2>&1

# ─── summary ───────────────────────────────────────────────────────────────

echo
if [ "$failed" -eq 0 ]; then
    printf '%s\n' "${G}all ${passed} checks passed${D}"
    exit 0
else
    printf '%s\n' "${R}${passed} passed, ${failed} failed${D}"
    exit 1
fi
