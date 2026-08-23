#!/usr/bin/env bash
#
# End-to-end check that smoltcp-socks really forwards a host through the SOCKS5
# proxy over a real macOS utun.
#
# What it does:
#   1. resolve x.com's current A record (the 172.66.0.x Cloudflare edge),
#   2. bring up the forwarder with `scripts/up.sh` for that IP,
#   3. curl https://x.com pinned to that IP, so the traffic *must* traverse the
#      /32 host route → the utun → smoltcp → the SOCKS5 proxy → the internet,
#   4. assert the connection succeeds AND the actor log shows it accepted a TCP
#      connection to port 443 (proving the traffic actually went through us,
#      not around us),
#   5. tear it all down with `scripts/down.sh`.
#
# Requirements: macOS, sudo, a SOCKS5 proxy on $SOCKS_PORT (default 7890) that
# can reach the public internet, and `dig` (ships with macOS).

set -u

SOCKS_PORT="${SOCKS_PORT:-7890}"
PROXY="${PROXY:-socks5://127.0.0.1:${SOCKS_PORT}}"
HOST="${HOST:-x.com}"
CURL_TIMEOUT="${CURL_TIMEOUT:-25}"
# debug log level: the script judges success on log evidence, so we want the
# socks5 handshake + relay lines visible. Override with LOG_LEVEL=info if quiet.
LOG_LEVEL="${LOG_LEVEL:-debug}"

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
UP="$REPO_DIR/scripts/up.sh"
DOWN="$REPO_DIR/scripts/down.sh"
LOGFILE="${LOGFILE:-/tmp/smoltcp-socks.log}"

if [ -t 1 ]; then
    G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; C=$'\033[36m'; D=$'\033[0m'
else
    G=''; R=''; Y=''; C=''; D=''
fi

note() { printf '%s %s\n' "${Y}…${D}" "$*"; }
ok()   { printf '%s %s\n' "${G}✓ PASS${D}" "$*"; }
bad()  { printf '%s %s\n' "${R}✗ FAIL${D}" "$*"; }

fail=0
cleanup() {
    note "tearing down the forwarder…"
    sudo "$DOWN" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ─── preflight ──────────────────────────────────────────────────────────────

[ "$(uname -s)" = "Darwin" ] || { bad "macOS only (got $(uname -s))"; exit 1; }
command -v dig  >/dev/null || { bad "dig not found"; exit 1; }
command -v curl >/dev/null || { bad "curl not found"; exit 1; }
[ -x "$UP" ]   || { bad "scripts/up.sh not executable"; exit 1; }
[ -x "$DOWN" ] || { bad "scripts/down.sh not executable"; exit 1; }

note "checking SOCKS5 proxy at 127.0.0.1:${SOCKS_PORT} can reach the internet…"
if ! curl -sS --socks5-hostname "127.0.0.1:${SOCKS_PORT}" --max-time 8 \
        -o /dev/null -w '' https://example.com 2>/dev/null; then
    bad "proxy at 127.0.0.1:${SOCKS_PORT} is unreachable or can't egress"
    exit 1
fi
ok "proxy is up and egresses to the internet"

# ─── clear any leftover smoltcp-socks from a previous/aborted run ──────────
# A stale process holds its TUN device and (worse) may own $IP's host route,
# which would make up.sh's route add fail. We run as root here, so we can see
# and stop root-owned strays.
note "checking for leftover smoltcp-socks processes…"
LEFTOVER=$(pgrep -f 'smoltcp-socks --device' 2>/dev/null || true)
if [ -n "$LEFTOVER" ]; then
    note "stopping leftover smoltcp-socks pids: ${LEFTOVER//$'\n'/ }"
    # SIGINT first (clean shutdown), then SIGKILL for any survivor.
    for p in $LEFTOVER; do kill -INT "$p" 2>/dev/null || true; done
    sleep 1
    for p in $LEFTOVER; do kill -0 "$p" 2>/dev/null && kill -KILL "$p" 2>/dev/null || true; done
fi
# Drop stale state files so up.sh's pidfile guard doesn't trip on a dead pid.
rm -f /tmp/smoltcp-socks.pid /tmp/smoltcp-socks.utun
ok "no leftover processes"

# ─── resolve the host ──────────────────────────────────────────────────────

note "resolving ${HOST}…"
IP=$(dig +short "${HOST}" A 2>/dev/null | grep -E '^[0-9]+\.' | head -n1)
if [ -z "$IP" ]; then
    bad "could not resolve ${HOST}"
    exit 1
fi
# Sanity: x.com is fronted by Cloudflare; the edge is usually 172.66.0.x. We
# accept whatever dig returned, but warn if it looks unexpected.
note "${HOST} → ${C}${IP}${D}"

# ─── baseline: confirm the IP currently egresses a *normal* interface ───────
BASE_IFACE=$(route get "$IP" 2>/dev/null | awk '/interface:/{print $2; exit}')
note "before: traffic to ${IP} would go via ${BASE_IFACE:-<unknown>}"
case "${BASE_IFACE:-}" in
    utun*)
        bad "a utun ('${BASE_IFACE}') already claims ${IP} — is a previous run still up?"
        exit 1
        ;;
esac

# ─── bring the forwarder up for this IP ─────────────────────────────────────
note "bringing up the forwarder for ${IP} → ${PROXY}…"
if ! DST="$IP" PROXY="$PROXY" LOG_LEVEL="$LOG_LEVEL" sudo -E "$UP"; then
    bad "scripts/up.sh failed"
    exit 1
fi

# Confirm the route now points at our utun.
DEVNAME=$(cat /tmp/smoltcp-socks.utun 2>/dev/null || true)
ROUTE_IFACE=$(route get "$IP" 2>/dev/null | awk '/interface:/{print $2; exit}')
if [ -z "$DEVNAME" ] || [ "$ROUTE_IFACE" != "$DEVNAME" ]; then
    bad "route to ${IP} is on '${ROUTE_IFACE}', expected utun '${DEVNAME}'"
    exit 1
fi
ok "route to ${IP} now via ${DEVNAME}"

# ─── curl through the tunnel ────────────────────────────────────────────────
# --resolve pins x.com to $IP, so curl dials $IP:443 — which the /32 route
# sends into the utun. SNI/Host stay "x.com", so the TLS handshake and HTTP
# request are valid. A 2xx/3xx/4xx server response means the full path works:
# curl → utun → smoltcp → SOCKS5 → internet → x.com edge.
note "curling https://${HOST} (pinned to ${IP}) through the tunnel…"
BODY_FILE="${BODY_FILE:-/tmp/smoltcp-socks.body}"
HTTP_CODE=$(curl -sS --resolve "${HOST}:443:${IP}" \
    --max-time "$CURL_TIMEOUT" \
    -D "${BODY_FILE}.headers" \
    -o "$BODY_FILE" \
    -w '%{http_code}' \
    "https://${HOST}/" 2>/tmp/smoltcp-socks.curl.err)
CURL_RC=$?
CURL_ERR=$(cat /tmp/smoltcp-socks.curl.err 2>/dev/null)
rm -f /tmp/smoltcp-socks.curl.err

if [ "$CURL_RC" -ne 0 ]; then
    bad "curl exited ${CURL_RC}: ${CURL_ERR}"
    note "tail of ${LOGFILE} (socks5 / relay / accept / warn lines):"
    grep -iE 'accepted tcp|first SYN|\[TCP\]|socks5|RELAY|dial|warn|error' "$LOGFILE" 2>/dev/null | tail -25 | sed 's/^/    /'
    note "raw tail:"
    tail -8 "$LOGFILE" 2>/dev/null | sed 's/^/    /'
    exit 1
fi
ok "curl got HTTP ${HTTP_CODE} from ${HOST}"

# ─── log the HTTP response we got back through the tunnel ──────────────────
BODY_SIZE=$(wc -c < "$BODY_FILE" 2>/dev/null | tr -d ' ')
note "response: HTTP ${HTTP_CODE}, ${BODY_SIZE:-0} bytes, headers:"
sed 's/^/    /' "${BODY_FILE}.headers" 2>/dev/null | head -25
note "first 12 lines of the body:"
head -12 "$BODY_FILE" 2>/dev/null | sed 's/^/    /'
rm -f "$BODY_FILE" "${BODY_FILE}.headers"

# ─── prove the traffic actually went through our actor ──────────────────────
note "checking the actor log for the forwarded connection…"
if ! grep -Eq 'accepted tcp.*(port: 443|:443)' "$LOGFILE" 2>/dev/null; then
    bad "actor log shows no accepted TCP connection to :443 — traffic may not have gone through us"
    note "tail of ${LOGFILE}:"
    tail -20 "$LOGFILE" 2>/dev/null
    exit 1
fi
ok "actor accepted a TCP connection to :443 (traffic traversed the utun)"

note "log evidence:"
grep -iE 'accepted tcp|first SYN|TCP.*(443|relay)' "$LOGFILE" 2>/dev/null | tail -6 | sed 's/^/    /'

echo
ok "all checks passed — ${HOST} (${IP}) is forwarded through ${PROXY}"
exit 0
