#!/usr/bin/env bash
# Setup for the TLS 1.2 decryption demo GIF (invoked from the vhs tape, hidden).
# Backs up the user's netwatch config, writes a demo config (keylog + Packets
# tab + BPF pinned to example.com so ambient HTTPS doesn't evict our flow), and
# schedules the traffic generator to start AFTER a short delay — so netwatch is
# already capturing when the TLS handshake happens (otherwise it misses the
# ClientHello and can't derive keys).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
KEYLOG="/tmp/netwatch-demo-keylog.txt"
CFG="$HOME/Library/Application Support/netwatch/config.toml"
[ "$(uname)" = "Darwin" ] || CFG="$HOME/.config/netwatch/config.toml"

mkdir -p "$(dirname "$CFG")"
[ -f "$CFG" ] && cp "$CFG" "$CFG.demobak"
: > "$KEYLOG"

IP="$(python3 -c "import socket;print(socket.gethostbyname('example.com'))")"
cat > "$CFG" <<EOF
default_tab = "packets"
capture_interface = "en0"
bpf_filter = "host $IP and tcp port 443"
tls_keylog_path = "$KEYLOG"
refresh_rate_ms = 500
EOF

# Generator waits ~4s so the TUI (launched right after this script) is capturing
# before the handshake. Runs detached; its stderr goes to a log.
( sleep 4; SSLKEYLOGFILE="$KEYLOG" python3 "$HERE/gen_tls12.py" example.com \
    >/tmp/netwatch-demo-gen.out 2>/tmp/netwatch-demo-gen.err ) &
echo "demo setup done (traffic starts in ~4s)"
