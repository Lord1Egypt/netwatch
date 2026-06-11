#!/usr/bin/env bash
#
# Validate passive TLS 1.2 application-data decryption end-to-end.
#
# Drives the REAL capture pipeline (PacketCollector + keylog watcher +
# StreamTracker::try_decrypt_tls_record) via the examples/tls12_decrypt_live.rs
# harness against live traffic, across every AEAD suite we support, plus a
# negative control (a CBC suite, which must gate off and decrypt nothing).
#
# Usage:
#   scripts/verify-tls12-decrypt.sh [host] [interface]
#
#   host       default: example.com   (any TLS-1.2-capable HTTPS host)
#   interface  default: auto-detected default route, else en0
#
# Requirements:
#   - pcap access: membership in the `access_bpf` group (macOS) or run as root.
#   - python3 linked against OpenSSL (honors SSLKEYLOGFILE) — LibreSSL won't work.
#
set -u

HOST="${1:-example.com}"

# ── Resolve the capture interface ───────────────────────────────────────────
if [ "${2:-}" != "" ]; then
  IFACE="$2"
elif command -v route >/dev/null 2>&1 && route get default >/dev/null 2>&1; then
  IFACE="$(route get default 2>/dev/null | awk '/interface:/{print $2}')"
elif command -v ip >/dev/null 2>&1; then
  IFACE="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
fi
IFACE="${IFACE:-en0}"

cd "$(dirname "$0")/.." || exit 2
echo "host=$HOST  interface=$IFACE"
echo

# ── Preflight: python must be OpenSSL-backed ────────────────────────────────
SSL_BACKEND="$(python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)' 2>/dev/null || true)"
case "$SSL_BACKEND" in
  OpenSSL*) echo "python ssl backend: $SSL_BACKEND  (honors SSLKEYLOGFILE)";;
  *) echo "ERROR: python3 ssl backend is '$SSL_BACKEND' — needs OpenSSL to write SSLKEYLOGFILE."
     echo "       Try a Homebrew python3 (brew install python3)."
     exit 2;;
esac
echo

# ── Build the harness once ──────────────────────────────────────────────────
echo "building example harness..."
if ! cargo build --example tls12_decrypt_live 2>build.log; then
  echo "ERROR: build failed:"; cat build.log; rm -f build.log; exit 2
fi
rm -f build.log
BIN=target/debug/examples/tls12_decrypt_live
echo "ok: $BIN"
echo

# ── Run one scenario; classify the harness output ───────────────────────────
# Args: <label> <openssl cipher list> <expect: aead|none>
run_case() {
  local label="$1" ciphers="$2" expect="$3"
  echo "──────────────────────────────────────────────────────────────────────"
  echo "CASE: $label"
  local out
  out="$(SSLCIPHERS="$ciphers" "$BIN" "$HOST" "$IFACE" 2>&1)"

  # Surface the key lines.
  echo "$out" | grep -E '\[py\] handshake|capture failed|python client failed|decrypted application-data' | sed 's/^/  /'

  if echo "$out" | grep -q 'capture failed to start'; then
    echo "  RESULT: ⚠️  capture could not start (pcap permissions?) — run via sudo or join access_bpf"
    return 2
  fi

  local count
  count="$(echo "$out" | sed -n 's/.*application-data records captured: \([0-9]*\).*/\1/p' | tail -1)"
  count="${count:-0}"

  if [ "$expect" = "aead" ]; then
    if echo "$out" | grep -q '✅ VERIFIED'; then
      echo "  RESULT: ✅ PASS — recovered our GET plaintext ($count records)"
      return 0
    fi
    echo "  RESULT: ❌ FAIL — expected to recover plaintext, got $count decrypted records"
    return 1
  else
    # Negative control: a non-AEAD suite must decrypt nothing.
    if [ "$count" -eq 0 ]; then
      echo "  RESULT: ✅ PASS — out-of-scope suite gated off, 0 records decrypted (as designed)"
      return 0
    fi
    echo "  RESULT: ❌ FAIL — negative control decrypted $count records (should be 0)"
    return 1
  fi
}

fails=0
skips=0
run_case "AES-128-GCM-SHA256 (0xc02b/0xc02f)" \
         "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256" aead || { [ $? -eq 2 ] && skips=$((skips+1)) || fails=$((fails+1)); }
run_case "AES-256-GCM-SHA384 (0xc02c/0xc030 — SHA-384 PRF)" \
         "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384" aead || { [ $? -eq 2 ] && skips=$((skips+1)) || fails=$((fails+1)); }
run_case "ChaCha20-Poly1305 (0xcca8/0xcca9 — RFC 7905, no explicit nonce)" \
         "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305" aead || { [ $? -eq 2 ] && skips=$((skips+1)) || fails=$((fails+1)); }
run_case "CBC suite — negative control (must NOT decrypt)" \
         "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA" none || { [ $? -eq 2 ] && skips=$((skips+1)) || fails=$((fails+1)); }

echo "──────────────────────────────────────────────────────────────────────"
if [ "$fails" -eq 0 ] && [ "$skips" -eq 0 ]; then
  echo "✅ ALL CASES PASSED — TLS 1.2 decryption verified across all AEAD suites + negative control."
  exit 0
elif [ "$fails" -eq 0 ]; then
  echo "⚠️  $skips case(s) skipped (capture/handshake issue); the rest passed."
  exit 0
else
  echo "❌ $fails case(s) FAILED, $skips skipped."
  exit 1
fi
