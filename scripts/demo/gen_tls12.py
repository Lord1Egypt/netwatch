#!/usr/bin/env python3
"""Sustained TLS 1.2 keep-alive traffic generator for the decryption demo.

Pinned to TLS 1.2 + AEAD ciphers so netwatch negotiates one of its supported
GCM/ChaCha suites. Writes the NSS keylog via the SSLKEYLOGFILE env var (set by
the caller). Sends a recognizable GET on a keep-alive so sequence-resync locks
on after the keylog watcher ingests the master secret.
"""
import os
import socket
import ssl
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "example.com"
ctx = ssl.create_default_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
raw = socket.create_connection((host, 443), timeout=10)
s = ctx.wrap_socket(raw, server_hostname=host)
sys.stderr.write("handshake %s %s\n" % (s.version(), s.cipher()[0]))
sys.stderr.flush()
s.settimeout(3.0)
for _ in range(200):
    req = (
        "GET / HTTP/1.1\r\nHost: %s\r\n"
        "Connection: keep-alive\r\n"
        "User-Agent: netwatch-live-demo\r\n\r\n" % host
    ).encode()
    try:
        s.sendall(req)
        s.recv(16384)
    except Exception as e:
        sys.stderr.write("stop: %s\n" % e)
        break
    time.sleep(0.5)
try:
    s.close()
except Exception:
    pass
