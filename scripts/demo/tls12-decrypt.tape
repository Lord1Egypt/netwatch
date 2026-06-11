# vhs tape: live TLS 1.2 decryption in the netwatch TUI.
# Render from the worktree root:  vhs scripts/demo/tls12-decrypt.tape
# Requires: pcap access (access_bpf or sudo), OpenSSL-backed python3.

Output demo-tls12-decrypt.gif

Set Shell zsh
Set FontSize 12
Set Width 1500
Set Height 850
Set Padding 14
Set PlaybackSpeed 1.0

# ── Hidden setup: write demo config + schedule traffic generator ──
Hide
Type "bash scripts/demo/setup.sh && clear" Enter
Sleep 1s
# Launch the real TUI; it opens on the Packets tab and starts live capture.
Type "./target/debug/netwatch" Enter
Show

# Capture is running; the generator fires its TLS 1.2 handshake at ~+4s.
# Wait for handshake + keylog ingest + a few decrypted records.
Sleep 12s

# Show only the records netwatch decrypted.
Type "/"
Sleep 800ms
Type "decrypted:true"
Sleep 1s
Enter
Sleep 3s

# Clear the filter, select a record, open the reassembled stream view.
Escape
Sleep 500ms
Type "f"
Sleep 400ms
Down Down Down Down Down
Sleep 400ms
Type "s"
Sleep 3s

# Scroll to reveal the decrypted server response under the request.
Down Down Down Down Down Down Down Down
Sleep 3s

# Close stream view and quit.
Escape
Sleep 500ms
Type "q"
Sleep 1s
