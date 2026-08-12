#!/usr/bin/env bash
# Grant the current user read/write access to macOS BPF devices so the
# Inglorious Network Scanner passive sniffer can capture WiFi traffic without
# running INS itself as root.
#
# What this installs:
#   /Library/LaunchDaemons/co.ingloriouslabs.netscan.bpfgrant.plist
#     — runs at every boot: chgrps /dev/bpf* to a dedicated `access_bpf` group
#       and chmods them g+rw (mode 660, root:access_bpf — NOT world-readable),
#       then adds your user to that group.
#
# What this does NOT do:
#   — give INS or any other tool the ability to inject packets.
#   — modify any network configuration.
#   — open any network port. INS still binds only to 127.0.0.1.
#
# Re-runnable; safe to run multiple times.
# Undo with tools/disable_sniffer.sh.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: this script must run as root. Re-run with: sudo $0" >&2
  exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
if [[ "$REAL_USER" == "root" ]]; then
  echo "error: couldn't detect the unprivileged user — run via sudo, not from a root shell." >&2
  exit 1
fi

GROUP="access_bpf"
LABEL="co.ingloriouslabs.netscan.bpfgrant"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

echo "→ Ensuring group '$GROUP' exists"
if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
  NEXT_GID=$(($(dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | sort -n | tail -1) + 1))
  dscl . -create "/Groups/$GROUP"
  dscl . -create "/Groups/$GROUP" PrimaryGroupID "$NEXT_GID"
  dscl . -create "/Groups/$GROUP" Password '*'
  echo "  created group $GROUP (gid $NEXT_GID)"
else
  echo "  group already exists"
fi

echo "→ Adding $REAL_USER to $GROUP"
dseditgroup -o edit -a "$REAL_USER" -t user "$GROUP" 2>/dev/null || true

echo "→ Installing LaunchDaemon to fix /dev/bpf* permissions on every boot"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>chgrp ${GROUP} /dev/bpf* 2>/dev/null; chmod g+rw /dev/bpf* 2>/dev/null</string>
  </array>
  <key>StandardOutPath</key><string>/var/log/ins-bpfgrant.log</string>
  <key>StandardErrorPath</key><string>/var/log/ins-bpfgrant.log</string>
</dict>
</plist>
EOF
chmod 644 "$PLIST"

echo "→ Loading LaunchDaemon"
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo "→ Applying permissions to existing /dev/bpf* devices right now"
chgrp "$GROUP" /dev/bpf* 2>/dev/null || true
chmod g+rw /dev/bpf* 2>/dev/null || true

echo
echo "✓ Done. The passive sniffer should start on next INS scan."
echo "  Note: you may need to log out and back in once for the group change"
echo "  to take effect for already-running login sessions."
echo
echo "  Verify: ls -l /dev/bpf0  (should show group '$GROUP', mode rw-rw----)"
echo "  Disable: sudo $(dirname "$0")/disable_sniffer.sh"
