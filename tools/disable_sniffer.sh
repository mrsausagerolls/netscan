#!/usr/bin/env bash
# Undo what enable_sniffer.sh did. Removes the BPF-access LaunchDaemon and
# resets /dev/bpf* permissions to root-only.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: this script must run as root. Re-run with: sudo $0" >&2
  exit 1
fi

LABEL="co.ingloriouslabs.netscan.bpfgrant"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

if [[ -f "$PLIST" ]]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo "✓ Removed $PLIST"
else
  echo "(no daemon installed)"
fi

chmod 600 /dev/bpf* 2>/dev/null || true
echo "✓ BPF devices back to root-only."
echo "  (Group membership in 'access_bpf' is left intact — remove with"
echo "   'sudo dseditgroup -o edit -d <user> -t user access_bpf' if you want.)"
