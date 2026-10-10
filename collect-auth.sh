#!/usr/bin/env bash
set -o pipefail

OUT="$HOME/soc-lab/logs/auth-live.log"
mkdir -p "$(dirname "$OUT")"
touch "$OUT"

echo "Collecting authentication events into: $OUT"
echo "Enter your password if sudo prompts you."
echo "Press Ctrl+C to stop."

sudo journalctl -f -n 0 -o short-iso |
  grep --line-buffered -Ei \
  'pam_unix|authentication failure|FAILED LOGIN|user unknown|sudo:' |
  tee -a "$OUT"
