#!/usr/bin/env bash
#
# flood-loop.sh
# Repeatedly fire both a full connect and a SYN (with random src) to your local server.

DEST=${1:-127.0.0.1}
PORT=${2:-8000}
COUNT=${3:-300}
SRC=${4:-127.0.0.1}

for i in $(seq 1 $COUNT); do
  # full TCP connect
  sudo ./flooder -m normal -d "$DEST" -p "$PORT" -s "$SRC" &
  # spoofed SYN flood (random src IP)
  sudo ./flooder -m syn -d "$DEST" -p "$PORT" -r "$SRC" &
done

wait
echo "Launched $COUNT pairs of normal+SYN workers."
