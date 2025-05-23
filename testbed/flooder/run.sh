#!/usr/bin/env bash
#
# run.sh
# Single-shot test driver.
# Usage:
#   ./run.sh [-r] [mode] [dest_ip] [port] [src_ip]
# Examples:
#   ./run.sh normal                         # full connect to 127.0.0.1:8000, src=127.0.0.1
#   ./run.sh syn                            # one SYN to 127.0.0.1:8000, src=127.0.0.1
#   ./run.sh syn -r                         # one SYN to 127.0.0.1:8000, random src IP
#   ./run.sh normal 10.0.0.5                # full connect to 10.0.0.5:8000
#   ./run.sh syn 10.0.0.5 443               # one SYN to 10.0.0.5:443
#   ./run.sh syn 10.0.0.5 80 192.168.1.100  # one SYN, fixed src

# parse args
RANDOM_FLAG=""
if [[ "$1" == "-r" ]]; then
  RANDOM_FLAG="-r"
  shift
fi

MODE=${1:-normal}
DEST=${2:-127.0.0.1}
PORT=${3:-8000}
SRC=${4:-127.0.0.1}

# build and run
make
sudo ./flooder -m "$MODE" -d "$DEST" -p "$PORT" -s "$SRC" $RANDOM_FLAG
