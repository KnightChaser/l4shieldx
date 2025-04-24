#!/bin/bash

# Usage: sudo ./run.sh [mode] [IP] [PORT]
# ./run.sh normal 127.0.0.1 8000   # full connect
# ./run.sh syn 127.0.0.1 8000 # single SYN
MODE=${1:-normal}
IP=${2:-127.0.0.1}
PORT=${3:-8000}

make
sudo ./flooder $MODE $IP $PORT
