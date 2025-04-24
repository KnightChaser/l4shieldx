#!/bin/bash

# Usage: ./run.sh [IP] [PORT]
TARGET_IP=${1:-127.0.0.1}
TARGET_PORT=${2:-8000}

make
./flooder $TARGET_IP $TARGET_PORT
