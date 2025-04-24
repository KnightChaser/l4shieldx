#!/bin/bash

for i in $(seq 1 5000); do
  sudo ./flooder normal 127.0.0.1 8000 &
  sudo ./flooder syn 127.0.0.1 8000 &
done
