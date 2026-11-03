#!/bin/bash
cd /root/02_build/gk3build/GhostLock-main/src/core || exit 1
OUT=${1:-/root/02_build/gk3build/gK17}
aarch64-linux-gnu-gcc -O2 -static -w -pthread -DTARGET_CONFIG_H='"target.h"' *.c -o "$OUT" 2>&1 | head -40
echo "=== exit ==="
ls -la "$OUT" 2>&1