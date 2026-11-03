#!/system/bin/sh
cd /data/local/tmp || exit 1
rm -f ckpt.log
export DIAG=8
export STAMP_OFF=128
export GK38_SOCKETS=8
export GK38_SENDS=256
export PRE_CTX_DEFER=1
export PIWALK_OWNER_NULL=1
export BF_TOL=0
export GK39_DRAIN_WAVES=3
export STAMP_PROBE=1
echo "=== START $(date) ==="
echo "=== PROBE PARAMS (对比 run17: 仅新增 STAMP_PROBE=1) ==="
env | /system/bin/grep -E 'DIAG|STAMP|GK38|PRE_CTX|PIWALK|BF_TOL|GK39' | sort
echo "=== RUN ==="
./gK96
echo "=== exit=$? ==="
