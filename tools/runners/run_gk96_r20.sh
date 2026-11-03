#!/system/bin/sh
cd /data/local/tmp || exit 1
rm -f ckpt.log
export DIAG=8
export STAMP_OFF=128
export GK38_SOCKETS=8
export GK38_SENDS=256
export PRE_CTX_DEFER=1
export PIWALK_OWNER_NULL=0
echo "=== START $(date) ==="
./gK96
echo "=== exit=$? ==="
