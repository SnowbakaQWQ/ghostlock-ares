#!/system/bin/sh
cd /data/local/tmp || exit 1
rm -f ckpt.log

export DIAG=8
export STAMP_OFF=128
export GK_CTX_LATE=1
export PREPARE_SLABS=48
export PRE_CTX_DEFER=1
export A45_DEFER=0
export GK88_F1_SPIN=2
export GK88_F1_BATCH=256
export GK39_DRAIN=3
export GK39_DRAIN_BATCH=256
export GK_PRE_FORK=1
export GK_PRE_FORK_WAVES=1
export GK_PRE_FORK_BATCH=700
export GK_PRE_CTX_AFTER_KILL=0
export GK_PRE_FORK_LATE=1
export GK_POST_F1=1
export GK_POST_F1_WAVES=3
export GK_POST_F1_BATCH=300
export GK_WARMUP_SENDS=2000
export GK38_SOCKETS=8
export WAITER_BASE_4_14=1
export PIWALK_OWNER_NULL=1
export SKB_DELTA=0
export SKB_BIAS_PTR=0
export WD_FL=1

echo "=== ENV ECHO $(date) ==="
for v in DIAG STAMP_OFF GK_CTX_LATE PREPARE_SLABS PRE_CTX_DEFER A45_DEFER GK88_F1_SPIN GK88_F1_BATCH GK39_DRAIN GK39_DRAIN_BATCH GK_PRE_FORK GK_PRE_FORK_WAVES GK_PRE_FORK_BATCH GK_PRE_CTX_AFTER_KILL GK_PRE_FORK_LATE GK_POST_F1 GK_POST_F1_WAVES GK_POST_F1_BATCH GK_WARMUP_SENDS GK38_SOCKETS WAITER_BASE_4_14 PIWALK_OWNER_NULL SKB_DELTA SKB_BIAS_PTR WD_FL; do
  eval "val=\$$v"
  echo "  $v=$val"
done

echo "=== dryrun gate ==="
./gK110 --dryrun 2>&1 | /system/bin/grep -E 'coordinate check|ptr_bias|write side|ptr   side|selinux_enforcing'

if [ "$1" = "--check" ]; then
  echo "=== [CHECK MODE] real run skipped ==="
  exit 0
fi

echo "=== START $(date) ==="
./gK110
echo "=== exit=$? $(date) ==="

echo "=== POST-RUN ASSERT $(date) ==="
assert_eq() {
  got=$(grep -a " $1 = " ckpt.log 2>/dev/null | tail -1 | sed 's/.*= *//;s/ .*//')
  if [ "$got" = "$2" ]; then
    echo "  OK   $1 = $got"
  else
    echo "  FAIL $1 = $got (expect $2)"
  fi
}
assert_eq g108_ctx_late 1
assert_eq pre_ctx_defer 1
assert_eq pre_ctx_release_at 2
assert_eq g101_pre_fork_on 1
assert_eq g101_pre_fork_total 700
assert_eq g115_post_f1_total 900
assert_eq gk106_warmup_sends 2000
assert_eq g38_sockets 8
assert_eq gk105_ptr_bias 0
assert_eq gk105_frag_off_lock 3712
assert_eq bf_tol_best_hits 4
echo "=== ASSERT DONE ==="
echo "=== getenforce: $(getenforce) ==="
