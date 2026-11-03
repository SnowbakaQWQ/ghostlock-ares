import sys, os
BASE='/root/02_build/gk3build/GhostLock-main/src/core'

def rd(p):
    return open(os.path.join(BASE,p),encoding='utf-8',errors='surrogateescape').read()
def wr(p,s):
    open(os.path.join(BASE,p),'w',encoding='utf-8',errors='surrogateescape').write(s)

ok=[]; fail=[]
def rep(p, old, new, tag):
    s=rd(p)
    if old not in s:
        fail.append(tag); return
    if new.split('\n')[0] in s and tag.startswith('idem'):
        ok.append(tag+'(skip)'); return
    wr(p, s.replace(old,new,1)); ok.append(tag)

# ---------- 1. util.c : ckpt_val / ckpt_str ----------
old_util = '''void ckpt_end(const char *tag) {
  char buf[192];
  snprintf(buf, sizeof(buf), "END   %s", tag);
  ckpt_write_line(buf);
}'''
new_util = old_util + '''
/* CKPTVAL: durable key=value record (write + fsync). */
void ckpt_val(const char *key, long val) {
  char buf[192];
  snprintf(buf, sizeof(buf), "VAL   %s = %ld (0x%lx)", key, val, (unsigned long)val);
  ckpt_write_line(buf);
}
void ckpt_str(const char *key, const char *s) {
  char buf[192];
  snprintf(buf, sizeof(buf), "STR   %s = %s", key, s ? s : "(null)");
  ckpt_write_line(buf);
}'''
rep('util.c', old_util, new_util, 'util.c:ckpt_val')

# ---------- 2. common.h : declarations ----------
rep('common.h', 'void ckpt_end(const char *tag);',
    'void ckpt_end(const char *tag);\nvoid ckpt_val(const char *key, long val);\nvoid ckpt_str(const char *key, const char *s);',
    'common.h:decl')

# ---------- 3. main.c : CMP_REQUEUE_PI durable ----------
old_cmp = '''  pr_info("CMP_REQUEUE_PI ret=%ld errno=%d (%s)\\n", req_ret, req_errno,
          req_ret < 0 ? (req_errno == EDEADLK ? "EDEADLK => dangling" : "NEGATIVE(other)=>no dangling") : "NON-NEGATIVE => no dangling");'''
new_cmp = old_cmp + '''
  ckpt_val("cmp_ret", (long)req_ret);
  ckpt_val("cmp_errno", (long)req_errno);
  ckpt_val("cmp_dangling", (long)(req_ret < 0 && req_errno == EDEADLK ? 1 : 0));
  ckpt_val("pi_target", (long)f_pi_target);
  ckpt_val("pi_chain", (long)f_pi_chain);
  ckpt_val("fire_from_main", (long)atomic_load(&fire_from_main));
  ckpt_val("punch_go_before", (long)atomic_load(&punch_consume_go));'''
rep('main.c', old_cmp, new_cmp, 'main.c:cmp_durable')

# ---------- 4. main.c : consumer durable ----------
old_cons = '''        ckpt_begin("consumer_sched_setattr");
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        ckpt_end("consumer_sched_setattr");'''
new_cons = '''        ckpt_val("cons_tid_target", (long)tid);
        ckpt_val("cons_call_idx", (long)atomic_load(&consumer_calls));
        ckpt_begin("consumer_sched_setattr");
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        ckpt_val("cons_sched_ret", (long)sched_ret);
        ckpt_val("cons_sched_errno", (long)errno);
        ckpt_end("consumer_sched_setattr");'''
rep('main.c', old_cons, new_cons, 'main.c:consumer_durable')

# ---------- 5. sendmsg_route.c : stamp values ----------
old_st = '''  if (probe) pr_info("PROBE=%d stamped\\n", probe);'''
new_st = old_st + '''
  ckpt_val("sm_probe", (long)probe);
  ckpt_val("sm_name_len", (long)SM_NAME_LEN);
  ckpt_val("sm_fake_task", (long)fake_task);
  ckpt_val("sm_fake_lock", (long)fake_lock);
  ckpt_val("sm_page_base", (long)page_base);
  ckpt_val("sm_name_08", (long)(*(uint64_t *)(void *)(name + 0x08)));
  ckpt_val("sm_name_10", (long)(*(uint64_t *)(void *)(name + 0x10)));
  ckpt_val("sm_name_18", (long)(*(uint32_t *)(void *)(name + 0x18)));
  ckpt_val("sm_snd_fd", (long)snd);
  { int sbv = 0; socklen_t sl = 4;
    getsockopt(snd, SOL_SOCKET, SO_SNDBUF, &sbv, &sl);
    ckpt_val("sm_sndbuf_eff", (long)sbv); }'''
rep('sendmsg_route.c', old_st, new_st, 'sendmsg:stamp_durable')

# ---------- 6. sendmsg_route.c : sendmsg call + page snapshot ----------
old_sm = '''errno = 0;
  int ret = (int)sendmsg(snd, &mh, MSG_NOSIGNAL);
  int se = errno;'''
new_sm = '''  ckpt_val("sm_go_fired", (long)(obs ? -1 : 1));
  ckpt_val("sm_delay_usec", (long)atomic_load(&main_route_delay_usec));
  ckpt_val("sm_maxseg", (long)SM_MSS);
  ckpt_val("sm_enter", 1);
  { uintptr_t pb = (uintptr_t)page_base;
    ckpt_val("pg_0x00", (long)(*(uint64_t *)(void *)(pb + 0x00)));
    ckpt_val("pg_0x08", (long)(*(uint64_t *)(void *)(pb + 0x08)));
    ckpt_val("pg_0x10", (long)(*(uint64_t *)(void *)(pb + 0x10)));
    ckpt_val("pg_task_0x400", (long)(*(uint64_t *)(void *)((uintptr_t)fake_task + 0x00)));
    ckpt_val("pg_task_0x410", (long)(*(uint64_t *)(void *)((uintptr_t)fake_task + 0x10))); }
  errno = 0;
  int ret = (int)sendmsg(snd, &mh, MSG_NOSIGNAL);
  int se = errno;
  ckpt_val("sm_sendmsg_ret", (long)ret);
  ckpt_val("sm_sendmsg_errno", (long)se);
  ckpt_val("sm_consumer_calls_after", (long)atomic_load(&consumer_calls));'''
rep('sendmsg_route.c', old_sm, new_sm, 'sendmsg:call_durable')

print('OK  :', ok)
print('FAIL:', fail)
