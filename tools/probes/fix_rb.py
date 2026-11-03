p='/root/02_build/gk3build/GhostLock-main/src/core/util.c'
s=open(p,encoding='utf-8',errors='surrogateescape').read()
old='      put64(p, LOCK_OFF + 0x08, fake_w0);'+chr(10)+'      put64(p, LOCK_OFF + 0x10, fake_w0);'
new=('      /* rb_entry(rb_leftmost, struct rt_mutex_waiter, tree_entry) must land on' + chr(10)
     + '       * the waiter base. FAKE_WAITER_* offsets are all waiter+0x20, so the' + chr(10)
     + '       * waiter base is fake_w0+0x20. Using bare fake_w0 made w->lock read' + chr(10)
     + '       * 0 instead of fake_lock and tripped BUG_ON(w->lock != lock). */' + chr(10)
     + '      put64(p, LOCK_OFF + 0x08, fake_w0 + 0x20);' + chr(10)
     + '      put64(p, LOCK_OFF + 0x10, fake_w0 + 0x20);')
assert old in s, 'anchor not found'
open(p,'w',encoding='utf-8',errors='surrogateescape').write(s.replace(old,new,1))
print('rb_leftmost -> fake_w0+0x20')
