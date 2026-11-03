p='/root/02_build/gk3build/GhostLock-main/src/core/sendmsg_route.c'
s=open(p,encoding='utf-8',errors='surrogateescape').read()
old='  /* page_base is a KERNEL address; never deref from userspace. */'+chr(10)+'  int ret = (int)sendmsg(snd, &mh, MSG_NOSIGNAL);'
new='  /* page_base is a KERNEL address; never deref from userspace. */'+chr(10)+'  errno = 0;'+chr(10)+'  int ret = (int)sendmsg(snd, &mh, MSG_NOSIGNAL);'
assert old in s, 'anchor missing'
open(p,'w',encoding='utf-8',errors='surrogateescape').write(s.replace(old,new,1))
print('errno=0 restored')
