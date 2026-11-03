/* ============================================================================
 * p0probe.c — GhostLock P0：区分「mm_struct slab 页没被 discard」与「被 discard 但合并」
 *
 * 【目的】节点 30/86 的 P0。当前阶段⑥卡在 payload 落页。
 *   已知：__free_one_page 默认 list_add（队首）⇒ 若 base 页顺利 discard 且未合并，
 *         第 1 次 sendmsg 就该拿到。而 gK105 发 2008 次仍 HWT
 *         ⇒ base 页根本不在 free_area[3]。
 *   两种可能：
 *     (a) 没 discard（SLUB 三道门没过：inuse / was_frozen / nr_partial>=min_partial）
 *     (b) discard 了但被合并进 order>=4
 *
 * 【指标设计（关键）】
 *   ❌ 不用 MemFree 作唯一判据：
 *      - 全局噪声可达数 MB，32KB 信号被淹没。
 *      - 而且热页会优先从 PCP 分配，discard 的页可能进 buddy 后又被立即拿走。
 *   ✅ 主判据 = SUnreclaim：
 *      mm_struct 属于不可回收 slab，计入 SUnreclaim。
 *      若 slab 页被 discard（归还 buddy）⇒ 该页移出 slab 记账 ⇒ SUnreclaim 明显下降。
 *      若只留在 node partial 链表不 discard ⇒ SUnreclaim 不变。
 *      ⇒ 「kill 之后 SUnreclaim 是否下降」= 「是否 discard」的直接判据。
 *   ✅ 辅助 = Slab（总量）、MemFree（32KB 粒度）、MemAvailable
 *
 * 【对照实验（同时验证 min_partial 门槛）】
 *   MODE=1：只分配 1 页（36 个 mm_struct）
 *           ⇒ 预期【不 discard】，因为 nr_partial < min_partial(5)
 *   MODE=48：分配 48 页（1728 个）—— 对齐 exploit 的 PREPARE_SLABS=48 默认值
 *           ⇒ 预期【可能 discard】
 *   两个 MODE 结果不同，就能证明 min_partial 门槛真实存在且方向正确。
 *
 * 【安全性】
 *   全程只用 clone(SIGCHLD) + kill + waitpid + 读 /proc/meminfo。
 *   完全不碰 futex / PI / rt_mutex ⇒ 绝不可能触发漏洞或内核崩溃。
 *
 * 【构建】
 *   aarch64-linux-gnu-gcc -O2 -static -w p0probe.c -o p0probe
 *
 * 【运行】
 *   ./p0probe            # 默认 MODE=48（对齐 exploit 默认）
 *   ./p0probe 1          # 只分配 1 页
 *   ./p0probe 48 30 100  # 48 页、30 个采样点、采样间隔 100ms
 * ==========================================================================*/

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MM_STRUCT_SZ   0x380UL              /* /sys/kernel/slab/mm_struct = :A-0000896（A级） */
#define ORDER3_SIZE    (4096UL << 3)        /* 32768, mm_cachep order=3 */
#define OBJS_PER_SLAB  (ORDER3_SIZE / MM_STRUCT_SZ)   /* = 36 */
#define MAXKIDS        4096

static pid_t kids[MAXKIDS];
static int kidcnt = 0;

/* ---------- meminfo ---------- */
static long meminfo_kb(const char *key) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[256];
    size_t klen = strlen(key);
    long v = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == ':') {
            v = strtol(line + klen + 1, NULL, 10);
            break;
        }
    }
    fclose(f);
    return v;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static double t_start;

/* ---------- 采样 ---------- */
struct sample {
    long free_kb, unrecl_kb, slab_kb, avail_kb;
};

static struct sample take(void) {
    struct sample s;
    s.free_kb   = meminfo_kb("MemFree");
    s.unrecl_kb = meminfo_kb("SUnreclaim");
    s.slab_kb   = meminfo_kb("Slab");
    s.avail_kb  = meminfo_kb("MemAvailable");
    return s;
}

static void print_sample(const char *tag, struct sample s) {
    printf("[%8.1fms] %-10s MemFree=%8ld  SUnreclaim=%8ld  Slab=%8ld  Avail=%8ld\n",
           now_ms() - t_start, tag, s.free_kb, s.unrecl_kb, s.slab_kb, s.avail_kb);
    fflush(stdout);
}

/* 连续采样 n 次，返回最后一次；同时记录 unrecl / free 的 min/max 用于看噪声 */
static struct sample burst(const char *tag, int n, int gap_ms,
                           long *u_min, long *u_max, long *f_min, long *f_max) {
    struct sample s = take();
    *u_min = *u_max = s.unrecl_kb;
    *f_min = *f_max = s.free_kb;
    for (int i = 0; i < n; i++) {
        usleep((useconds_t)gap_ms * 1000);
        s = take();
        if (s.unrecl_kb < *u_min) *u_min = s.unrecl_kb;
        if (s.unrecl_kb > *u_max) *u_max = s.unrecl_kb;
        if (s.free_kb   < *f_min) *f_min = s.free_kb;
        if (s.free_kb   > *f_max) *f_max = s.free_kb;
    }
    print_sample(tag, s);
    return s;
}

/* ---------- 子进程 ---------- */
static pid_t spawn_one(void) {
    pid_t c = (pid_t)syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
    if (c == 0) {
        /* child：立刻进入 pause，持有一个独立 mm_struct */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() == 1) _exit(0);
        for (;;) pause();
    }
    return c;
}

static void kill_all(void) {
    for (int i = 0; i < kidcnt; i++) {
        if (kids[i] > 0) kill(kids[i], SIGKILL);
    }
    for (int i = 0; i < kidcnt; i++) {
        if (kids[i] > 0) waitpid(kids[i], NULL, 0);
    }
    kidcnt = 0;
}

int main(int argc, char **argv) {
    int pages    = (argc > 1) ? atoi(argv[1]) : 48;
    int n_samp   = (argc > 2) ? atoi(argv[2]) : 30;
    int gap_ms   = (argc > 3) ? atoi(argv[3]) : 100;

    if (pages < 1) pages = 1;
    int want = pages * (int)OBJS_PER_SLAB;
    if (want > MAXKIDS) {
        printf("[!] pages=%d -> %d kids exceeds MAXKIDS=%d, clamped\n",
               pages, want, MAXKIDS);
        want = MAXKIDS;
        pages = want / (int)OBJS_PER_SLAB;
    }

    t_start = now_ms();

    printf("========================================\n");
    printf(" GhostLock P0 probe\n");
    printf("========================================\n");
    printf("MM_STRUCT_SZ   = %lu (0x%lx)\n", MM_STRUCT_SZ, MM_STRUCT_SZ);
    printf("OBJS_PER_SLAB  = %lu  (order-3 = 32768B)\n", OBJS_PER_SLAB);
    printf("pages (slabs)  = %d   -> kids = %d\n", pages, want);
    printf("page bytes est = %d KB\n", pages * 32);
    printf("samples        = %d x %d ms\n", n_samp, gap_ms);
    printf("uid=%d\n", (int)getuid());
    fflush(stdout);

    long umin, umax, fmin, fmax;
    struct sample base, after_spawn, after_kill;

    /* ---- 阶段 0：基线 ---- */
    printf("\n---- phase 0: baseline ----\n");
    base = burst("baseline", n_samp, gap_ms, &umin, &umax, &fmin, &fmax);
    long base_umin = umin, base_umax = umax, base_fmin = fmin, base_fmax = fmax;
    printf("  noise: SUnreclaim range = %ld .. %ld (spread %ld kB)\n",
           umin, umax, umax - umin);
    printf("  noise: MemFree    range = %ld .. %ld (spread %ld kB)\n",
           fmin, fmax, fmax - fmin);
    fflush(stdout);

    /* ---- 阶段 1：分配 ---- */
    printf("\n---- phase 1: spawn %d clone children (each own mm_struct) ----\n", want);
    double t0 = now_ms();
    for (int i = 0; i < want; i++) {
        pid_t c = spawn_one();
        if (c < 0) {
            printf("[!] clone failed at i=%d errno=%d (%s)\n", i, errno, strerror(errno));
            break;
        }
        kids[kidcnt++] = c;
    }
    printf("  spawned %d in %.1f ms\n", kidcnt, now_ms() - t0);
    fflush(stdout);

    after_spawn = burst("after-spawn", n_samp / 2 > 0 ? n_samp / 2 : 1,
                        gap_ms, &umin, &umax, &fmin, &fmax);

    /* ---- 阶段 2：kill ---- */
    printf("\n---- phase 2: SIGKILL all + waitpid ----\n");
    t0 = now_ms();
    kill_all();
    printf("  killed+reaped in %.1f ms\n", now_ms() - t0);
    fflush(stdout);

    /* ---- 阶段 3：观察（重点）---- */
    printf("\n---- phase 3: observe (RCU grace period may delay free_mm) ----\n");
    after_kill = burst("after-kill", n_samp, gap_ms, &umin, &umax, &fmin, &fmax);

    /* ---- 汇总 ---- */
    long d_unrecl = after_kill.unrecl_kb - base.unrecl_kb;
    long d_free   = after_kill.free_kb   - base.free_kb;
    long d_slab   = after_kill.slab_kb   - base.slab_kb;
    long peak_unrecl = after_spawn.unrecl_kb - base.unrecl_kb;
    long expect_kb = (long)pages * 32;

    printf("\n========================================\n");
    printf(" SUMMARY\n");
    printf("========================================\n");
    printf(" expected slab footprint     = %ld kB (%d pages x 32KB)\n", expect_kb, pages);
    printf(" SUnreclaim baseline         = %ld kB\n", base.unrecl_kb);
    printf(" SUnreclaim after-spawn      = %ld kB  (delta %+ld)\n",
           after_spawn.unrecl_kb, peak_unrecl);
    printf(" SUnreclaim after-kill       = %ld kB  (delta %+ld)\n",
           after_kill.unrecl_kb, d_unrecl);
    printf(" Slab       after-kill       = %ld kB  (delta %+ld)\n",
           after_kill.slab_kb, d_slab);
    printf(" MemFree    after-kill       = %ld kB  (delta %+ld)\n",
           after_kill.free_kb, d_free);
    printf(" noise floor: SUnreclaim spread in baseline = %ld kB\n",
           base_umax - base_umin);
    printf(" noise floor: MemFree    spread in baseline = %ld kB\n",
           base_fmax - base_fmin);
    printf("\n----------------------------------------\n");
    printf(" VERDICT (auto):\n");
    printf("----------------------------------------\n");

    long noise = base_umax - base_umin;
    if (noise < 64) noise = 64;          /* 最小容许噪声门槛 64 kB */

    if (d_unrecl <= -(noise)) {
        printf("  * SUnreclaim 明显下降 (%+ld kB, 超过噪声 %ld kB)\n", d_unrecl, noise);
        printf("  => 【discard 发生了】slab 页已归还 buddy。\n");
        printf("     若 exploit 仍拿不到 base 页，则问题在【合并】或【被抢】⇒ 转 P1(H6)\n");
    } else if (d_unrecl >= -(noise / 2) && d_unrecl <= (noise)) {
        printf("  * SUnreclaim 基本不变 (%+ld kB，在噪声 %ld kB 内)\n", d_unrecl, noise);
        printf("  => 【没 discard】页仍留在 node partial 链表。\n");
        printf("     ⇒ 查 SLUB 三道门：inuse==0 / was_frozen==0 / node->nr_partial>=min_partial(5)\n");
        printf("     ⇒ 若本 MODE 是 1 页而 MODE=48 有下降，则直接证实 min_partial 门槛。\n");
    } else {
        printf("  * SUnreclaim 反而上升 (%+ld kB)\n", d_unrecl);
        printf("  => 异常。可能有其他进程干扰，或采样点太早（RCU 未过 grace period）。\n");
        printf("     ⇒ 建议加大采样次数/间隔重跑，或换空闲时段。\n");
    }

    if (d_free > 0) {
        printf("  * MemFree 上升 %+ld kB (%.1f 页 of 32KB)\n",
               d_free, (double)d_free / 32.0);
        printf("    （注：热页会优先从 PCP 拿走，MemFree 上扬幅度通常小于 discard 页数）\n");
    } else {
        printf("  * MemFree 未上升 (%+ld kB)。PCP 缓存或即时被抢都可能造成，不单独作判据。\n",
               d_free);
    }

    printf("\n");
    return 0;
}
