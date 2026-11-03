/* ============================================================================
 * p0probe2.c — GhostLock P0 第二轮：用 CLONE_VM 对照，把 mm_struct 从 SUnreclaim 里剥离
 *
 * 【为什么要重做（节点 92 的教训）】
 *   p0probe（第一版）用全局 SUnreclaim 当主判据，结果被淹没：
 *     1728 个 clone(SIGCHLD) 让 SUnreclaim 涨了 18228 kB，
 *     而 mm_struct 理论贡献只有 1536 kB（48 页 × 32KB）⇒ 占 8.4%。
 *     其余 92% 来自 task_struct / 内核栈 / page tables 等，分不开。
 *   ⇒ 全局 SUnreclaim 不能直接回答「mm_struct 页是否 discard」。
 *
 * 【本版核心：单变量对照】
 *   A 组 = clone(CLONE_VM | CLONE_SIGHAND | SIGCHLD) × N
 *          ⇒ 子进程**共享父进程的 mm**，不分配新 mm_struct
 *          ⇒ 但照样产生 task_struct、内核栈、信号结构
 *   B 组 = clone(SIGCHLD) × N
 *          ⇒ 每个子进程分配**独立 mm_struct**（896B）
 *          ⇒ task_struct / 内核栈 等影响与 A 组**相同**
 *
 *   ⇒ B - A = mm_struct 的净贡献（消掉了所有非 mm 的 slab）
 *   ⇒ 再看 kill 后的残留：
 *       B 的残留显著 > A 的残留  ⇒ mm_struct 页【没 discard】
 *       B 的残留 ≈ A 的残留      ⇒ mm_struct 页【discard 了】
 *
 * 【执行顺序（交替，避免系统状态漂移）】
 *   1. 静默等待（SUnreclaim 稳定）
 *   2. A 组 spawn → 采样 → kill → 采样（含长观察）
 *   3. 静默等待回基线
 *   4. B 组 spawn → 采样 → kill → 采样（含长观察）
 *   5. 计算 B-A
 *   为减少漂移，可用 --abba 参数做 A→B→B→A 四段（时间序抵消线性漂移）
 *
 * 【安全性】
 *   全程只用 clone / kill / waitpid / 读 /proc/meminfo。
 *   不碰 futex / PI / rt_mutex ⇒ 结构上不可能触发漏洞或内核崩溃。
 *
 * 【构建】
 *   aarch64-linux-gnu-gcc -O2 -static -w p0probe2.c -o p0probe2
 *
 * 【运行】
 *   ./p0probe2                  # 默认 N=1728, 10s 长观察
 *   ./p0probe2 1728 60 200      # N, 长观察采样次数, 间隔ms
 *   ./p0probe2 --abba           # 用 A→B→B→A 四段
 * ==========================================================================*/

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MM_STRUCT_SZ   0x380UL
#define ORDER3_SIZE    (4096UL << 3)
#define OBJS_PER_SLAB  (ORDER3_SIZE / MM_STRUCT_SZ)    /* 36 */
#define MAXKIDS        4096

static pid_t kids[MAXKIDS];
static int kidcnt = 0;
static int use_clone_vm = 0;          /* 1 = A组(共享mm), 0 = B组(独立mm) */

/* ===== CLONE_VM 必须给独立栈 =====
 * 教训（2026-10-27 实测段错误 segfault）：
 *   raw clone 带 CLONE_VM 时，子进程与父进程**共享同一个地址空间**。
 *   若 child_stack 传 NULL，子进程的 SP 与父进程相同，它的 prologue
 *   会直接把父进程的栈帧踩掉 ⇒ 父进程立刻 Segmentation fault（exit 139）。
 *   ⇒ CLONE_VM 组必须为每个子进程 mmap 一块独立栈，并把栈顶传进去。
 *   不带 CLONE_VM 时传 NULL 才是安全的（子进程有独立的地址空间副本）。
 * 栈大小取 64KB（子进程只执行 prctl + pause，实际只触碰顶部 1 页）。 */
#define STK_SZ (64UL * 1024UL)
static void *stk_pool = NULL;
static size_t stk_pool_n = 0;

static int alloc_stack_pool(int n) {
    if (stk_pool) {
        munmap(stk_pool, stk_pool_n);
        stk_pool = NULL;
    }
    stk_pool_n = (size_t)n * STK_SZ;
    stk_pool = mmap(NULL, stk_pool_n, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stk_pool == MAP_FAILED) {
        stk_pool = NULL;
        return -1;
    }
    return 0;
}

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

struct sample { long free_kb, unrecl_kb, slab_kb; };

static struct sample take(void) {
    struct sample s;
    s.free_kb   = meminfo_kb("MemFree");
    s.unrecl_kb = meminfo_kb("SUnreclaim");
    s.slab_kb   = meminfo_kb("Slab");
    return s;
}

static void show(const char *tag, struct sample s) {
    printf("[%8.1fms] %-16s MemFree=%8ld SUnreclaim=%8ld Slab=%8ld\n",
           now_ms() - t_start, tag, s.free_kb, s.unrecl_kb, s.slab_kb);
    fflush(stdout);
}

/* 静默等待：连续 n 次采样，若 SUnreclaim 的 max-min 收敛到 tol 以内则提前返回 */
static long settle(const char *tag, int max_iter, int gap_ms, long tol) {
    long lo = 0x7fffffff, hi = 0;
    for (int i = 0; i < max_iter; i++) {
        usleep((useconds_t)gap_ms * 1000);
        long v = meminfo_kb("SUnreclaim");
        if (v < lo) lo = v;
        if (v > hi) hi = v;
        if (i >= 3 && (hi - lo) <= tol) {
            printf("  [%s] settled after %d x %dms: SUnreclaim=%ld (span %ld)\n",
                   tag, i + 1, gap_ms, v, hi - lo);
            fflush(stdout);
            return v;
        }
    }
    printf("  [%s] not fully settled: SUnreclaim range %ld..%ld (span %ld)\n",
           tag, lo, hi, hi - lo);
    fflush(stdout);
    return meminfo_kb("SUnreclaim");
}

/* ---------- spawn ---------- */
static pid_t spawn_one(int idx) {
    pid_t c;
    if (use_clone_vm) {
        /* 每个子进程一块独立栈，栈顶向下增长 ⇒ 传 (base + (idx+1)*STK_SZ) */
        char *top = (char *)stk_pool + (size_t)(idx + 1) * STK_SZ;
        c = (pid_t)syscall(SYS_clone,
                           CLONE_VM | CLONE_SIGHAND | SIGCHLD,
                           (void *)top, NULL, NULL, 0);
    } else {
        c = (pid_t)syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
    }
    if (c == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        for (;;) pause();
    }
    return c;
}

static int spawn_all(int n) {
    kidcnt = 0;
    if (use_clone_vm && alloc_stack_pool(n) < 0) {
        printf("  [!] mmap stack pool failed errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    for (int i = 0; i < n && kidcnt < MAXKIDS; i++) {
        pid_t c = spawn_one(i);
        if (c < 0) {
            printf("  [!] clone failed at i=%d errno=%d (%s)\n", i, errno, strerror(errno));
            return -1;
        }
        kids[kidcnt++] = c;
    }
    return kidcnt;
}

static void free_stack_pool(void) {
    if (stk_pool) {
        munmap(stk_pool, stk_pool_n);
        stk_pool = NULL;
        stk_pool_n = 0;
    }
}

static void kill_all(void) {
    for (int i = 0; i < kidcnt; i++) if (kids[i] > 0) kill(kids[i], SIGKILL);
    for (int i = 0; i < kidcnt; i++) if (kids[i] > 0) waitpid(kids[i], NULL, 0);
    kidcnt = 0;
}

/* ---------- 一段实验 ---------- */
struct result {
    long base_unrecl, peak_unrecl, resid_unrecl;
    long base_free,  peak_free,  resid_free;
    int  n;
};

static struct result run_seg(const char *label, int n, int obs_cnt, int obs_gap) {
    struct result r;
    memset(&r, 0, sizeof(r));
    r.n = n;

    printf("\n==== SEGMENT %s (n=%d, %s) ====\n", label, n,
           use_clone_vm ? "CLONE_VM (shared mm, NO new mm_struct)" : "plain clone (new mm_struct)");

    settle("pre", 20, 100, 8);

    struct sample b = take();
    show("base", b);
    r.base_unrecl = b.unrecl_kb;
    r.base_free   = b.free_kb;

    double t0 = now_ms();
    int got = spawn_all(n);
    printf("  spawned %d in %.1f ms\n", got, now_ms() - t0);
    fflush(stdout);

    usleep(300 * 1000);
    struct sample p = take();
    show("after-spawn", p);
    r.peak_unrecl = p.unrecl_kb;
    r.peak_free   = p.free_kb;

    t0 = now_ms();
    kill_all();
    printf("  killed+reaped in %.1f ms\n", now_ms() - t0);
    fflush(stdout);
    /* A 组用过的栈池要释放，否则它的 108MB 映射会干扰下一段的 MemFree 读数。
     * 注意：必须在所有子进程 waitpid 之后才 munmap。 */
    free_stack_pool();

    /* 长观察：取最后一次；同时打印关键节点便于看回落曲线 */
    for (int i = 0; i < obs_cnt; i++) {
        usleep((useconds_t)obs_gap * 1000);
        struct sample s = take();
        if (i == 0 || i == 4 || i == 9 || i == obs_cnt - 1) show("observe", s);
    }
    struct sample q = take();
    r.resid_unrecl = q.unrecl_kb;
    r.resid_free   = q.free_kb;

    printf("  --> %s: peak dU=%+ld  resid dU=%+ld  (kb)\n", label,
           r.peak_unrecl - r.base_unrecl, r.resid_unrecl - r.base_unrecl);
    return r;
}

int main(int argc, char **argv) {
    int n        = 1728;
    int obs_cnt  = 60;
    int obs_gap  = 200;
    int abba     = 0;

    int ai = 1;
    if (argc > 1 && strcmp(argv[1], "--abba") == 0) { abba = 1; ai = 2; }
    if (argc > ai)     n       = atoi(argv[ai]);
    if (argc > ai + 1) obs_cnt = atoi(argv[ai + 1]);
    if (argc > ai + 2) obs_gap = atoi(argv[ai + 2]);

    if (n < 1) n = 1;
    if (n > MAXKIDS) n = MAXKIDS;

    t_start = now_ms();

    printf("==================================================\n");
    printf(" GhostLock P0 probe v2  (CLONE_VM controlled)\n");
    printf("==================================================\n");
    printf(" OBJS_PER_SLAB = %lu   (order-3 32768B / 896B)\n", OBJS_PER_SLAB);
    printf(" N (kids/segment) = %d   -> mm_struct pages = ~%d\n", n, n / (int)OBJS_PER_SLAB);
    printf(" observe = %d x %d ms\n", obs_cnt, obs_gap);
    printf(" mode    = %s\n", abba ? "A-B-B-A (drift-cancelling)" : "A then B");
    printf(" uid = %d\n", (int)getuid());
    printf(" mm_struct theoretical contribution at N: %ld kB (%d pages x 32 kB)\n",
           (long)(n / (int)OBJS_PER_SLAB) * 32, n / (int)OBJS_PER_SLAB);
    fflush(stdout);

    struct result a1, b1, b2, a2;
    memset(&a1, 0, sizeof(a1)); memset(&b1, 0, sizeof(b1));
    memset(&b2, 0, sizeof(b2)); memset(&a2, 0, sizeof(a2));

    use_clone_vm = 1;  a1 = run_seg("A1 (CLONE_VM)", n, obs_cnt, obs_gap);
    use_clone_vm = 0;  b1 = run_seg("B1 (plain)  ", n, obs_cnt, obs_gap);
    if (abba) {
        use_clone_vm = 0;  b2 = run_seg("B2 (plain)  ", n, obs_cnt, obs_gap);
        use_clone_vm = 1;  a2 = run_seg("A2 (CLONE_VM)", n, obs_cnt, obs_gap);
    }

    /* ---- 汇总 ---- */
    long A_peak = a1.peak_unrecl - a1.base_unrecl;
    long B_peak = b1.peak_unrecl - b1.base_unrecl;
    long A_res  = a1.resid_unrecl - a1.base_unrecl;
    long B_res  = b1.resid_unrecl - b1.base_unrecl;
    if (abba) {
        A_peak = (A_peak + (a2.peak_unrecl - a2.base_unrecl)) / 2;
        B_peak = (B_peak + (b2.peak_unrecl - b2.base_unrecl)) / 2;
        A_res  = (A_res + (a2.resid_unrecl - a2.base_unrecl)) / 2;
        B_res  = (B_res + (b2.resid_unrecl - b2.base_unrecl)) / 2;
    }

    long mm_theory = (long)(n / (int)OBJS_PER_SLAB) * 32;

    printf("\n==================================================\n");
    printf(" SUMMARY  (all values = delta vs that segment's own baseline, kB)\n");
    printf("==================================================\n");
    printf("                        %-12s %-12s %s\n", "peak", "residual", "meaning");
    printf("  A (CLONE_VM, no mm)   %+12ld %+12ld   non-mm slab cost\n", A_peak, A_res);
    printf("  B (plain, +mm)        %+12ld %+12ld   non-mm + mm cost\n", B_peak, B_res);
    printf("  ------------------------------------------------\n");
    printf("  B - A (mm_struct net) %+12ld %+12ld   <== KEY\n",
           B_peak - A_peak, B_res - A_res);
    printf("\n  mm_struct theoretical peak contribution = %ld kB (%d pages)\n",
           mm_theory, n / (int)OBJS_PER_SLAB);
    printf("\n--------------------------------------------------\n");
    printf(" VERDICT\n");
    printf("--------------------------------------------------\n");

    long mm_peak = B_peak - A_peak;      /* mm 的净占用 */
    long mm_res  = B_res  - A_res;       /* mm 的净残留 */

    printf("  [peak] mm_struct net = %+ld kB (theory %ld kB, ratio %.2fx)\n",
           mm_peak, mm_theory, mm_theory ? (double)mm_peak / mm_theory : 0.0);
    if (mm_peak < 0) {
        printf("         ⇒ 负值异常（A 组漂移或系统波动），本段不可用，需重跑/换 abba 模式\n");
    } else if (mm_peak < mm_theory / 3) {
        printf("         ⇒ 远小于理论 ⇒ clone 大量复用已有 partial 空闲对象，没建新页\n");
        printf("           需加大 N，使 partial 空闲耗尽后才建新页\n");
    } else {
        printf("         ⇒ 与理论同量级 ⇒ 确认 mm_struct 贡献已成功分离 ✓\n");
    }

    printf("\n  [residual] mm_struct net = %+ld kB\n", mm_res);
    if (mm_peak < mm_theory / 3) {
        printf("         ⇒ 因 peak 不达标，residual 判据暂不成立\n");
    } else if (mm_res <= -(mm_peak * 4 / 5)) {
        printf("         ⇒ 基本全部回收 ⇒ 【mm_struct 页 discard 了】\n");
        printf("            ⇒ exploit 仍拿不到 base 页 ⇒ 问题在【合并/被抢】⇒ 转 P1(H6)\n");
    } else if (mm_res >= (mm_peak / 2)) {
        printf("         ⇒ 大部分未回收 ⇒ 【mm_struct 页没 discard】\n");
        printf("            ⇒ 查 SLUB 三道门：inuse==0 / was_frozen==0 /\n");
        printf("              node->nr_partial >= min_partial(5)  ⇒ 转 P2\n");
    } else {
        printf("         ⇒ 部分回收（%+ld / %+ld）⇒ 边界情况\n", mm_res, mm_peak);
        printf("            ⇒ 加大 N 或延长观察，确认是否只是 RCU/workqueue 延迟\n");
    }
    printf("\n");
    return 0;
}