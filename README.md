# GhostLock — ares (Redmi K40 Gaming / MediaTek MT6893) port

> CVE-2026-43499 kernel LPE PoC, adapted for **Xiaomi ares / Redmi K40 游戏增强版**
> (Dimensity 1200 / MT6893, Android 13 HyperOS 1.0, kernel `4.14.186-g844fd19c6`).
>
> ## Status: **UNFINISHED — local privilege escalation NOT achieved.**
> 7 stages: ①–⑤ fully evidenced, **⑥ blocked on "getting the payload onto the page"**.
> Published in the hope that someone can crack the last step. See [Where we are stuck](#-where-we-are-stuck).

---

## TL;DR — English

This is an *adaptation attempt* of the public GhostLock / CVE-2026-43499 rtmutex UAF
exploit chain to a **locked-bootloader, unrootable** MT6893 device. The whole userland
chain works and is locally evidenced:

| # | Stage | Result |
|---|---|---|
| ① | CVE trigger + dangling `rt_mutex_waiter` | ✅ `cmp_errno = 35` (`-EDEADLK`) |
| ② | Kernel address leak (KernelSnitch) | ✅ `bf_tol_hits=1`, `best_hits=4` |
| ③ | Stack stamp overwrites the waiter | ✅ `errno=99`, `optlen=0x108`, `off=0x80` |
| ④ | PI walk executes | ✅ full stack in ramoops |
| ⑤ | `trylock` passes → enters `rb_erase_cached` | ✅ 5 hits in `db_history` |
| ⑥ | **Write primitive lands (`selinux=0`)** | ❌ **BLOCKED** |
| ⑦ | Verification (`getenforce`) | ⬜ still `Enforcing` |

**The single blocker:** the leaked `mm_struct` slab page (`base`) never seems to be
handed back to the buddy allocator's `free_area[3]`, so the `sendmsg()` order-3 frag
page-spray never reclaims it and the payload never lands at the stamped address.
Two hypotheses remain open: (a) the page is never discarded by SLUB, or (b) it is
discarded but immediately merged into a higher order. See [docs/FINDINGS.zh.md](docs/FINDINGS.zh.md).

If you have this device class (or any 4.14 `VA_BITS=39` MediaTek kernel) and want to
push it over the line — PRs, issues and hypotheses are welcome.

---

## 这是什么

这是把公开的 **GhostLock / CVE-2026-43499**（`rtmutex` 悬空 `rt_mutex_waiter` UAF）
适配到本机 —— **Redmi K40 游戏增强版（`ares` / MT6893）** —— 的完整工作现场。

约束条件很极端：

- Bootloader **已锁**，A/B 分区，官方解锁通道已关闭 ⇒ 只能走内核提权
- 设备**无 root**，`/proc/kallsyms`、`dmesg`、pstore、`last_kmsg` **全部 denied**
- 唯一的观测手段：**用户态 ckpt 打点** + **AEE 崩溃日志明文**（`/data/vendor/aee_exp/db_history`）

> ⚠️ 本仓库是一个**未完成**的适配实验。它包含大量"哪些路走不通"的记录，
> 这些记录本身可能比代码更有价值。

---

## 目录结构

```
src/                  适配后的 exploit 源码（含多机型 offset 表）
  core/
    main.c            主利用逻辑（线程编排、stamp、PI walk 触发）
    util.c            工具函数（sendmsg 喷页、地址换算、ckpt 打点）
    slide.c           KASLR 泄漏
    mcast_route.c     栈 stamp 载体（setsockopt IP_MSFILTER 路径）
    sendmsg_route.c   页喷（sendmsg + order-3 skb frag）
    fops.c / pipe.c / root.c / miniadb.c
    kernelsnitch/     KernelSnitch 地址泄露（bruteforce，纯算术 hash 比对）
    ares/offsets.h    ★ 本机偏移表（ares / MT6893 / 4.14.186）
    target.h          ★ 目标地址常量
    <其他机型>/        ace6t / op15 / opd2502 / rmx5070 / findx8
artifacts/
  bin/                gK108（基线）、gK109（P3 修正）、gK92（rb_erase 里程碑）
                      + MD5SUMS.txt + build.sh
  profile/            GhostLock App 的 profile（assets_ares.conf / profile_ares.bin）
tools/
  runners/            ★ 上机脚本（含完整环境变量 export + dryrun 闸门 + 事后断言）
                      run_gk110/111/112.sh 含 assert_eq 校验，是"单变量"规矩的模板
  probes/             p0probe.c / p0probe2.c（P0 MemFree 区分实验）
                      fix_errno.py / fix_rb*.py / patch.py / parse_ioctl.py
  rebuild74.py        幂等 patch 脚本（崩溃后回滚重建源码树用）
logs/
  ckpt/               60+ 次实跑的 ckpt 打点日志（gK41 ~ gK116）
  ckpt_early/         早期（gK3~gK16）ckpt 日志，44 份
  aee/                AEE 取证明文（db_history CSV + ZZ_INTERNAL）
  evidence/           hwt_1056_raw.log.gz（126306 行 HWT 现场日志）
                      gk_stage_snapshots.tar.gz（各阶段源码快照）
  ghostlock-SUCCESS-run1.log
reference/
  syms/               syms7.txt（⚠ 见下文"符号表不可靠"）、all_syms.txt
  notes/              机型笔记、PROFILE_SCHEMA_ZH.md、上游各移植版 README
                      （aresin_OFFSETS/PROGRESS、k40、k419、pckm00、ccp_*）
  upstream/           上游 PoC 资料（NebuSec/CyberMeowfia、IonStack 等）
docs/
  FINDINGS.zh.md      ★ 全部结论 + 证据等级 + 已证伪路线
  MEMORYBANK.md       研究过程的完整记忆快照（待追加）
```

---

## 编译与运行

**交叉编译**（宿主有 `gcc-aarch64-linux-gnu` 即可，无需 NDK）：

```bash
cd src/core
aarch64-linux-gnu-gcc -O2 -static -w -pthread \
    -DTARGET_CONFIG_H='"target.h"' *.c -o gKxxx
# 或用 artifacts/bin/build.sh：
./build.sh /tmp/out
```

已验证可复现：`gK108` = `1f52c2da6fd5c9523aa3699942dabefc`（size 951792）。

**部署运行**（`/sdcard` 是 `noexec`，必须放 `/data/local/tmp`）：

```bash
cp gK109 /data/local/tmp/ && chmod 755 /data/local/tmp/gK109
cd /data/local/tmp && ./gK109
```

⚠️ **必须显式传全套环境变量**，并把回显写进 ckpt 日志。
裸跑会导致两次实验之间差好几个参数、结果完全无法归因（这是踩过的坑，见教训 #10）。

**每次上机后第一件事**：`getenforce` —— 这是唯一的成败判据，崩点只能推中间状态。

---

## 🔴 Where we are stuck

阶段⑥ = **让 payload 落进 `base` 页**。链路如下：

1. **base 页的来源**
   `base = leaked_mm_struct & ~0x7fff`（order-3 复合页，8 页对齐）。
   `mm_struct` 由 `dup_mm/fork` 走 `kmem_cache(mm_cachep)` 分配，
   对象大小 **896 B**（不是官方 5.15/6.1 的 1024，也不是别的移植版的 1280），
   一个 order-3 slab 页装 36 个对象。

2. **页要回到 buddy 才能被喷到** —— 需要过 SLUB 三道门
   ① `inuse == 0` ② `was_frozen == 0` ③ `node->nr_partial >= min_partial(=5)`
   实测：`cpu_partial=13` / `min_partial=5`；`slab_after_ctx_late_close` 与 `before` 完全相同
   ⇒ frozen 模型成立，但 slab 总噪声 14.46 MB 远大于 32 KB 的信号 ⇒ **无法用 slab 统计判断**。

3. **`sendmsg` 拿页**
   `alloc_skb_with_frags` → `max_page_order = 3`，gfp **去掉了 `__GFP_DIRECT_RECLAIM` 且带 `__GFP_NORETRY`**
   ⇒ order-3 失败**立即降级** order-1 → order-0，**不会等待、不会回收**
   ⇒ "先占满 `free_area[3]` 再让 base 页成为唯一页"这条策略**结构性不可行**。

4. **`__free_one_page` 默认是 `list_add`（队首，LIFO），不是 `list_add_tail`**
   ⇒ 只要 base 页顺利 discard 且**未被合并**，它就在队首，**第 1 次 `sendmsg` 就该拿到**。
   ⇒ 而实测发 2008 次仍 HWT（= payload 未落页）⇒ **base 页根本不在 `free_area[3]`**。

**⇒ 只剩两种可能：**
- **(a) 压根没 discard**（SLUB 三道门没过）
- **(b) discard 了但被合并进 order ≥ 4**（`MAX_ORDER=11`，buddy 链空闲时会一路并到 4 MB）

**建议的下一步（P0）**：只跑 ctx 分配 + `close` + `kill`（**不触发 PI walk**），
在 discard 前后读 `/proc/meminfo` 的 `MemFree`：

- `ΔMemFree ≈ 0` ⇒ 没 discard ⇒ 去查 SLUB 三道门
- `ΔMemFree > 0`（32 KB 整数倍）⇒ discard 了 ⇒ 问题在**合并**或抢占

> 局限：合并不改变 `MemFree`（页仍然是 free），这个实验只能区分
> "discard vs 没 discard"，分不出"合并 vs 没合并"。

**若确认是合并（H6）**：让 base 页的 order-3 buddy **不空闲**。
依据：`pre_ctx 35 + child_leak 1 = 36` = 正好一页（base 页），`post_ctx 36` = 另一页。
若两者物理相邻，清空 base 页时 post_ctx 页仍有对象 ⇒ buddy 不空闲 ⇒ 不合并 ⇒ 留在队首。
**这个几何配置从未被验证过。**

---

## ✅ 已经查清的部分（源码 + 反汇编双证）

### 写原语路径

`rb_erase_cached @ 0xffffff80090d57c0`：

```
0x57c0  ldp  x9,x8,[x0,#8]   ; x9=rb_right, x8=rb_left
0x57d8  cbz  x8,+0x12c       ; left==0 ⇒ 走写原语路径
0x58ec  ldr  x10,[x0]        ; pc
0x58f0  ands x8,x10,#~3      ; P = pc & ~3
0x5904  str  x9,[x8,#8]      ; ★ *(P+8) = child(0)  ← 8 字节 store
0x591c  tbz  w10,#0,+0x284   ; pc bit0==0 (RED) ⇒ 干净 ret，不进 rebalance
```

- stamp 默认写 `left=0 / right=0 / pc=P` ⇒ **正好走这条路** ⇒ **只要 payload 落页，写原语就成**
- **写原语是 8 字节 store**，不是 1 字节！会清掉 `target..target+7`

### 写目标（关键纠正）

| | 地址 | offset（相对 `KIMAGE_TEXT_BASE=0xffffff8008080000`） |
|---|---|---|
| ✅ **正确** | `0xffffff800a100b08` = `&selinux_state` | **`0x02080B08`** |
| ❌ 作废 | `0xffffff800a100b28` = `selinux_enforcing_boot` | `0x02080B28` |

`0xa100b28` 是 **`selinux_enforcing_boot`**：`static int`，仅 `__init` 期读一次，
**运行期改它 `getenforce` 永远不会变**。
历史上所有"写原语成功但 `getenforce` 没变"的轮次，很可能都是写到了这个死变量上。

真开关是 `struct selinux_state.enforcing`（`bool`，结构体 `+1`）。
`selinux_init @0x9730544` 反汇编三重自洽：

```
0x9730590  add x8, x8, #0xb08   ; x8 = &selinux_state = 0xa100b08
0x97305a4  stp xzr,xzr,[x8]     ; memset 起点 = 结构体起点
0x97305ac  str xzr,[x0,#24]!    ; → &state->ss  (+24) ✓
0x97305b4  str xzr,[x19,#16]!   ; → &state->avc (+16) ✓
0x97305b8  strb w10,[x8,#1]     ; state->enforcing (bool @+1)
```

8 字节清零覆盖 `+0..+7`：`disabled / enforcing / checkreqprot / initialized / policycap[0..3]`。
`avc(@+16)` / `ss(@+24)` **不在写范围内，安全**。
`initialized=0` 已查源码：只导致少做 inode 重校验，**不会 panic**。

### 颜色位铁律

- **被 erase 的悬空 waiter** 的 `pc` 必须 **bit0 = 0（RED）**
  否则进 `____rb_erase_color`，拿 `P->rb_left`（.bss 里的 0）当 `rb_node` 解引用 ⇒ **必 panic**
- ⚠️ 方向相反的**另一处**：`enqueue` 侧 `w1` 的两个 `pc` 必须 **= 1（BLACK）**，防 `__rb_insert` 旋转
- 两者正好相反，历史上搞混过

### 崩点判据表

| 崩点 | 含义 |
|---|---|
| `KE at _raw_spin_trylock+0x1c` | `fake_lock` 指向**未映射页** ⇒ payload 未落页（或泄漏是假阳性） |
| `HWT`（硬挂，无崩点） | `trylock` 失败 ⇒ 无限自旋 ⇒ `fake_lock` 处内容 ≠ 0 ⇒ payload 未落页 |
| `KE at rt_mutex_adjust_prio_chain+0x14c` | 页**已映射**但内容不是 payload（`*(fake_lock+0x10)` 无效） |
| `KE at rt_mutex_adjust_prio_chain+0x65c` | `BUG_ON(w->lock != lock)`，页已映射但锁树错 |
| `KE at rb_erase_cached+0x30` | 被 erase 节点是**双子树**（`left!=0 且 right!=0`） |

> `+0x1c/0x70` 里的 `/0x70` 是**函数总长度**，不是另一个偏移。

### 泄漏质量判据

`bf_tol_hits == 1` **且** `best_hits == 4` ⇒ 唯一解 + 满分，最可信。
`best_hits == 3` ⇒ 必是假阳性（同一真 `mm_struct` 下 5 个固定 futex 地址必然全部相等）。

---

## ❌ 已证伪的路线（别再走一遍）

| 路线 | 为什么不行 |
|---|---|
| `STAMP_KEEP_LOCK`（保留真锁） | waiter->lock 本身悬空，结构性不可行 |
| 扩 `pre_ctx` 到 107 | 8 个 mm_struct 本就同页，无意义 |
| `post-release` 900 次 fork 冲击 | slab 反而升 312 kB |
| 增大喷页量（59 MB 洪水） | base 页被淹没，越大越差 |
| "占满 `free_area[3]`" | `__GFP_NORETRY` 导致直接降级，结构性不可行 |
| 为 `sched_setattr` 路径预置 `pi_waiters` | 该路径 `orig_waiter=NULL ⇒ top_waiter=NULL`，**整块检查被跳过** |
| 用户态直读内核内存验证 payload 落页（`WD_FL` 探针） | `ARM64_PAN=y` ⇒ EL0 访问任何内核地址必 fault，探针**设计上不可能工作** |
| `prio` 改 200 | 第一轮 `top_waiter` 与 prio 无关 |

---

## ⚠️ 两个坑（本机特有）

1. **`syms7.txt` 的 D 型符号「名字 ↔ 地址」配对不可靠**
   `selinux_state` / `selinux_blob_sizes` / `selinux_enforcing` 三条名字与地址**错位一格**，
   靠反汇编三重自洽才纠正。推测是 kallsyms 压缩名解码时漏符号导致串位。
   ⇒ **用任何 D 型符号前必须反汇编独立验证。**
   （另：`KALLSYMS_ALL` 未开 ⇒ `vmlinux.elf` 里完全没有数据符号）

2. **设备崩溃后必须做源码 NUL 检测**
   有一次内核崩溃重启后，`util.c` 变成 **46245 字节全 0**。
   ```bash
   find . -name '*.c' -o -name '*.h' | xargs -I{} sh -c \
     'tr -d "\0" < {} | head -c1 | grep -q . || echo NUL:{}'
   ```

---

## 未能获取的证据（已知边界）

- `/proc/kallsyms`、`dmesg`、pstore、`/proc/last_kmsg`、`/data/tombstones` ⇒ **全部 denied**
- `db.fatal.NN.*.dbg` **已加密**（熵满、无明文）⇒ **取不到寄存器与 fault address**
- AEE 文本报告里 `virtual address` 后的值**全为空**（AEE 脱敏）
- ⇒ 崩点只能从 `ZZ_INTERNAL` / `db_history` 的明文里取
- ⇒ 替代方案：用**崩点形态**区分页是否映射（见上表），已足够

---

## 上游 / 致谢

- 原始 PoC：**NebuSec / CyberMeowfia**（Apache-2.0）
- `IonStack/CVE-2026-43499` 及其他移植版（4.19 / 6.x）
- 本适配（`ares` / MT6893 / 4.14.186）：**Snow** — 由许愿式编程 + AI 协作完成

## License / 免责声明

Apache-2.0（沿用上游）。

**仅供安全研究与自有设备使用。** 本项目是一个**未完成**的、针对**作者本人持有设备**的
适配实验。请勿用于未授权设备。使用风险自负 —— 利用链会触发内核 panic 并导致设备重启，
反复触发可能损坏存储。
