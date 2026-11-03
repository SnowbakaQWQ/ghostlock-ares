# GhostLock CVE-2026-43499 - Redmi K40 (alioth)

Target: Redmi K40 (alioth, SM8250, 8 GB, 4.19.157-perf, MIUI V816 Android 13, BL locked).
Goal: Firefox JIT chain loads preload, kernel privilege escalation to root.
Hard constraint: do not brick the phone; BL unlock is rejected.

## Fixed Route

`slide pselect (futex PI)` is a proven dead end on this kernel; skip it entirely:

```text
KernelSnitch mm leak (PC-hybrid) -> prepare FOPS page -> punch (PI walk on fake waiter)
-> fops hijack -> configfs arbitrary read/write -> scan_kaslr_base (configfs read, 8 GB / 2 MB step)
-> linear-map calibration (memstart_addr) -> pipe physrw -> root
```

## Build Commands

Windows / pwsh; inner quotes for `cmd /c` use backtick:

```powershell
cmd /c "D:\project\my_py_project\ghostlock-cve-2026-43499-4.19-k40\ghostlock-app\ndk\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd @build_wakefix.rsp"
```

- Output: `build/alioth/bin/preload.so`.
- `build_wakefix.rsp` carries the terminating-form rb node, `punch nice=1`, and drops the ineffective early wake. For dual-pile builds use `build_wakefix_dualpile.rsp`.
- Target header: `src/targets/alioth-4.19.157-perf/target.h`.

## Host Tools

- NDK: `D:\codeTool\ndk\android-ndk-r26b` (aarch64 clang for preload builds).
- adb: `D:\software\commonTool\scrcpy-win64-v2.7\adb.exe` (verified in M2; `tools-k40\platform-tools\adb.exe` is absent on this host).
- `D:\codeTool\commonTool`: cc_switch, electron, Git, Navicat for MySQL, qClaw, SVN, Unity, WeChat devtools.
- `D:\codeTool\ide`: Android Studio, GoLand, HBuilderX, IntelliJ IDEA, VS Code / VS Code Insiders, Trae CN, WebStorm.
- `D:\codeTool\zig`: zig-windows-x86_64-0.11.0.
- `D:\codeTool\codeEnv`: cocos, Creator, flutterEnv, go, jdk8/17/21, maven, python, unity, webEnv.

## Material Sources (convention)

All external reference material (kernel source trees, ROM trees, rootfs
dumps) lives under `materials/` (git-ignored; may be a junction to the real
tree elsewhere on disk). Do not put source trees under `kernelsrc/`.

Before requesting source material, check ADR-0004. If the material is already
registered, use that path. If it is missing, request it with an explicit target
path and kind (kernel tree / ROM tree / rootfs dump / other artifact). When the
user provides it, the receiving agent places it under the conventional
`materials/` path below, verifies that the checkout is complete enough for the
claim being audited, records provenance in
`docs/adr/0004-material-source-locations.md`, then updates the task record.

Conventional paths:

- Kernel trees: `materials/kernelsrc/<vendor>-<soc>-<android>-<variant>`.
- ROM / boot images: `materials/rom/<device>-<build>`.
- Rootfs / userspace dumps: `materials/rootfs/<device>-<build>`.
- Other external artifacts: `materials/external/<name>`.

Current entries:

- Kernel source for alioth (Xiaomi SM8250, 4.19.157):
  `materials/kernelsrc/sm8250-a13-stable` (junction to
  `D:\project\my_py_project\mozi9-kernel-proxy`; full fs/mm/kernel/include
  trees, Makefile SUBLEVEL=157). Verify kernel-code claims against THIS tree,
  not `kernelsrc/` — the `kernelsrc/*` clones are broken leftovers (Windows
  `aux.c` reserved-name checkout failure) and must not be cited.

## Architecture

```text
src/main.c          preload entry / exploit orchestration
src/kernelsnitch    futex timing side channel -> mm leak, collision/candidate export
src/slide.c         pselect/futex UAF staging (dead-end route, kept for reference)
src/fops.c          fake FOPS page preparation + hijack
src/util.c          helper routines (delta, export, mm validation)
src/pipe.c          pipe physrw primitives
src/root.c          cred/SELinux patching, root shell
tools/              PC-side solvers (collision search, slab model, dual pile)
```

Data flow:

```text
device: preload -> kernelsnitch export (collision_addr/candidate_addr + timing)
PC:     ks_collisions.txt -> solver -> ks_mm_answer.txt (22-byte, atomic)
device: answer backfill -> kernelsnitch accepts mm -> FOPS punch -> configfs -> pipe -> root
```

## Key Constants (alioth 4.19.157)

- `KIMAGE_TEXT_BASE = 0xffffff8008080000`
- `PAGE_OFFSET = 0xffffffc000000000`, `PHYS_OFFSET = 0x80000000`, 39-bit VA.
- 4.19 arm64 has **no linear-map randomization**: `__phys_to_virt(x) = (x - PHYS_OFFSET) | PAGE_OFFSET`; delta is always 0.
- `mm_struct = 0x388`, `task_struct = 0x1140`, cred `0x7e0/0x7e8`, task pi fields `0x8b4-0x8d8`.
- ashmem fops family + `anon_pipe_buf_ops 0x018e8640` + `memstart_addr 0x0267adc8` (see target.h for full table).

## Device Protocol (hard requirements)

- PC answer is **exactly 22 bytes** ending with LF: `mm=0x<16hex>`.
- Push must be atomic: write `.tmp`, `sync`, `mv -f` over `ks_mm_answer.txt`, `sync`.
- Before every run: clear both `ks_mm_answer.txt` and `ghostlock_ks_cache.txt` (stale answers cause wrong kernel writes).
- `/data/local/tmp` is wiped on reboot; recreate `preload_wakefix.so` (mode 666) each round.
- `/data/local/tmp/ks_log.txt` must be pre-created with mode 666; open with bare `O_WRONLY` only (SELinux grants `write`, not `append`).

## Proven Dead Ends

- slide pselect route: panics on this kernel; do not route through it.
- delta candidate enumeration (0-7): invalid premise; 4.19 linear map has no randomization, so delta is always 0. Blind scans were structurally doomed.
- CVE-2019-13272: ptrace_link is unpatched but there are zero usable setuid-root binaries as trampolines; `/system` read-only overlay cannot be planted.
- manifest generic entry `redmi_k40_4.19.so`: slide route, immediate reboot; do not match.
- PC-side legacy `futex_addr=` data (e.g. `run5_coll16`): mixed semantics (collision + timing candidates); solvers must only parse `collision_addr=`.
- Rejected mm candidates: `0xffffffe585065e00`, `0xffffffd5b5c69380`, `0xffffffc02cd1ea00` (device-rejected or panic-inducing false positives).

## Operating Safety

- Continuously advance: after each subtask completes, immediately move to the next action and keep waiting for the agent to finish; do not stop to await user instruction. Pause only on hard constraints (safety risk / resources requiring user decision).
- Every on-device run can cost a reboot; do not run without a falsifiable hypothesis.
- One shot per boot: a failed attempt pollutes kernel state. Never auto-retry in the same boot; stop, capture evidence, reboot.
- Kernel-mode spin is unkillable; only recovery is user long-press power (adb reboot usually fails).
- Sustained full load triggers thermal shutdown; cool down between scans.
- Gate every on-device run on low load (check `/proc/loadavg`; LMKD silently SIGKILLs fork-heavy preload under load and the log just stops mid-marker).
- Run preload in foreground (`nohup` background gets silently killed).
- Never clean up with `pkill -f`: the `-f` pattern matches the caller's own shell cmdline and kills it (exit 137). Verify with `ps`, kill by PID, or skip if no residue.
- After any panic/reboot, hash-verify pushed binaries before reuse; panic can corrupt page cache and zero files.
- PC-side hash word order is fixed (ADR-0001): `w[0..3] = address_low, address_high, mm_low, mm_high`, `initval = addr & 0xfff`; reuse `jhash2`, do not invent variants.
- Slide pselect route is re-opened as parallel track M5 per ADR-0003 (shelved, not disproven; delta is a compile-time 0). The generic `redmi_k40_4.19.so` manifest entry remains banned. Do not port the upstream repo's input-region waiter layout or loggers/bootid leak nodes to alioth: both are proven wrong on 4.19. Use v12 ready-bitmap encoding + terminal-form rb nodes.

## Cross-Device Lessons

Detailed porting lessons from the q4q (SM-F9360) adaptation — evidence
discipline, crash bisection, module-loading pitfalls — live in
`docs/lessons-q4q.md`. Consult it before new device adaptation or any
kernel-stage (FOPS/physrw/KSU) debugging. Device-specific values from q4q
must never be copied here; only the method transfers.

## Links

- Status: `docs/status.md`; Roadmap: `docs/roadmap.md`; QA: `docs/ci-status.md`.
- History archive: `docs/history.md`; ADRs: `docs/adr/`; Specs: `docs/specs/`.
- Repo: https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40
- myroot Pages (device payload host): https://ccp-p.github.io/myroot/
