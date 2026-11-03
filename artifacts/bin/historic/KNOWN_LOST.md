# 已知损坏资产

本目录记录因“设备崩溃破坏存储”事故而永久丢失的资产。

## 全零（无法恢复）

| 资产 | 大小 | 说明 |
|---|---|---|
| `gK79` | 951360 B | 二进制全零。原文件在 /sdcard/Download 上时就已全零。同代可用替代：`gK79_verify`（完好，md5 46379707） |
| `gK57` | 951144 B | 二进制全零（/root/02_build 内）。README 级别的损失——它是唯一一次拿到完整内核寄存器现场的实验。**寄存器内容已抢救**：见 `logs/evidence/last_kmsg_gK57.txt` |
| `pre.log` / `r116_gk30_mm360.log` / `run_092557.log` / `run_gk9_A.log` / `run_sm2_100808.log` | 14~838 B | 早期 ckpt 日志全零，已剔除 |

## 教训

设备内核崩溃（panic/HWT）后，存储可能出现文件被清零。
**每次崩溃后必须做全量 NUL 检测**，不要假设文件完好。

检测脚本（shell 版有二进制误报，用 Python 版）：

```python
import os
for root,d,fs in os.walk(.):
    if .git in root: continue
    for f in fs:
        p=os.path.join(root,f)
        b=open(p,rb).read()
        if len(b)>0 and sum(1 for x in b if x)==0: print(ALL-NUL:,p)
```
