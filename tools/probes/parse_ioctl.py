import re

lines = open('/tmp/kbase_ioctl.txt').read().split('\n')

# 解析: 找到 mov wX,#imm16 后紧跟 movk wX,#imm16,lsl#16 -> 组成 32 位常量
pending = {}
consts = {}   # addr -> value

for ln in lines:
    m = re.match(r'([0-9a-f]+):\t([0-9a-f]{8}) \t(\w+)\t(.*)', ln)
    if not m:
        continue
    addr, op, mnem, args = m.group(1), m.group(2), m.group(3), m.group(4)

    if mnem == 'mov':
        mm = re.match(r'w(\d+), #(0x[0-9a-f]+)', args)
        if mm:
            pending[mm.group(1)] = int(mm.group(2), 16)
    elif mnem == 'movk':
        mm = re.match(r'w(\d+), #(0x[0-9a-f]+), lsl #16', args)
        if mm:
            reg = mm.group(1)
            if reg in pending:
                val = pending[reg] | (int(mm.group(2), 16) << 16)
                consts[addr] = val
                del pending[reg]

# 只保留看起来像 ioctl 编码的值（_IO* 高位为 0x40/0x80/0xc0 开头）
ioctls = {}
for a, v in consts.items():
    if (v >> 24) in (0x40, 0x80, 0xc0, 0x00) and (v & 0xff) < 0x80:
        ioctls[a] = v

print(f'共解析出 {len(consts)} 个 32 位常量，其中疑似 ioctl {len(ioctls)} 个')
print()
print('addr        cmd          size  dir  type  nr')
for a, v in sorted(ioctls.items(), key=lambda x: x[1]):
    size = (v >> 16) & 0x3fff
    d = (v >> 30) & 3
    typ = (v >> 8) & 0xff
    nr = v & 0xff
    dirstr = ['none', 'W', 'R', 'RW'][d]
    print(f'0x{a}  0x{v:08x}  {size:5d}  {dirstr:2s}  0x{typ:02x}  {nr:3d}')