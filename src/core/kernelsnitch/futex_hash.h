#pragma once

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------
typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint8_t u8;

// #include <linux/bitops.h>
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define fallthrough __attribute__((fallthrough));
// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */
// #include <linux/bitops.h>
// #include <linux/unaligned/packed_struct.h>

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((u32)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)            \
{                        \
    a -= c;  a ^= rol32(c, 4);  c += b;    \
    b -= a;  b ^= rol32(a, 6);  a += c;    \
    c -= b;  c ^= rol32(b, 8);  b += a;    \
    a -= c;  a ^= rol32(c, 16); c += b;    \
    b -= a;  b ^= rol32(a, 19); a += c;    \
    c -= b;  c ^= rol32(b, 4);  b += a;    \
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)            \
{                        \
    c ^= b; c -= rol32(b, 14);        \
    a ^= c; a -= rol32(c, 11);        \
    b ^= a; b -= rol32(a, 25);        \
    c ^= b; c -= rol32(b, 16);        \
    a ^= c; a -= rol32(c, 4);        \
    b ^= a; b -= rol32(a, 14);        \
    c ^= b; c -= rol32(b, 24);        \
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL        0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */


/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{

    u32 a, b, c;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL + (length<<2) + initval;

    /* Handle most of the key */
    while (length > 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __jhash_mix(a, b, c);
        length -= 3;
        k += 3;
    }

    /* Handle the last 3 u32's: all the case statements fall through */
    switch (length) {
    case 3: c += k[2];    fallthrough;
    case 2: b += k[1];    fallthrough;
    case 1: a += k[0];
        __jhash_final(a, b, c);
    case 0:    /* Nothing left to add */
        break;
    }

    return c;
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#define OFFSET_OF(TYPE, FIELD) ((size_t) &((TYPE *)0)->FIELD)
#ifndef KS_PAGE_MASK
#define KS_PAGE_MASK 0xfffULL
#endif

#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = 0ULL } }

typedef union {
    struct {
        uint64_t i_seq;
        unsigned long pgoff;
        unsigned int offset;
    } shared;
    struct {
        union {
            // struct mm_struct *mm;
            void *mm;
            uint64_t __tmp;
        };
        unsigned long address;
        unsigned int offset;
    } private;
    struct {
        uint64_t ptr;
        unsigned long word;
        unsigned int offset;
    } both;
} futex_key_t;

uint32_t futex_hash_no_trunc(futex_key_t *key)
{
    uint32_t hash = jhash2((uint32_t *)key, OFFSET_OF(typeof(*key), both.offset) / 4,
              key->both.offset);

    return hash;
}

uint32_t __futex_hash(futex_key_t *key, uint32_t futex_hashsize)
{
    uint32_t hash = futex_hash_no_trunc(key);

    return hash & (futex_hashsize-1);
}

/* [源码] futex.c:689 key->both.offset |= FUT_OFF_MMSHARED;
 * [反汇编] get_futex_key 0x81746f0 orr w8,w8,#0x1  => 值为 1 */
#ifndef FUT_OFF_MMSHARED
#define FUT_OFF_MMSHARED 0x1
#endif
unsigned long futex_hashsize = (unsigned long)-1;
void futex_init(void)
{
    futex_hashsize = SYSCHK(sysconf(_SC_NPROCESSORS_ONLN) * 256);
    /* Allow overriding the futex hash table size for porting: some kernels use
     * a fixed 1<<FUTEX_HASHBITS (=256) instead of cpu_cnt*256. */
    {
        const char *hs = getenv("KS_HASHSIZE");
        if (hs && *hs) { futex_hashsize = (unsigned long)strtoul(hs, 0, 0); return; }
    }
    /* ===== 重建134（gK34）：暂时恢复 256 默认，优先复现 2026-10-19 成功条件 =====
     * 反汇编算出内核是 2048，但实测 2048 也 leak failed，说明 hashsize 不是关键变量。
     * 成功那次是 256，先复现，再用 KS_HASHSIZE 做单变量对比。
     * （下面这段旧说明保留备查）
     * ===== 重建129（gK31）：删掉 4.14 强制 256 的错误特判 =====
     * [源码] kernel/futex.c:4206
     *     futex_hashsize = roundup_pow_of_two(256 * num_possible_cpus());
     * [反汇编] futex_init @ 0xffffff80097120e4:
     *     +0x18 clz x8,x8 / +0x20 neg / +0x24 lsl x2,x19,x8  => 1<<ilog2(256*ncpu)
     *     +0x54 bl alloc_large_system_hash(..., hint=2048, max=2048, &futex_shift)
     *     +0x68 lsl x8,x19,x8 (futex_shift) => futex_hashsize = 1<<11 = 2048
     * [实测] 本机 8 核（possible 0-7），256*8 = 2048。
     *
     * 原代码把客户端 hashsize 硬编码成 256，与内核实际 2048 不一致，
     * 导致 futex_hash() 算出的桶号完全错误 —— 碰撞判据失效，
     * KernelSnitch 只能靠巧合返回 bogus 地址（r115 11.6GiB / r116 6.32GiB 均如此）。
     * 删掉该特判后，hashsize = ncpu*256 = 2048，与内核一致。 */
    /* ===== gK44：hashsize 由 256 改为 2048（源码铁证）=====
     * [B-源码] kernel/futex.c:4201-4214（4.14.186 本机源码）：
     *   futex_hashsize = roundup_pow_of_two(256 * num_possible_cpus());
     *   futex_queues = alloc_large_system_hash("futex", ..., 
     *       futex_hashsize, 0, ..., &futex_shift, NULL,
     *       futex_hashsize, futex_hashsize);   // hint = max = futex_hashsize
     *   futex_hashsize = 1UL << futex_shift;
     * [A-实测] /sys/devices/system/cpu/possible = 0-7 ⇒ num_possible_cpus() = 8
     * [C-计算] 256 * 8 = 2048 = 2^11；hint==max 时不缩放 ⇒ futex_shift = 11
     *   ⇒ **内核 futex_hashsize = 2048**
     *
     * 之前硬编码 256 是错的。影响：
     *   客户端桶 = hash32 & 0xFF（8bit），内核桶 = hash32 & 0x7FF（11bit）
     *   ⇒ 判据变宽松，假阳性期望从 0.0011 升到 0.571（522 倍）
     *   ⇒ 注意：真碰撞在两种 hashsize 下都能识别（低8位是低11位的子集），
     *     所以 hashsize 不是「真值识别失败」的根因，但修正后假阳几乎归零。
     */
    futex_hashsize = 2048;
}
uint32_t futex_hash(size_t addr, size_t mm)
{
    ASSERT_pr((futex_hashsize != (unsigned long)-1), "need to call futex_init() first\n");
    futex_key_t key;
    key.private.mm = (void *)mm;
    key.private.address = addr & ~KS_PAGE_MASK;
    /* ===== 重建132（gK32b）：PRIVATE futex 的 offset 是裸值，不能加标志位 =====
     * [源码] kernel/futex.c:569-590（!fshared 的 PROCESS_PRIVATE 快速路径）:
     *     key->both.offset = address % PAGE_SIZE;   // 裸 offset，无标志位
     *     address -= key->both.offset;
     *     key->private.mm = mm;
     *     key->private.address = address;
     *     get_futex_key_refs(key);   // 只读 offset，不写
     * [反汇编] get_futex_key @ 0xffffff800817445c:
     *   PRIVATE 路径 0x8174694-0x81746b8: ldr/and #3/cmp —— 只读，无 orr
     *   SHARED 路径才有 orr: 0x81746dc orr #2 (INODE) / 0x81746f0 orr #1 (MMSHARED)
     * 重建131 误把 SHARED 分支的 orr 当成 PRIVATE 也有，是错的，已回滚。 */
    key.private.offset = (addr & KS_PAGE_MASK);
    return __futex_hash(&key, futex_hashsize);
}
