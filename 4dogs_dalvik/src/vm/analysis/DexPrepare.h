/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
DEX preparation declarations.

DEX准备声明。
*/
#ifndef DALVIK_DEXPREPARE_H_
#define DALVIK_DEXPREPARE_H_

/*
Global DEX optimizer control.  Determines the circumstances in which we
try to rewrite instructions in the DEX file.

Optimizing is performed ahead-of-time by dexopt and, in some cases, at
load time by the VM.

全局DEX优化器控制。定义在DEX文件中重写指令的环境。

某些情况下，在VM加载时，通过dexopt优化。
*/
enum DexOptimizerMode {	  
    OPTIMIZE_MODE_UNKNOWN = 0,
    /* 不优化 */
    OPTIMIZE_MODE_NONE,         /* never optimize (except "essential") */
    /* 仅优化校验过的类(默认) */
    OPTIMIZE_MODE_VERIFIED,     /* only optimize verified classes (default) */
    /* 优化校验 & 未校验的类(有风险) */
    OPTIMIZE_MODE_ALL,          /* optimize verified & unverified (risky) */
    /* 在加载时全部优化校验过的类 */
    OPTIMIZE_MODE_FULL          /* fully opt verified classes at load time */
};

/* 
some additional bit flags for dexopt 

一些dexopt的额外bit标识。
*/
enum DexoptFlags {
	  /* 优化激活？ */
    DEXOPT_OPT_ENABLED       = 1,       /* optimizations enabled? */
    /* 当校验失败时优化？ */
    DEXOPT_OPT_ALL           = 1 << 1,  /* optimize when verify fails? */
    /* 校验激活 */
    DEXOPT_VERIFY_ENABLED    = 1 << 2,  /* verification enabled? */
    /* 校验引导类？ */
    DEXOPT_VERIFY_ALL        = 1 << 3,  /* verify bootstrap classes? */
    /* dex在引导类路径中? */
    DEXOPT_IS_BOOTSTRAP      = 1 << 4,  /* is dex in bootstrap class path? */
    /* 在优化中生成寄存器maps */
    DEXOPT_GEN_REGISTER_MAPS = 1 << 5,  /* generate register maps during vfy */
    /* 指定单机处理目标 */
    DEXOPT_UNIPROCESSOR      = 1 << 6,  /* specify uniprocessor target */
    /* 指定SMP目标 */
    DEXOPT_SMP               = 1 << 7   /* specify SMP target */
}; 

/*
An enumeration of problems that can turn up during verification.

验证过程中出现的问题枚举
*/
enum VerifyError {
    VERIFY_ERROR_NONE = 0,      /* no error; must be zero */
    VERIFY_ERROR_GENERIC,       /* VerifyError */
    VERIFY_ERROR_NO_CLASS,      /* NoClassDefFoundError */
    VERIFY_ERROR_NO_FIELD,      /* NoSuchFieldError */
    VERIFY_ERROR_NO_METHOD,     /* NoSuchMethodError */
    VERIFY_ERROR_ACCESS_CLASS,  /* IllegalAccessError */
    VERIFY_ERROR_ACCESS_FIELD,  /* IllegalAccessError */
    VERIFY_ERROR_ACCESS_METHOD, /* IllegalAccessError */
    VERIFY_ERROR_CLASS_CHANGE,  /* IncompatibleClassChangeError */
    VERIFY_ERROR_INSTANTIATION, /* InstantiationError */
};

/*
Identifies the type of reference in the instruction that generated the
verify error (e.g. VERIFY_ERROR_ACCESS_CLASS could come from a method,
field, or class reference).

This must fit in two bits.

在生成校验错误的指令中定义引用类型(例如: VERIFY_ERROR_ACCESS_CLASS可能来自于一个方法、域或类引用)。
*/
enum VerifyErrorRefType {
    VERIFY_ERROR_REF_CLASS  = 0,
    VERIFY_ERROR_REF_FIELD  = 1,
    VERIFY_ERROR_REF_METHOD = 2,
};

#define kVerifyErrorRefTypeShift 6

#define VERIFY_OK(_failure) ((_failure) == VERIFY_ERROR_NONE)

/*
Given the full path to a DEX or Jar file, and (if appropriate) the name
within the Jar, open the optimized version from the cache.

If "*pNewFile" is set, a new file has been created with only a stub
"opt" header, and the caller is expected to fill in the blanks.

Returns the file descriptor, locked and seeked past the "opt" header.

给定DEX或Jar文件全路径，打开来自缓存的优化版本。
*/
int dvmOpenCachedDexFile(const char* fileName, const char* cachedFile,
    u4 modWhen, u4 crc, bool isBootstrap, bool* pNewFile, bool createIfMissing);

/*
Unlock the specified file descriptor.  Use in conjunction with
dvmOpenCachedDexFile().

Returns true on success.

解锁指定的DEX文件。配合dvmOpenCachedDexFile()使用。
*/
bool dvmUnlockCachedDexFile(int fd);

/*
Verify the contents of the "opt" header, and check the DEX file's
dependencies on its source zip (if available).

校验“opt”头的内容，并且检查DEX文件在源压缩文件中的依赖。
*/
bool dvmCheckOptHeaderAndDependencies(int fd, bool sourceAvail, u4 modWhen,
    u4 crc, bool expectVerify, bool expectOpt);

/*
Optimize a DEX file.  The file must start with the "opt" header, followed
by the plain DEX data.  It must be mmap()able.

"fileName" is only used for debug output.

优化一个DEX文件。这个文件必须以“opt”头为起始，后面拼接完整的DEX数据。它必须能被mmap()映射。
*/
bool dvmOptimizeDexFile(int fd, off_t dexOffset, long dexLen,
    const char* fileName, u4 modWhen, u4 crc, bool isBootstrap);

/*
Continue the optimization process on the other side of a fork/exec.

NOTE TODO：
*/
bool dvmContinueOptimization(int fd, off_t dexOffset, long dexLength,
    const char* fileName, u4 modWhen, u4 crc, bool isBootstrap);

/*
Prepare DEX data that is only available to the VM as in-memory data.

准备DEX数据提只供给虚拟机内存数据。
*/
bool dvmPrepareDexInMemory(u1* addr, size_t len, DvmDex** ppDvmDex);

/*
Prep data structures.

准备数据结构。
*/ 
bool dvmCreateInlineSubsTable(void);
void dvmFreeInlineSubsTable(void);

#endif  // DALVIK_DEXPREPARE_H_
