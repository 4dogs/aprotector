/*
 * Copyright (C) 2009 The Android Open Source Project
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
 * Jit control
 */
#ifndef DALVIK_INTERP_JIT_H_
#define DALVIK_INTERP_JIT_H_

#include "InterpDefs.h"
#include "mterp/common/jit-config.h"

#define JIT_MAX_TRACE_LEN 100			/* TRACE最大的数量 */

#if defined (WITH_SELF_VERIFICATION)

/* shadow空间默认的长度 */
#define REG_SPACE 256                /* default size of shadow space */
/* 堆空间默认的长度 */
#define HEAP_SPACE JIT_MAX_TRACE_LEN /* default size of heap space */

/**
 * @brief Shadow堆
 */
struct ShadowHeap {
    int addr;			/* 地址 */
    int data;			/* 数据 */
};

/**
 * @brief 指令trace
 */
struct InstructionTrace {
    int addr;						/* 地址 */
    DecodedInstruction decInsn;		/* 解码指令 */
};

/**
 * @brief Shadow区域
 * @note 为自校验提供帮助
 */
struct ShadowSpace {
    const u2* startPC;          /* starting pc of jitted region */
    u4* fp;                     /* starting fp of jitted region */
    const Method *method;
    DvmDex* methodClassDex;
    JValue retval;
    const u1* interpStackEnd;
    SelfVerificationState jitExitState;  /* exit point for JIT'ed code */
    SelfVerificationState selfVerificationState;  /* current SV running state */
    const u2* endPC;            /* ending pc of jitted region */
    void* shadowFP;       /* pointer to fp in shadow space */
    int* registerSpace;         /* copy of register state */
    int registerSpaceSize;      /* current size of register space */
    ShadowHeap heapSpace[HEAP_SPACE]; /* copy of heap space */
    ShadowHeap* heapSpaceTail;        /* tail pointer to heapSpace */
    const void* endShadowFP;    /* ending fp in shadow space */
    InstructionTrace trace[JIT_MAX_TRACE_LEN]; /* opcode trace for debugging */
    int traceLength;            /* counter for current trace length */
};

/*
 * Self verification functions.
 */
/*
 * 自校验函数
 */
extern "C" {
void* dvmSelfVerificationShadowSpaceAlloc(Thread* self);
void dvmSelfVerificationShadowSpaceFree(Thread* self);
void* dvmSelfVerificationSaveState(const u2* pc, u4* fp,
                                   Thread* self,
                                   int targetTrace);
void* dvmSelfVerificationRestoreState(const u2* pc, u4* fp,
                                      SelfVerificationState exitPoint,
                                      Thread *self);
void dvmCheckSelfVerification(const u2* pc, Thread* self);
}
#endif

/*
 * Offsets for metadata in the trace run array from the trace that ends with
 * invoke instructions.
 */
/**
 * @brief 以一个invoke指令为结尾的trace请求元数据的偏移
 */
#define JIT_TRACE_CLASS_DESC    1			/* 类描述 */
#define JIT_TRACE_CLASS_LOADER  2			/* 类加载器，类对象 */
#define JIT_TRACE_CUR_METHOD    3			/* 当前函数 */

/*
 * JitTable hash function.
 */
/*
 * JitTable 哈希表
 */
static inline u4 dvmJitHashMask( const u2* p, u4 mask ) {
	/*
	 * 右移12位 异或 本身后 向左移动1位
	 */
    return ((((u4)p>>12)^(u4)p)>>1) & (mask);
}

static inline u4 dvmJitHash( const u2* p ) {
    return dvmJitHashMask( p, gDvmJit.jitTableMask );
}

/*
 * The width of the chain field in JitEntryInfo sets the upper
 * bound on the number of translations.  Be careful if changing
 * the size of JitEntry struct - the Dalvik PC to JitEntry
 * hash functions have built-in knowledge of the size.
 */
/**
 * @note
 *	在JitEntryInfo中chain字段的宽度上界
 *	如果改变JitEntry结构的大小 - Dalvik虚拟机 JitEntry hash函数必须知道
 *	这个长度
 */
#define JIT_ENTRY_CHAIN_WIDTH 2
#define JIT_MAX_ENTRIES (1 << (JIT_ENTRY_CHAIN_WIDTH * 8))		/* 32 */

/*
 * The trace profiling counters are allocated in blocks and individual
 * counters must not move so long as any referencing trace exists.
 */
#define JIT_PROF_BLOCK_ENTRIES 1024
#define JIT_PROF_BLOCK_BUCKETS (JIT_MAX_ENTRIES / JIT_PROF_BLOCK_ENTRIES)

typedef s4 JitTraceCounter_t;

struct JitTraceProfCounters {
    unsigned int           next;
    JitTraceCounter_t      *buckets[JIT_PROF_BLOCK_BUCKETS];
};

/*
 * Entries in the JIT's address lookup hash table.
 * Fields which may be updated by multiple threads packed into a
 * single 32-bit word to allow use of atomic update.
 */

/**
 * @brief Jit哈希表项配置项
 */
struct JitEntryInfo {
    unsigned int           isMethodEntry:1;			/* 是函数入口 */
    unsigned int           inlineCandidate:1;
    unsigned int           profileEnabled:1;		/* profiling启动 */
    JitInstructionSetType  instructionSet:3;		/* 要编译的硬件平台 */
    unsigned int           profileOffset:5;			/* profiling关闭 */
    unsigned int           unused:5;
	/* 下一个链接单元的索引 */
    u2                     chain;                 /* Index of next in chain */
};

/**
 * @brief 一个Jit项的选项
 */
union JitEntryInfoUnion {
    JitEntryInfo info;
    volatile int infoWord;
};

/**
 * @brief Jit HASH表项
 */
struct JitEntry {
    JitEntryInfoUnion   u;				/* 选项 */
	/* Dalvik字节码的指针 */
    const u2*           dPC;            /* Dalvik code address */
	/* 编译出的本地代码缓冲指针 */
    void*               codeAddress;    /* Code address of native translation */
};

extern "C" {
void dvmCheckJit(const u2* pc, Thread* self);					/* 检查Jit */
void* dvmJitGetTraceAddr(const u2* dPC);						/* 获取Trace的地址 */
void* dvmJitGetMethodAddr(const u2* dPC);						/* 获取函数地址 */
void* dvmJitGetTraceAddrThread(const u2* dPC, Thread* self);	/* 获取trace地址的线程 */
void* dvmJitGetMethodAddrThread(const u2* dPC, Thread* self);	/* 获取函数地址的线程 */
void dvmJitCheckTraceRequest(Thread* self);						/* 检查trace请求 */
void dvmJitStopTranslationRequests(void);						/* 停止编译请求 */

/* JIT性能监视 */
#if defined(WITH_JIT_TUNING)
void dvmBumpNoChain(int from);
void dvmBumpNormal(void);
void dvmBumpPunt(int from);
#endif

void dvmJitStats(void);											/* Jit的状态 */
bool dvmJitResizeJitTable(unsigned int size);					/* 重新设置Jit表的大小 */
void dvmJitResetTable(void);									/* 重设置Jit表 */
JitEntry *dvmJitFindEntry(const u2* pc, bool isMethodEntry);	/* 查找Jit表 */
s8 dvmJitd2l(double d);										
s8 dvmJitf2l(float f);
void dvmJitSetCodeAddr(const u2* dPC, void *nPC, JitInstructionSetType set,
                       bool isMethodEntry, int profilePrefixSize);			/* 设置Jit代码地址 */
void dvmJitEndTraceSelect(Thread* self, const u2* dPC);						/* 结束trace选择 */
JitTraceCounter_t *dvmJitNextTraceCounter(void);							/* 下一个trace计数器 */
void dvmJitTraceProfilingOff(void);											/* trace profiling关闭 */
void dvmJitTraceProfilingOn(void);											/* trace profiling开启 */
void dvmJitChangeProfileMode(TraceProfilingModes newState);					/* 改变profile模式 */
void dvmJitDumpTraceDesc(JitTraceDescription *trace);						/* 打印trace描述 */
void dvmJitUpdateThreadStateSingle(Thread* threead);						/* 更新单个线程状态 */
void dvmJitUpdateThreadStateAll(void);										/* 更新所有线程状态 */
void dvmJitResumeTranslation(Thread* self, const u2* pc, const u4* fp);		/* 回复编译 */
}

#endif  // DALVIK_INTERP_JIT_H_
