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
 * Android's method call profiling goodies.
 */
#ifndef DALVIK_PROFILE_H_
#define DALVIK_PROFILE_H_

#ifndef NOT_VM      /* for utilities that sneakily include this file */

#include <stdio.h>

struct Thread;      // extern


/* boot init */
/* profiling启动初始化与关闭 */
bool dvmProfilingStartup(void);
void dvmProfilingShutdown(void);

/*
 * Method trace state.  This is currently global.  In theory we could make
 * most of this per-thread.
 */
/**
 * @brief 函数trace状态
 */
struct MethodTraceState {
    /* active state */
    pthread_mutex_t startStopLock;		/* 同步锁 */
    pthread_cond_t  threadExitCond;		/* 条件变量 */
    FILE*   traceFile;					/* trace的文件句柄 */
    bool    directToDdms;				/* 将trace的内容直接输出到DDMS */
    int     bufferSize;					/* 缓冲的大小 */
    int     flags;						/* trace的标志 */

    int     traceEnabled;				/* 启动trace */
    u1*     buf;						/* 缓冲指针 */
    volatile int curOffset;				/* 当前的偏移 */
    u8      startWhen;					/* 线程启动的时间 */
    int     overflow;					/* 缓冲是否溢出 */

    int     traceVersion;				/* trace版本 */
	/*
	 * 两种获取时间的不同
	 */
    size_t  recordSize;					/* TRACE记录结构的大小 */
};

/*
 * Memory allocation profiler state.  This is used both globally and
 * per-thread.
 *
 * If you add a field here, zero it out in dvmStartAllocCounting().
 */
/**
 * @brief 内存分配 profiler状态。可以在全局与每条线程中使用。
 */
struct AllocProfState {
	/* 已经启动 */
    bool    enabled;            // is allocation tracking enabled?

	/* 对象分配的次数 */
    int     allocCount;         // #of objects allocated
	/* 对象分配的大小 */
    int     allocSize;          // cumulative size of objects

	/* 分配失败的次数 */
    int     failedAllocCount;   // #of times an allocation failed
	/* 分配失败的大小 */
    int     failedAllocSize;    // cumulative size of failed allocations

	/* 对象释放的次数 */
    int     freeCount;          // #of objects freed
	/* 对象释放的大小 */
    int     freeSize;           // cumulative size of freed objects

	/* 用于垃圾回收的那次分配数量 */
    int     gcCount;            // #of times an allocation triggered a GC

	/* 初始化的类数量 */
    int     classInitCount;     // #of initialized classes
	/* 初始化的类时间 */
    u8      classInitTime;      // cumulative time spent in class init (nsec)
};


/*
 * Start/stop method tracing.
 */
/**
 * @brief 开始/停止 函数的tracing
 */
void dvmMethodTraceStart(const char* traceFileName, int traceFd, int bufferSize,
        int flags, bool directToDdms);
bool dvmIsMethodTraceActive(void);
void dvmMethodTraceStop(void);

/*
 * Start/stop emulator tracing.
 */
/**
 * @brief 开始/停止 仿真器的tracing
 */
void dvmEmulatorTraceStart(void);
void dvmEmulatorTraceStop(void);

/*
 * Start/stop Dalvik instruction counting.
 */
/**
 * @brief 开始/停止 dalvik指令计数
 */
void dvmStartInstructionCounting();
void dvmStopInstructionCounting();

/*
 * Bit flags for dvmMethodTraceStart "flags" argument.  These must match
 * the values in android.os.Debug.
 */
/**
 * @brief 位标记对于 dvmMethodTraceStart 的 "flags"参数。
 *	在android.os.Debug中的值
 */
enum {
    TRACE_ALLOC_COUNTS      = 0x01,
};

/*
 * Call these when a method enters or exits.
 */
/**
 * @brief 当一个函数进入或者退出时调用这些
 */
#define TRACE_METHOD_ENTER(_self, _method)                                  \
    do {                                                                    \
        if (_self->interpBreak.ctl.subMode & kSubModeMethodTrace)           \
            dvmMethodTraceAdd(_self, _method, METHOD_TRACE_ENTER);          \
        if (_self->interpBreak.ctl.subMode & kSubModeEmulatorTrace)         \
            dvmEmitEmulatorTrace(_method, METHOD_TRACE_ENTER);              \
    } while(0);
#define TRACE_METHOD_EXIT(_self, _method)                                   \
    do {                                                                    \
        if (_self->interpBreak.ctl.subMode & kSubModeMethodTrace)           \
            dvmMethodTraceAdd(_self, _method, METHOD_TRACE_EXIT);           \
        if (_self->interpBreak.ctl.subMode & kSubModeEmulatorTrace)         \
            dvmEmitEmulatorTrace(_method, METHOD_TRACE_EXIT);               \
    } while(0);
#define TRACE_METHOD_UNROLL(_self, _method)                                 \
    do {                                                                    \
        if (_self->interpBreak.ctl.subMode & kSubModeMethodTrace)           \
            dvmMethodTraceAdd(_self, _method, METHOD_TRACE_UNROLL);         \
        if (_self->interpBreak.ctl.subMode & kSubModeEmulatorTrace)         \
            dvmEmitEmulatorTrace(_method, METHOD_TRACE_UNROLL);             \
    } while(0);

void dvmMethodTraceAdd(struct Thread* self, const Method* method, int action);
void dvmEmitEmulatorTrace(const Method* method, int action);

void dvmMethodTraceGCBegin(void);
void dvmMethodTraceGCEnd(void);
void dvmMethodTraceClassPrepBegin(void);
void dvmMethodTraceClassPrepEnd(void);

extern "C" void dvmFastMethodTraceEnter(const Method* method, struct Thread* self);
extern "C" void dvmFastMethodTraceExit(struct Thread* self);
extern "C" void dvmFastNativeMethodTraceExit(const Method* method, struct Thread* self);

/*
 * Start/stop alloc counting.
 */
/**
 * @brief 开始/停止分配计数
 */
void dvmStartAllocCounting(void);
void dvmStopAllocCounting(void);

#endif


/*
 * Enumeration for the two "action" bits.
 */
enum {
    METHOD_TRACE_ENTER = 0x00,      // method entry
    METHOD_TRACE_EXIT = 0x01,       // method exit
    METHOD_TRACE_UNROLL = 0x02,     // method exited by exception unrolling
    // 0x03 currently unused
};

#define TOKEN_CHAR      '*'

/*
 * Common definitions, shared with the dump tool.
 */
/**
 * @brief 一些公用的定义，通过dumptool共享
 */
#define METHOD_ACTION_MASK      0x03            /* 取两位 */
#define METHOD_ID(_method)      ((_method) & (~METHOD_ACTION_MASK))
#define METHOD_ACTION(_method)  (((unsigned int)(_method)) & METHOD_ACTION_MASK)
#define METHOD_COMBINE(_method, _action)    ((_method) | (_action))

#endif  // DALVIK_PROFILE_H_
