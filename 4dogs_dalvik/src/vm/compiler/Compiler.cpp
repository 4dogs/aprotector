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

#include <sys/mman.h>
#include <errno.h>
#include <cutils/ashmem.h>

#include "Dalvik.h"
#include "interp/Jit.h"
#include "CompilerInternals.h"
/* x86架构定义 */
#ifdef ARCH_IA32
#include "codegen/x86/Translator.h"
#include "codegen/x86/Lower.h"
#endif

/*
 * 以下这两个函数从template引出来
 * 一个获取代码模板的开始一个获取代码模板的末尾
 * 不同硬件平台有不同模板代码
 * 因为JIT编译好后的本地代码需要有一段本平台下的
 * 引导代码初始化环境并且执行JIT指令
 */
extern "C" void dvmCompilerTemplateStart(void);
extern "C" void dmvCompilerTemplateEnd(void);

/**
 * @brief 返回编译工作队列的长度
 * @return 返回订单的数量
 */
static inline bool workQueueLength(void)
{
    return gDvmJit.compilerQueueLength;
}

/**
 * @brief 取出一条编译工作队列 
 * @return 返回一个CompilerWorkOrder结构
 */
static CompilerWorkOrder workDequeue(void)
{
	/* 断言确定当前工作节点不是无效的 */
    assert(gDvmJit.compilerWorkQueue[gDvmJit.compilerWorkDequeueIndex].kind
           != kWorkOrderInvalid);
    CompilerWorkOrder work =
        gDvmJit.compilerWorkQueue[gDvmJit.compilerWorkDequeueIndex];				/* 取出当前的工作节点 */
    gDvmJit.compilerWorkQueue[gDvmJit.compilerWorkDequeueIndex++].kind =
        kWorkOrderInvalid;															/* 设置当前的工作节点类型为无效的并且索引增加 */
	/* 如果索引到达工作队列最大值则索引重新设置为0 */
    if (gDvmJit.compilerWorkDequeueIndex == COMPILER_WORK_QUEUE_SIZE) {
        gDvmJit.compilerWorkDequeueIndex = 0;
    }
    gDvmJit.compilerQueueLength--;				/* 长度递减 */
    if (gDvmJit.compilerQueueLength == 0) {
        dvmSignalCond(&gDvmJit.compilerQueueEmpty);
    }

    /* Remember the high water mark of the queue length */
    if (gDvmJit.compilerQueueLength > gDvmJit.compilerMaxQueued)
        gDvmJit.compilerMaxQueued = gDvmJit.compilerQueueLength;

    return work;
}

/*
 * Enqueue a work order - retrying until successful.  If attempt to enqueue
 * is repeatedly unsuccessful, assume the JIT is in a bad state and force a
 * code cache reset.
 */
#define ENQUEUE_MAX_RETRIES 20	/** @brief 重新尝试入列次数 */
void dvmCompilerForceWorkEnqueue(const u2 *pc, WorkOrderKind kind, void* info)
{
    bool success;
    int retries = 0;
    do {
        success = dvmCompilerWorkEnqueue(pc, kind, info);
        if (!success) {
            retries++;
            if (retries > ENQUEUE_MAX_RETRIES) {
                ALOGE("JIT: compiler queue wedged - forcing reset");
                gDvmJit.codeCacheFull = true;  // Force reset
                success = true;  // Because we'll drop the order now anyway
            } else {
                dvmLockMutex(&gDvmJit.compilerLock);
				/* 通知compilerThreadStart线程队列激活了 */
                pthread_cond_wait(&gDvmJit.compilerQueueActivity,
                                  &gDvmJit.compilerLock);
                dvmUnlockMutex(&gDvmJit.compilerLock);

            }
        }
    } while (!success);
}

/*
 * Attempt to enqueue a work order, returning true if successful.
 *
 * NOTE: Make sure that the caller frees the info pointer if the return value
 * is false.
 */
/**
 * @brief 附加一个trace队列到订单
 * @param pc 要trace的dalvik指令指针
 * @param kind 订单的类型
 * @param info 指向JitTraceDescription结构的指针
 */
bool dvmCompilerWorkEnqueue(const u2 *pc, WorkOrderKind kind, void* info)
{
    int cc;
    int i;
    int numWork;
    bool result = true;

	/* 加锁 */
    dvmLockMutex(&gDvmJit.compilerLock);

    /*
     * Return if queue or code cache is full.
     */
	/* 如果队列或者代码缓存已经满了则直接返回 */
    if (gDvmJit.compilerQueueLength == COMPILER_WORK_QUEUE_SIZE ||
        gDvmJit.codeCacheFull == true) {
        dvmUnlockMutex(&gDvmJit.compilerLock);
        return false;
    }

    for (numWork = gDvmJit.compilerQueueLength,
           i = gDvmJit.compilerWorkDequeueIndex;
         numWork > 0;
         numWork--) {
        /* Already enqueued */
		/* 编译编译队列查看是否编译过 */
        if (gDvmJit.compilerWorkQueue[i++].pc == pc) {
            dvmUnlockMutex(&gDvmJit.compilerLock);
            return true;
        }
        /* Wrap around */
		/* 下一轮  */
        if (i == COMPILER_WORK_QUEUE_SIZE)
            i = 0;
    }

	/* 获取一个订单 */
    CompilerWorkOrder *newOrder =
        &gDvmJit.compilerWorkQueue[gDvmJit.compilerWorkEnqueueIndex];
    newOrder->pc = pc;					/* 设置偏移 */
    newOrder->kind = kind;				/* 类型 */
    newOrder->info = info;				/* JIT描述 */
    newOrder->result.methodCompilationAborted = NULL;		/* JitTranslationInfo结构 */
    newOrder->result.codeAddress = NULL;
	/* 如果是以调试模式启动，则丢弃代码 */
    newOrder->result.discardResult =
        (kind == kWorkOrderTraceDebug) ? true : false;
    newOrder->result.cacheVersion = gDvmJit.cacheVersion;	/* trace请求版本 */
    newOrder->result.requestingThread = dvmThreadSelf();	/* 线程句柄 */

    gDvmJit.compilerWorkEnqueueIndex++;		/* 入列索引增加 */
	/* 到达最大索引数 */
    if (gDvmJit.compilerWorkEnqueueIndex == COMPILER_WORK_QUEUE_SIZE)
        gDvmJit.compilerWorkEnqueueIndex = 0;
    gDvmJit.compilerQueueLength++;			/* 队列长度增加 */
	/* 设置条件变量 */
    cc = pthread_cond_signal(&gDvmJit.compilerQueueActivity);
    assert(cc == 0);

    dvmUnlockMutex(&gDvmJit.compilerLock);
    return result;
}

/* Block until the queue length is 0, or there is a pending suspend request */
/**
 * @brief 丢弃编译队列
 */
void dvmCompilerDrainQueue(void)
{
    Thread *self = dvmThreadSelf();

    dvmLockMutex(&gDvmJit.compilerLock);
	/* 遍历整个队列，并不停的检测编译线程是否终止，并且自身线程没有被挂起 */
    while (workQueueLength() != 0 && !gDvmJit.haltCompilerThread &&
           self->suspendCount == 0) {
        /*
         * Use timed wait here - more than one mutator threads may be blocked
         * but the compiler thread will only signal once when the queue is
         * emptied. Furthermore, the compiler thread may have been shutdown
         * so the blocked thread may never get the wakeup signal.
         */
		/* 使用等待时间 - 超过一个mutator线程被阻塞但是编译器线程将
		 * 仅有一条一次当队列被提交，编译器线程不关闭，阻塞线程将永远不会唤醒*/
        dvmRelativeCondWait(&gDvmJit.compilerQueueEmpty, &gDvmJit.compilerLock,                             1000, 0);
    }
    dvmUnlockMutex(&gDvmJit.compilerLock);
}

/**
 * @brief 编译器设置代码缓冲
 * @retval 0 失败
 * @retval 1 成功
 */
bool dvmCompilerSetupCodeCache(void)
{
    int fd;

    /* Allocate the code cache */
	/* 分配代码缓冲 */
    fd = ashmem_create_region("dalvik-jit-code-cache", gDvmJit.codeCacheSize);
    if (fd < 0) {
        ALOGE("Could not create %u-byte ashmem region for the JIT code cache",
             gDvmJit.codeCacheSize);
        return false;
    }
	/* 进程私有，可读可写可执行 */
    gDvmJit.codeCache = mmap(NULL, gDvmJit.codeCacheSize,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE , fd, 0);
    close(fd);
    if (gDvmJit.codeCache == MAP_FAILED) {
        ALOGE("Failed to mmap the JIT code cache: %s", strerror(errno));
        return false;
    }

	/* 页掩码 */
    gDvmJit.pageSizeMask = getpagesize() - 1;

    /* This can be found through "dalvik-jit-code-cache" in /proc/<pid>/maps */
    // ALOGD("Code cache starts at %p", gDvmJit.codeCache);

	/* arm mips */
#ifndef ARCH_IA32
    /* Copy the template code into the beginning of the code cache */
	/* 复制模板代码到代码缓冲的开始 */
    int templateSize = (intptr_t) dmvCompilerTemplateEnd -
                       (intptr_t) dvmCompilerTemplateStart;
    memcpy((void *) gDvmJit.codeCache,
           (void *) dvmCompilerTemplateStart,
           templateSize);

    /*
     * Work around a CPU bug by keeping the 32-bit ARM handler code in its own
     * page.
     */
	/*
	 * 貌似是一个CPU的BUG，保持32位的ARM处理代码在它自己的页中
	 */
    if (dvmCompilerInstructionSet() == DALVIK_JIT_THUMB2) {
        templateSize = (templateSize + 4095) & ~4095;
    }

    gDvmJit.templateSize = templateSize;		/* 模板的长度 */
    gDvmJit.codeCacheByteUsed = templateSize;	/* 代码缓冲的使用情况 */

    /* Only flush the part in the code cache that is being used now */
	/* 刷入被使用的代码缓存 */
    dvmCompilerCacheFlush((intptr_t) gDvmJit.codeCache,
                          (intptr_t) gDvmJit.codeCache + templateSize, 0);

	/* 修改内存属性 */
    int result = mprotect(gDvmJit.codeCache, gDvmJit.codeCacheSize,
                          PROTECT_CODE_CACHE_ATTRS);

    if (result == -1) {
        ALOGE("Failed to remove the write permission for the code cache");
        dvmAbort();
    }
#else
	/* 
	 * 如果是x86体系，则有另外一套方法实现模板的设置。
	 * 从代码上看应该是两个不同的人完成的
	 */
    gDvmJit.codeCacheByteUsed = 0;
    stream = (char*)gDvmJit.codeCache + gDvmJit.codeCacheByteUsed;
    ALOGV("codeCache = %p stream = %p before initJIT", gDvmJit.codeCache, stream);
    streamStart = stream;
    initJIT(NULL, NULL);
    gDvmJit.templateSize = (stream - streamStart);
    gDvmJit.codeCacheByteUsed = (stream - streamStart);
    ALOGV("stream = %p after initJIT", stream);
#endif

    return true;
}

/**
 * @brief 遍历dalvik栈
 * @param thread 线程结构指针
 * @param print 是否打印
 */
static void crawlDalvikStack(Thread *thread, bool print)
{
    void *fp = thread->interpSave.curFrame;			/* 获取栈指针 */
    StackSaveArea* saveArea = NULL;
    int stackLevel = 0;

    if (print) {
        ALOGD("Crawling tid %d (%s / %p %s)", thread->systemTid,
             dvmGetThreadStatusStr(thread->status),
             thread->inJitCodeCache,
             thread->inJitCodeCache ? "jit" : "interp");
    }
    /* Crawl the Dalvik stack frames to clear the returnAddr field */
	/* 遍历清除返回地址字段 */
    while (fp != NULL) {
        saveArea = SAVEAREA_FROM_FP(fp);	/* 取出一个单元 */

        if (print) {
            if (dvmIsBreakFrame((u4*)fp)) {
                ALOGD("  #%d: break frame (%p)",
                     stackLevel, saveArea->returnAddr);
            }
            else {
                ALOGD("  #%d: %s.%s%s (%p)",
                     stackLevel,
                     saveArea->method->clazz->descriptor,
                     saveArea->method->name,
                     dvmIsNativeMethod(saveArea->method) ?
                         " (native)" : "",
                     saveArea->returnAddr);
            }
        }
        stackLevel++;
        saveArea->returnAddr = NULL;			/* 设置返回值为NULL */
        assert(fp != saveArea->prevFrame);
        fp = saveArea->prevFrame;
    }
    /* Make sure the stack is fully unwound to the bottom */
    assert(saveArea == NULL ||
           (u1 *) (saveArea+1) == thread->interpStackStart);
}

/**
 * @brief 重新设置代码缓冲区
 */
static void resetCodeCache(void)
{
    Thread* thread;
    u8 startTime = dvmGetRelativeTimeUsec();		/* 获取相对的启动时间 */
    int inJit = 0;
    int byteUsed = gDvmJit.codeCacheByteUsed;		/* 获取当前代码缓冲的使用量 */

    /* If any thread is found stuck in the JIT state, don't reset the cache  */
	/* 任意线程被发现处于JIT状态，不要重新设置缓冲 */
    dvmLockThreadList(NULL);
    for (thread = gDvm.threadList; thread != NULL; thread = thread->next) {
        /*
         * Crawl the stack to wipe out the returnAddr field so that
         * 1) the soon-to-be-deleted code in the JIT cache won't be used
         * 2) or the thread stuck in the JIT land will soon return
         *    to the interpreter land
         */
        crawlDalvikStack(thread, false);
        if (thread->inJitCodeCache) {
            inJit++;
        }
        /* Cancel any ongoing trace selection */
        dvmDisableSubMode(thread, kSubModeJitTraceBuild);
    }
    dvmUnlockThreadList();

    if (inJit) {
        ALOGD("JIT code cache reset delayed (%d bytes %d/%d)",
             gDvmJit.codeCacheByteUsed, gDvmJit.numCodeCacheReset,
             ++gDvmJit.numCodeCacheResetDelayed);
        return;
    }

    /* Lock the mutex to clean up the work queue */
    dvmLockMutex(&gDvmJit.compilerLock);

    /* Update the translation cache version */
    gDvmJit.cacheVersion++;

    /* Drain the work queue to free the work orders */
	/* 循环丢弃所有编译的队列 */
    while (workQueueLength()) {
        CompilerWorkOrder work = workDequeue();
        free(work.info);
    }

    /* Reset the JitEntry table contents to the initial unpopulated state */
	/* 重新设置JitTable */
    dvmJitResetTable();

    UNPROTECT_CODE_CACHE(gDvmJit.codeCache, gDvmJit.codeCacheByteUsed);
    /*
     * Wipe out the code cache content to force immediate crashes if
     * stale JIT'ed code is invoked.
     */
	/* 清除JIT代码 */
    dvmCompilerCacheClear((char *) gDvmJit.codeCache + gDvmJit.templateSize,
                          gDvmJit.codeCacheByteUsed - gDvmJit.templateSize);

    dvmCompilerCacheFlush((intptr_t) gDvmJit.codeCache,
                          (intptr_t) gDvmJit.codeCache +
                          gDvmJit.codeCacheByteUsed, 0);

    PROTECT_CODE_CACHE(gDvmJit.codeCache, gDvmJit.codeCacheByteUsed);

    /* Reset the current mark of used bytes to the end of template code */
    gDvmJit.codeCacheByteUsed = gDvmJit.templateSize;
    gDvmJit.numCompilations = 0;

    /* Reset the work queue */
	/* 重设订单队列 */
    memset(gDvmJit.compilerWorkQueue, 0,
           sizeof(CompilerWorkOrder) * COMPILER_WORK_QUEUE_SIZE);
    gDvmJit.compilerWorkEnqueueIndex = gDvmJit.compilerWorkDequeueIndex = 0;
    gDvmJit.compilerQueueLength = 0;

    /* Reset the IC patch work queue */
	/* 重设IC patch工作队列 */
    dvmLockMutex(&gDvmJit.compilerICPatchLock);
    gDvmJit.compilerICPatchIndex = 0;
    dvmUnlockMutex(&gDvmJit.compilerICPatchLock);

    /*
     * Reset the inflight compilation address (can only be done in safe points
     * or by the compiler thread when its thread state is RUNNING).
     */
    gDvmJit.inflightBaseAddr = NULL;

    /* All clear now */
    gDvmJit.codeCacheFull = false;

    dvmUnlockMutex(&gDvmJit.compilerLock);

    ALOGD("JIT code cache reset in %lld ms (%d bytes %d/%d)",
         (dvmGetRelativeTimeUsec() - startTime) / 1000,
         byteUsed, ++gDvmJit.numCodeCacheReset,
         gDvmJit.numCodeCacheResetDelayed);
}

/*
 * Perform actions that are only safe when all threads are suspended. Currently
 * we do:
 * 1) Check if the code cache is full. If so reset it and restart populating it
 *    from scratch.
 * 2) Patch predicted chaining cells by consuming recorded work orders.
 */
/**
 * @brief 检查编译代码缓冲池是否满了
 */
void dvmCompilerPerformSafePointChecks(void)
{
	/*  */
    if (gDvmJit.codeCacheFull) {
        resetCodeCache();
    }
    dvmCompilerPatchInlineCache();
}

/**
 * @brief 编译器线程启动函数
 * @retval 0 表示失败
 * @retval 1 表示成功
 */
static bool compilerThreadStartup(void)
{
    JitEntry *pJitTable = NULL;
    unsigned char *pJitProfTable = NULL;
    JitTraceProfCounters *pJitTraceProfCounters = NULL;
    unsigned int i;

	/* 针对硬件平台的初始化 */
    if (!dvmCompilerArchInit())
        goto fail;

    /*
     * Setup the code cache if we have not inherited a valid code cache
     * from the zygote.
     */
	/* 如果没有从zygote继承一个有效的代码缓冲则设置代码缓冲 */
    if (gDvmJit.codeCache == NULL) {
        if (!dvmCompilerSetupCodeCache())
            goto fail;
    }

    /* Allocate the initial arena block */
	/* 分配编译器要用到的内存 */
    if (dvmCompilerHeapInit() == false) {
        goto fail;
    }

    /* Cache the thread pointer */
	/* 缓存线程指针 */
    gDvmJit.compilerThread = dvmThreadSelf();

    dvmLockMutex(&gDvmJit.compilerLock);

    /* Track method-level compilation statistics */
	/* track method两个级别的编译统计 */
    gDvmJit.methodStatsTable = dvmHashTableCreate(32, NULL);

#if defined(WITH_JIT_TUNING)
    gDvm.verboseShutdown = true;
#endif

    dvmUnlockMutex(&gDvmJit.compilerLock);

    /* Set up the JitTable */
	/* 设置JitTable表 */
	
    /* Power of 2? */
	/* JitTable大小为2的冥 */
    assert(gDvmJit.jitTableSize &&
           !(gDvmJit.jitTableSize & (gDvmJit.jitTableSize - 1)));

	/* 分配一个Jit表的内存 */
    dvmInitMutex(&gDvmJit.tableLock);
    dvmLockMutex(&gDvmJit.tableLock);
    pJitTable = (JitEntry*)
                calloc(gDvmJit.jitTableSize, sizeof(*pJitTable));
    if (!pJitTable) {
        ALOGE("jit table allocation failed");
        dvmUnlockMutex(&gDvmJit.tableLock);
        goto fail;
    }
    /*
     * NOTE: the profile table must only be allocated once, globally.
     * Profiling is turned on and off by nulling out gDvm.pJitProfTable
     * and then restoring its original value.  However, this action
     * is not synchronized for speed so threads may continue to hold
     * and update the profile table after profiling has been turned
     * off by null'ng the global pointer.  Be aware.
     */
	/*
	 * 注解: profile表仅分配一次,并且是全局的。它通过gDvm.pJitProfTable
	 * 为NULL时关闭。与JitTable生存期一致。但是它的关闭并不是高速同步的，
	 * 也许线程会保持并且更新一个profile表在已经关闭了profiling之后。
	 */
    pJitProfTable = (unsigned char *)malloc(JIT_PROF_SIZE);
    if (!pJitProfTable) {
        ALOGE("jit prof table allocation failed");
        free(pJitProfTable);
        dvmUnlockMutex(&gDvmJit.tableLock);
        goto fail;
    }
    memset(pJitProfTable, gDvmJit.threshold, JIT_PROF_SIZE);

	/* 遍历JitTable并初始化 */
    for (i=0; i < gDvmJit.jitTableSize; i++) {
       pJitTable[i].u.info.chain = gDvmJit.jitTableSize;
    }
    /* Is chain field wide enough for termination pattern? */
	/* 是否赋值正确 */
    assert(pJitTable[0].u.info.chain == gDvmJit.jitTableSize);

    /* Allocate the trace profiling structure */
	/* 分配trace热点分析结构 */
    pJitTraceProfCounters = (JitTraceProfCounters*)
                             calloc(1, sizeof(*pJitTraceProfCounters));
    if (!pJitTraceProfCounters) {
        ALOGE("jit trace prof counters allocation failed");
        dvmUnlockMutex(&gDvmJit.tableLock);
        goto fail;
    }

    gDvmJit.pJitEntryTable = pJitTable;
    gDvmJit.jitTableMask = gDvmJit.jitTableSize - 1;
    gDvmJit.jitTableEntriesUsed = 0;
    gDvmJit.compilerHighWater =
        COMPILER_WORK_QUEUE_SIZE - (COMPILER_WORK_QUEUE_SIZE/4);
    /*
     * If the VM is launched with wait-on-the-debugger, we will need to hide
     * the profile table here
     */
	/*
	 * 如果VM通过wait-on-the-debugger方式运行，我们需要隐藏profile表
	 */
    gDvmJit.pProfTable = dvmDebuggerOrProfilerActive() ? NULL : pJitProfTable;
    gDvmJit.pProfTableCopy = pJitProfTable;
    gDvmJit.pJitTraceProfCounters = pJitTraceProfCounters;
    dvmJitUpdateThreadStateAll();
    dvmUnlockMutex(&gDvmJit.tableLock);

    /* Signal running threads to refresh their cached pJitTable pointers */
	/* 开启所有的线程去刷新他们的JitTable指针 */
    dvmSuspendAllThreads(SUSPEND_FOR_REFRESH);
    dvmResumeAllThreads(SUSPEND_FOR_REFRESH);

    /* Enable signature breakpoints by customizing the following code */
#if defined(SIGNATURE_BREAKPOINT)
    /*
     * Suppose one sees the following native crash in the bugreport:
     * I/DEBUG   ( 1638): Build fingerprint: 'unknown'
     * I/DEBUG   ( 1638): pid: 2468, tid: 2507  >>> com.google.android.gallery3d
     * I/DEBUG   ( 1638): signal 11 (SIGSEGV), fault addr 00001400
     * I/DEBUG   ( 1638):  r0 44ea7190  r1 44e4f7b8  r2 44ebc710  r3 00000000
     * I/DEBUG   ( 1638):  r4 00000a00  r5 41862dec  r6 4710dc10  r7 00000280
     * I/DEBUG   ( 1638):  r8 ad010f40  r9 46a37a12  10 001116b0  fp 42a78208
     * I/DEBUG   ( 1638):  ip 00000090  sp 4710dbc8  lr ad060e67  pc 46b90682
     * cpsr 00000030
     * I/DEBUG   ( 1638):  #00  pc 46b90682 /dev/ashmem/dalvik-jit-code-cache
     * I/DEBUG   ( 1638):  #01  pc 00060e62  /system/lib/libdvm.so
     *
     * I/DEBUG   ( 1638): code around pc:
     * I/DEBUG   ( 1638): 46b90660 6888d01c 34091dcc d2174287 4a186b68
     * I/DEBUG   ( 1638): 46b90670 d0052800 68006809 28004790 6b68d00e
     * I/DEBUG   ( 1638): 46b90680 512000bc 37016eaf 6ea866af 6f696028
     * I/DEBUG   ( 1638): 46b90690 682a6069 429a686b e003da08 6df1480b
     * I/DEBUG   ( 1638): 46b906a0 1c2d4788 47806d70 46a378fa 47806d70
     *
     * Clearly it is a JIT bug. To find out which translation contains the
     * offending code, the content of the memory dump around the faulting PC
     * can be pasted into the gDvmJit.signatureBreakpoint[] array and next time
     * when a similar compilation is being created, the JIT compiler replay the
     * trace in the verbose mode and one can investigate the instruction
     * sequence in details.
     *
     * The length of the signature may need additional experiments to determine.
     * The rule of thumb is don't include PC-relative instructions in the
     * signature since it may be affected by the alignment of the compiled code.
     * However, a signature that's too short might increase the chance of false
     * positive matches. Using gdbjithelper to disassembly the memory content
     * first might be a good companion approach.
     *
     * For example, if the next 4 words starting from 46b90680 is pasted into
     * the data structure:
     */

    gDvmJit.signatureBreakpointSize = 4;
    gDvmJit.signatureBreakpoint =
        malloc(sizeof(u4) * gDvmJit.signatureBreakpointSize);
    gDvmJit.signatureBreakpoint[0] = 0x512000bc;
    gDvmJit.signatureBreakpoint[1] = 0x37016eaf;
    gDvmJit.signatureBreakpoint[2] = 0x6ea866af;
    gDvmJit.signatureBreakpoint[3] = 0x6f696028;

    /*
     * The following log will be printed when a match is found in subsequent
     * testings:
     *
     * D/dalvikvm( 2468): Signature match starting from offset 0x34 (4 words)
     * D/dalvikvm( 2468): --------
     * D/dalvikvm( 2468): Compiler: Building trace for computeVisibleItems,
     * offset 0x1f7
     * D/dalvikvm( 2468): 0x46a37a12: 0x0090 add-int v42, v5, v26
     * D/dalvikvm( 2468): 0x46a37a16: 0x004d aput-object v13, v14, v42
     * D/dalvikvm( 2468): 0x46a37a1a: 0x0028 goto, (#0), (#0)
     * D/dalvikvm( 2468): 0x46a3794e: 0x00d8 add-int/lit8 v26, v26, (#1)
     * D/dalvikvm( 2468): 0x46a37952: 0x0028 goto, (#0), (#0)
     * D/dalvikvm( 2468): 0x46a378ee: 0x0002 move/from16 v0, v26, (#0)
     * D/dalvikvm( 2468): 0x46a378f2: 0x0002 move/from16 v1, v29, (#0)
     * D/dalvikvm( 2468): 0x46a378f6: 0x0035 if-ge v0, v1, (#10)
     * D/dalvikvm( 2468): TRACEINFO (554): 0x46a37624
     * Lcom/cooliris/media/GridLayer;computeVisibleItems 0x1f7 14 of 934, 8
     * blocks
     *     :
     *     :
     * D/dalvikvm( 2468): 0x20 (0020): ldr     r0, [r5, #52]
     * D/dalvikvm( 2468): 0x22 (0022): ldr     r2, [pc, #96]
     * D/dalvikvm( 2468): 0x24 (0024): cmp     r0, #0
     * D/dalvikvm( 2468): 0x26 (0026): beq     0x00000034
     * D/dalvikvm( 2468): 0x28 (0028): ldr     r1, [r1, #0]
     * D/dalvikvm( 2468): 0x2a (002a): ldr     r0, [r0, #0]
     * D/dalvikvm( 2468): 0x2c (002c): blx     r2
     * D/dalvikvm( 2468): 0x2e (002e): cmp     r0, #0
     * D/dalvikvm( 2468): 0x30 (0030): beq     0x00000050
     * D/dalvikvm( 2468): 0x32 (0032): ldr     r0, [r5, #52]
     * D/dalvikvm( 2468): 0x34 (0034): lsls    r4, r7, #2
     * D/dalvikvm( 2468): 0x36 (0036): str     r0, [r4, r4]
     * D/dalvikvm( 2468): -------- dalvik offset: 0x01fb @ goto, (#0), (#0)
     * D/dalvikvm( 2468): L0x0195:
     * D/dalvikvm( 2468): -------- dalvik offset: 0x0195 @ add-int/lit8 v26,
     * v26, (#1)
     * D/dalvikvm( 2468): 0x38 (0038): ldr     r7, [r5, #104]
     * D/dalvikvm( 2468): 0x3a (003a): adds    r7, r7, #1
     * D/dalvikvm( 2468): 0x3c (003c): str     r7, [r5, #104]
     * D/dalvikvm( 2468): -------- dalvik offset: 0x0197 @ goto, (#0), (#0)
     * D/dalvikvm( 2468): L0x0165:
     * D/dalvikvm( 2468): -------- dalvik offset: 0x0165 @ move/from16 v0, v26,
     * (#0)
     * D/dalvikvm( 2468): 0x3e (003e): ldr     r0, [r5, #104]
     * D/dalvikvm( 2468): 0x40 (0040): str     r0, [r5, #0]
     *
     * The "str r0, [r4, r4]" is indeed the culprit of the native crash.
     */
#endif

    return true;

fail:
    return false;

}

/**
 * @brief Jit编译器主工作线程
 * @note 真正的一切从这里开始
 */
static void *compilerThreadStart(void *arg)
{
    dvmChangeStatus(NULL, THREAD_VMWAIT);						/* 当线程启动后，首先将dalvik虚拟机设置为等待状态 */

    /*
     * If we're not running stand-alone, wait a little before
     * recieving translation requests on the assumption that process start
     * up code isn't worth compiling.  We'll resume when the framework
     * signals us that the first screen draw has happened, or the timer
     * below expires (to catch daemons).
     *
     * There is a theoretical race between the callback to
     * VMRuntime.startJitCompiation and when the compiler thread reaches this
     * point. In case the callback happens earlier, in order not to permanently
     * hold the system_server (which is not using the timed wait) in
     * interpreter-only mode we bypass the delay here.
     */
    if (gDvmJit.runningInAndroidFramework &&
        !gDvmJit.alreadyEnabledViaFramework) {
        /*
         * If the current VM instance is the system server (detected by having
         * 0 in gDvm.systemServerPid), we will use the indefinite wait on the
         * conditional variable to determine whether to start the JIT or not.
         * If the system server detects that the whole system is booted in
         * safe mode, the conditional variable will never be signaled and the
         * system server will remain in the interpreter-only mode. All
         * subsequent apps will be started with the --enable-safemode flag
         * explicitly appended.
         */
        if (gDvm.systemServerPid == 0) {
            dvmLockMutex(&gDvmJit.compilerLock);
            pthread_cond_wait(&gDvmJit.compilerQueueActivity,
                              &gDvmJit.compilerLock);
            dvmUnlockMutex(&gDvmJit.compilerLock);
            ALOGD("JIT started for system_server");
        } else {
            dvmLockMutex(&gDvmJit.compilerLock);
            /*
             * TUNING: experiment with the delay & perhaps make it
             * target-specific
             */
            dvmRelativeCondWait(&gDvmJit.compilerQueueActivity,
                                 &gDvmJit.compilerLock, 3000, 0);
            dvmUnlockMutex(&gDvmJit.compilerLock);
        }
		
		/* 检测是否退出 */
        if (gDvmJit.haltCompilerThread) {
             return NULL;
        }
    }

	/* 编译器线程初始化函数，这里对JitTable以及Profiling进行了内存分配 */
    compilerThreadStartup();

    dvmLockMutex(&gDvmJit.compilerLock);
    /*
     * Since the compiler thread will not touch any objects on the heap once
     * being created, we just fake its state as VMWAIT so that it can be a
     * bit late when there is suspend request pending.
     */
	/*
	 * 编译器线程不会接触任何在堆上创建的对象，当有挂起请求发送过来设置它的状态为VMWAIT
	 */
    while (!gDvmJit.haltCompilerThread) {
		/* 编译工作队列为空 */
        if (workQueueLength() == 0) {
            int cc;
            cc = pthread_cond_signal(&gDvmJit.compilerQueueEmpty);			/* 通知编译工作队列为空 */
            assert(cc == 0);
            pthread_cond_wait(&gDvmJit.compilerQueueActivity,
                              &gDvmJit.compilerLock);
            continue;
        } else {
            do {/* 这个循环内，不停的检测工作队列是否为空，如果不为空则不停的循环处理 */
                CompilerWorkOrder work = workDequeue();				/* 取出一个编译任务 */
                dvmUnlockMutex(&gDvmJit.compilerLock);
#if defined(WITH_JIT_TUNING)
                /*
                 * This is live across setjmp().  Mark it volatile to suppress
                 * a gcc warning.  We should not need this since it is assigned
                 * only once but gcc is not smart enough.
                 */
				 /* 记录编译时间，起始时间 */
                volatile u8 startTime = dvmGetRelativeTimeUsec();
#endif
                /*
                 * Check whether there is a suspend request on me.  This
                 * is necessary to allow a clean shutdown.
                 *
                 * However, in the blocking stress testing mode, let the
                 * compiler thread continue doing compilations to unblock
                 * other requesting threads. This may occasionally cause
                 * shutdown from proceeding cleanly in the standalone invocation
                 * of the vm but this should be acceptable.
                 */
                if (!gDvmJit.blockingMode)
                    dvmCheckSuspendPending(dvmThreadSelf());
                /* Is JitTable filling up? */
				/* JitTable是否填充满 */
                if (gDvmJit.jitTableEntriesUsed >
                    (gDvmJit.jitTableSize - gDvmJit.jitTableSize/4)) {
					/* 重新设置JitTable的空间 */
                    bool resizeFail =
                        dvmJitResizeJitTable(gDvmJit.jitTableSize * 2);
                    /*
                     * If the jit table is full, consider it's time to reset
                     * the code cache too.
                     */
					/* 重新设置标记 */
                    gDvmJit.codeCacheFull |= resizeFail;
                }
				
				/* 检查是否已经关闭线程 */
                if (gDvmJit.haltCompilerThread) {
                    ALOGD("Compiler shutdown in progress - discarding request");
                } else if (!gDvmJit.codeCacheFull) {
                    jmp_buf jmpBuf;
                    work.bailPtr = &jmpBuf;
                    bool aborted = setjmp(jmpBuf);				/* 初始化jmp_buf */
                    if (!aborted) {								/* 初始化成功则返回0 */
                        bool codeCompiled = dvmCompilerDoWork(&work);			/* 编译代码，从dvmLockMutex使用来看编译操作是线程独立的可以不用同步 */
                        /*
                         * Make sure we are still operating with the
                         * same translation cache version.  See
                         * Issue 4271784 for details.
                         */

						/* 编译完成后运行这段编译好的代码 */
                        dvmLockMutex(&gDvmJit.compilerLock);
                        if ((work.result.cacheVersion ==
                             gDvmJit.cacheVersion) &&
                             codeCompiled &&
                             !work.result.discardResult &&
                             work.result.codeAddress) {
                            dvmJitSetCodeAddr(work.pc, work.result.codeAddress,
                                              work.result.instructionSet,
                                              false, /* not method entry */
                                              work.result.profileCodeSize);
                        }
                        dvmUnlockMutex(&gDvmJit.compilerLock);
                    }/* 完成编译并运行代码 */
                    dvmCompilerArenaReset();
                }
                free(work.info);			/* 是否编译工作的信息缓存 */
#if defined(WITH_JIT_TUNING)
                gDvmJit.jitTime += dvmGetRelativeTimeUsec() - startTime;		/* 检查编译时间 */
#endif
                dvmLockMutex(&gDvmJit.compilerLock);		/* 操作编译工作队列需要线程独占 */
            } while (workQueueLength() != 0);
        }
    }
    pthread_cond_signal(&gDvmJit.compilerQueueEmpty);		/* 编译工作队列为空 */
    dvmUnlockMutex(&gDvmJit.compilerLock);					/* 与循环末尾的dvmLockMutex对应 */

    /*
     * As part of detaching the thread we need to call into Java code to update
     * the ThreadGroup, and we should not be in VMWAIT state while executing
     * interpreted code.
     */
	/*
	 * 以上Jit编译器把要编译的代码编译好后则更新Java代码的线程组为运行状态，
	 * 让代码继续运行。
	 * 在执行解释器代码时，不应该处于VMWAIT状态。
	 */
    dvmChangeStatus(NULL, THREAD_RUNNING);

    if (gDvm.verboseShutdown)
        ALOGD("Compiler thread shutting down");
    return NULL;
}

/**
 * Jit编译器入口点函数
 * @retval 0 表示失败
 * @retval 1 表示成功 
 */
bool dvmCompilerStartup(void)
{
	/* 初始化一些线程同步方面的变量 */
    dvmInitMutex(&gDvmJit.compilerLock);
    dvmInitMutex(&gDvmJit.compilerICPatchLock);
    dvmInitMutex(&gDvmJit.codeCacheProtectionLock);
    dvmLockMutex(&gDvmJit.compilerLock);
    pthread_cond_init(&gDvmJit.compilerQueueActivity, NULL);
    pthread_cond_init(&gDvmJit.compilerQueueEmpty, NULL);

    /* Reset the work queue */
	/* 设置工作队列 */
    gDvmJit.compilerWorkEnqueueIndex = gDvmJit.compilerWorkDequeueIndex = 0;
    gDvmJit.compilerQueueLength = 0;
    dvmUnlockMutex(&gDvmJit.compilerLock);

    /*
     * Defer rest of initialization until we're sure JIT'ng makes sense. Launch
     * the compiler thread, which will do the real initialization if and
     * when it is signalled to do so.
     */
	/*
	 * 以下这个函数创建compilerThreadStart编译线程，当这条线程会执行真正的初始化工作
	 */
    return dvmCreateInternalThread(&gDvmJit.compilerHandle, "Compiler",
                                   compilerThreadStart, NULL);
}

/**
 * 关闭Jit编译器
 */
void dvmCompilerShutdown(void)
{
    void *threadReturn;

    /* Disable new translation requests */
	/* 关闭新的编译请求 */
    gDvmJit.pProfTable = NULL;
    gDvmJit.pProfTableCopy = NULL;
    dvmJitUpdateThreadStateAll();					/* 更新所有线程状态 */

	/*
	 * 以下代码应该是检测在虚拟机关闭之前等待所有编译工作队列完成
	 * dvmCompilerDumpStats()函数应该会更新所有工作队列的当前状态
	 * gDvmJit.compilerQueueLength会随着这个函数进行更新，这个常数
	 * 即是当前工作队列的数量。
	 */
    if (gDvm.verboseShutdown ||
            gDvmJit.profileMode == kTraceProfilingContinuous) {
        dvmCompilerDumpStats();
        while (gDvmJit.compilerQueueLength)
          sleep(5);
    }

	/* 如果编译器工作线程存在 */
    if (gDvmJit.compilerHandle) {

        gDvmJit.haltCompilerThread = true;			/* 设置关闭标志为true */

		/* 发送关闭信号 */
        dvmLockMutex(&gDvmJit.compilerLock);
        pthread_cond_signal(&gDvmJit.compilerQueueActivity);
        dvmUnlockMutex(&gDvmJit.compilerLock);

		/* 关闭compilerThreadStart线程 */
        if (pthread_join(gDvmJit.compilerHandle, &threadReturn) != 0)
            ALOGW("Compiler thread join failed");
        else if (gDvm.verboseShutdown)
            ALOGD("Compiler thread has shut down");
    }

    /* Break loops within the translation cache */
    dvmJitUnchainAll();

    /*
     * NOTE: our current implementatation doesn't allow for the compiler
     * thread to be restarted after it exits here.  We aren't freeing
     * the JitTable or the ProfTable because threads which still may be
     * running or in the process of shutting down may hold references to
	 * 
     * them.
     */
}

/**
 * @brief 更新编译器全局状态
 * @note 在"vm/Profile.cpp"中的updateActiveProfilers中被调用
 */
void dvmCompilerUpdateGlobalState()
{
    bool jitActive;
    bool jitActivate;
    bool needUnchain = false;

    /*
     * The tableLock might not be initialized yet by the compiler thread if
     * debugger is attached from the very beginning of the VM launch. If
     * pProfTableCopy is NULL, the lock is not initialized yet and we don't
     * need to refresh anything either.
     */
	/*
	 * 如果在调试器附加到虚拟机启动器的非常早之前，编译器线程对tableLock
	 * 并没有初始化完成。这是我们不能更新任何状态。
	 */
    if (gDvmJit.pProfTableCopy == NULL) {
        return;
    }

    /*
     * On the first enabling of method tracing, switch the compiler
     * into a mode that includes trace support for invokes and returns.
     * If there are any existing translations, flush them.  NOTE:  we
     * can't blindly flush the translation cache because this code
     * may be executed before the compiler thread has finished
     * initialization.
     */

	/*
	 * 第一次启用函数tracing，转化编译器到保护支持invokes与returns
	 * 指令的trace格式。如果已经存在了一些编译代码则直接刷入他们到缓存中。
	 * NOTE：我们不能在编译器线程未初始化完成之前刷入代码
	 */
	/* activeProfilers 表明 开启profiler */
    if ((gDvm.activeProfilers != 0) &&
        !gDvmJit.methodTraceSupport) {
        bool resetRequired;
        /*
         * compilerLock will prevent new compilations from being
         * installed while we are working.
         */
        dvmLockMutex(&gDvmJit.compilerLock);
		/* 增加缓冲版本 */
        gDvmJit.cacheVersion++; // invalidate compilations in flight
        gDvmJit.methodTraceSupport = true;
        resetRequired = (gDvmJit.numCompilations != 0);
        dvmUnlockMutex(&gDvmJit.compilerLock);
        if (resetRequired) {
            dvmSuspendAllThreads(SUSPEND_FOR_CC_RESET);
            resetCodeCache();		/* 重新更新代码缓冲区 */
            dvmResumeAllThreads(SUSPEND_FOR_CC_RESET);
        }
    }

    dvmLockMutex(&gDvmJit.tableLock);
	/* 通过判断pProfTable表判断JIT是否被激活 */
    jitActive = gDvmJit.pProfTable != NULL;
    jitActivate = !dvmDebuggerOrProfilerActive();	/* 处于调试阶段或者profile开启 */

    if (jitActivate && !jitActive) {
        gDvmJit.pProfTable = gDvmJit.pProfTableCopy;	/* 处于调试获取副本 */
    } else if (!jitActivate && jitActive) {
        gDvmJit.pProfTable = NULL;
        needUnchain = true;
    }
    dvmUnlockMutex(&gDvmJit.tableLock);
    if (needUnchain)
        dvmJitUnchainAll();
    // Make sure all threads have current values
	/* 对所有线程设置JitTable表 */
    dvmJitUpdateThreadStateAll();
}
