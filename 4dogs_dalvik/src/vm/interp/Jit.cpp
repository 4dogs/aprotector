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
#ifdef WITH_JIT

/*
 * Target independent portion of Android's Jit
 */

#include "Dalvik.h"
#include "Jit.h"

#include "libdex/DexOpcodes.h"
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#include "compiler/Compiler.h"
#include "compiler/CompilerUtility.h"
#include "compiler/CompilerIR.h"
#include <errno.h>


/*
 * 自校验函数过程
 */
#if defined(WITH_SELF_VERIFICATION)
/* Allocate space for per-thread ShadowSpace data structures */
/**
 * @brief 自校验shadow空间分配
 * @param self 线程结构指针
 */
void* dvmSelfVerificationShadowSpaceAlloc(Thread* self)
{
	/* 分配shadow空间 */
    self->shadowSpace = (ShadowSpace*) calloc(1, sizeof(ShadowSpace));
    if (self->shadowSpace == NULL)
        return NULL;

	/* 寄存器个数 */
    self->shadowSpace->registerSpaceSize = REG_SPACE;
    self->shadowSpace->registerSpace =
        (int*) calloc(self->shadowSpace->registerSpaceSize, sizeof(int));

    return self->shadowSpace->registerSpace;
}

/* Free per-thread ShadowSpace data structures */
/**
 * @brief 释放每条线程的shadow空间数据结构
 */ 
void dvmSelfVerificationShadowSpaceFree(Thread* self)
{
    free(self->shadowSpace->registerSpace);
    free(self->shadowSpace);
}

/*
 * Save out PC, FP, thread state, and registers to shadow space.
 * Return a pointer to the shadow space for JIT to use.
 *
 * The set of saved state from the Thread structure is:
 *     pc  (Dalvik PC)
 *     fp  (Dalvik FP)
 *     retval
 *     method
 *     methodClassDex
 *     interpStackEnd
 */
/**
 * @brief 自校验保存状态
 * @param pc dalvik的PC寄存器
 * @param fp dalvik的FP框架指针
 * @param self 线程结构
 * @param targetTrace
 * @note 保存PC，FP，线程状态，以及寄存器到shadow区
 * @return 指向一个shadow区域提供给JIT使用
 */
void* dvmSelfVerificationSaveState(const u2* pc, u4* fp,
                                   Thread* self, int targetTrace)
{
    ShadowSpace *shadowSpace = self->shadowSpace;
    unsigned preBytes = self->interpSave.method->outsSize*4 +
        sizeof(StackSaveArea);
    unsigned postBytes = self->interpSave.method->registersSize*4;

    //ALOGD("### selfVerificationSaveState(%d) pc: %#x fp: %#x",
    //    self->threadId, (int)pc, (int)fp);

    if (shadowSpace->selfVerificationState != kSVSIdle) {
        ALOGD("~~~ Save: INCORRECT PREVIOUS STATE(%d): %d",
            self->threadId, shadowSpace->selfVerificationState);
        ALOGD("********** SHADOW STATE DUMP **********");
        ALOGD("PC: %#x FP: %#x", (int)pc, (int)fp);
    }
    shadowSpace->selfVerificationState = kSVSStart;

    // Dynamically grow shadow register space if necessary
    if (preBytes + postBytes > shadowSpace->registerSpaceSize * sizeof(u4)) {
        free(shadowSpace->registerSpace);
        shadowSpace->registerSpaceSize = (preBytes + postBytes) / sizeof(u4);
        shadowSpace->registerSpace =
            (int*) calloc(shadowSpace->registerSpaceSize, sizeof(u4));
    }

    // Remember original state
    shadowSpace->startPC = pc;
    shadowSpace->fp = fp;
    shadowSpace->retval = self->interpSave.retval;
    shadowSpace->interpStackEnd = self->interpStackEnd;

    /*
     * Store the original method here in case the trace ends with a
     * return/invoke, the last method.
     */
    shadowSpace->method = self->interpSave.method;
    shadowSpace->methodClassDex = self->interpSave.methodClassDex;

    shadowSpace->shadowFP = shadowSpace->registerSpace +
                            shadowSpace->registerSpaceSize - postBytes/4;

    self->interpSave.curFrame = (u4*)shadowSpace->shadowFP;
    self->interpStackEnd = (u1*)shadowSpace->registerSpace;

    // Create a copy of the stack
    memcpy(((char*)shadowSpace->shadowFP)-preBytes, ((char*)fp)-preBytes,
        preBytes+postBytes);

    // Setup the shadowed heap space
    shadowSpace->heapSpaceTail = shadowSpace->heapSpace;

    // Reset trace length
    shadowSpace->traceLength = 0;

    return shadowSpace;
}

/*
 * Save ending PC, FP and compiled code exit point to shadow space.
 * Return a pointer to the shadow space for JIT to restore state.
 */
/**
 * @brief 重新保存状态
 */
void* dvmSelfVerificationRestoreState(const u2* pc, u4* fp,
                                      SelfVerificationState exitState,
                                      Thread* self)
{
    ShadowSpace *shadowSpace = self->shadowSpace;
    shadowSpace->endPC = pc;
    shadowSpace->endShadowFP = fp;
    shadowSpace->jitExitState = exitState;

    //ALOGD("### selfVerificationRestoreState(%d) pc: %#x fp: %#x endPC: %#x",
    //    self->threadId, (int)shadowSpace->startPC, (int)shadowSpace->fp,
    //    (int)pc);

    if (shadowSpace->selfVerificationState != kSVSStart) {
        ALOGD("~~~ Restore: INCORRECT PREVIOUS STATE(%d): %d",
            self->threadId, shadowSpace->selfVerificationState);
        ALOGD("********** SHADOW STATE DUMP **********");
        ALOGD("Dalvik PC: %#x endPC: %#x", (int)shadowSpace->startPC,
            (int)shadowSpace->endPC);
        ALOGD("Interp FP: %#x", (int)shadowSpace->fp);
        ALOGD("Shadow FP: %#x endFP: %#x", (int)shadowSpace->shadowFP,
            (int)shadowSpace->endShadowFP);
    }

    // Special case when punting after a single instruction
    if (exitState == kSVSPunt && pc == shadowSpace->startPC) {
        shadowSpace->selfVerificationState = kSVSIdle;
    } else {
        shadowSpace->selfVerificationState = exitState;
    }

    /* Restore state before returning */
    self->interpSave.pc = shadowSpace->startPC;
    self->interpSave.curFrame = shadowSpace->fp;
    self->interpSave.method = shadowSpace->method;
    self->interpSave.methodClassDex = shadowSpace->methodClassDex;
    self->interpSave.retval = shadowSpace->retval;
    self->interpStackEnd = shadowSpace->interpStackEnd;

    return shadowSpace;
}

/* Print contents of virtual registers */
/**
 * @brief 打印虚拟寄存器的值
 */
static void selfVerificationPrintRegisters(int* addr, int* addrRef,
                                           int numWords)
{
    int i;
    for (i = 0; i < numWords; i++) {
        ALOGD("(v%d) 0x%8x%s", i, addr[i], addr[i] != addrRef[i] ? " X" : "");
    }
}

/* Print values maintained in shadowSpace */
/**
 * @brief 打印shadow区域中的值
 */
static void selfVerificationDumpState(const u2* pc, Thread* self)
{
    ShadowSpace* shadowSpace = self->shadowSpace;
    StackSaveArea* stackSave = SAVEAREA_FROM_FP(self->interpSave.curFrame);
    int frameBytes = (int) shadowSpace->registerSpace +
                     shadowSpace->registerSpaceSize*4 -
                     (int) shadowSpace->shadowFP;
    int localRegs = 0;
    int frameBytes2 = 0;
    if ((uintptr_t)self->interpSave.curFrame < (uintptr_t)shadowSpace->fp) {
        localRegs = (stackSave->method->registersSize -
                     stackSave->method->insSize)*4;
        frameBytes2 = (int) shadowSpace->fp -
                      (int)self->interpSave.curFrame - localRegs;
    }
    ALOGD("********** SHADOW STATE DUMP **********");
    ALOGD("CurrentPC: %#x, Offset: 0x%04x", (int)pc,
        (int)(pc - stackSave->method->insns));
    ALOGD("Class: %s", shadowSpace->method->clazz->descriptor);
    ALOGD("Method: %s", shadowSpace->method->name);
    ALOGD("Dalvik PC: %#x endPC: %#x", (int)shadowSpace->startPC,
        (int)shadowSpace->endPC);
    ALOGD("Interp FP: %#x endFP: %#x", (int)shadowSpace->fp,
        (int)self->interpSave.curFrame);
    ALOGD("Shadow FP: %#x endFP: %#x", (int)shadowSpace->shadowFP,
        (int)shadowSpace->endShadowFP);
    ALOGD("Frame1 Bytes: %d Frame2 Local: %d Bytes: %d", frameBytes,
        localRegs, frameBytes2);
    ALOGD("Trace length: %d State: %d", shadowSpace->traceLength,
        shadowSpace->selfVerificationState);
}

/* Print decoded instructions in the current trace */
/**
 * @brief 打印解码指令在当前的trace
 */
static void selfVerificationDumpTrace(const u2* pc, Thread* self)
{
    ShadowSpace* shadowSpace = self->shadowSpace;
    StackSaveArea* stackSave = SAVEAREA_FROM_FP(self->interpSave.curFrame);
    int i, addr, offset;
    DecodedInstruction *decInsn;

    ALOGD("********** SHADOW TRACE DUMP **********");
    for (i = 0; i < shadowSpace->traceLength; i++) {
        addr = shadowSpace->trace[i].addr;
        offset =  (int)((u2*)addr - stackSave->method->insns);
        decInsn = &(shadowSpace->trace[i].decInsn);
        /* Not properly decoding instruction, some registers may be garbage */
        ALOGD("%#x: (0x%04x) %s",
            addr, offset, dexGetOpcodeName(decInsn->opcode));
    }
}

/* Code is forced into this spin loop when a divergence is detected */
static void selfVerificationSpinLoop(ShadowSpace *shadowSpace)
{
    const u2 *startPC = shadowSpace->startPC;
    JitTraceDescription* desc = dvmCopyTraceDescriptor(startPC, NULL);
    if (desc) {
        dvmCompilerWorkEnqueue(startPC, kWorkOrderTraceDebug, desc);
        /*
         * This function effectively terminates the VM right here, so not
         * freeing the desc pointer when the enqueuing fails is acceptable.
         */
    }
    gDvmJit.selfVerificationSpin = true;
    while(gDvmJit.selfVerificationSpin) sleep(10);
}

/*
 * If here, we're re-interpreting an instruction that was included
 * in a trace that was just executed.  This routine is called for
 * each instruction in the original trace, and compares state
 * when it reaches the end point.
 *
 * TUNING: the interpretation mechanism now supports a counted
 * single-step mechanism.  If we were to associate an instruction
 * count with each trace exit, we could just single-step the right
 * number of cycles and then compare.  This would improve detection
 * of control divergences, as well as (slightly) simplify this code.
 */
/**
 * @brief 检查自校验
 * @param pc dalvik pc指针
 * @param self 线程结构
 */
void dvmCheckSelfVerification(const u2* pc, Thread* self)
{
    ShadowSpace *shadowSpace = self->shadowSpace;
    SelfVerificationState state = shadowSpace->selfVerificationState;

    DecodedInstruction decInsn;
    dexDecodeInstruction(pc, &decInsn);

    //ALOGD("### DbgIntp(%d): PC: %#x endPC: %#x state: %d len: %d %s",
    //    self->threadId, (int)pc, (int)shadowSpace->endPC, state,
    //    shadowSpace->traceLength, dexGetOpcodeName(decInsn.opcode));

	/* 空闲状态或者开始则打印信息 */
    if (state == kSVSIdle || state == kSVSStart) {
        ALOGD("~~~ DbgIntrp: INCORRECT PREVIOUS STATE(%d): %d",
            self->threadId, state);
        selfVerificationDumpState(pc, self);
        selfVerificationDumpTrace(pc, self);
    }

    /*
     * Generalize the self verification state to kSVSDebugInterp unless the
     * entry reason is kSVSBackwardBranch or kSVSSingleStep.
     */
	/*
	 * 产生自校验状态到kSVSDebugInterp除非状态不等于分支状态并且不等于单步指令状态
	 */
    if (state != kSVSBackwardBranch && state != kSVSSingleStep) {
        shadowSpace->selfVerificationState = kSVSDebugInterp;
    }

    /*
     * Check if the current pc matches the endPC. Only check for non-zero
     * trace length when backward branches are involved.
     */
    if (pc == shadowSpace->endPC &&
        (state == kSVSDebugInterp || state == kSVSSingleStep ||
         (state == kSVSBackwardBranch && shadowSpace->traceLength != 0))) {

        shadowSpace->selfVerificationState = kSVSIdle;

        /* Check register space */
        int frameBytes = (int) shadowSpace->registerSpace +
                         shadowSpace->registerSpaceSize*4 -
                         (int) shadowSpace->shadowFP;
        if (memcmp(shadowSpace->fp, shadowSpace->shadowFP, frameBytes)) {
            if (state == kSVSBackwardBranch) {
                /* State mismatch on backward branch - try one more iteration */
                shadowSpace->selfVerificationState = kSVSDebugInterp;
                goto log_and_continue;
            }
            ALOGD("~~~ DbgIntp(%d): REGISTERS DIVERGENCE!", self->threadId);
            selfVerificationDumpState(pc, self);
            selfVerificationDumpTrace(pc, self);
            ALOGD("*** Interp Registers: addr: %#x bytes: %d",
                (int)shadowSpace->fp, frameBytes);
            selfVerificationPrintRegisters((int*)shadowSpace->fp,
                                           (int*)shadowSpace->shadowFP,
                                           frameBytes/4);
            ALOGD("*** Shadow Registers: addr: %#x bytes: %d",
                (int)shadowSpace->shadowFP, frameBytes);
            selfVerificationPrintRegisters((int*)shadowSpace->shadowFP,
                                           (int*)shadowSpace->fp,
                                           frameBytes/4);
            selfVerificationSpinLoop(shadowSpace);
        }
        /* Check new frame if it exists (invokes only) */
        if ((uintptr_t)self->interpSave.curFrame < (uintptr_t)shadowSpace->fp) {
            StackSaveArea* stackSave =
                SAVEAREA_FROM_FP(self->interpSave.curFrame);
            int localRegs = (stackSave->method->registersSize -
                             stackSave->method->insSize)*4;
            int frameBytes2 = (int) shadowSpace->fp -
                              (int) self->interpSave.curFrame - localRegs;
            if (memcmp(((char*)self->interpSave.curFrame)+localRegs,
                ((char*)shadowSpace->endShadowFP)+localRegs, frameBytes2)) {
                if (state == kSVSBackwardBranch) {
                    /*
                     * State mismatch on backward branch - try one more
                     * iteration.
                     */
                    shadowSpace->selfVerificationState = kSVSDebugInterp;
                    goto log_and_continue;
                }
                ALOGD("~~~ DbgIntp(%d): REGISTERS (FRAME2) DIVERGENCE!",
                    self->threadId);
                selfVerificationDumpState(pc, self);
                selfVerificationDumpTrace(pc, self);
                ALOGD("*** Interp Registers: addr: %#x l: %d bytes: %d",
                    (int)self->interpSave.curFrame, localRegs, frameBytes2);
                selfVerificationPrintRegisters((int*)self->interpSave.curFrame,
                                               (int*)shadowSpace->endShadowFP,
                                               (frameBytes2+localRegs)/4);
                ALOGD("*** Shadow Registers: addr: %#x l: %d bytes: %d",
                    (int)shadowSpace->endShadowFP, localRegs, frameBytes2);
                selfVerificationPrintRegisters((int*)shadowSpace->endShadowFP,
                                               (int*)self->interpSave.curFrame,
                                               (frameBytes2+localRegs)/4);
                selfVerificationSpinLoop(shadowSpace);
            }
        }

        /* Check memory space */
        bool memDiff = false;
        ShadowHeap* heapSpacePtr;
        for (heapSpacePtr = shadowSpace->heapSpace;
             heapSpacePtr != shadowSpace->heapSpaceTail; heapSpacePtr++) {
            int memData = *((unsigned int*) heapSpacePtr->addr);
            if (heapSpacePtr->data != memData) {
                if (state == kSVSBackwardBranch) {
                    /*
                     * State mismatch on backward branch - try one more
                     * iteration.
                     */
                    shadowSpace->selfVerificationState = kSVSDebugInterp;
                    goto log_and_continue;
                }
                ALOGD("~~~ DbgIntp(%d): MEMORY DIVERGENCE!", self->threadId);
                ALOGD("Addr: %#x Intrp Data: %#x Jit Data: %#x",
                    heapSpacePtr->addr, memData, heapSpacePtr->data);
                selfVerificationDumpState(pc, self);
                selfVerificationDumpTrace(pc, self);
                memDiff = true;
            }
        }
        if (memDiff) selfVerificationSpinLoop(shadowSpace);


        /*
         * Success.  If this shadowed trace included a single-stepped
         * instruction, we need to stay in the interpreter for one
         * more interpretation before resuming.
         */
        if (state == kSVSSingleStep) {
            assert(self->jitResumeNPC != NULL);
            assert(self->singleStepCount == 0);
            self->singleStepCount = 1;
            dvmEnableSubMode(self, kSubModeCountedStep);
        }

        /*
         * Switch off shadow replay mode.  The next shadowed trace
         * execution will turn it back on.
         */
        dvmDisableSubMode(self, kSubModeJitSV);

        self->jitState = kJitDone;
        return;
    }
log_and_continue:
    /* If end not been reached, make sure max length not exceeded */
    if (shadowSpace->traceLength >= JIT_MAX_TRACE_LEN) {
        ALOGD("~~~ DbgIntp(%d): CONTROL DIVERGENCE!", self->threadId);
        ALOGD("startPC: %#x endPC: %#x currPC: %#x",
            (int)shadowSpace->startPC, (int)shadowSpace->endPC, (int)pc);
        selfVerificationDumpState(pc, self);
        selfVerificationDumpTrace(pc, self);
        selfVerificationSpinLoop(shadowSpace);
        return;
    }
    /* Log the instruction address and decoded instruction for debug */
    shadowSpace->trace[shadowSpace->traceLength].addr = (int)pc;
    shadowSpace->trace[shadowSpace->traceLength].decInsn = decInsn;
    shadowSpace->traceLength++;
}
#endif

/*
 * If one of our fixed tables or the translation buffer fills up,
 * call this routine to avoid wasting cycles on future translation requests.
 */
/**
 * @brief 停止翻译请求
 */
void dvmJitStopTranslationRequests()
{
    /*
     * Note 1: This won't necessarily stop all translation requests, and
     * operates on a delayed mechanism.  Running threads look to the copy
     * of this value in their private thread structures and won't see
     * this change until it is refreshed (which happens on interpreter
     * entry).
     * Note 2: This is a one-shot memory leak on this table. Because this is a
     * permanent off switch for Jit profiling, it is a one-time leak of 1K
     * bytes, and no further attempt will be made to re-allocate it.  Can't
     * free it because some thread may be holding a reference.
     */
    gDvmJit.pProfTable = NULL;
    dvmJitUpdateThreadStateAll();
}

#if defined(WITH_JIT_TUNING)
/* Convenience function to increment counter from assembly code */
void dvmBumpNoChain(int from)
{
    gDvmJit.noChainExit[from]++;
}

/* Convenience function to increment counter from assembly code */
void dvmBumpNormal()
{
    gDvmJit.normalExit++;
}

/* Convenience function to increment counter from assembly code */
void dvmBumpPunt(int from)
{
    gDvmJit.puntExit++;
}
#endif

/* Dumps debugging & tuning stats to the log */
/**
 * @brief 打印调试器并且转换状态到记录
 */
void dvmJitStats()
{
    int i;
    int hit;			/* 表中不为0的项 */
    int not_hit;		/* 表中没有为0的项 */
    int chains;			/* 表项数量 */
    int stubs;			/* 与dvmCompilerGetInterpretTemplate返回值相等的数量 */
	/* JIT表 */
    if (gDvmJit.pJitEntryTable) {
		/* 遍历JIT表 */
        for (i=0, stubs=chains=hit=not_hit=0;
             i < (int) gDvmJit.jitTableSize;
             i++) {
            if (gDvmJit.pJitEntryTable[i].dPC != 0) {
                hit++;
				/* 如果表 */
                if (gDvmJit.pJitEntryTable[i].codeAddress ==
                      dvmCompilerGetInterpretTemplate())
                    stubs++;
            } else
                not_hit++;
            if (gDvmJit.pJitEntryTable[i].u.info.chain != gDvmJit.jitTableSize)
                chains++;
        }
        ALOGD("JIT: table size is %d, entries used is %d",
             gDvmJit.jitTableSize,  gDvmJit.jitTableEntriesUsed);
        ALOGD("JIT: %d traces, %d slots, %d chains, %d thresh, %s",
             hit, not_hit + hit, chains, gDvmJit.threshold,
             gDvmJit.blockingMode ? "Blocking" : "Non-blocking");

#if defined(WITH_JIT_TUNING)
        ALOGD("JIT: Code cache patches: %d", gDvmJit.codeCachePatches);

        ALOGD("JIT: Lookups: %d hits, %d misses; %d normal, %d punt",
             gDvmJit.addrLookupsFound, gDvmJit.addrLookupsNotFound,
             gDvmJit.normalExit, gDvmJit.puntExit);

        ALOGD("JIT: ICHits: %d", gDvmICHitCount);

        ALOGD("JIT: noChainExit: %d IC miss, %d interp callsite, "
             "%d switch overflow",
             gDvmJit.noChainExit[kInlineCacheMiss],
             gDvmJit.noChainExit[kCallsiteInterpreted],
             gDvmJit.noChainExit[kSwitchOverflow]);

        ALOGD("JIT: ICPatch: %d init, %d rejected, %d lock-free, %d queued, "
             "%d dropped",
             gDvmJit.icPatchInit, gDvmJit.icPatchRejected,
             gDvmJit.icPatchLockFree, gDvmJit.icPatchQueued,
             gDvmJit.icPatchDropped);

        ALOGD("JIT: Invoke: %d mono, %d poly, %d native, %d return",
             gDvmJit.invokeMonomorphic, gDvmJit.invokePolymorphic,
             gDvmJit.invokeNative, gDvmJit.returnOp);
        ALOGD("JIT: Inline: %d mgetter, %d msetter, %d pgetter, %d psetter",
             gDvmJit.invokeMonoGetterInlined, gDvmJit.invokeMonoSetterInlined,
             gDvmJit.invokePolyGetterInlined, gDvmJit.invokePolySetterInlined);
        ALOGD("JIT: Total compilation time: %llu ms", gDvmJit.jitTime / 1000);
        ALOGD("JIT: Avg unit compilation time: %llu us",
             gDvmJit.numCompilations == 0 ? 0 :
             gDvmJit.jitTime / gDvmJit.numCompilations);
        ALOGD("JIT: Potential GC blocked by compiler: max %llu us / "
             "avg %llu us (%d)",
             gDvmJit.maxCompilerThreadBlockGCTime,
             gDvmJit.numCompilerThreadBlockGC == 0 ?
                 0 : gDvmJit.compilerThreadBlockGCTime /
                     gDvmJit.numCompilerThreadBlockGC,
             gDvmJit.numCompilerThreadBlockGC);
#endif

        ALOGD("JIT: %d Translation chains, %d interp stubs",
             gDvmJit.translationChains, stubs);
		/* 如果profile模式等于profiling继续模式 */
        if (gDvmJit.profileMode == kTraceProfilingContinuous) {
            dvmCompilerSortAndPrintTraceProfiles();
        }
    }
}


/* End current trace now & don't include current instruction */
/**
 * @brief 转化JIT选定状态
 * @param self 线程结构
 * @param dPC dalvik的PC指针
 */
void dvmJitEndTraceSelect(Thread* self, const u2* dPC)
{
    if (self->jitState == kJitTSelect) {
        self->jitState = kJitTSelectEnd;
    }
    if (self->jitState == kJitTSelectEnd) {
        // Clean up and finish now.
		/* 增加最后一个空的代码trace块 */
        dvmCheckJit(dPC, self);
    }
}

/*
 * Find an entry in the JitTable, creating if necessary.
 * Returns null if table is full.
 */
/**
 * @brief 查找并且添加一个表项到表中
 * @param dPC dalvik字节码的指针
 * @param callerLocked 调用者锁死
 * @param isMethodEntry 是否是函数入口项
 * @retval non-null 查找到了并且返回表项
 * @retval null 表已经满了
 * @note 判断两个节点相等则isMethodEntry也必须相等
 */
static JitEntry *lookupAndAdd(const u2* dPC, bool callerLocked,
                              bool isMethodEntry)
{
	/* 貌似在这份代码中所有关于JitTable表的项数 */
    u4 chainEndMarker = gDvmJit.jitTableSize;	/* 获取表大小 */
    u4 idx = dvmJitHash(dPC);					/* hash计算索引 */

    /*
     * Walk the bucket chain to find an exact match for our PC and trace/method
     * type
     */
	/*
	 * 遍历JitTable
	 */
    while ((gDvmJit.pJitEntryTable[idx].u.info.chain != chainEndMarker) &&
           ((gDvmJit.pJitEntryTable[idx].dPC != dPC) ||
            (gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry !=
             isMethodEntry))) {
		/* 获取下一个节点的索引 */
        idx = gDvmJit.pJitEntryTable[idx].u.info.chain;
    }

	/* 已经到达末尾，检查末尾最后一个节点，如果不匹配 */
    if (gDvmJit.pJitEntryTable[idx].dPC != dPC ||
        gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry != isMethodEntry) {
        /*
         * No match.  Aquire jitTableLock and find the last
         * slot in the chain. Possibly continue the chain walk in case
         * some other thread allocated the slot we were looking
         * at previuosly (perhaps even the dPC we're trying to enter).
         */
		/*
		 * 如果不匹配
		 */
        if (!callerLocked)
            dvmLockMutex(&gDvmJit.tableLock);
        /*
         * At this point, if .dPC is NULL, then the slot we're
         * looking at is the target slot from the primary hash
         * (the simple, and common case).  Otherwise we're going
         * to have to find a free slot and chain it.
         */
		/* 检查表是否已经满了 */
        ANDROID_MEMBAR_FULL(); /* Make sure we reload [].dPC after lock */

		/* 如果最后一个节点不为空 */
        if (gDvmJit.pJitEntryTable[idx].dPC != NULL) {
            u4 prev;
			/* 循环进行匹配，匹配则循环 */
            while (gDvmJit.pJitEntryTable[idx].u.info.chain != chainEndMarker) {
                if (gDvmJit.pJitEntryTable[idx].dPC == dPC &&
                    gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry ==
                        isMethodEntry) {
                    /* Another thread got there first for this dPC */
                    if (!callerLocked)
                        dvmUnlockMutex(&gDvmJit.tableLock);
                    return &gDvmJit.pJitEntryTable[idx];
                }
				/* 下一个节点 */
                idx = gDvmJit.pJitEntryTable[idx].u.info.chain;
            }
            /* Here, idx should be pointing to the last cell of an
             * active chain whose last member contains a valid dPC */
            assert(gDvmJit.pJitEntryTable[idx].dPC != NULL);
            /* Linear walk to find a free cell and add it to the end */
            prev = idx;
            while (true) {
                idx++;
                if (idx == chainEndMarker)
                    idx = 0;  /* Wraparound */
                if ((gDvmJit.pJitEntryTable[idx].dPC == NULL) ||
                    (idx == prev))
                    break;
            }
            if (idx != prev) {
                JitEntryInfoUnion oldValue;
                JitEntryInfoUnion newValue;
                /*
                 * Although we hold the lock so that noone else will
                 * be trying to update a chain field, the other fields
                 * packed into the word may be in use by other threads.
                 */
                do {
                    oldValue = gDvmJit.pJitEntryTable[prev].u;
                    newValue = oldValue;
                    newValue.info.chain = idx;
                } while (android_atomic_release_cas(oldValue.infoWord,
                        newValue.infoWord,
                        &gDvmJit.pJitEntryTable[prev].u.infoWord) != 0);
            }
        }
        if (gDvmJit.pJitEntryTable[idx].dPC == NULL) {
            gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry = isMethodEntry;
            /*
             * Initialize codeAddress and allocate the slot.  Must
             * happen in this order (since dPC is set, the entry is live.
             */
            android_atomic_release_store((int32_t)dPC,
                 (volatile int32_t *)(void *)&gDvmJit.pJitEntryTable[idx].dPC);
            /* for simulator mode, we need to initialized codeAddress to null */
            gDvmJit.pJitEntryTable[idx].codeAddress = NULL;
            gDvmJit.pJitEntryTable[idx].dPC = dPC;
            gDvmJit.jitTableEntriesUsed++;
        } else {
            /* Table is full */
            idx = chainEndMarker;
        }
        if (!callerLocked)
            dvmUnlockMutex(&gDvmJit.tableLock);
    }
    return (idx == chainEndMarker) ? NULL : &gDvmJit.pJitEntryTable[idx];
}

/* Dump a trace description */
/** 
 * @brief 打印一个trace的描述
 */
void dvmJitDumpTraceDesc(JitTraceDescription *trace)
{
    int i;
    bool done = false;
    const u2* dpc;
    const u2* dpcBase;
    int curFrag = 0;
    ALOGD("===========================================");
    ALOGD("Trace dump %#x, Method %s off %#x",(int)trace,
         trace->method->name,trace->trace[curFrag].info.frag.startOffset);
    dpcBase = trace->method->insns;
    while (!done) {
        DecodedInstruction decInsn;
        if (trace->trace[curFrag].isCode) {
            ALOGD("Frag[%d]- Insts: %d, start: %#x, hint: %#x, end: %d",
                 curFrag, trace->trace[curFrag].info.frag.numInsts,
                 trace->trace[curFrag].info.frag.startOffset,
                 trace->trace[curFrag].info.frag.hint,
                 trace->trace[curFrag].info.frag.runEnd);
            dpc = dpcBase + trace->trace[curFrag].info.frag.startOffset;
            for (i=0; i<trace->trace[curFrag].info.frag.numInsts; i++) {
                dexDecodeInstruction(dpc, &decInsn);
                ALOGD("    0x%04x - %s %#x",(dpc-dpcBase),
                     dexGetOpcodeName(decInsn.opcode),(int)dpc);
                dpc += dexGetWidthFromOpcode(decInsn.opcode);
            }
            if (trace->trace[curFrag].info.frag.runEnd) {
                done = true;
            }
        } else {
            ALOGD("Frag[%d]- META info: 0x%08x", curFrag,
                 (int)trace->trace[curFrag].info.meta);
        }
        curFrag++;
    }
    ALOGD("-------------------------------------------");
}

/*
 * Append the class ptr of "this" and the current method ptr to the current
 * trace. That is, the trace runs will contain the following components:
 *  + trace run that ends with an invoke (existing entry)
 *  + thisClass (new)
 *  + calleeMethod (new)
 */
/**
 * @brief 插入一个类与函数的信息到trace请求中
 * @param self 线程结构指针
 * @param thisClass 类对象指针
 * @param calleeMethod 被调用者指针
 * @param insn 解码指令结构指针
 * @note 一个trace请求必须包含以下三种组建
 *	- trace运行在以一个invoke指令为结束(存在项)
 *	- 类指针
 *	- 被调用者
 */
static void insertClassMethodInfo(Thread* self,
                                  const ClassObject* thisClass,
                                  const Method* calleeMethod,
                                  const DecodedInstruction* insn)
{
    int currTraceRun = ++self->currTraceRun;	/* 增加当前的trace索引 */
	/* 记录类描述 */
    self->trace[currTraceRun].info.meta = thisClass ?
                                    (void *) thisClass->descriptor : NULL;
    self->trace[currTraceRun].isCode = false;

    currTraceRun = ++self->currTraceRun;
    self->trace[currTraceRun].info.meta = thisClass ?
                                    (void *) thisClass->classLoader : NULL;
    self->trace[currTraceRun].isCode = false;

    currTraceRun = ++self->currTraceRun;
    self->trace[currTraceRun].info.meta = (void *) calleeMethod;
    self->trace[currTraceRun].isCode = false;
}

/*
 * Check if the next instruction following the invoke is a move-result and if
 * so add it to the trace. That is, this will add the trace run that includes
 * the move-result to the trace list.
 *
 *  + trace run that ends with an invoke (existing entry)
 *  + thisClass (existing entry)
 *  + calleeMethod (existing entry)
 *  + move result (new)
 *
 * lastPC, len, offset are all from the preceding invoke instruction
 */
/**
 * @brief 插入move-result指令
 * @param lastPC 当前要trace指令的指针
 * @param len 当前指令的长度
 * @param offset
 * @param self 线程结构指针
 * @note 检查如果下一条指令跟随invoke的是一条move-result指令则插入它到trace中
 */
static void insertMoveResult(const u2 *lastPC, int len, int offset,
                             Thread *self)
{
    DecodedInstruction nextDecInsn;
    const u2 *moveResultPC = lastPC + len;					/* move-result指令的地址 */

    dexDecodeInstruction(moveResultPC, &nextDecInsn);		/* 解码 */
	/* 如果不是return则直接返回 */
    if ((nextDecInsn.opcode != OP_MOVE_RESULT) &&
        (nextDecInsn.opcode != OP_MOVE_RESULT_WIDE) &&
        (nextDecInsn.opcode != OP_MOVE_RESULT_OBJECT))
        return;

    /* We need to start a new trace run */
	/* 添加一个trace */
    int currTraceRun = ++self->currTraceRun;
    self->currRunHead = moveResultPC;									/* 指令的地址 */
    self->trace[currTraceRun].info.frag.startOffset = offset + len;		/* 离函数开头的偏移 */
    self->trace[currTraceRun].info.frag.numInsts = 1;					/* 指令数量 */
    self->trace[currTraceRun].info.frag.runEnd = false;					/* 运行没有结束 */
    self->trace[currTraceRun].info.frag.hint = kJitHintNone;			/* 无附加选项 */
    self->trace[currTraceRun].isCode = true;							/* 是代码 */
    self->totalTraceLen++;												/* trace总数增加 */

    self->currRunLen = dexGetWidthFromInstruction(moveResultPC);		/* 这次trace需要的长度 */
}

/*
 * Adds to the current trace request one instruction at a time, just
 * before that instruction is interpreted.  This is the primary trace
 * selection function.  NOTE: return instruction are handled a little
 * differently.  In general, instructions are "proposed" to be added
 * to the current trace prior to interpretation.  If the interpreter
 * then successfully completes the instruction, is will be considered
 * part of the request.  This allows us to examine machine state prior
 * to interpretation, and also abort the trace request if the instruction
 * throws or does something unexpected.  However, return instructions
 * will cause an immediate end to the translation request - which will
 * be passed to the compiler before the return completes.  This is done
 * in response to special handling of returns by the interpreter (and
 * because returns cannot throw in a way that causes problems for the
 * translated code.
 */
/**
 * @brief 对JIT进行检查 
 * @param pc 要编译的当前指针
 * @param self 当前线程的结构
 * @note 添加一个指令的当前trace请求，在指令被解释之前。这是选定函数的
 *	主要trace。NOTE：返回指令被处理有微小的不同。通常指令被提交增加到
 *	一个trace在解释之前。如果解释起正确的完整指令的执行，它将被作为请求
 *	的一部分。这需要我们检查机器状态在解释指令之前，并且它也可能中断
 *	trace请求如果指令抛出或者做了一些异常操作。但是返回指令将导致一个立即
 *	的结束在编译请求期间 - 在传递给编译器之前返回完成。通过解释器返回一个
 *	回应经过特殊处理的returns。
 */
void dvmCheckJit(const u2* pc, Thread* self)
{
    const ClassObject *thisClass = self->callsiteClass;	/* 获取当前的类对象 */
    const Method* curMethod = self->methodToCall;		/* 获取当前的函数 */
    int flags, len;
    int allDone = false;
    /* Stay in break/single-stop mode for the next instruction */
	/* 保持break/single-stop模式在下一条指令 */
    bool stayOneMoreInst = false;

    /* Prepare to handle last PC and stage the current PC & method*/
	/* 指令分析的地址 */
    const u2 *lastPC = self->lastPC;

    self->lastPC = pc;

	/* 
	 * Jit的状态
	 * kJitSelect : 继续选定下一个指令
	 * kJitSelectEnd : 选择指令完毕
	 */
    switch (self->jitState) {
        int offset;
        DecodedInstruction decInsn;
        case kJitTSelect:
            /* First instruction - just remember the PC and exit */
			/* 第一条指令 - 仅记住PC指针并且退出 */
            if (lastPC == NULL) break;
            /* Grow the trace around the last PC if jitState is kJitTSelect */
			/* 解码第一条指令 */
            dexDecodeInstruction(lastPC, &decInsn);
			/* TRACE_OPCODE_FILTER开启OPCODE是否被JIT支持 */
#if TRACE_OPCODE_FILTER
            /* Only add JIT support opcode to trace. End the trace if
             * this opcode is not supported.
             */
			/*
			 * 如果遇到不支持的OPCODE指令则直接退出循环
			 */
            if (!dvmIsOpcodeSupportedByJit(decInsn.opcode)) {
                self->jitState = kJitTSelectEnd;		/* 选择完毕 */
                break;
            }
#endif
            /*
             * Treat {PACKED,SPARSE}_SWITCH as trace-ending instructions due
             * to the amount of space it takes to generate the chaining
             * cells.
             */
			/*
			 * 遇到{PACKED,SPARSE}_SWITCH作为trace结束的指令，并且分配产生
			 * 链接单元的空间
			 */
            if (self->totalTraceLen != 0 &&
                (decInsn.opcode == OP_PACKED_SWITCH ||
                 decInsn.opcode == OP_SPARSE_SWITCH)) {
                self->jitState = kJitTSelectEnd;
                break;
            }

			/* 打印TRACE信息 */
#if defined(SHOW_TRACE)
            ALOGD("TraceGen: adding %s. lpc:%#x, pc:%#x",
                 dexGetOpcodeName(decInsn.opcode), (int)lastPC, (int)pc);
#endif
            flags = dexGetFlagsFromOpcode(decInsn.opcode);					/* 获取OP标志 */
            len = dexGetWidthFromInstruction(lastPC);						/* 获取指令长度 */
            offset = lastPC - self->traceMethod->insns;						/* 当前指令相对于函数头的偏移 */
            assert((unsigned) offset < dvmGetMethodInsnsSize(self->traceMethod));
			/* lastPC指针应该是与trace末尾同步的，不同步则是一个新的开始 */
            if (lastPC != self->currRunHead + self->currRunLen) {
                int currTraceRun;
                /* We need to start a new trace run */
				/* 开启一个新的trace请求 */
                currTraceRun = ++self->currTraceRun;		/* 保存原有的 */
				/* 重新设置开始位置 */
                self->currRunLen = 0;						/* 总共有多少长度的指令要trace */
                self->currRunHead = (u2*)lastPC;
                self->trace[currTraceRun].info.frag.startOffset = offset;
                self->trace[currTraceRun].info.frag.numInsts = 0;
                self->trace[currTraceRun].info.frag.runEnd = false;
                self->trace[currTraceRun].info.frag.hint = kJitHintNone;
                self->trace[currTraceRun].isCode = true;
            }
            self->trace[self->currTraceRun].info.frag.numInsts++;	/* 当前trace指令数量增加 */
            self->totalTraceLen++;
            self->currRunLen += len;			/* trace整体代码长度增加 */

            /*
             * If the last instruction is an invoke, we will try to sneak in
             * the move-result* (if existent) into a separate trace run.
             */
			/*
			 * 如果最后一条指令是一个调用指令，则在暗中尝试move-result指令到
			 * 一个分离的trace run中
			 */
            {
              int needReservedRun = (flags & kInstrInvoke) ? 1 : 0;

              /* Will probably never hit this with the current trace builder */
			  /* 在正常的trace编译时可能从不会遇到这种情况 */
			  /* google为什么会这样编码呢？ */
			  /* #define MAX_JIT_RUN_LEN 64 */
              if (self->currTraceRun ==
                   (MAX_JIT_RUN_LEN - 1 - needReservedRun)) {
                self->jitState = kJitTSelectEnd;
              }
            }

			/* 不是GOTO指令并且是分支或者SWITCH或者调用或者返回则算作
			 * JIT结束*/
            if (!dexIsGoto(flags) &&
                  ((flags & (kInstrCanBranch |
                             kInstrCanSwitch |
                             kInstrCanReturn |
                             kInstrInvoke)) != 0)) {
                    self->jitState = kJitTSelectEnd;
#if defined(SHOW_TRACE)
                ALOGD("TraceGen: ending on %s, basic block end",
                     dexGetOpcodeName(decInsn.opcode));
#endif

                /*
                 * If the current invoke is a {virtual,interface}, get the
                 * current class/method pair into the trace as well.
                 * If the next instruction is a variant of move-result, insert
                 * it to the trace too.
                 */
				/*
				 * 如果是invoke 一个虚函数或者接口,获取当前的类/函数成对的放入
				 * trace。如果下一条指令是一个"move-result"，也插入到trace中
				 */
                if (flags & kInstrInvoke) {
					/* 插入类/函数信息 */
                    insertClassMethodInfo(self, thisClass, curMethod,
                                          &decInsn);
					/* 插入move-result指令 */
                    insertMoveResult(lastPC, len, offset, self);
                }
            }/* end if */
            /* Break on throw or self-loop */
			/* 中断在一个trhow指令或者自循环指令 */
            if ((decInsn.opcode == OP_THROW) || (lastPC == pc)){
                self->jitState = kJitTSelectEnd;
            }
			/* 如果达到最大数量的trace */
            if (self->totalTraceLen >= JIT_MAX_TRACE_LEN) {
                self->jitState = kJitTSelectEnd;
            }
			/* 此标志没有返回标志 */
            if ((flags & kInstrCanReturn) != kInstrCanReturn) {
                break;
            }
            else {
                /*
                 * Last instruction is a return - stay in the dbg interpreter
                 * for one more instruction if it is a non-void return, since
                 * we don't want to start a trace with move-result as the first
                 * instruction (which is already included in the trace
                 * containing the invoke.
                 */
				/*
				 * 最后一条指令是return - 保持在调试解释器
				 * 在更多的指令只要此return是一条非 void-return指令，直到我们不想
				 * 开启一个trace通过move-result作为第一条指令
				 */
                if (decInsn.opcode != OP_RETURN_VOID) {
                    stayOneMoreInst = true;
                }
            }
            /* NOTE: intentional fallthrough for returns */
			/* 选择结束 */
        case kJitTSelectEnd:
            {
                /* Empty trace - set to bail to interpreter */
				/* 
				 * 空的trace - 设置失败对解释器
				 */
				
				/*
				 * void *dvmCompilerGetInterpretTemplate()
				 * {
				 *		return (void*)((int)gDvmJit.codeCache +
				 *			templateEntryOffsets[TEMPLATE_INTERPRET]);
				 * }
				 */
                if (self->totalTraceLen == 0) {
					/* 设置代码地址 */
                    dvmJitSetCodeAddr(self->currTraceHead,									/* 要编译的地址 */
                                      dvmCompilerGetInterpretTemplate(),					/* 编译好后存放的地址 */
                                      dvmCompilerGetInterpretTemplateSet(),					/* 指令集合 */
                                      false /* Not method entry */, 0);
                    self->jitState = kJitDone;					/* 完成JIT */
                    allDone = true;
                    break;
                }

                int lastTraceDesc = self->currTraceRun;			/* 获取trace最后的索引 */

                /* Extend a new empty desc if the last slot is meta info */
				/*
				 * 扩展一个新的空描述如果最后一个trace槽是meta信息
				 * 增加一个空的trace槽  
				 * 如果最后一个槽是一个代码则不需要添加了
				 */
                if (!self->trace[lastTraceDesc].isCode) {
                    lastTraceDesc = ++self->currTraceRun;
                    self->trace[lastTraceDesc].info.frag.startOffset = 0;
                    self->trace[lastTraceDesc].info.frag.numInsts = 0;
                    self->trace[lastTraceDesc].info.frag.hint = kJitHintNone;
                    self->trace[lastTraceDesc].isCode = true;
                }

                /* Mark the end of the trace runs */
				/* 标记trace结尾 */
                self->trace[lastTraceDesc].info.frag.runEnd = true;

				/* 这个JitTraceDescription要直接作用于编译相关 */
                JitTraceDescription* desc =
                   (JitTraceDescription*)malloc(sizeof(JitTraceDescription) +
                     sizeof(JitTraceRun) * (self->currTraceRun+1));

                if (desc == NULL) {
                    ALOGE("Out of memory in trace selection");
					/* 用此函数结束编译请求 */
                    dvmJitStopTranslationRequests();
                    self->jitState = kJitDone;
                    allDone = true;
                    break;
                }

                desc->method = self->traceMethod;						/* 设置订单的函数体 */
				/* 复制trace请求 */
                memcpy((char*)&(desc->trace[0]),
                    (char*)&(self->trace[0]),
                    sizeof(JitTraceRun) * (self->currTraceRun+1));
#if defined(SHOW_TRACE)
                ALOGD("TraceGen:  trace done, adding to queue");
                dvmJitDumpTraceDesc(desc);
#endif
				/* 订单入列 */
                if (dvmCompilerWorkEnqueue(
                       self->currTraceHead,kWorkOrderTrace,desc)) {
                    /* Work order successfully enqueued */
					/* 如果处于阻塞模式则丢弃编译队列 */
                    if (gDvmJit.blockingMode) {
                        dvmCompilerDrainQueue();
                    }
                } else {
                    /*
                     * Make sure the descriptor for the abandoned work order is
                     * freed.
                     */
                    free(desc);
                }
                self->jitState = kJitDone;
                allDone = true;
            }
            break;
        case kJitDone:
            allDone = true;
            break;
        case kJitNot:
            allDone = true;
            break;
        default:
            ALOGE("Unexpected JIT state: %d", self->jitState);
            dvmAbort();
            break;
    }

    /*
     * If we're done with trace selection, switch off the control flags.
     */

	/*
	 * 完成trace设置，关闭控制标志
	 */
     if (allDone) {
		 /* 清除当前线程的kSubModeJitTraceBuild标志 */
         dvmDisableSubMode(self, kSubModeJitTraceBuild);
		 /* 如果还是等待下一条指令 */
         if (stayOneMoreInst) {
             // Clear jitResumeNPC explicitly since we know we don't need it
             // here.
			 /* 明确的清楚jitResumeNPC变量 */
             self->jitResumeNPC = NULL;
			 /* 继续保持单步执行一条指令 */
             // Keep going in single-step mode for at least one more inst
             if (self->singleStepCount == 0)
                 self->singleStepCount = 1;
             dvmEnableSubMode(self, kSubModeCountedStep);
         }
     }
     return;
}

/**
 * @brief 从JitTable中找寻JitEntry
 * @param pc dalvik的地址
 * @param isMethodEntry 是否是函数入口
 */
JitEntry *dvmJitFindEntry(const u2* pc, bool isMethodEntry)
{
	/* 通过pc指针地址作为哈希值 */
    int idx = dvmJitHash(pc);

    /* Expect a high hit rate on 1st shot */
	/* 如果已经存在并且isMethodEntry与参数一致则直接返回 */
    if ((gDvmJit.pJitEntryTable[idx].dPC == pc) &&
        (gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry == isMethodEntry))
        return &gDvmJit.pJitEntryTable[idx];
    else {
		/* Jit表的长度 */
        int chainEndMarker = gDvmJit.jitTableSize;
		/* 遍历 */
        while (gDvmJit.pJitEntryTable[idx].u.info.chain != chainEndMarker) {
            idx = gDvmJit.pJitEntryTable[idx].u.info.chain;
            if ((gDvmJit.pJitEntryTable[idx].dPC == pc) &&
                (gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry ==
                isMethodEntry))
                return &gDvmJit.pJitEntryTable[idx];
        }
    }
    return NULL;
}

/*
 * Walk through the JIT profile table and find the corresponding JIT code, in
 * the specified format (ie trace vs method). This routine needs to be fast.
 */
/**
 * @brief 通常的获取代码地址
 * @param dPC dalvik字节码地址
 * @param methodEntry 函数入口
 * @note 遍历JIT profile表并且寻找JIT代码在指定的格式。
 */
void* getCodeAddrCommon(const u2* dPC, bool methodEntry)
{
    int idx = dvmJitHash(dPC);							/* hash值 */
    const u2* pc = gDvmJit.pJitEntryTable[idx].dPC;		/* dalvik字节码地址 */


	/* 如果表项地址不为空 */
    if (pc != NULL) {
		/* vm/interp/InterpDefs.h
		 * static inline bool dvmJitHideTranslation()
		 * {
		 *		return (gDvm.sumThreadSuspendCount != 0) ||
		 *				(gDvmJit.codeCacheFull == true) ||
		 *				(gDvmJit.pProfTable == NULL);
		 */
        bool hideTranslation = dvmJitHideTranslation();		/* 编译隐藏 */
		/* 如果表项的指针与参数的相同并且isMethodEntry也相同 */
        if (pc == dPC &&
            gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry == methodEntry) {
			/*  */
            int offset = (gDvmJit.profileMode >= kTraceProfilingContinuous) ?
                 0 : gDvmJit.pJitEntryTable[idx].u.info.profileOffset;
            intptr_t codeAddress =
                (intptr_t)gDvmJit.pJitEntryTable[idx].codeAddress;
			/* 性能监视 */
#if defined(WITH_JIT_TUNING)
            gDvmJit.addrLookupsFound++;
#endif
			/* 如果有隐藏或者代码地址为NULL则返回NULL否则返回以编译代码 + 偏移 */
            return hideTranslation || !codeAddress ?  NULL :
                  (void *)(codeAddress + offset);
        } else {
			/* 如果没有找到 */
            int chainEndMarker = gDvmJit.jitTableSize;
			/* pJitEntryTable[idx].u.info.chain指向下一个节点 */
            while (gDvmJit.pJitEntryTable[idx].u.info.chain != chainEndMarker) {
				/* 获取下一个节点的索引 */
                idx = gDvmJit.pJitEntryTable[idx].u.info.chain;
				/* 如果得到匹配 */
                if (gDvmJit.pJitEntryTable[idx].dPC == dPC &&
                    gDvmJit.pJitEntryTable[idx].u.info.isMethodEntry ==
                        methodEntry) {
                    int offset = (gDvmJit.profileMode >=
                        kTraceProfilingContinuous) ? 0 :
                        gDvmJit.pJitEntryTable[idx].u.info.profileOffset;
                    intptr_t codeAddress =
                        (intptr_t)gDvmJit.pJitEntryTable[idx].codeAddress;
#if defined(WITH_JIT_TUNING)
                    gDvmJit.addrLookupsFound++;
#endif
                    return hideTranslation || !codeAddress ? NULL :
                        (void *)(codeAddress + offset);
                }
            }
        }
    }
#if defined(WITH_JIT_TUNING)
    gDvmJit.addrLookupsNotFound++;
#endif
    return NULL;
}

/*
 * If a translated code address, in trace format, exists for the davik byte code
 * pointer return it.
 */
/**
 * @brief 获取trace地址
 * @param dPC dalvik字节码地址
 * @return 返回一个已经经过编译的代码
 */
void* dvmJitGetTraceAddr(const u2* dPC)
{
    return getCodeAddrCommon(dPC, false /* method entry */);
}

/*
 * If a translated code address, in whole-method format, exists for the davik
 * byte code pointer return it.
 */
/**
 * @brief 获取函数入口地址
 * @param dPC dalvik字节码指针
 * @return 返回一个函数入口指针
 */
void* dvmJitGetMethodAddr(const u2* dPC)
{
    return getCodeAddrCommon(dPC, true /* method entry */);
}

/*
 * Similar to dvmJitGetTraceAddr, but returns null if the calling
 * thread is in a single-step mode.
 */
/**
 * @brief 获取trace地址线程
 * @param dPC dalvik字节码
 * @param self 线程结构指针
 * @return 返回代码地址
 * @note 如果线程解释器的中断标志被设置为不等于0则返回NULL
 *	否则返回代码地址
 */
void* dvmJitGetTraceAddrThread(const u2* dPC, Thread* self)
{
    return (self->interpBreak.ctl.breakFlags != 0) ? NULL :
            getCodeAddrCommon(dPC, false /* method entry */);
}

/*
 * Similar to dvmJitGetMethodAddr, but returns null if the calling
 * thread is in a single-step mode.
 */
/**
 * @brief 同dvmJitGetTraceAddr不同的是返回函数入口项
 */
void* dvmJitGetMethodAddrThread(const u2* dPC, Thread* self)
{
    return (self->interpBreak.ctl.breakFlags != 0) ? NULL :
            getCodeAddrCommon(dPC, true /* method entry */);
}

/*
 * Register the translated code pointer into the JitTable.
 * NOTE: Once a codeAddress field transitions from initial state to
 * JIT'd code, it must not be altered without first halting all
 * threads.  We defer the setting of the profile prefix size until
 * after the new code address is set to ensure that the prefix offset
 * is never applied to the initial interpret-only translation.  All
 * translations with non-zero profile prefixes will still be correct
 * if entered as if the profile offset is 0, but the interpret-only
 * template cannot handle a non-zero prefix.
 * NOTE: JitTable must not be in danger of reset while this
 * code is executing. see Issue 4271784 for details.
 */
/**
 * @brief 设置代码地址
 * @param dPC 要设置的dalvik字节码地址
 * @param nPC 编译后代码的存放地址
 * @param set 指令类型
 * @param isMethodEntry 是否是函数入口
 * @param profilePrefixSize
 * @note 注册一个要编译代码的指针到JitTable。一旦codeAddress字段从
 *	初始化状态编译到JIT代码，首先必须关闭所有线程。
 */
void dvmJitSetCodeAddr(const u2* dPC, void *nPC, JitInstructionSetType set,
                       bool isMethodEntry, int profilePrefixSize)
{
    JitEntryInfoUnion oldValue;
    JitEntryInfoUnion newValue;
    /*
     * Get the JitTable slot for this dPC (or create one if JitTable
     * has been reset between the time the trace was requested and
     * now.
     */
	/* 获取JitTable槽为这个dPC(或者创建一个如果JitTable已经被重新设置
	 * 在trace被请求与当前之间*/
    JitEntry *jitEntry = isMethodEntry ?
        lookupAndAdd(dPC, false /* caller holds tableLock */, isMethodEntry) :
                     dvmJitFindEntry(dPC, isMethodEntry);
    assert(jitEntry);
    /* Note: order of update is important */
    do {
        oldValue = jitEntry->u;
        newValue = oldValue;
        newValue.info.isMethodEntry = isMethodEntry;
        newValue.info.instructionSet = set;
        newValue.info.profileOffset = profilePrefixSize;
    } while (android_atomic_release_cas(
             oldValue.infoWord, newValue.infoWord,
             &jitEntry->u.infoWord) != 0);
    jitEntry->codeAddress = nPC;
}

/*
 * Determine if valid trace-bulding request is active.  If so, set
 * the proper flags in interpBreak and return.  Trace selection will
 * then begin normally via dvmCheckBefore.
 */
/**
 * @brief 检查trace请求
 * @param self 线程结构指针
 * @note 关于热点过滤：
 *	第一个级别的触发条件是故意放宽的 - 我们不需要这个条件很容易标识
 *	潜在的traces然后编译它，但是也允许重新进入到代码缓冲中。
 *
 *	第二个级别的过滤器存在的目的是选定我们已经编译的trace块代码。
 *	它需要一个过滤器值(filterKey)在一段时间出现两次。
 *	
 */
void dvmJitCheckTraceRequest(Thread* self)
{
    int i;
    /*
     * A note on trace "hotness" filtering:
     *
     * Our first level trigger is intentionally loose - we need it to
     * fire easily not just to identify potential traces to compile, but
     * also to allow re-entry into the code cache.
     *
     * The 2nd level filter (done here) exists to be selective about
     * what we actually compile.  It works by requiring the same
     * trace head "key" (defined as filterKey below) to appear twice in
     * a relatively short period of time.   The difficulty is defining the
     * shape of the filterKey.  Unfortunately, there is no "one size fits
     * all" approach.
     *
     * For spiky execution profiles dominated by a smallish
     * number of very hot loops, we would want the second-level filter
     * to be very selective.  A good selective filter is requiring an
     * exact match of the Dalvik PC.  In other words, defining filterKey as:
     *     intptr_t filterKey = (intptr_t)self->interpSave.pc
     *
     * However, for flat execution profiles we do best when aggressively
     * translating.  A heuristically decent proxy for this is to use
     * the value of the method pointer containing the trace as the filterKey.
     * Intuitively, this is saying that once any trace in a method appears hot,
     * immediately translate any other trace from that same method that
     * survives the first-level filter.  Here, filterKey would be defined as:
     *     intptr_t filterKey = (intptr_t)self->interpSave.method
     *
     * The problem is that we can't easily detect whether we're dealing
     * with a spiky or flat profile.  If we go with the "pc" match approach,
     * flat profiles perform poorly.  If we go with the loose "method" match,
     * we end up generating a lot of useless translations.  Probably the
     * best approach in the future will be to retain profile information
     * across runs of each application in order to determine it's profile,
     * and then choose once we have enough history.
     *
     * However, for now we've decided to chose a compromise filter scheme that
     * includes elements of both.  The high order bits of the filter key
     * are drawn from the enclosing method, and are combined with a slice
     * of the low-order bits of the Dalvik pc of the trace head.  The
     * looseness of the filter can be adjusted by changing with width of
     * the Dalvik pc slice (JIT_TRACE_THRESH_FILTER_PC_BITS).  The wider
     * the slice, the tighter the filter.
     *
     * Note: the fixed shifts in the function below reflect assumed word
     * alignment for method pointers, and half-word alignment of the Dalvik pc.
     * for method pointers and half-word alignment for dalvik pc.
     */
	
	/*
	 * 将函数指针 | PC寄存器指针 的值合成一个 过滤关键值
	 */

	/* method的值向右移动30位，取末尾两位到32位数的高地址 */
    u4 methodKey = (u4)self->interpSave.method <<
                   (JIT_TRACE_THRESH_FILTER_PC_BITS - 2);
	/* 当前的PC指针向左移动1位，取PC指针的31位 然后取这31位的低6位 */
    u4 pcKey = ((u4)self->interpSave.pc >> 1) &
               ((1 << JIT_TRACE_THRESH_FILTER_PC_BITS) - 1);
    intptr_t filterKey = (intptr_t)(methodKey | pcKey);				/* 过滤关键值 */

    // Shouldn't be here if already building a trace.
	/* 如果已经编译一个trace应该断言不会失败  */
    assert((self->interpBreak.ctl.subMode & kSubModeJitTraceBuild)==0);

    /* Check if the JIT request can be handled now */
	/* 检查JIT请求现在能被处理 */

	/*
	 * 这里至少保证了一个地址的请求要出现两次。第一次没有在过滤器表中则随机设置到一个槽中
	 * 然后直接设置kJitDone返回，如果第二次出现则清空当前的槽，然后将这个地址放入到JIT表中
	 */
    if ((gDvmJit.pJitEntryTable != NULL) &&
        ((self->interpBreak.ctl.breakFlags & kInterpSingleStep) == 0)){				/* 从这里可以看出当为单步运行时不能进行运行 */
        /* Bypass the filter for hot trace requests or during stress mode */
		/* 存在请求 */
        if (self->jitState == kJitTSelectRequest &&
            gDvmJit.threshold > 6) {		/* 阀值大于6 */
            /* Two-level filtering scheme */
			/* 第二个级别的过滤语法 */
            for (i=0; i< JIT_TRACE_THRESH_FILTER_SIZE; i++) {
				/* 如果找到了则清0 */
                if (filterKey == self->threshFilter[i]) {
                    self->threshFilter[i] = 0; // Reset filter entry
                    break;
                }
            }
			/* 达到末尾，表示没有找到过滤器，则添加 */
            if (i == JIT_TRACE_THRESH_FILTER_SIZE) {
                /*
                 * Use random replacement policy - otherwise we could miss a
                 * large loop that contains more traces than the size of our
                 * filter array.
                 */
				/* 采用随机规则 - 设置过滤关键值 */
                i = rand() % JIT_TRACE_THRESH_FILTER_SIZE;
                self->threshFilter[i] = filterKey;
                self->jitState = kJitDone;
            }
        }

        /* If the compiler is backlogged, cancel any JIT actions */
		/* 如果编译队列的数量过大则放弃编译动作 */
        if (gDvmJit.compilerQueueLength >= gDvmJit.compilerHighWater) {
            self->jitState = kJitDone;
        }

        /*
         * Check for additional reasons that might force the trace select
         * request to be dropped
         */
		/*
		 * 检查附加条件强行放弃掉一个trace选择请求
		 *
		 * 当前状态是“选择请求”
		 * 检查当前解释器运行的指针是否已经JIT编译，如果经过编译则什么也不做
		 * 如果没有找到则添加如果添加失败则结束请求
		 */
        if (self->jitState == kJitTSelectRequest ||
            self->jitState == kJitTSelectRequestHot) {
            if (dvmJitFindEntry(self->interpSave.pc, false)) {
                /* In progress - nothing do do */
               self->jitState = kJitDone;
            } else {
                JitEntry *slot = lookupAndAdd(self->interpSave.pc,
                                              false /* lock */,
                                              false /* method entry */);
                if (slot == NULL) {
                    /*
                     * Table is full.  This should have been
                     * detected by the compiler thread and the table
                     * resized before we run into it here.  Assume bad things
                     * are afoot and disable profiling.
                     */
                    self->jitState = kJitDone;
                    ALOGD("JIT: JitTable full, disabling profiling");
                    dvmJitStopTranslationRequests();
                }
            }
        }

		/* 检查请求，如果是选定请求则准备编译数据 */
        switch (self->jitState) {
            case kJitTSelectRequest:
            case kJitTSelectRequestHot:
                self->jitState = kJitTSelect;
                self->traceMethod = self->interpSave.method;
                self->currTraceHead = self->interpSave.pc;
                self->currTraceRun = 0;
                self->totalTraceLen = 0;
                self->currRunHead = self->interpSave.pc;
                self->currRunLen = 0;
                self->trace[0].info.frag.startOffset =
                     self->interpSave.pc - self->interpSave.method->insns;
                self->trace[0].info.frag.numInsts = 0;
                self->trace[0].info.frag.runEnd = false;
                self->trace[0].info.frag.hint = kJitHintNone;
                self->trace[0].isCode = true;
                self->lastPC = 0;
                /* Turn on trace selection mode */
				/* 开启trace编译状态 */
                dvmEnableSubMode(self, kSubModeJitTraceBuild);
#if defined(SHOW_TRACE)
                ALOGD("Starting trace for %s at %#x",
                     self->interpSave.method->name, (int)self->interpSave.pc);
#endif
                break;
            case kJitDone:
                break;
            default:
                ALOGE("Unexpected JIT state: %d", self->jitState);
                dvmAbort();
        }
    } else {
        /* Cannot build trace this time */
        self->jitState = kJitDone;
    }
}

/*
 * Resizes the JitTable.  Must be a power of 2, and returns true on failure.
 * Stops all threads, and thus is a heavyweight operation. May only be called
 * by the compiler thread.
 */
/**
 * @brief 重新设置JTI表的大小
 * @param size 表的大小，必须是2的次方
 * @retval 1 表示失败
 * @retval 0 表示成功
 */
bool dvmJitResizeJitTable( unsigned int size )
{
    JitEntry *pNewTable;
    JitEntry *pOldTable;
    JitEntry tempEntry;
    unsigned int oldSize;
    unsigned int i;

    assert(gDvmJit.pJitEntryTable != NULL);
    assert(size && !(size & (size - 1)));   /* Is power of 2? */

    ALOGI("Jit: resizing JitTable from %d to %d", gDvmJit.jitTableSize, size);

    if (size <= gDvmJit.jitTableSize) {
        return true;
    }

    /* Make sure requested size is compatible with chain field width */
    tempEntry.u.info.chain = size;
    if (tempEntry.u.info.chain != size) {
        ALOGD("Jit: JitTable request of %d too big", size);
        return true;
    }

	/* 分配一块内存 */
    pNewTable = (JitEntry*)calloc(size, sizeof(*pNewTable));
    if (pNewTable == NULL) {
        return true;
    }
    for (i=0; i< size; i++) {
        pNewTable[i].u.info.chain = size;  /* Initialize chain termination */
    }

    /* Stop all other interpreting/jit'ng threads */
	/* 挂起所有线程 */
    dvmSuspendAllThreads(SUSPEND_FOR_TBL_RESIZE);

    pOldTable = gDvmJit.pJitEntryTable;
    oldSize = gDvmJit.jitTableSize;

    dvmLockMutex(&gDvmJit.tableLock);
    gDvmJit.pJitEntryTable = pNewTable;
    gDvmJit.jitTableSize = size;
    gDvmJit.jitTableMask = size - 1;
    gDvmJit.jitTableEntriesUsed = 0;

	/* 将旧的值复制到新的表中 */
    for (i=0; i < oldSize; i++) {
        if (pOldTable[i].dPC) {
            JitEntry *p;
            u2 chain;
            p = lookupAndAdd(pOldTable[i].dPC, true /* holds tableLock*/,
                             pOldTable[i].u.info.isMethodEntry);
            p->codeAddress = pOldTable[i].codeAddress;
            /* We need to preserve the new chain field, but copy the rest */
            chain = p->u.info.chain;
            p->u = pOldTable[i].u;
            p->u.info.chain = chain;
        }
    }

    dvmUnlockMutex(&gDvmJit.tableLock);

    free(pOldTable);

    /* Restart the world */
    dvmResumeAllThreads(SUSPEND_FOR_TBL_RESIZE);

    return false;
}

/*
 * Reset the JitTable to the initial clean state.
 */
/**
 * @brief 重新JIT表
 * @note 被"vm/compiler/Compiler.cpp"resetCodeCache函数调用
 */
void dvmJitResetTable()
{
    JitEntry *jitEntry = gDvmJit.pJitEntryTable;
    unsigned int size = gDvmJit.jitTableSize;
    unsigned int i;

    dvmLockMutex(&gDvmJit.tableLock);

    /* Note: If need to preserve any existing counts. Do so here. */
	/* 如果需要保存存在的计数器, 这里做的是清0的操作 */
    if (gDvmJit.pJitTraceProfCounters) {
        for (i=0; i < JIT_PROF_BLOCK_BUCKETS; i++) {
            if (gDvmJit.pJitTraceProfCounters->buckets[i])
                memset((void *) gDvmJit.pJitTraceProfCounters->buckets[i],
                       0, sizeof(JitTraceCounter_t) * JIT_PROF_BLOCK_ENTRIES);
        }
        gDvmJit.pJitTraceProfCounters->next = 0;
    }

    memset((void *) jitEntry, 0, sizeof(JitEntry) * size);
    for (i=0; i< size; i++) {
        jitEntry[i].u.info.chain = size;  /* Initialize chain termination */
    }
    gDvmJit.jitTableEntriesUsed = 0;
    dvmUnlockMutex(&gDvmJit.tableLock);
}

/*
 * Return the address of the next trace profile counter.  This address
 * will be embedded in the generated code for the trace, and thus cannot
 * change while the trace exists.
 */
/**
 * @brief Jit下一个trace计数器
 * @return 返回Jit trace的数量
 */
JitTraceCounter_t *dvmJitNextTraceCounter()
{
    int idx = gDvmJit.pJitTraceProfCounters->next / JIT_PROF_BLOCK_ENTRIES;
    int elem = gDvmJit.pJitTraceProfCounters->next % JIT_PROF_BLOCK_ENTRIES;
    JitTraceCounter_t *res;
    /* Lazily allocate blocks of counters */
	/* 如果当前的idx所在为0 */
    if (!gDvmJit.pJitTraceProfCounters->buckets[idx]) {
        JitTraceCounter_t *p =
              (JitTraceCounter_t*) calloc(JIT_PROF_BLOCK_ENTRIES, sizeof(*p));
        if (!p) {
            ALOGE("Failed to allocate block of trace profile counters");
            dvmAbort();
        }
        gDvmJit.pJitTraceProfCounters->buckets[idx] = p;
    }
    res = &gDvmJit.pJitTraceProfCounters->buckets[idx][elem];
    gDvmJit.pJitTraceProfCounters->next++;
    return res;
}

/*
 * Float/double conversion requires clamping to min and max of integer form.  If
 * target doesn't support this normally, use these.
 */
/**
 * @brief 有符号double类型判断
 * @note d 大于等于 0x7fff... 则返回 0x7fff...
 *		 d 小于等于 0x8000... 则返回 0x8000...
 *		 d 不等于 d 貌似不可能发生 返回0
 *		 如果是其他情况则返回 d 原值
 */
s8 dvmJitd2l(double d)
{
    static const double kMaxLong = (double)(s8)0x7fffffffffffffffULL;
    static const double kMinLong = (double)(s8)0x8000000000000000ULL;
    if (d >= kMaxLong)
        return (s8)0x7fffffffffffffffULL;
    else if (d <= kMinLong)
        return (s8)0x8000000000000000ULL;
    else if (d != d) // NaN case
        return 0;
    else
        return (s8)d;
}

s8 dvmJitf2l(float f)
{
    static const float kMaxLong = (float)(s8)0x7fffffffffffffffULL;
    static const float kMinLong = (float)(s8)0x8000000000000000ULL;
    if (f >= kMaxLong)
        return (s8)0x7fffffffffffffffULL;
    else if (f <= kMinLong)
        return (s8)0x8000000000000000ULL;
    else if (f != f) // NaN case
        return 0;
    else
        return (s8)f;
}

/* Should only be called by the compiler thread */
/**
 * @brief 改变Profile模式 
 * @param newState 新的状态
 * @note 被编译器线程调用
 */
void dvmJitChangeProfileMode(TraceProfilingModes newState)
{
    if (gDvmJit.profileMode != newState) {
		/* 设置新的状态 */
        gDvmJit.profileMode = newState;
        dvmJitUnchainAll();   /* 解除所有链接 */
    }
}

/**
 * @brief trace profiling开启
 */
void dvmJitTraceProfilingOn()
{
    if (gDvmJit.profileMode == kTraceProfilingPeriodicOff)
        dvmCompilerForceWorkEnqueue(NULL, kWorkOrderProfileMode,
                                    (void*) kTraceProfilingPeriodicOn);
    else if (gDvmJit.profileMode == kTraceProfilingDisabled)
        dvmCompilerForceWorkEnqueue(NULL, kWorkOrderProfileMode,
                                    (void*) kTraceProfilingContinuous);
}

/**
 * @brief trace profiling关闭
 */
void dvmJitTraceProfilingOff()
{
	/* kTraceProfilingPeriodicOn == kTraceProfilingPeriodicOff */
    if (gDvmJit.profileMode == kTraceProfilingPeriodicOn)
        dvmCompilerForceWorkEnqueue(NULL, kWorkOrderProfileMode,
                                    (void*) kTraceProfilingPeriodicOff);
	/* kTraceProfilingContinuous == kTraceProfilingDisabled */
    else if (gDvmJit.profileMode == kTraceProfilingContinuous)
        dvmCompilerForceWorkEnqueue(NULL, kWorkOrderProfileMode,
                                    (void*) kTraceProfilingDisabled);
}

/*
 * Update JIT-specific info in Thread structure for a single thread
 */
/**
 * @brief 更新JIT指定信息在一个线程结构
 * @param thread 线程结构
 */
void dvmJitUpdateThreadStateSingle(Thread* thread)
{
    thread->pJitProfTable = gDvmJit.pProfTable;
    thread->jitThreshold = gDvmJit.threshold;
}

/*
 * Walk through the thread list and refresh all local copies of
 * JIT global state (which was placed there for fast access).
 */
/**
 * @brief 更新线程的所有JIT状态
 */
void dvmJitUpdateThreadStateAll()
{
    Thread* self = dvmThreadSelf();
    Thread* thread;

    dvmLockThreadList(self);
    for (thread = gDvm.threadList; thread != NULL; thread = thread->next) {
        dvmJitUpdateThreadStateSingle(thread);
    }
    dvmUnlockThreadList();

}
#endif /* WITH_JIT */
