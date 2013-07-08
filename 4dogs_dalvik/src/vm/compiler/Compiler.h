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

#ifndef DALVIK_VM_COMPILER_H_
#define DALVIK_VM_COMPILER_H_

#include <setjmp.h>
#include "Thread.h"

/*
 * Uncomment the following to enable JIT signature breakpoint
 * #define SIGNATURE_BREAKPOINT
 */

#define COMPILER_WORK_QUEUE_SIZE        100			/* 订单队列数量 */
#define COMPILER_IC_PATCH_QUEUE_SIZE    64
#define COMPILER_PC_OFFSET_SIZE         100

/* Architectural-independent parameters for predicted chains */
#define PREDICTED_CHAIN_CLAZZ_INIT       0
#define PREDICTED_CHAIN_METHOD_INIT      0
#define PREDICTED_CHAIN_COUNTER_INIT     0
/* A fake value which will avoid initialization and won't match any class */
#define PREDICTED_CHAIN_FAKE_CLAZZ       0xdeadc001
/* Has to be positive */
#define PREDICTED_CHAIN_COUNTER_AVOID    0x7fffffff
/* Rechain after this many misses - shared globally and has to be positive */
#define PREDICTED_CHAIN_COUNTER_RECHAIN  8192

#define COMPILER_TRACED(X)
#define COMPILER_TRACEE(X)
#define COMPILER_TRACE_CHAINING(X)

/* Macro to change the permissions applied to a chunk of the code cache */
#define PROTECT_CODE_CACHE_ATTRS       (PROT_READ | PROT_EXEC)
#define UNPROTECT_CODE_CACHE_ATTRS     (PROT_READ | PROT_EXEC | PROT_WRITE)

/* Acquire the lock before removing PROT_WRITE from the specified mem region */
#define UNPROTECT_CODE_CACHE(addr, size)                                       \
    {                                                                          \
        dvmLockMutex(&gDvmJit.codeCacheProtectionLock);                        \
        mprotect((void *) (((intptr_t) (addr)) & ~gDvmJit.pageSizeMask),       \
                 (size) + (((intptr_t) (addr)) & gDvmJit.pageSizeMask),        \
                 (UNPROTECT_CODE_CACHE_ATTRS));                                \
    }

/* Add the PROT_WRITE to the specified memory region then release the lock */
#define PROTECT_CODE_CACHE(addr, size)                                         \
    {                                                                          \
        mprotect((void *) (((intptr_t) (addr)) & ~gDvmJit.pageSizeMask),       \
                 (size) + (((intptr_t) (addr)) & gDvmJit.pageSizeMask),        \
                 (PROTECT_CODE_CACHE_ATTRS));                                  \
        dvmUnlockMutex(&gDvmJit.codeCacheProtectionLock);                      \
    }

#define SINGLE_STEP_OP(opcode)                                                 \
    (gDvmJit.includeSelectedOp !=                                              \
     ((gDvmJit.opList[opcode >> 3] & (1 << (opcode & 0x7))) != 0))

/**
 * @brief 指令集合类型
 * @note 描述了要将dalvik字节码编译到哪种硬件平台
 */
typedef enum JitInstructionSetType {
    DALVIK_JIT_NONE = 0,
    DALVIK_JIT_ARM,
    DALVIK_JIT_THUMB,
    DALVIK_JIT_THUMB2,
    DALVIK_JIT_IA32,
    DALVIK_JIT_MIPS
} JitInstructionSetType;

/* Description of a compiled trace. */
/**
 * @brief trace编译完成的描述
 * @note 用于存放编译完成后的结果
 */
typedef struct JitTranslationInfo {
    void *codeAddress;						/* 已编译的代码地址 */
    JitInstructionSetType instructionSet;	/* 硬件平台类型 */
    int profileCodeSize;					/* profile代码长度 */
	/* 丢弃结果 */
    bool discardResult;         // Used for debugging divergence and IC patching
	/* 不能编译整个函数 */
    bool methodCompilationAborted;  // Cannot compile the whole method
	/* debug时需要的支持线程 */
    Thread *requestingThread;   // For debugging purpose
	/* 标记trace请求 */
    int cacheVersion;           // Used to identify stale trace requests
} JitTranslationInfo;

/**
 * @brief 编译订单的类型
 * @note 表明一个订单是否有效，是method还是trace，或者更改profiling的类型
 */
typedef enum WorkOrderKind {
	/* 无效的订单 */
    kWorkOrderInvalid = 0,      // Should never see by the backend
	/* method方式 */
    kWorkOrderMethod = 1,       // Work is to compile a whole method
	/* trace方式 */
    kWorkOrderTrace = 2,        // Work is to compile code fragment(s)
	/* 在调试代码的trace模式下 */
    kWorkOrderTraceDebug = 3,   // Work is to compile/debug code fragment(s)
	/* 改变profiling模式 */
    kWorkOrderProfileMode = 4,  // Change profiling mode
} WorkOrderKind;

/**
 * @brief 编译工作的订单
 */
typedef struct CompilerWorkOrder {
    const u2* pc;					/* dalvik字节码指针 */
    WorkOrderKind kind;				/* 订单的类型 */
    void* info;						/* 订单的说明信息 */
    JitTranslationInfo result;		/* 编译代码的结果 */
    jmp_buf *bailPtr;				/* 用于异常处理的jmp_buf指针 */
} CompilerWorkOrder;

/* Chain cell for predicted method invocation */
typedef struct PredictedChainingCell {
    u4 branch;                  /* Branch to chained destination */
#ifdef __mips__
    u4 delay_slot;              /* nop goes here */
#elif defined(ARCH_IA32)
    u4 branch2;                 /* IA32 branch instr may be > 32 bits */
#endif
    const ClassObject *clazz;   /* key for prediction */
    const Method *method;       /* to lookup native PC from dalvik PC */
    const ClassObject *stagedClazz;   /* possible next key for prediction */
} PredictedChainingCell;

/* Work order for inline cache patching */
typedef struct ICPatchWorkOrder {
    PredictedChainingCell *cellAddr;    /* Address to be patched */
    PredictedChainingCell cellContent;  /* content of the new cell */
	/* 类描述 */
    const char *classDescriptor;        /* Descriptor of the class object */
	/* 类对象指针 */
    Object *classLoader;                /* Class loader */
	/* serial number */
    u4 serialNumber;                    /* Serial # (for verification only) */
} ICPatchWorkOrder;

/*
 * Trace description as will appear in the translation cache.  Note
 * flexible array at end, as these will be of variable size.  To
 * conserve space in the translation cache, total length of JitTraceRun
 * array must be recomputed via seqential scan if needed.
 */
/**
 * @brief Jit trace的描述符号
 */
typedef struct {
    const Method* method;		/* 函数体 */
	/* trace描述符号 */
    JitTraceRun trace[0];       // Variable-length trace descriptors
} JitTraceDescription;

/**
 * @brief Jit函数属性
 */
typedef enum JitMethodAttributes {
	/* 代码是被调用者的一部分（被一个热点路径调用） */
    kIsCallee = 0,      /* Code is part of a callee (invoked by a hot trace) */
	/* 代码是热点的一部分 */
    kIsHot,             /* Code is part of a hot trace */
	/* 函数是叶子节点 */
    kIsLeaf,            /* Method is leaf */
	/* 函数是空的 */	
    kIsEmpty,           /* Method is empty */
	/* 函数不抛出异常 */
    kIsThrowFree,       /* Method doesn't throw */
	/* 函数是一个getter的一部分 */
    kIsGetter,          /* Method fits the getter pattern */
	/* 函数是一个setter的一部分 */
    kIsSetter,          /* Method fits the setter pattern */
	/* 函数不能被编译 */
    kCannotCompile,     /* Method cannot be compiled */
} JitMethodAttributes;

#define METHOD_IS_CALLEE        (1 << kIsCallee)
#define METHOD_IS_HOT           (1 << kIsHot)
#define METHOD_IS_LEAF          (1 << kIsLeaf)
#define METHOD_IS_EMPTY         (1 << kIsEmpty)
#define METHOD_IS_THROW_FREE    (1 << kIsThrowFree)
#define METHOD_IS_GETTER        (1 << kIsGetter)
#define METHOD_IS_SETTER        (1 << kIsSetter)
#define METHOD_CANNOT_COMPILE   (1 << kCannotCompile)

/* Vectors to provide optimization hints */
typedef enum JitOptimizationHints {
    kJitOptNoLoop = 0,          // Disable loop formation/optimization
} JitOptimizationHints;

#define JIT_OPT_NO_LOOP         (1 << kJitOptNoLoop)

/* Customized node traversal orders for different needs */
/**
 * @brief 数据流分析模式
 */
typedef enum DataFlowAnalysisMode {
	/* 所有的节点？什么意思？ */
    kAllNodes = 0,              // All nodes
	/* 所有节点都是可以搜索的 */
    kReachableNodes,            // All reachable nodes
	/* 深度优先 */
    kPreOrderDFSTraversal,      // Depth-First-Search / Pre-Order
    kPostOrderDFSTraversal,     // Depth-First-Search / Post-Order
    kPostOrderDOMTraversal,     // Dominator tree / Post-Order
} DataFlowAnalysisMode;

/**
 * @brief 编译时的函数状态
 */
typedef struct CompilerMethodStats {
	/* 函数体指针 */
    const Method *method;       // Used as hash entry signature
	/* dalvik字节码数量 */
    int dalvikSize;             // # of bytes for dalvik bytecodes
	/* 已经编译的dalvik字节码数量 */
    int compiledDalvikSize;     // # of compiled dalvik bytecodes
	/* 产生的本地代码数量 */
    int nativeSize;             // # of bytes for produced native code
	/* 属性 */
    int attributes;             // attribute vector
} CompilerMethodStats;

struct CompilationUnit;
struct BasicBlock;
struct SSARepresentation;
struct GrowableList;
struct JitEntry;
struct MIR;

bool dvmCompilerSetupCodeCache(void);
bool dvmCompilerArchInit(void);
void dvmCompilerArchDump(void);
bool dvmCompilerStartup(void);
void dvmCompilerShutdown(void);
void dvmCompilerForceWorkEnqueue(const u2* pc, WorkOrderKind kind, void* info);
bool dvmCompilerWorkEnqueue(const u2* pc, WorkOrderKind kind, void* info);
void *dvmCheckCodeCache(void *method);
CompilerMethodStats *dvmCompilerAnalyzeMethodBody(const Method *method,
                                                  bool isCallee);
bool dvmCompilerCanIncludeThisInstruction(const Method *method,
                                          const DecodedInstruction *insn);
bool dvmCompileMethod(const Method *method, JitTranslationInfo *info);
bool dvmCompileTrace(JitTraceDescription *trace, int numMaxInsts,
                     JitTranslationInfo *info, jmp_buf *bailPtr, int optHints);
void dvmCompilerDumpStats(void);
void dvmCompilerDrainQueue(void);
void dvmJitUnchainAll(void);
void dvmJitScanAllClassPointers(void (*callback)(void *ptr));
void dvmCompilerSortAndPrintTraceProfiles(void);
void dvmCompilerPerformSafePointChecks(void);
void dvmCompilerInlineMIR(struct CompilationUnit *cUnit,
                          JitTranslationInfo *info);
void dvmInitializeSSAConversion(struct CompilationUnit *cUnit);
int dvmConvertSSARegToDalvik(const struct CompilationUnit *cUnit, int ssaReg);
bool dvmCompilerLoopOpt(struct CompilationUnit *cUnit);
void dvmCompilerInsertBackwardChaining(struct CompilationUnit *cUnit);
void dvmCompilerNonLoopAnalysis(struct CompilationUnit *cUnit);
bool dvmCompilerFindLocalLiveIn(struct CompilationUnit *cUnit,
                                struct BasicBlock *bb);
bool dvmCompilerDoSSAConversion(struct CompilationUnit *cUnit,
                                struct BasicBlock *bb);
bool dvmCompilerDoConstantPropagation(struct CompilationUnit *cUnit,
                                      struct BasicBlock *bb);
bool dvmCompilerFindInductionVariables(struct CompilationUnit *cUnit,
                                       struct BasicBlock *bb);
/* Clear the visited flag for each BB */
bool dvmCompilerClearVisitedFlag(struct CompilationUnit *cUnit,
                                 struct BasicBlock *bb);
char *dvmCompilerGetDalvikDisassembly(const DecodedInstruction *insn,
                                      const char *note);
char *dvmCompilerFullDisassembler(const struct CompilationUnit *cUnit,
                                  const struct MIR *mir);
char *dvmCompilerGetSSAString(struct CompilationUnit *cUnit,
                              struct SSARepresentation *ssaRep);
void dvmCompilerDataFlowAnalysisDispatcher(struct CompilationUnit *cUnit,
                bool (*func)(struct CompilationUnit *, struct BasicBlock *),
                DataFlowAnalysisMode dfaMode,
                bool isIterative);
void dvmCompilerMethodSSATransformation(struct CompilationUnit *cUnit);
bool dvmCompilerBuildLoop(struct CompilationUnit *cUnit);
void dvmCompilerUpdateGlobalState(void);
JitTraceDescription *dvmCopyTraceDescriptor(const u2 *pc,
                                            const struct JitEntry *desc);
extern "C" void *dvmCompilerGetInterpretTemplate();
JitInstructionSetType dvmCompilerGetInterpretTemplateSet();
u8 dvmGetRegResourceMask(int reg);
void dvmDumpCFG(struct CompilationUnit *cUnit, const char *dirPrefix);
bool dvmIsOpcodeSupportedByJit(Opcode opcode);

#endif  // DALVIK_VM_COMPILER_H_
