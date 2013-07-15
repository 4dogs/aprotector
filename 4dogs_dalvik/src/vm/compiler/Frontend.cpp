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

#include "Dalvik.h"
#include "libdex/DexOpcodes.h"
#include "libdex/DexCatch.h"
#include "interp/Jit.h"
#include "CompilerInternals.h"
#include "Dataflow.h"

/**
 * @brief 确定当前的指针是一个有效的指令
 * @param codePtr 指向一个dalvik字节码流
 * @retval 0 不是有效指令
 * @retval 1 是有效指令
 */
static inline bool contentIsInsn(const u2 *codePtr) {
    u2 instr = *codePtr;
    Opcode opcode = (Opcode)(instr & 0xff);

    /*
     * Since the low 8-bit in metadata may look like OP_NOP, we need to check
     * both the low and whole sub-word to determine whether it is code or data.
     */
    return (opcode != OP_NOP || instr == 0);
}

/*
 * Parse an instruction, return the length of the instruction
 */
/*
 * @brief分析一条dalvik指令，并返回指令的长度
 * @param codePtr dalvik字节码流指针
 * @param decInsn 解码指令结构
 * @param printMe 是否打印调试信息
 * @return 指令长度
 */
static inline int parseInsn(const u2 *codePtr, DecodedInstruction *decInsn,
                            bool printMe)
{
    // Don't parse instruction data
    if (!contentIsInsn(codePtr)) {
        return 0;
    }

    u2 instr = *codePtr;
    Opcode opcode = dexOpcodeFromCodeUnit(instr);

    dexDecodeInstruction(codePtr, decInsn);
	/* 打印反汇编指令的信息 */
    if (printMe) {
        char *decodedString = dvmCompilerGetDalvikDisassembly(decInsn, NULL);
        ALOGD("%p: %#06x %s", codePtr, opcode, decodedString);
    }
    return dexGetWidthFromOpcode(opcode);
}

/** @brief 未知的目标 */
#define UNKNOWN_TARGET 0xffffffff

/*
 * Identify block-ending instructions and collect supplemental information
 * regarding the following instructions.
 */
/**
 * @brief 寻找基本块的边界
 * @param caller 指向调用者的函数体结构
 * @param insn MIR结构的当前指令
 * @param curOffset 在dalvik字节码指令流的偏移
 * @param target 要输出的目标在dalvik字节码指令流的偏移
 * @param isInvoke 是否是调用指令
 * @param callee 被调用者的函数体结构
 * @retval 0 失败
 * @retval 1 成功
 * @note 处理调用指令与分支指令，如果是调用指令则参数callee返回被调用函数的
 *	函数体，isInvoke为true。参数target返回跳转目标在字节码流中的偏移。
 *	如果当前指令是VOID，RETURN，THROW三种指令则不进行处理。并且target返回
 *	0xffffffff。
 */
static inline bool findBlockBoundary(const Method *caller, MIR *insn,
                                     unsigned int curOffset,
                                     unsigned int *target, bool *isInvoke,
                                     const Method **callee)
{
    switch (insn->dalvikInsn.opcode) {
        /* Target is not compile-time constant */
		/* 目标不是编译内容 */
        case OP_RETURN_VOID:
        case OP_RETURN:
        case OP_RETURN_WIDE:
        case OP_RETURN_OBJECT:
        case OP_THROW:
			/*
			 * 从这里可以看出如果指令是空指令（VOID）
			 * 返回指令（RETURN，RETURN_WIDE，RETURN_OBJECT，RETURN_OBJECT）
			 * 异常抛出指令（THROW）
			 * 都不可以进行编译
			 */
			*target = UNKNOWN_TARGET;
			break;
        case OP_INVOKE_VIRTUAL:
        case OP_INVOKE_VIRTUAL_RANGE:
        case OP_INVOKE_INTERFACE:
        case OP_INVOKE_INTERFACE_RANGE:
        case OP_INVOKE_VIRTUAL_QUICK:
        case OP_INVOKE_VIRTUAL_QUICK_RANGE:
			/*
			 * 这里是调用虚接口
			 */
            *isInvoke = true;
            break;
        case OP_INVOKE_SUPER:
        case OP_INVOKE_SUPER_RANGE: {
			/*
			 * 这里是调用父类
			 */
            int mIndex = caller->clazz->pDvmDex->
                pResMethods[insn->dalvikInsn.vB]->methodIndex;			/* 从DEX文件头中的函数常量池中取出父类的函数ID */
            const Method *calleeMethod =
                caller->clazz->super->vtable[mIndex];					/* 通过类ID从调用者的虚表中取出函数结构 */

			
			/* 如果是native函数，应该是通过JNI接口调用的 */
            if (calleeMethod && !dvmIsNativeMethod(calleeMethod)) {
                *target = (unsigned int) calleeMethod->insns;
            }
            *isInvoke = true;
            *callee = calleeMethod;
            break;
        }
        case OP_INVOKE_STATIC:
        case OP_INVOKE_STATIC_RANGE: {
			/* 调用静态方法 */
            const Method *calleeMethod =
                caller->clazz->pDvmDex->pResMethods[insn->dalvikInsn.vB];

            if (calleeMethod && !dvmIsNativeMethod(calleeMethod)) {
                *target = (unsigned int) calleeMethod->insns;
            }
            *isInvoke = true;
            *callee = calleeMethod;
            break;
        }
        case OP_INVOKE_SUPER_QUICK:
        case OP_INVOKE_SUPER_QUICK_RANGE: {
			/* 调用父类函数 */
            const Method *calleeMethod =
                caller->clazz->super->vtable[insn->dalvikInsn.vB];

            if (calleeMethod && !dvmIsNativeMethod(calleeMethod)) {
                *target = (unsigned int) calleeMethod->insns;
            }
            *isInvoke = true;
            *callee = calleeMethod;
            break;
        }
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_DIRECT_RANGE: {
			/* 直接调用函数 */
            const Method *calleeMethod =
                caller->clazz->pDvmDex->pResMethods[insn->dalvikInsn.vB];
            if (calleeMethod && !dvmIsNativeMethod(calleeMethod)) {
                *target = (unsigned int) calleeMethod->insns;
            }
            *isInvoke = true;
            *callee = calleeMethod;
            break;
        }
        case OP_GOTO:
        case OP_GOTO_16:
        case OP_GOTO_32:
			/* GOTO指令 */
            *target = curOffset + (int) insn->dalvikInsn.vA;
            break;

        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE:
			/* IF指令 */
            *target = curOffset + (int) insn->dalvikInsn.vC;
            break;

        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ:
			/* IF指令不等于的情况 */
            *target = curOffset + (int) insn->dalvikInsn.vB;
            break;

        default:
            return false;
    }
    return true;
}

/**
 * @brief 确定一条指令是GOTO指令
 */
static inline bool isGoto(MIR *insn)
{
    switch (insn->dalvikInsn.opcode) {
        case OP_GOTO:
        case OP_GOTO_16:
        case OP_GOTO_32:
            return true;
        default:
            return false;
    }
}

/*
 * Identify unconditional branch instructions
 */
/**
 * @brief 确实是否是一个无条件的分支指令
 * @param insn指向MIR结构指针
 * @retval 0 不是无条件的分支指令
 * @retval 1 是无条件的分支指令
 * @note 如果是RETURN指令则返回true，以及Goto指令返回true
 */
static inline bool isUnconditionalBranch(MIR *insn)
{
    switch (insn->dalvikInsn.opcode) {
        case OP_RETURN_VOID:
        case OP_RETURN:
        case OP_RETURN_WIDE:
        case OP_RETURN_OBJECT:
            return true;
        default:
            return isGoto(insn);
    }
}

/*
 * dvmHashTableLookup() callback
 */
/**
 * @brief dvmHashtableLoopup函数的回调函数用于比较两个函数的大小
 */
static int compareMethod(const CompilerMethodStats *m1,
                         const CompilerMethodStats *m2)
{
    return (int) m1->method - (int) m2->method;
}

/*
 * Analyze the body of the method to collect high-level information regarding
 * inlining:
 * - is empty method?
 * - is getter/setter?
 * - can throw exception?
 *
 * Currently the inliner only handles getters and setters. When its capability
 * becomes more sophisticated more information will be retrieved here.
 */
/**
 * @brief 分析函数体
 * @note 1.是否是一个空的函数？2.是否是getter/setter(JAVA语言中的东西)？是否抛出一个异常？
 */
static int analyzeInlineTarget(DecodedInstruction *dalvikInsn, int attributes,
                               int offset)
{
    int flags = dexGetFlagsFromOpcode(dalvikInsn->opcode);
    int dalvikOpcode = dalvikInsn->opcode;

    if (flags & kInstrInvoke) {
        attributes &= ~METHOD_IS_LEAF;
    }

    if (!(flags & kInstrCanReturn)) {
        if (!(dvmCompilerDataFlowAttributes[dalvikOpcode] &
              DF_IS_GETTER)) {
            attributes &= ~METHOD_IS_GETTER;
        }
        if (!(dvmCompilerDataFlowAttributes[dalvikOpcode] &
              DF_IS_SETTER)) {
            attributes &= ~METHOD_IS_SETTER;
        }
    }

    /*
     * The expected instruction sequence is setter will never return value and
     * getter will also do. Clear the bits if the behavior is discovered
     * otherwise.
     */
    if (flags & kInstrCanReturn) {
        if (dalvikOpcode == OP_RETURN_VOID) {
            attributes &= ~METHOD_IS_GETTER;
        }
        else {
            attributes &= ~METHOD_IS_SETTER;
        }
    }

    if (flags & kInstrCanThrow) {
        attributes &= ~METHOD_IS_THROW_FREE;
    }

    if (offset == 0 && dalvikOpcode == OP_RETURN_VOID) {
        attributes |= METHOD_IS_EMPTY;
    }

    /*
     * Check if this opcode is selected for single stepping.
     * If so, don't inline the callee as there is no stack frame for the
     * interpreter to single-step through the instruction.
     */
    if (SINGLE_STEP_OP(dalvikOpcode)) {
        attributes &= ~(METHOD_IS_GETTER | METHOD_IS_SETTER);
    }

    return attributes;
}

/*
 * Analyze each method whose traces are ever compiled. Collect a variety of
 * statistics like the ratio of exercised vs overall code and code bloat
 * ratios. If isCallee is true, also analyze each instruction in more details
 * to see if it is suitable for inlining.
 */
/**
 * @brief 分析函数统计信息
 * @param method 函数体指针
 * @param isCallee 是否是被调用者
 * @return 返回一个函数状态结构指针
 */
CompilerMethodStats *dvmCompilerAnalyzeMethodBody(const Method *method,
                                                  bool isCallee)
{
    const DexCode *dexCode = dvmGetMethodCode(method);					/* 获取函数的代码结构 */
    const u2 *codePtr = dexCode->insns;									/* 代码体指针 */
    const u2 *codeEnd = dexCode->insns + dexCode->insnsSize;			/* 代码体末尾 */
    int insnSize = 0;
    int hashValue = dvmComputeUtf8Hash(method->name);					/* 函数名的HASH值 */

    CompilerMethodStats dummyMethodEntry; // For hash table lookup
    CompilerMethodStats *realMethodEntry; // For hash table storage

    /* For lookup only */
	/* 在虚拟机HASH表中找寻函数 */
    dummyMethodEntry.method = method;
    realMethodEntry = (CompilerMethodStats *)
		/* dvmHashTableLoopup在"vm/Hash.cpp"中实现 */
        dvmHashTableLookup(gDvmJit.methodStatsTable,
                           hashValue,
                           &dummyMethodEntry,
                           (HashCompareFunc) compareMethod,
                           false);

    /* This method has never been analyzed before - create an entry */
	/* 如果没有找到，realMethodEntry为空则分配一个，并且插入 */
    if (realMethodEntry == NULL) {
        realMethodEntry =
            (CompilerMethodStats *) calloc(1, sizeof(CompilerMethodStats));
        realMethodEntry->method = method;

        dvmHashTableLookup(gDvmJit.methodStatsTable, hashValue,
                           realMethodEntry,
                           (HashCompareFunc) compareMethod,
                           true);
    }

    /* This method is invoked as a callee and has been analyzed - just return */
	/* 如果要分析的函数是被调用者则直接返回 */
    if ((isCallee == true) && (realMethodEntry->attributes & METHOD_IS_CALLEE))
        return realMethodEntry;

    /*
     * Similarly, return if this method has been compiled before as a hot
     * method already.
     */
	/* 如果是调用者并且已经作为一个热点被编译过则直接返回*/
    if ((isCallee == false) &&
        (realMethodEntry->attributes & METHOD_IS_HOT))
        return realMethodEntry;

    int attributes;

    /* Method hasn't been analyzed for the desired purpose yet */
	/* 对被调用者与调用者分别设置属性 */
    if (isCallee) {
        /* Aggressively set the attributes until proven otherwise */
        attributes = METHOD_IS_LEAF | METHOD_IS_THROW_FREE | METHOD_IS_CALLEE |
                     METHOD_IS_GETTER | METHOD_IS_SETTER;
    } else {
        attributes = METHOD_IS_HOT;
    }

    /* Count the number of instructions */
	/* 统计指令数量 */
    while (codePtr < codeEnd) {
        DecodedInstruction dalvikInsn;
        int width = parseInsn(codePtr, &dalvikInsn, false);		/* 获取指令长度 */

        /* Terminate when the data section is seen */
		/* 如果指令长度为0跳出循环 */
        if (width == 0)
            break;

        if (isCallee) {
			/* 如果是被调用者 */
            attributes = analyzeInlineTarget(&dalvikInsn, attributes, insnSize);
        }

        insnSize += width;			/* 指令的总长度 */
        codePtr += width;			/* 指针递增 */
    }

    /*
     * Only handle simple getters/setters with one instruction followed by
     * return
     */
	/*
	 * 仅处理简单的 getters/setters 只有一条return指令的情况
	 */
    if ((attributes & (METHOD_IS_GETTER | METHOD_IS_SETTER)) &&
        (insnSize != 3)) {
		/* 取消掉getter/setter属性 */
        attributes &= ~(METHOD_IS_GETTER | METHOD_IS_SETTER);
    }

    realMethodEntry->dalvikSize = insnSize * 2;
    realMethodEntry->attributes |= attributes;

#if 0
    /* Uncomment the following to explore various callee patterns */
    if (attributes & METHOD_IS_THROW_FREE) {
        ALOGE("%s%s is inlinable%s", method->clazz->descriptor, method->name,
             (attributes & METHOD_IS_EMPTY) ? " empty" : "");
    }

    if (attributes & METHOD_IS_LEAF) {
        ALOGE("%s%s is leaf %d%s", method->clazz->descriptor, method->name,
             insnSize, insnSize < 5 ? " (small)" : "");
    }

    if (attributes & (METHOD_IS_GETTER | METHOD_IS_SETTER)) {
        ALOGE("%s%s is %s", method->clazz->descriptor, method->name,
             attributes & METHOD_IS_GETTER ? "getter": "setter");
    }
    if (attributes ==
        (METHOD_IS_LEAF | METHOD_IS_THROW_FREE | METHOD_IS_CALLEE)) {
        ALOGE("%s%s is inlinable non setter/getter", method->clazz->descriptor,
             method->name);
    }
#endif

    return realMethodEntry;
}

/*
 * Crawl the stack of the thread that requesed compilation to see if any of the
 * ancestors are on the blacklist.
 */
/**
 * @brief 通过查看dalvik的栈空间来找寻函数
 * @param thread 当前线程结构
 * @param curMethodName 要找寻函数的名称
 */
static bool filterMethodByCallGraph(Thread *thread, const char *curMethodName)
{
    /* Crawl the Dalvik stack frames and compare the method name*/
	/* 查看dalvik栈帧并且寻找函数名称 */
    StackSaveArea *ssaPtr = ((StackSaveArea *) thread->interpSave.curFrame) - 1;
    while (ssaPtr != ((StackSaveArea *) NULL) - 1) { /* ssaPtr 不等于 0xffffffff */
        const Method *method = ssaPtr->method;		/* 获取在栈上的方法结构体 */
        if (method) {
			/* 在HASH表中查找 */
            int hashValue = dvmComputeUtf8Hash(method->name);
            bool found =
                dvmHashTableLookup(gDvmJit.methodTable, hashValue,
                               (char *) method->name,
                               (HashCompareFunc) strcmp, false) !=
                NULL;
            if (found) {
                ALOGD("Method %s (--> %s) found on the JIT %s list",
                     method->name, curMethodName,
                     gDvmJit.includeSelectedMethod ? "white" : "black");
                return true;
            }

        }
        ssaPtr = ((StackSaveArea *) ssaPtr->prevFrame) - 1;
    };
    return false;
}

/*
 * Since we are including instructions from possibly a cold method into the
 * current trace, we need to make sure that all the associated information
 * with the callee is properly initialized. If not, we punt on this inline
 * target.
 *
 * TODO: volatile instructions will be handled later.
 */
bool dvmCompilerCanIncludeThisInstruction(const Method *method,
                                          const DecodedInstruction *insn)
{
    switch (insn->opcode) {
        case OP_NEW_INSTANCE:
        case OP_CHECK_CAST: {
            ClassObject *classPtr = (ClassObject *)(void*)
              (method->clazz->pDvmDex->pResClasses[insn->vB]);

            /* Class hasn't been initialized yet */
            if (classPtr == NULL) {
                return false;
            }
            return true;
        }
        case OP_SGET:
        case OP_SGET_WIDE:
        case OP_SGET_OBJECT:
        case OP_SGET_BOOLEAN:
        case OP_SGET_BYTE:
        case OP_SGET_CHAR:
        case OP_SGET_SHORT:
        case OP_SPUT:
        case OP_SPUT_WIDE:
        case OP_SPUT_OBJECT:
        case OP_SPUT_BOOLEAN:
        case OP_SPUT_BYTE:
        case OP_SPUT_CHAR:
        case OP_SPUT_SHORT: {
            void *fieldPtr = (void*)
              (method->clazz->pDvmDex->pResFields[insn->vB]);

            if (fieldPtr == NULL) {
                return false;
            }
            return true;
        }
        case OP_INVOKE_SUPER:
        case OP_INVOKE_SUPER_RANGE: {
            int mIndex = method->clazz->pDvmDex->
                pResMethods[insn->vB]->methodIndex;
            const Method *calleeMethod = method->clazz->super->vtable[mIndex];
            if (calleeMethod == NULL) {
                return false;
            }
            return true;
        }
        case OP_INVOKE_SUPER_QUICK:
        case OP_INVOKE_SUPER_QUICK_RANGE: {
            const Method *calleeMethod = method->clazz->super->vtable[insn->vB];
            if (calleeMethod == NULL) {
                return false;
            }
            return true;
        }
        case OP_INVOKE_STATIC:
        case OP_INVOKE_STATIC_RANGE:
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_DIRECT_RANGE: {
            const Method *calleeMethod =
                method->clazz->pDvmDex->pResMethods[insn->vB];
            if (calleeMethod == NULL) {
                return false;
            }
            return true;
        }
        case OP_CONST_CLASS: {
            void *classPtr = (void*)
                (method->clazz->pDvmDex->pResClasses[insn->vB]);

            if (classPtr == NULL) {
                return false;
            }
            return true;
        }
        case OP_CONST_STRING_JUMBO:
        case OP_CONST_STRING: {
            void *strPtr = (void*)
                (method->clazz->pDvmDex->pResStrings[insn->vB]);

            if (strPtr == NULL) {
                return false;
            }
            return true;
        }
        default:
            return true;
    }
}

/* Split an existing block from the specified code offset into two */
static BasicBlock *splitBlock(CompilationUnit *cUnit,
                              unsigned int codeOffset,
                              BasicBlock *origBlock,
                              BasicBlock **immedPredBlockP)
{
    MIR *insn = origBlock->firstMIRInsn;
    while (insn) {
        if (insn->offset == codeOffset) break;
        insn = insn->next;
    }
    if (insn == NULL) {
        ALOGE("Break split failed");
        dvmAbort();
    }
    BasicBlock *bottomBlock = dvmCompilerNewBB(kDalvikByteCode,
                                               cUnit->numBlocks++);
    dvmInsertGrowableList(&cUnit->blockList, (intptr_t) bottomBlock);

    bottomBlock->startOffset = codeOffset;
    bottomBlock->firstMIRInsn = insn;
    bottomBlock->lastMIRInsn = origBlock->lastMIRInsn;

    /* Handle the taken path */
    bottomBlock->taken = origBlock->taken;
    if (bottomBlock->taken) {
        origBlock->taken = NULL;
        dvmCompilerClearBit(bottomBlock->taken->predecessors, origBlock->id);
        dvmCompilerSetBit(bottomBlock->taken->predecessors, bottomBlock->id);
    }

    /* Handle the fallthrough path */
    bottomBlock->needFallThroughBranch = origBlock->needFallThroughBranch;
    bottomBlock->fallThrough = origBlock->fallThrough;
    origBlock->fallThrough = bottomBlock;
    origBlock->needFallThroughBranch = true;
    dvmCompilerSetBit(bottomBlock->predecessors, origBlock->id);
    if (bottomBlock->fallThrough) {
        dvmCompilerClearBit(bottomBlock->fallThrough->predecessors,
                            origBlock->id);
        dvmCompilerSetBit(bottomBlock->fallThrough->predecessors,
                          bottomBlock->id);
    }

    /* Handle the successor list */
    if (origBlock->successorBlockList.blockListType != kNotUsed) {
        bottomBlock->successorBlockList = origBlock->successorBlockList;
        origBlock->successorBlockList.blockListType = kNotUsed;
        GrowableListIterator iterator;

        dvmGrowableListIteratorInit(&bottomBlock->successorBlockList.blocks,
                                    &iterator);
        while (true) {
            SuccessorBlockInfo *successorBlockInfo =
                (SuccessorBlockInfo *) dvmGrowableListIteratorNext(&iterator);
            if (successorBlockInfo == NULL) break;
            BasicBlock *bb = successorBlockInfo->block;
            dvmCompilerClearBit(bb->predecessors, origBlock->id);
            dvmCompilerSetBit(bb->predecessors, bottomBlock->id);
        }
    }

    origBlock->lastMIRInsn = insn->prev;

    insn->prev->next = NULL;
    insn->prev = NULL;

    /*
     * Update the immediate predecessor block pointer so that outgoing edges
     * can be applied to the proper block.
     */
    if (immedPredBlockP) {
        assert(*immedPredBlockP == origBlock);
        *immedPredBlockP = bottomBlock;
    }
    return bottomBlock;
}

/*
 * Given a code offset, find out the block that starts with it. If the offset
 * is in the middle of an existing block, split it into two. If immedPredBlockP
 * is non-null and is the block being split, update *immedPredBlockP to point
 * to the bottom block so that outgoing edges can be setup properly (by the
 * caller).
 */
static BasicBlock *findBlock(CompilationUnit *cUnit,
                             unsigned int codeOffset,
                             bool split, bool create,
                             BasicBlock **immedPredBlockP)
{
    GrowableList *blockList = &cUnit->blockList;
    BasicBlock *bb;
    unsigned int i;

    for (i = 0; i < blockList->numUsed; i++) {
        bb = (BasicBlock *) blockList->elemList[i];
        if (bb->blockType != kDalvikByteCode) continue;
        if (bb->startOffset == codeOffset) return bb;
        /* Check if a branch jumps into the middle of an existing block */
        if ((split == true) && (codeOffset > bb->startOffset) &&
            (bb->lastMIRInsn != NULL) &&
            (codeOffset <= bb->lastMIRInsn->offset)) {
            BasicBlock *newBB = splitBlock(cUnit, codeOffset, bb,
                                           bb == *immedPredBlockP ?
                                               immedPredBlockP : NULL);
            return newBB;
        }
    }
    if (create) {
          bb = dvmCompilerNewBB(kDalvikByteCode, cUnit->numBlocks++);
          dvmInsertGrowableList(&cUnit->blockList, (intptr_t) bb);
          bb->startOffset = codeOffset;
          return bb;
    }
    return NULL;
}

/* Dump the CFG into a DOT graph */
void dvmDumpCFG(CompilationUnit *cUnit, const char *dirPrefix)
{
    const Method *method = cUnit->method;
    FILE *file;
    char *signature = dexProtoCopyMethodDescriptor(&method->prototype);
    char startOffset[80];
    sprintf(startOffset, "_%x", cUnit->entryBlock->fallThrough->startOffset);
    char *fileName = (char *) dvmCompilerNew(
                                  strlen(dirPrefix) +
                                  strlen(method->clazz->descriptor) +
                                  strlen(method->name) +
                                  strlen(signature) +
                                  strlen(startOffset) +
                                  strlen(".dot") + 1, true);
    sprintf(fileName, "%s%s%s%s%s.dot", dirPrefix,
            method->clazz->descriptor, method->name, signature, startOffset);
    free(signature);

    /*
     * Convert the special characters into a filesystem- and shell-friendly
     * format.
     */
    int i;
    for (i = strlen(dirPrefix); fileName[i]; i++) {
        if (fileName[i] == '/') {
            fileName[i] = '_';
        } else if (fileName[i] == ';') {
            fileName[i] = '#';
        } else if (fileName[i] == '$') {
            fileName[i] = '+';
        } else if (fileName[i] == '(' || fileName[i] == ')') {
            fileName[i] = '@';
        } else if (fileName[i] == '<' || fileName[i] == '>') {
            fileName[i] = '=';
        }
    }
    file = fopen(fileName, "w");
    if (file == NULL) {
        return;
    }
    fprintf(file, "digraph G {\n");

    fprintf(file, "  rankdir=TB\n");

    int numReachableBlocks = cUnit->numReachableBlocks;
    int idx;
    const GrowableList *blockList = &cUnit->blockList;

    for (idx = 0; idx < numReachableBlocks; idx++) {
        int blockIdx = cUnit->dfsOrder.elemList[idx];
        BasicBlock *bb = (BasicBlock *) dvmGrowableListGetElement(blockList,
                                                                  blockIdx);
        if (bb == NULL) break;
        if (bb->blockType == kEntryBlock) {
            fprintf(file, "  entry [shape=Mdiamond];\n");
        } else if (bb->blockType == kExitBlock) {
            fprintf(file, "  exit [shape=Mdiamond];\n");
        } else if (bb->blockType == kDalvikByteCode) {
            fprintf(file, "  block%04x [shape=record,label = \"{ \\\n",
                    bb->startOffset);
            const MIR *mir;
            fprintf(file, "    {block id %d\\l}%s\\\n", bb->id,
                    bb->firstMIRInsn ? " | " : " ");
            for (mir = bb->firstMIRInsn; mir; mir = mir->next) {
                fprintf(file, "    {%04x %s\\l}%s\\\n", mir->offset,
                        mir->ssaRep ?
                            dvmCompilerFullDisassembler(cUnit, mir) :
                            dexGetOpcodeName(mir->dalvikInsn.opcode),
                        mir->next ? " | " : " ");
            }
            fprintf(file, "  }\"];\n\n");
        } else if (bb->blockType == kExceptionHandling) {
            char blockName[BLOCK_NAME_LEN];

            dvmGetBlockName(bb, blockName);
            fprintf(file, "  %s [shape=invhouse];\n", blockName);
        }

        char blockName1[BLOCK_NAME_LEN], blockName2[BLOCK_NAME_LEN];

        if (bb->taken) {
            dvmGetBlockName(bb, blockName1);
            dvmGetBlockName(bb->taken, blockName2);
            fprintf(file, "  %s:s -> %s:n [style=dotted]\n",
                    blockName1, blockName2);
        }
        if (bb->fallThrough) {
            dvmGetBlockName(bb, blockName1);
            dvmGetBlockName(bb->fallThrough, blockName2);
            fprintf(file, "  %s:s -> %s:n\n", blockName1, blockName2);
        }

        if (bb->successorBlockList.blockListType != kNotUsed) {
            fprintf(file, "  succ%04x [shape=%s,label = \"{ \\\n",
                    bb->startOffset,
                    (bb->successorBlockList.blockListType == kCatch) ?
                        "Mrecord" : "record");
            GrowableListIterator iterator;
            dvmGrowableListIteratorInit(&bb->successorBlockList.blocks,
                                        &iterator);
            SuccessorBlockInfo *successorBlockInfo =
                (SuccessorBlockInfo *) dvmGrowableListIteratorNext(&iterator);

            int succId = 0;
            while (true) {
                if (successorBlockInfo == NULL) break;

                BasicBlock *destBlock = successorBlockInfo->block;
                SuccessorBlockInfo *nextSuccessorBlockInfo =
                  (SuccessorBlockInfo *) dvmGrowableListIteratorNext(&iterator);

                fprintf(file, "    {<f%d> %04x: %04x\\l}%s\\\n",
                        succId++,
                        successorBlockInfo->key,
                        destBlock->startOffset,
                        (nextSuccessorBlockInfo != NULL) ? " | " : " ");

                successorBlockInfo = nextSuccessorBlockInfo;
            }
            fprintf(file, "  }\"];\n\n");

            dvmGetBlockName(bb, blockName1);
            fprintf(file, "  %s:s -> succ%04x:n [style=dashed]\n",
                    blockName1, bb->startOffset);

            if (bb->successorBlockList.blockListType == kPackedSwitch ||
                bb->successorBlockList.blockListType == kSparseSwitch) {

                dvmGrowableListIteratorInit(&bb->successorBlockList.blocks,
                                            &iterator);

                succId = 0;
                while (true) {
                    SuccessorBlockInfo *successorBlockInfo =
                        (SuccessorBlockInfo *)
                            dvmGrowableListIteratorNext(&iterator);
                    if (successorBlockInfo == NULL) break;

                    BasicBlock *destBlock = successorBlockInfo->block;

                    dvmGetBlockName(destBlock, blockName2);
                    fprintf(file, "  succ%04x:f%d:e -> %s:n\n",
                            bb->startOffset, succId++,
                            blockName2);
                }
            }
        }
        fprintf(file, "\n");

        /*
         * If we need to debug the dominator tree, uncomment the following code
         */
#if 1
        dvmGetBlockName(bb, blockName1);
        fprintf(file, "  cfg%s [label=\"%s\", shape=none];\n",
                blockName1, blockName1);
        if (bb->iDom) {
            dvmGetBlockName(bb->iDom, blockName2);
            fprintf(file, "  cfg%s:s -> cfg%s:n\n\n",
                    blockName2, blockName1);
        }
#endif
    }
    fprintf(file, "}\n");
    fclose(file);
}

/* Verify if all the successor is connected with all the claimed predecessors */
static bool verifyPredInfo(CompilationUnit *cUnit, BasicBlock *bb)
{
    BitVectorIterator bvIterator;

    dvmBitVectorIteratorInit(bb->predecessors, &bvIterator);
    while (true) {
        int blockIdx = dvmBitVectorIteratorNext(&bvIterator);
        if (blockIdx == -1) break;
        BasicBlock *predBB = (BasicBlock *)
            dvmGrowableListGetElement(&cUnit->blockList, blockIdx);
        bool found = false;
        if (predBB->taken == bb) {
            found = true;
        } else if (predBB->fallThrough == bb) {
            found = true;
        } else if (predBB->successorBlockList.blockListType != kNotUsed) {
            GrowableListIterator iterator;
            dvmGrowableListIteratorInit(&predBB->successorBlockList.blocks,
                                        &iterator);
            while (true) {
                SuccessorBlockInfo *successorBlockInfo =
                    (SuccessorBlockInfo *)
                        dvmGrowableListIteratorNext(&iterator);
                if (successorBlockInfo == NULL) break;
                BasicBlock *succBB = successorBlockInfo->block;
                if (succBB == bb) {
                    found = true;
                    break;
                }
            }
        }
        if (found == false) {
            char blockName1[BLOCK_NAME_LEN], blockName2[BLOCK_NAME_LEN];
            dvmGetBlockName(bb, blockName1);
            dvmGetBlockName(predBB, blockName2);
            dvmDumpCFG(cUnit, "/sdcard/cfg/");
            ALOGE("Successor %s not found from %s",
                 blockName1, blockName2);
            dvmAbort();
        }
    }
    return true;
}

/* Identify code range in try blocks and set up the empty catch blocks */
static void processTryCatchBlocks(CompilationUnit *cUnit)
{
    const Method *meth = cUnit->method;
    const DexCode *pCode = dvmGetMethodCode(meth);
    int triesSize = pCode->triesSize;
    int i;
    int offset;

    if (triesSize == 0) {
        return;
    }

    const DexTry *pTries = dexGetTries(pCode);
    BitVector *tryBlockAddr = cUnit->tryBlockAddr;

    /* Mark all the insn offsets in Try blocks */
    for (i = 0; i < triesSize; i++) {
        const DexTry* pTry = &pTries[i];
        /* all in 16-bit units */
        int startOffset = pTry->startAddr;
        int endOffset = startOffset + pTry->insnCount;

        for (offset = startOffset; offset < endOffset; offset++) {
            dvmCompilerSetBit(tryBlockAddr, offset);
        }
    }

    /* Iterate over each of the handlers to enqueue the empty Catch blocks */
    offset = dexGetFirstHandlerOffset(pCode);
    int handlersSize = dexGetHandlersSize(pCode);

    for (i = 0; i < handlersSize; i++) {
        DexCatchIterator iterator;
        dexCatchIteratorInit(&iterator, pCode, offset);

        for (;;) {
            DexCatchHandler* handler = dexCatchIteratorNext(&iterator);

            if (handler == NULL) {
                break;
            }

            /*
             * Create dummy catch blocks first. Since these are created before
             * other blocks are processed, "split" is specified as false.
             */
            findBlock(cUnit, handler->address,
                      /* split */
                      false,
                      /* create */
                      true,
                      /* immedPredBlockP */
                      NULL);
        }

        offset = dexCatchIteratorGetEndOffset(&iterator, pCode);
    }
}

/* Process instructions with the kInstrCanBranch flag */
static void processCanBranch(CompilationUnit *cUnit, BasicBlock *curBlock,
                             MIR *insn, int curOffset, int width, int flags,
                             const u2* codePtr, const u2* codeEnd)
{
    int target = curOffset;
    switch (insn->dalvikInsn.opcode) {
        case OP_GOTO:
        case OP_GOTO_16:
        case OP_GOTO_32:
            target += (int) insn->dalvikInsn.vA;
            break;
        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE:
            target += (int) insn->dalvikInsn.vC;
            break;
        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ:
            target += (int) insn->dalvikInsn.vB;
            break;
        default:
            ALOGE("Unexpected opcode(%d) with kInstrCanBranch set",
                 insn->dalvikInsn.opcode);
            dvmAbort();
    }
    BasicBlock *takenBlock = findBlock(cUnit, target,
                                       /* split */
                                       true,
                                       /* create */
                                       true,
                                       /* immedPredBlockP */
                                       &curBlock);
    curBlock->taken = takenBlock;
    dvmCompilerSetBit(takenBlock->predecessors, curBlock->id);

    /* Always terminate the current block for conditional branches */
    if (flags & kInstrCanContinue) {
        BasicBlock *fallthroughBlock = findBlock(cUnit,
                                                 curOffset +  width,
                                                 /*
                                                  * If the method is processed
                                                  * in sequential order from the
                                                  * beginning, we don't need to
                                                  * specify split for continue
                                                  * blocks. However, this
                                                  * routine can be called by
                                                  * compileLoop, which starts
                                                  * parsing the method from an
                                                  * arbitrary address in the
                                                  * method body.
                                                  */
                                                 true,
                                                 /* create */
                                                 true,
                                                 /* immedPredBlockP */
                                                 &curBlock);
        curBlock->fallThrough = fallthroughBlock;
        dvmCompilerSetBit(fallthroughBlock->predecessors, curBlock->id);
    } else if (codePtr < codeEnd) {
        /* Create a fallthrough block for real instructions (incl. OP_NOP) */
        if (contentIsInsn(codePtr)) {
            findBlock(cUnit, curOffset + width,
                      /* split */
                      false,
                      /* create */
                      true,
                      /* immedPredBlockP */
                      NULL);
        }
    }
}

/* Process instructions with the kInstrCanSwitch flag */
static void processCanSwitch(CompilationUnit *cUnit, BasicBlock *curBlock,
                             MIR *insn, int curOffset, int width, int flags)
{
    u2 *switchData= (u2 *) (cUnit->method->insns + curOffset +
								insn->dalvikInsn.vB);
		int size;
		int *keyTable;
		int *targetTable;
		int i;
		int firstKey;

		/*
		 * Packed switch data format:
		 *  ushort ident = 0x0100   magic value
		 *  ushort size             number of entries in the table
		 *  int first_key           first (and lowest) switch case value
		 *  int targets[size]       branch targets, relative to switch opcode
		 *
		 * Total size is (4+size*2) 16-bit code units.
		 */
		if (insn->dalvikInsn.opcode == OP_PACKED_SWITCH) {
			assert(switchData[0] == kPackedSwitchSignature);
			size = switchData[1];
			firstKey = switchData[2] | (switchData[3] << 16);
			targetTable = (int *) &switchData[4];
			keyTable = NULL;        // Make the compiler happy
		/*
		 * Sparse switch data format:
		 *  ushort ident = 0x0200   magic value
		 *  ushort size             number of entries in the table; > 0
		 *  int keys[size]          keys, sorted low-to-high; 32-bit aligned
		 *  int targets[size]       branch targets, relative to switch opcode
		 *
		 * Total size is (2+size*4) 16-bit code units.
		 */
		} else {
			assert(switchData[0] == kSparseSwitchSignature);
			size = switchData[1];
			keyTable = (int *) &switchData[2];
			targetTable = (int *) &switchData[2 + size*2];
			firstKey = 0;   // To make the compiler happy
		}

		if (curBlock->successorBlockList.blockListType != kNotUsed) {
			ALOGE("Successor block list already in use: %d",
				 curBlock->successorBlockList.blockListType);
			dvmAbort();
		}
		curBlock->successorBlockList.blockListType =
			(insn->dalvikInsn.opcode == OP_PACKED_SWITCH) ?
			kPackedSwitch : kSparseSwitch;
		dvmInitGrowableList(&curBlock->successorBlockList.blocks, size);

		for (i = 0; i < size; i++) {
			BasicBlock *caseBlock = findBlock(cUnit, curOffset + targetTable[i],
											  /* split */
											  true,
											  /* create */
											  true,
											  /* immedPredBlockP */
											  &curBlock);
			SuccessorBlockInfo *successorBlockInfo =
				(SuccessorBlockInfo *) dvmCompilerNew(sizeof(SuccessorBlockInfo),
													  false);
			successorBlockInfo->block = caseBlock;
			successorBlockInfo->key = (insn->dalvikInsn.opcode == OP_PACKED_SWITCH)?
									  firstKey + i : keyTable[i];
			dvmInsertGrowableList(&curBlock->successorBlockList.blocks,
								  (intptr_t) successorBlockInfo);
			dvmCompilerSetBit(caseBlock->predecessors, curBlock->id);
		}

		/* Fall-through case */
		BasicBlock *fallthroughBlock = findBlock(cUnit,
												 curOffset +  width,
												 /* split */
												 false,
												 /* create */
												 true,
												 /* immedPredBlockP */
												 NULL);
		curBlock->fallThrough = fallthroughBlock;
		dvmCompilerSetBit(fallthroughBlock->predecessors, curBlock->id);
	}

	/* Process instructions with the kInstrCanThrow flag */
	/**
	 * @brief 处理抛出异常指令
	 */
	static void processCanThrow(CompilationUnit *cUnit, BasicBlock *curBlock,
								MIR *insn, int curOffset, int width, int flags,
								BitVector *tryBlockAddr, const u2 *codePtr,
								const u2* codeEnd)
	{
		const Method *method = cUnit->method;
		const DexCode *dexCode = dvmGetMethodCode(method);

		/* In try block */
		if (dvmIsBitSet(tryBlockAddr, curOffset)) {
			DexCatchIterator iterator;

			if (!dexFindCatchHandler(&iterator, dexCode, curOffset)) {
				ALOGE("Catch block not found in dexfile for insn %x in %s",
					 curOffset, method->name);
				dvmAbort();

			}
			if (curBlock->successorBlockList.blockListType != kNotUsed) {
				ALOGE("Successor block list already in use: %d",
					 curBlock->successorBlockList.blockListType);
				dvmAbort();
			}
			curBlock->successorBlockList.blockListType = kCatch;
			dvmInitGrowableList(&curBlock->successorBlockList.blocks, 2);

			for (;;) {
				DexCatchHandler* handler = dexCatchIteratorNext(&iterator);

				if (handler == NULL) {
					break;
				}

				BasicBlock *catchBlock = findBlock(cUnit, handler->address,
												   /* split */
												   false,
												   /* create */
												   false,
												   /* immedPredBlockP */
												   NULL);

				SuccessorBlockInfo *successorBlockInfo =
				  (SuccessorBlockInfo *) dvmCompilerNew(sizeof(SuccessorBlockInfo),
														false);
				successorBlockInfo->block = catchBlock;
				successorBlockInfo->key = handler->typeIdx;
				dvmInsertGrowableList(&curBlock->successorBlockList.blocks,
									  (intptr_t) successorBlockInfo);
				dvmCompilerSetBit(catchBlock->predecessors, curBlock->id);
			}
		} else {
			BasicBlock *ehBlock = dvmCompilerNewBB(kExceptionHandling,
												   cUnit->numBlocks++);
			curBlock->taken = ehBlock;
			dvmInsertGrowableList(&cUnit->blockList, (intptr_t) ehBlock);
			ehBlock->startOffset = curOffset;
			dvmCompilerSetBit(ehBlock->predecessors, curBlock->id);
		}

		/*
		 * Force the current block to terminate.
		 *
		 * Data may be present before codeEnd, so we need to parse it to know
		 * whether it is code or data.
		 */
		if (codePtr < codeEnd) {
			/* Create a fallthrough block for real instructions (incl. OP_NOP) */
			if (contentIsInsn(codePtr)) {
				BasicBlock *fallthroughBlock = findBlock(cUnit,
														 curOffset + width,
														 /* split */
														 false,
														 /* create */
														 true,
														 /* immedPredBlockP */
														 NULL);
				/*
				 * OP_THROW and OP_THROW_VERIFICATION_ERROR are unconditional
				 * branches.
				 */
				if (insn->dalvikInsn.opcode != OP_THROW_VERIFICATION_ERROR &&
					insn->dalvikInsn.opcode != OP_THROW) {
					curBlock->fallThrough = fallthroughBlock;
					dvmCompilerSetBit(fallthroughBlock->predecessors, curBlock->id);
				}
			}
		}
	}

	/*
	 * Similar to dvmCompileTrace, but the entity processed here is the whole
	 * method.
	 *
	 * TODO: implementation will be revisited when the trace builder can provide
	 * whole-method traces.
	 */
	/**
	 * @brief method模式的编译，类似dvmCompileTrace
	 */
	bool dvmCompileMethod(const Method *method, JitTranslationInfo *info)
	{
		CompilationUnit cUnit;
		const DexCode *dexCode = dvmGetMethodCode(method);
		const u2 *codePtr = dexCode->insns;
		const u2 *codeEnd = dexCode->insns + dexCode->insnsSize;
		int numBlocks = 0;
		unsigned int curOffset = 0;

		/* Method already compiled */
		if (dvmJitGetMethodAddr(codePtr)) {
			info->codeAddress = NULL;
			return false;
		}

		memset(&cUnit, 0, sizeof(cUnit));
		cUnit.method = method;

		cUnit.jitMode = kJitMethod;

		/* Initialize the block list */
		dvmInitGrowableList(&cUnit.blockList, 4);

		/*
		 * FIXME - PC reconstruction list won't be needed after the codegen routines
		 * are enhanced to true method mode.
		 */
		/* Initialize the PC reconstruction list */
		dvmInitGrowableList(&cUnit.pcReconstructionList, 8);

		/* Allocate the bit-vector to track the beginning of basic blocks */
		BitVector *tryBlockAddr = dvmCompilerAllocBitVector(dexCode->insnsSize,
															true /* expandable */);
		cUnit.tryBlockAddr = tryBlockAddr;

		/* Create the default entry and exit blocks and enter them to the list */
		BasicBlock *entryBlock = dvmCompilerNewBB(kEntryBlock, numBlocks++);
		BasicBlock *exitBlock = dvmCompilerNewBB(kExitBlock, numBlocks++);

		cUnit.entryBlock = entryBlock;
		cUnit.exitBlock = exitBlock;

		dvmInsertGrowableList(&cUnit.blockList, (intptr_t) entryBlock);
		dvmInsertGrowableList(&cUnit.blockList, (intptr_t) exitBlock);

		/* Current block to record parsed instructions */
		BasicBlock *curBlock = dvmCompilerNewBB(kDalvikByteCode, numBlocks++);
		curBlock->startOffset = 0;
		dvmInsertGrowableList(&cUnit.blockList, (intptr_t) curBlock);
		entryBlock->fallThrough = curBlock;
		dvmCompilerSetBit(curBlock->predecessors, entryBlock->id);

		/*
		 * Store back the number of blocks since new blocks may be created of
		 * accessing cUnit.
		 */
		cUnit.numBlocks = numBlocks;

		/* Identify code range in try blocks and set up the empty catch blocks */
		processTryCatchBlocks(&cUnit);

		/* Parse all instructions and put them into containing basic blocks */
		while (codePtr < codeEnd) {
			MIR *insn = (MIR *) dvmCompilerNew(sizeof(MIR), true);
			insn->offset = curOffset;
			int width = parseInsn(codePtr, &insn->dalvikInsn, false);
			insn->width = width;

			/* Terminate when the data section is seen */
			if (width == 0)
				break;

			dvmCompilerAppendMIR(curBlock, insn);

			codePtr += width;
			int flags = dexGetFlagsFromOpcode(insn->dalvikInsn.opcode);

			if (flags & kInstrCanBranch) {
				processCanBranch(&cUnit, curBlock, insn, curOffset, width, flags,
								 codePtr, codeEnd);
			} else if (flags & kInstrCanReturn) {
				curBlock->fallThrough = exitBlock;
				dvmCompilerSetBit(exitBlock->predecessors, curBlock->id);
				/*
				 * Terminate the current block if there are instructions
				 * afterwards.
				 */
				if (codePtr < codeEnd) {
					/*
					 * Create a fallthrough block for real instructions
					 * (incl. OP_NOP).
					 */
					if (contentIsInsn(codePtr)) {
						findBlock(&cUnit, curOffset + width,
								  /* split */
								  false,
								  /* create */
								  true,
								  /* immedPredBlockP */
								  NULL);
					}
				}
			} else if (flags & kInstrCanThrow) {
				processCanThrow(&cUnit, curBlock, insn, curOffset, width, flags,
								tryBlockAddr, codePtr, codeEnd);
			} else if (flags & kInstrCanSwitch) {
				processCanSwitch(&cUnit, curBlock, insn, curOffset, width, flags);
			}
			curOffset += width;
			BasicBlock *nextBlock = findBlock(&cUnit, curOffset,
											  /* split */
											  false,
											  /* create */
											  false,
											  /* immedPredBlockP */
											  NULL);
			if (nextBlock) {
				/*
				 * The next instruction could be the target of a previously parsed
				 * forward branch so a block is already created. If the current
				 * instruction is not an unconditional branch, connect them through
				 * the fall-through link.
				 */
				assert(curBlock->fallThrough == NULL ||
					   curBlock->fallThrough == nextBlock ||
					   curBlock->fallThrough == exitBlock);

				if ((curBlock->fallThrough == NULL) &&
					(flags & kInstrCanContinue)) {
					curBlock->fallThrough = nextBlock;
					dvmCompilerSetBit(nextBlock->predecessors, curBlock->id);
				}
				curBlock = nextBlock;
			}
		}

		if (cUnit.printMe) {
			dvmCompilerDumpCompilationUnit(&cUnit);
		}

		/* Adjust this value accordingly once inlining is performed */
		cUnit.numDalvikRegisters = cUnit.method->registersSize;

		/* Verify if all blocks are connected as claimed */
		/* FIXME - to be disabled in the future */
		dvmCompilerDataFlowAnalysisDispatcher(&cUnit, verifyPredInfo,
											  kAllNodes,
											  false /* isIterative */);


		/* Perform SSA transformation for the whole method */
		dvmCompilerMethodSSATransformation(&cUnit);

#ifndef ARCH_IA32
		dvmCompilerInitializeRegAlloc(&cUnit);  // Needs to happen after SSA naming

		/* Allocate Registers using simple local allocation scheme */
		dvmCompilerLocalRegAlloc(&cUnit);
#endif

		/* Convert MIR to LIR, etc. */
		dvmCompilerMethodMIR2LIR(&cUnit);

		// Debugging only
		//dvmDumpCFG(&cUnit, "/sdcard/cfg/");

		/* Method is not empty */
		if (cUnit.firstLIRInsn) {
			/* Convert LIR into machine code. Loop for recoverable retries */
			do {
				dvmCompilerAssembleLIR(&cUnit, info);
				cUnit.assemblerRetries++;
				if (cUnit.printMe && cUnit.assemblerStatus != kSuccess)
					ALOGD("Assembler abort #%d on %d",cUnit.assemblerRetries,
						  cUnit.assemblerStatus);
			} while (cUnit.assemblerStatus == kRetryAll);

			if (cUnit.printMe) {
				dvmCompilerCodegenDump(&cUnit);
			}

			if (info->codeAddress) {
				dvmJitSetCodeAddr(dexCode->insns, info->codeAddress,
								  info->instructionSet, true, 0);
				/*
				 * Clear the codeAddress for the enclosing trace to reuse the info
				 */
				info->codeAddress = NULL;
			}
		}

		return false;
	}

	/* Extending the trace by crawling the code from curBlock */
	static bool exhaustTrace(CompilationUnit *cUnit, BasicBlock *curBlock)
	{
		unsigned int curOffset = curBlock->startOffset;
		const u2 *codePtr = cUnit->method->insns + curOffset;

		if (curBlock->visited == true) return false;

		curBlock->visited = true;

		if (curBlock->blockType == kEntryBlock ||
			curBlock->blockType == kExitBlock) {
			return false;
		}

		/*
		 * Block has been parsed - check the taken/fallThrough in case it is a split
		 * block.
		 */
		if (curBlock->firstMIRInsn != NULL) {
			  bool changed = false;
			  if (curBlock->taken)
				  changed |= exhaustTrace(cUnit, curBlock->taken);
			  if (curBlock->fallThrough)
				  changed |= exhaustTrace(cUnit, curBlock->fallThrough);
			  return changed;
		}
		while (true) {
			MIR *insn = (MIR *) dvmCompilerNew(sizeof(MIR), true);
			insn->offset = curOffset;
			int width = parseInsn(codePtr, &insn->dalvikInsn, false);
			insn->width = width;

			/* Terminate when the data section is seen */
			if (width == 0)
				break;

			dvmCompilerAppendMIR(curBlock, insn);

			codePtr += width;
			int flags = dexGetFlagsFromOpcode(insn->dalvikInsn.opcode);

			/* Stop extending the trace after seeing these instructions */
			if (flags & (kInstrCanReturn | kInstrCanSwitch | kInstrInvoke)) {
				curBlock->fallThrough = cUnit->exitBlock;
				dvmCompilerSetBit(cUnit->exitBlock->predecessors, curBlock->id);
				break;
			} else if (flags & kInstrCanBranch) {
				processCanBranch(cUnit, curBlock, insn, curOffset, width, flags,
								 codePtr, NULL);
				if (curBlock->taken) {
					exhaustTrace(cUnit, curBlock->taken);
				}
				if (curBlock->fallThrough) {
					exhaustTrace(cUnit, curBlock->fallThrough);
				}
				break;
			}
			curOffset += width;
			BasicBlock *nextBlock = findBlock(cUnit, curOffset,
											  /* split */
											  false,
											  /* create */
											  false,
											  /* immedPredBlockP */
											  NULL);
			if (nextBlock) {
				/*
				 * The next instruction could be the target of a previously parsed
				 * forward branch so a block is already created. If the current
				 * instruction is not an unconditional branch, connect them through
				 * the fall-through link.
				 */
				assert(curBlock->fallThrough == NULL ||
					   curBlock->fallThrough == nextBlock ||
					   curBlock->fallThrough == cUnit->exitBlock);

				if ((curBlock->fallThrough == NULL) &&
					(flags & kInstrCanContinue)) {
					curBlock->needFallThroughBranch = true;
					curBlock->fallThrough = nextBlock;
					dvmCompilerSetBit(nextBlock->predecessors, curBlock->id);
				}
				/* Block has been visited - no more parsing needed */
				if (nextBlock->visited == true) {
					return true;
				}
				curBlock = nextBlock;
			}
		}
		return true;
	}

	/* Compile a loop */
	/**
	 * @brief 编译一个循环
	 * @param cUnti 编译单元指针
	 * @param startOffset 当前指令开始的偏移
	 * @param desc JIT Trace描述符
	 * @param numMaxInsts 指令的最大数量
	 * @param info Jit转换信息
	 * @param bailPtr 异常处理指针
	 * @param optHints 优化选项
	 * @retval 0 失败
	 * @retval 1 成功
	 * @note 被dvmCompilerTrace调用，在dvmCompilerTrace中如果发现当前指令
	 *	是一条分支指令并且目标偏移小于当前偏移，则进行调用
	 */
	static bool compileLoop(CompilationUnit *cUnit, unsigned int startOffset,
							JitTraceDescription *desc, int numMaxInsts,
							JitTranslationInfo *info, jmp_buf *bailPtr,
							int optHints)
	{
		int numBlocks = 0;
		unsigned int curOffset = startOffset;			/* 当前的指令偏移 */
		bool changed;
		BasicBlock *bb;
#if defined(WITH_JIT_TUNING)
		CompilerMethodStats *methodStats;
#endif

		cUnit->jitMode = kJitLoop;						/* Jit的模式 */

		/* Initialize the block list */
		/* 初始化基础块链表 */
		dvmInitGrowableList(&cUnit->blockList, 4);

		/* Initialize the PC reconstruction list */
		dvmInitGrowableList(&cUnit->pcReconstructionList, 8);

		/* Create the default entry and exit blocks and enter them to the list */
		/* 创建一个默认的入口block与退出block */
		BasicBlock *entryBlock = dvmCompilerNewBB(kEntryBlock, numBlocks++);
		entryBlock->startOffset = curOffset;
		BasicBlock *exitBlock = dvmCompilerNewBB(kExitBlock, numBlocks++);

		cUnit->entryBlock = entryBlock;
		cUnit->exitBlock = exitBlock;

		dvmInsertGrowableList(&cUnit->blockList, (intptr_t) entryBlock);
		dvmInsertGrowableList(&cUnit->blockList, (intptr_t) exitBlock);

		/* Current block to record parsed instructions */
		/* 加入第一个指令的block */
		BasicBlock *curBlock = dvmCompilerNewBB(kDalvikByteCode, numBlocks++);
		curBlock->startOffset = curOffset;

		dvmInsertGrowableList(&cUnit->blockList, (intptr_t) curBlock);
		entryBlock->fallThrough = curBlock;
		dvmCompilerSetBit(curBlock->predecessors, entryBlock->id);

		/*
		 * Store back the number of blocks since new blocks may be created of
		 * accessing cUnit.
		 */
		/* 保存block的数量直到新的blocks被访问中的编译单元创建 */
		cUnit->numBlocks = numBlocks;

		/* 数据流分析派遣函数 */
		do {
			dvmCompilerDataFlowAnalysisDispatcher(cUnit,
												  dvmCompilerClearVisitedFlag,
												  kAllNodes,
												  false /* isIterative */);
			changed = exhaustTrace(cUnit, curBlock);
		} while (changed);

		/*
		 * 目标的block
		 * PC重构block
		 * 异常的block
		 */

		/* Backward chaining block */
		/* 分配一个block节点属性为kChainingCellBackwardBranch，表明此节点的指令在这条指令之前 */
		bb = dvmCompilerNewBB(kChainingCellBackwardBranch, cUnit->numBlocks++);
		dvmInsertGrowableList(&cUnit->blockList, (intptr_t) bb);
		cUnit->backChainBlock = bb;

		/* A special block to host PC reconstruction code */
		/* 为本地重建代码建立一个block跟在所属代码的后边 */
		bb = dvmCompilerNewBB(kPCReconstruction, cUnit->numBlocks++);
		dvmInsertGrowableList(&cUnit->blockList, (intptr_t) bb);

		/* And one final block that publishes the PC and raises the exception */
		/* 发布到PC上并且抛出一个异常 */
		bb = dvmCompilerNewBB(kExceptionHandling, cUnit->numBlocks++);
		dvmInsertGrowableList(&cUnit->blockList, (intptr_t) bb);
		cUnit->puntBlock = bb;

		/* 当前函数的寄存器数量 */
		cUnit->numDalvikRegisters = cUnit->method->registersSize;

		/* Verify if all blocks are connected as claimed */
		/* FIXME - to be disabled in the future */
		/* 验证所有声明链接的block */
		/* 增加一个关闭特性 */
		dvmCompilerDataFlowAnalysisDispatcher(cUnit, verifyPredInfo,
											  kAllNodes,
											  false /* isIterative */);


		/* Try to identify a loop */
		/* 尝试标记一个循环 */
		if (!dvmCompilerBuildLoop(cUnit))
			goto bail;

		/* 循环优化 */
		dvmCompilerLoopOpt(cUnit);

		/*
		 * Change the backward branch to the backward chaining cell after dataflow
		 * analsys/optimizations are done.
		 */
		/*
		 * 在数据流分析/优化完成后改变向前分支到向前链接单元
		 */
		dvmCompilerInsertBackwardChaining(cUnit);

#if defined(ARCH_IA32)
		/* Convert MIR to LIR, etc. */
		dvmCompilerMIR2LIR(cUnit, info);
#else
		dvmCompilerInitializeRegAlloc(cUnit);

		/* Allocate Registers using simple local allocation scheme */
		dvmCompilerLocalRegAlloc(cUnit);

		/* Convert MIR to LIR, etc. */
		dvmCompilerMIR2LIR(cUnit);
#endif

		/* Loop contains never executed blocks / heavy instructions */
		/* 循环保护从不执行的块/heavy指令 */
		if (cUnit->quitLoopMode) {
			/* 退出循环模式 */
			if (cUnit->printMe || gDvmJit.receivedSIGUSR2) {
				ALOGD("Loop trace @ offset %04x aborted due to unresolved code info",
					 cUnit->entryBlock->startOffset);
			}
			goto bail;
		}

		/* Convert LIR into machine code. Loop for recoverable retries */
		/* 转变LIR到机器代码 */
		do {
			dvmCompilerAssembleLIR(cUnit, info);
			cUnit->assemblerRetries++;
			if (cUnit->printMe && cUnit->assemblerStatus != kSuccess)
				ALOGD("Assembler abort #%d on %d", cUnit->assemblerRetries,
					  cUnit->assemblerStatus);
		} while (cUnit->assemblerStatus == kRetryAll);

		/* Loop is too big - bail out */
		/* 编译失败 */
		if (cUnit->assemblerStatus == kRetryHalve) {
			goto bail;
		}

		/* 打印编译代码信息 */
		if (cUnit->printMe || gDvmJit.receivedSIGUSR2) {
			ALOGD("Loop trace @ offset %04x", cUnit->entryBlock->startOffset);
			dvmCompilerCodegenDump(cUnit);
		}

		/*
		 * If this trace uses class objects as constants,
		 * dvmJitInstallClassObjectPointers will switch the thread state
		 * to running and look up the class pointers using the descriptor/loader
		 * tuple stored in the callsite info structure. We need to make this window
		 * as short as possible since it is blocking GC.
		 */
		/*
		 * 如果这个trace使用类对象作为常量，dvmJitInstallClassObjectPointers将交换
		 * 线程状态到运行并且使用描述符/加载器找出在callsite信息结构中的类指针。
		 */
		if (cUnit->hasClassLiterals && info->codeAddress) {
			dvmJitInstallClassObjectPointers(cUnit, (char *) info->codeAddress);
		}

		/*
		 * Since callsiteinfo is allocated from the arena, delay the reset until
		 * class pointers are resolved.
		 */
		/* 直到callsiteinfo被分配从arena内存区域，延时重设直到类指针被解析  */
		dvmCompilerArenaReset();

		/* 到这里汇编状态必须是成功 */
		assert(cUnit->assemblerStatus == kSuccess);
#if defined(WITH_JIT_TUNING)
		/* Locate the entry to store compilation statistics for this method */
		/* 保存编译统计信息为这个函数 */
		methodStats = dvmCompilerAnalyzeMethodBody(desc->method, false);
		methodStats->nativeSize += cUnit->totalSize;
#endif
		return info->codeAddress != NULL;

		/* 失败 */
	bail:
		/* Retry the original trace with JIT_OPT_NO_LOOP disabled */
		/* 尝试原始的trace在关闭JIT_OPT_NO_LOOP选项下 */
		dvmCompilerArenaReset();				/* 重设置arena内存区域 */
		return dvmCompileTrace(desc, numMaxInsts, info, bailPtr,
							   optHints | JIT_OPT_NO_LOOP);
	}

	/**
	 * @brief 确定函数是否在当前字节码的类表中
	 * @param method 要确定的函数体
	 * @retval 0 不在
	 * @retval 1 在
	 */
	static bool searchClassTablePrefix(const Method* method) {
		/* 类表不为空 */
		if (gDvmJit.classTable == NULL) {
			return false;
		}
		HashIter iter;
		HashTable* pTab = gDvmJit.classTable;		/* 取出类HASH表 */
		/* 遍历整个HASH表 */
		for (dvmHashIterBegin(pTab, &iter); !dvmHashIterDone(&iter);
			dvmHashIterNext(&iter))
		{
			/* 取出HASH数据 */
			const char* str = (const char*) dvmHashIterData(&iter);
			/* 对比当前函数是否属于类表中的类 */
			if (strncmp(method->clazz->descriptor, str, strlen(str)) == 0) {
				return true;
			}
		}
		return false;
	}

	/*
	 * Main entry point to start trace compilation. Basic blocks are constructed
	 * first and they will be passed to the codegen routines to convert Dalvik
	 * bytecode into machine code.
	 */
	/**
	 * @brief trace模式的编译函数
	 * @param desc 指向一个JitTraceDescription结构的指针，此值从订单处获得
	 * @param numMaxInsts 最大的编译代码数量 
	 * @param info 指向一个编译成功后保存编译结果的结构JitTranslationInfo
	 * @param bailPtr 用于异常处理，jmp_buf的指针
	 * @param optHints
	 * @note 主要的入口点来实现trace模式的编译。首先基本代码被构建并且它们将被传递到
	 * codegen目录的对应代码将dalvik字节码转换成本地的机器代码。
	 */
	bool dvmCompileTrace(JitTraceDescription *desc, int numMaxInsts,
						 JitTranslationInfo *info, jmp_buf *bailPtr,
						 int optHints)
	{
		const DexCode *dexCode = dvmGetMethodCode(desc->method);	/* 获取函数代码 */
		const JitTraceRun* currRun = &desc->trace[0];				/* 取出热点代码信息 */
		unsigned int curOffset = currRun->info.frag.startOffset;	/* 获取在代码段的偏移 */
		unsigned int startOffset = curOffset;
		unsigned int numInsts = currRun->info.frag.numInsts;		/* 获取指令的数量，这里默认应该是1 */		
		const u2 *codePtr = dexCode->insns + curOffset;				/* 获取要编译的开始指针 */
		int traceSize = 0;  // # of half-words
		const u2 *startCodePtr = codePtr;
		BasicBlock *curBB, *entryCodeBB;
		int numBlocks = 0;
		static int compilationId;									/* 编译ID号 */
		CompilationUnit cUnit;										/* 编译单元结构，用于整个编译期间记录信息 */
		GrowableList *blockList;									/* 一个动态数组用于记录基础块的内存 */
#if defined(WITH_JIT_TUNING)
		/* 编译信息统计，函数的状态 */
		CompilerMethodStats *methodStats;
#endif

		/* If we've already compiled this trace, just return success */
		/* 如果以前编译过这个代码，并且没有丢弃结构则直接返回成功 */
		/* dvmJitGetTraceAddr 在"vm/interp/Jit.cpp"中实现 */
		if (dvmJitGetTraceAddr(startCodePtr) && !info->discardResult) {
			/*
			 * Make sure the codeAddress is NULL so that it won't clobber the
			 * existing entry.
			 */
			/* 确保codeAddress设置为NULL */
			info->codeAddress = NULL;
			return true;
		}

		/* If the work order is stale, discard it */
		/* 如果订单是之前的订单则丢弃它 */
		if (info->cacheVersion != gDvmJit.cacheVersion) {
			return false;
		}

		compilationId++;		/* 编译ID增加 */
		memset(&cUnit, 0, sizeof(CompilationUnit));		/* 初始化编译单元 */

#if defined(WITH_JIT_TUNING)
		/* Locate the entry to store compilation statistics for this method */
		/* 保存编译源代码所在函数的信息到编译统计表 */
		methodStats = dvmCompilerAnalyzeMethodBody(desc->method, false);
#endif

		/* Set the recover buffer pointer */
		/* 设置jmp_buf指针，异常时使用 */
		cUnit.bailPtr = bailPtr;

		/* Initialize the printMe flag */
		/* 初始化打印信息标志 */
		cUnit.printMe = gDvmJit.printMe;

		/* Setup the method */
		/* 设置对应的函数体 */
		cUnit.method = desc->method;

		/* Store the trace descriptor and set the initial mode */
		/* 保存trace描述并且设置编译单元的初始化模式 */
		cUnit.traceDesc = desc;
		cUnit.jitMode = kJitTrace;

		/* Initialize the PC reconstruction list */
		/* 初始化PC重建列表 */
		dvmInitGrowableList(&cUnit.pcReconstructionList, 8);

		/* Initialize the basic block list */
		/* 初始化基本块列表 */
		blockList = &cUnit.blockList;
		dvmInitGrowableList(blockList, 8);

		/* ---------- 内存初始化完毕 ---------- */

		
		/* ---------- 以下是对编译代码地址的合法性检查 ---------- */

		/* Identify traces that we don't want to compile */
		/* 检查是否在不进行编译的类中 */
		if (gDvmJit.classTable) {
			bool classFound = searchClassTablePrefix(desc->method);			/* 当前函数是否在类表中 */
			if (gDvmJit.classTable && gDvmJit.includeSelectedMethod != classFound) {
				/* 没有找到直接返回 */
				return false;
			}
		}

		/* 如果存在函数记录表 */
		if (gDvmJit.methodTable) {
			/* 类名 + 函数名 */
			int len = strlen(desc->method->clazz->descriptor) +
					  strlen(desc->method->name) + 1;
			char *fullSignature = (char *)dvmCompilerNew(len, true);
			strcpy(fullSignature, desc->method->clazz->descriptor);
			strcat(fullSignature, desc->method->name);

			int hashValue = dvmComputeUtf8Hash(fullSignature);				/* 进行hash操作 */

			/*
			 * Doing three levels of screening to see whether we want to skip
			 * compiling this method
			 */
			/*
			 * 是否是要跳过编译这个函数的三种等级
			 */

			/* First, check the full "class;method" signature */
			/* 第一，检查整个"class;method"签名,确定函数是否已经在表之中了 */
			bool methodFound =
				dvmHashTableLookup(gDvmJit.methodTable, hashValue,
								   fullSignature, (HashCompareFunc) strcmp,
								   false) !=
				NULL;

			/* Full signature not found - check the enclosing class */
			/* 函数名签名没有找到 - 单检查类名 */
			if (methodFound == false) {
				int hashValue = dvmComputeUtf8Hash(desc->method->clazz->descriptor);
				methodFound =
					dvmHashTableLookup(gDvmJit.methodTable, hashValue,
								   (char *) desc->method->clazz->descriptor,
								   (HashCompareFunc) strcmp, false) !=
					NULL;
				/* Enclosing class not found - check the method name */
				/* 类名没有找到，则直接检查函数名 */
				if (methodFound == false) {
					int hashValue = dvmComputeUtf8Hash(desc->method->name);
					methodFound =
						dvmHashTableLookup(gDvmJit.methodTable, hashValue,
									   (char *) desc->method->name,
									   (HashCompareFunc) strcmp, false) !=
						NULL;

					/*
					 * Debug by call-graph is enabled. Check if the debug list
					 * covers any methods on the VM stack.
					 */
					/* 如果还没有找到则查看call-graph是否开启。检查在调试列表上虚拟机栈中的函数 */
					if (methodFound == false && gDvmJit.checkCallGraph == true) {
						methodFound =
							filterMethodByCallGraph(info->requestingThread,
													desc->method->name);
					}
				}
			}

			/*
			 * Under the following conditions, the trace will be *conservatively*
			 * compiled by only containing single-step instructions to and from the
			 * interpreter.
			 * 1) If includeSelectedMethod == false, the method matches the full or
			 *    partial signature stored in the hash table.
			 *
			 * 2) If includeSelectedMethod == true, the method does not match the
			 *    full and partial signature stored in the hash table.
			 */
			/*
			 * 在以下条件下，trace将受到*保护*
			 * 编译仅包含single-step指令从解释器。
			 * 1) 如果includeSelectedMethod == false，函数签名必须匹配"类名+函数名"
			 *	或者部分的签名在hash表中。
			 * 2) 如果includeSelectedMethod == true, 那么函数签名可以不用在hash表中匹配。
			 */
			/* 存在函数表并且函数必须被找到才可以 */
			if (gDvmJit.methodTable && gDvmJit.includeSelectedMethod != methodFound) {
				/* 如果是X86架构直接返回false */
#ifdef ARCH_IA32
				return false;
#else
				cUnit.allSingleStep = true;
#endif
			} else {
				/* Compile the trace as normal */
				/* 正常的编译trace */

				/* Print the method we cherry picked */
				/* 打印信息 */
				if (gDvmJit.includeSelectedMethod == true) {
					cUnit.printMe = true;
				}
			}
		}

		// Each pair is a range, check whether curOffset falls into a range.
		/* 检查trace的偏移是否在合法的范围内 */
		bool includeOffset = (gDvmJit.num_entries_pcTable < 2);
		for (int pcOff = 0; pcOff < gDvmJit.num_entries_pcTable; ) {
			/* 最后的边界检查，由于是成对的增加计数 */
			if (pcOff+1 >= gDvmJit.num_entries_pcTable) {
			  break;
			}
			/* 成对的匹配一个是上界，一个是下界 */
			if (curOffset >= gDvmJit.pcTable[pcOff] && curOffset <= gDvmJit.pcTable[pcOff+1]) {
				includeOffset = true;			/* 在合法范围则标记 */
				break;
			}
			pcOff += 2;				/* 成对的增加 */
		}
		/* 不在合法范围内则直接退出 */
		if (!includeOffset) {
			return false;
		}

		/* ---------- 以上都是在做订单的地址范围的合法检查 ---------- */


		/* ---------- 以下是真实的进行编译 ---------- */

		/* Allocate the entry block */
		/* 分配一个块 */
		curBB = dvmCompilerNewBB(kEntryBlock, numBlocks++);			/* 第一个項被设置为kEntryBlock类型 */
		dvmInsertGrowableList(blockList, (intptr_t) curBB);
		curBB->startOffset = curOffset;								/* 一个要进行编译的代码偏移 */

		/* 字节码的块 */
		entryCodeBB = dvmCompilerNewBB(kDalvikByteCode, numBlocks++);
		dvmInsertGrowableList(blockList, (intptr_t) entryCodeBB);
		entryCodeBB->startOffset = curOffset;
		/* 形成一个链表，fallThrough是指令顺序字段 */
		curBB->fallThrough = entryCodeBB;
		curBB = entryCodeBB;

		/* 打印调试信息 */
		if (cUnit.printMe) {
			ALOGD("--------\nCompiler: Building trace for %s, offset %#x",
				 desc->method->name, curOffset);
		}

		/* ---------- 以下代码负责建立MIR链表 ---------- */

		/*
		 * Analyze the trace descriptor and include up to the maximal number
		 * of Dalvik instructions into the IR.
		 */
		/*
		 * 分析trace描述符并且包括到dalvik最大指令数量到IR中。
		 */
		while (1) {
			MIR *insn;
			int width;
			insn = (MIR *)dvmCompilerNew(sizeof(MIR), true);
			insn->offset = curOffset;
			/* 返回指令长度 */
			width = parseInsn(codePtr, &insn->dalvikInsn, cUnit.printMe);

			/* The trace should never incude instruction data */
			assert(width);
			insn->width = width;
			traceSize += width;						/* traceSize加上指令的长度 */
			dvmCompilerAppendMIR(curBB, insn);		/* 插入一个MIR到基本块链表 */
			cUnit.numInsts++;						/* 增加要编译的指令数量 */

			/* 获取当前指令的OPCODE标记 */
			int flags = dexGetFlagsFromOpcode(insn->dalvikInsn.opcode);

			/* 如果当前的指令是一个调用指令 */
			if (flags & kInstrInvoke) {
				/* 获取被调用函数的函数体结构，currRun是订单信息结构 */
				const Method *calleeMethod = (const Method *)
					currRun[JIT_TRACE_CUR_METHOD].info.meta;
				assert(numInsts == 1);

				/* 
				 * 获取调用者信息
				 */
				CallsiteInfo *callsiteInfo =
					(CallsiteInfo *)dvmCompilerNew(sizeof(CallsiteInfo), true);
				callsiteInfo->classDescriptor = (const char *)
					currRun[JIT_TRACE_CLASS_DESC].info.meta;
				callsiteInfo->classLoader = (Object *)
					currRun[JIT_TRACE_CLASS_LOADER].info.meta;
				callsiteInfo->method = calleeMethod;
				insn->meta.callsiteInfo = callsiteInfo;
			}

			/* Instruction limit reached - terminate the trace here */
			/* 指令的最大数到达,numMaxInsts是以参数形式穿进来的 */
			if (cUnit.numInsts >= numMaxInsts) {
				break;		/* 退出循环 */
			}

			/* 如果编译完成 */
			/* 以下这个是关于订单方面的 */
			if (--numInsts == 0) {
				/* 到达末尾退出循环 */
				if (currRun->info.frag.runEnd) {
					break;		/* 退出MIR链表建立循环 */
				} else {
					/* Advance to the next trace description (ie non-meta info) */
					/* 找到一个代码trace描述符号(例如：没有 meta信息) */
					do {
						currRun++;		/* 下一个 */
					} while (!currRun->isCode);

					/* Dummy end-of-run marker seen */
					/* 到达最后一个块 */
					if (currRun->info.frag.numInsts == 0) {
						break;
					}

					/* 插入这条指令到基本块链表中 */
					curBB = dvmCompilerNewBB(kDalvikByteCode, numBlocks++);
					dvmInsertGrowableList(blockList, (intptr_t) curBB);
					curOffset = currRun->info.frag.startOffset;
					numInsts = currRun->info.frag.numInsts;
					curBB->startOffset = curOffset;
					codePtr = dexCode->insns + curOffset;
				}
			} else {
				/* 偏移与指针增加 */
				curOffset += width;
				codePtr += width;
			}
		}/* 完成MIR链表的建立 */
		/* ---------- 以上代码负责建立MIR链表 ---------- */

		/* 以上代码将dalvik的指令流转换成中间指令格式MIR */

#if defined(WITH_JIT_TUNING)
		/* Convert # of half-word to bytes */
		/* 记录trace的大小 */
		methodStats->compiledDalvikSize += traceSize * 2;
#endif

		/*
		 * Now scan basic blocks containing real code to connect the
		 * taken/fallthrough links. Also create chaining cells for code not included
		 * in the trace.
		 */
		/*
		 * 现在扫描包含真实代码的从taken/fallthrough字段到基本块链表
		 */
		size_t blockId;
		for (blockId = 0; blockId < blockList->numUsed; blockId++) {
			curBB = (BasicBlock *) dvmGrowableListGetElement(blockList, blockId);		/* 从指定的索引中获取基本块的节点 */
			MIR *lastInsn = curBB->lastMIRInsn;											/* 获取MIR指令指针 */
			/* Skip empty blocks */
			/* 跳过空块 */
			if (lastInsn == NULL) {
				continue;
			}

			/* 取出当前指令的偏移 */
			curOffset = lastInsn->offset;												/* 当前指令的偏移 */
			unsigned int targetOffset = curOffset;										/* 目标偏移，如果指令是分支指令 */
			unsigned int fallThroughOffset = curOffset + lastInsn->width;				/* 顺序执行的下一条指令的偏移 */
			bool isInvoke = false;
			const Method *callee = NULL;

			/* 
			 * 这个函数用于更新targetOffset的值，
			 * 如果是一个跳转指令targetOffset将被更新
			 * 并且callee函数结构会被更新
			 */
			findBlockBoundary(desc->method, curBB->lastMIRInsn, curOffset,
							  &targetOffset, &isInvoke, &callee);

			/* Link the taken and fallthrough blocks */
			/* 链接taken与fallthrough字段 */
			BasicBlock *searchBB;

			/* 获取当前指令的标记 */
			int flags = dexGetFlagsFromOpcode(lastInsn->dalvikInsn.opcode);

			/* 是否是调用指令 */
			if (flags & kInstrInvoke) {
				cUnit.hasInvoke = true;
			}

			/* Backward branch seen */
			/* 
			 * 目标的偏移要比当前指令的偏移要小
			 * 这种情况下应该是一个循环
			 * 但是产生这种循环并不是通过循环指令，而是单纯的跳转
			 * (optHints & JIT_OPT_NO_LOOP) == 0 这句应该就是判断
			 * 此次编译是否对循环进行编译的
			 */

			/*
			 * 从以下这个if中的return语句可以看出循环是作为JIT编译
			 * 的基本单元而言的
			 */
			if (isInvoke == false &&
				(flags & kInstrCanBranch) != 0 &&
				targetOffset < curOffset &&
				(optHints & JIT_OPT_NO_LOOP) == 0) {
				dvmCompilerArenaReset();				/* 重设所有Arena区域 */
				/* 编译循环 */
				return compileLoop(&cUnit, startOffset, desc, numMaxInsts,
								   info, bailPtr, optHints);
			}

			/* No backward branch in the trace - start searching the next BB */
			/* 
			 * 没有一个向前的分支指令，则继续向前遍历基本块 
			 * 这个循环，在顺序执行方面就浪费时间了，是可以优化的
			 * 因为顺序执行，只进行一次匹配，而向下跳转则需要遍历完接下来的
			 * 链表，用于找寻对应的基础块
			 */
			size_t searchBlockId;
			for (searchBlockId = blockId+1; searchBlockId < blockList->numUsed;
				 searchBlockId++) {
				/* 获取一个指令节点 */
				searchBB = (BasicBlock *) dvmGrowableListGetElement(blockList,
																	searchBlockId);
				/* 
				 * 如果目标的偏移 等于  下一条指令的偏移
				 * 这应该是个向下的跳转
				 */
				if (targetOffset == searchBB->startOffset) {
					curBB->taken = searchBB;			/* 跳转就使用taken字段 */
					dvmCompilerSetBit(searchBB->predecessors, curBB->id);
				}

				/*
				 * 如果当前指令的偏移 等于 下一条指令的偏移
				 * 这个情况是顺序的执行
				 */
				if (fallThroughOffset == searchBB->startOffset) {
					curBB->fallThrough = searchBB;		/* 顺序就使用fallThrough字段 */
					dvmCompilerSetBit(searchBB->predecessors, curBB->id);

					/*
					 * Fallthrough block of an invoke instruction needs to be
					 * aligned to 4-byte boundary (alignment instruction to be
					 * inserted later.
					 */
					/*
					 * 如果是一个调用指令的fallthrough块需要使用4字节的对齐
					 */
					if (flags & kInstrInvoke) {
						searchBB->isFallThroughFromInvoke = true;		/* 表明这个block之前的指令是一个调用指令 */
					}
					/* 优化：这里应该退出循环 */
				}
			}/* 循环遍历下一条指令块 */

			/*
			 * Some blocks are ended by non-control-flow-change instructions,
			 * currently only due to trace length constraint. In this case we need
			 * to generate an explicit branch at the end of the block to jump to
			 * the chaining cell.
			 */
			/*
			 * 一些基础块链表结束在一个 没有非控制流的改变指令，
			 * 目前由于仅在trace长度的约束。在这种情况下需要产生一个明确的分支在块
			 * 的末尾跳转到chaining cell。
			 */
			curBB->needFallThroughBranch =
				((flags & (kInstrCanBranch | kInstrCanSwitch | kInstrCanReturn |
						   kInstrInvoke)) == 0);

			/* 
			 * 如果是SWITCH指令包
			 */
			if (lastInsn->dalvikInsn.opcode == OP_PACKED_SWITCH ||
				lastInsn->dalvikInsn.opcode == OP_SPARSE_SWITCH) {
				int i;
				const u2 *switchData = desc->method->insns + lastInsn->offset +
								 lastInsn->dalvikInsn.vB;
				int size = switchData[1];
				int maxChains = MIN(size, MAX_CHAINED_SWITCH_CASES);

				/*
				 * Generate the landing pad for cases whose ranks are higher than
				 * MAX_CHAINED_SWITCH_CASES. The code will re-enter the interpreter
				 * through the NoChain point.
				 */
				if (maxChains != size) {
					cUnit.switchOverflowPad =
						desc->method->insns + lastInsn->offset;
				}

				/* 取出目标的偏移 */
				s4 *targets = (s4 *) (switchData + 2 +
						(lastInsn->dalvikInsn.opcode == OP_PACKED_SWITCH ?
						 2 : size * 2));

				/* One chaining cell for the first MAX_CHAINED_SWITCH_CASES cases */
				for (i = 0; i < maxChains; i++) {
					BasicBlock *caseChain = dvmCompilerNewBB(kChainingCellNormal,
															 numBlocks++);
					dvmInsertGrowableList(blockList, (intptr_t) caseChain);
					caseChain->startOffset = lastInsn->offset + targets[i];
				}

				/* One more chaining cell for the default case */
				BasicBlock *caseChain = dvmCompilerNewBB(kChainingCellNormal,
														 numBlocks++);
				dvmInsertGrowableList(blockList, (intptr_t) caseChain);
				caseChain->startOffset = lastInsn->offset + lastInsn->width;
			/* Fallthrough block not included in the trace */
			/* 下一个基本块不包括在trace热点中 */
			/* 
			 * 首先确定这条指令是一个无条件的跳转指令，例如RETURN或者GOTO
			 * 并且判断顺序执行的基本块指针为NULL
			 */
			} else if (!isUnconditionalBranch(lastInsn) &&
					   curBB->fallThrough == NULL) {
				BasicBlock *fallThroughBB;
				/*
				 * If the chaining cell is after an invoke or
				 * instruction that cannot change the control flow, request a hot
				 * chaining cell.
				 */
				/*
				 * 如果链接单元是一个在调用指令或者非分支指令之后，请求一个
				 * 热点链接单元
				 */
				if (isInvoke || curBB->needFallThroughBranch) {
					fallThroughBB = dvmCompilerNewBB(kChainingCellHot, numBlocks++);
				} else {
					fallThroughBB = dvmCompilerNewBB(kChainingCellNormal,
													 numBlocks++);
				}
				dvmInsertGrowableList(blockList, (intptr_t) fallThroughBB);
				fallThroughBB->startOffset = fallThroughOffset;
				curBB->fallThrough = fallThroughBB;
				dvmCompilerSetBit(fallThroughBB->predecessors, curBB->id);
			}
			/* Target block not included in the trace */
			/* 目标基本块不包含在trace中 */

			/*
			 *  当前指令的下一条指令非跳转指令
			 *  当前指令是跳转指令
			 *  当前指令是调用指令
			 *  当前指令跳转的目标有效
			 *  目标偏移不是当前的偏移
			 */
			if (curBB->taken == NULL &&
				(isGoto(lastInsn) || isInvoke ||
				(targetOffset != UNKNOWN_TARGET && targetOffset != curOffset))) {
				BasicBlock *newBB = NULL;
				/* 如果是调用指令 */
				if (isInvoke) {
					/* Monomorphic callee */
					/* 
					 * 被调用者函数体结构存在
					 * 如果是调用指令则新的基础块的startOffset字段内容为0
					 */
					if (callee) {
						/* JNI call doesn't need a chaining cell */
						/* 
						 * JNI单元的调用不需要一个链接单元
						 * dvmIsNativeMethod("vm\oo\Object.h")
						 * method->accessFlags & ACC_NATIVE != 0
						 */
						if (!dvmIsNativeMethod(callee)) {
							/* 非JNI调用 */
							newBB = dvmCompilerNewBB(kChainingCellInvokeSingleton,
													 numBlocks++);
							newBB->startOffset = 0;
							newBB->containingMethod = callee;
						}
					/* Will resolve at runtime */
					/* 如果被调用者函数结构体为空则目标偏移为0 */
					} else {
						newBB = dvmCompilerNewBB(kChainingCellInvokePredicted,
												 numBlocks++);
						newBB->startOffset = 0;
					}
				/* For unconditional branches, request a hot chaining cell */
				/* 这里处理无条件的分支，需要一个热点链接单元 */
				} else {
#if !defined(WITH_SELF_VERIFICATION)
					/* 这里是分支与正常指令 */
					newBB = dvmCompilerNewBB(dexIsGoto(flags) ?
													  kChainingCellHot :
													  kChainingCellNormal,
											 numBlocks++);
					newBB->startOffset = targetOffset;
#else
					/* Handle branches that branch back into the block */
					/* 如果跳转目标在当前的trace块之中 */
					if (targetOffset >= curBB->firstMIRInsn->offset &&
						targetOffset <= curBB->lastMIRInsn->offset) {
						newBB = dvmCompilerNewBB(kChainingCellBackwardBranch,
												 numBlocks++);
					} else {
						/* 如果目标是在之外 */
						newBB = dvmCompilerNewBB(dexIsGoto(flags) ?
														  kChainingCellHot :
														  kChainingCellNormal,
												 numBlocks++);
					}
					/* 新的基础块的偏移为目标偏移 */
					newBB->startOffset = targetOffset;
#endif
				}/* 这里是处理无条件分支指令 */
				if (newBB) {
					curBB->taken = newBB;
					dvmCompilerSetBit(newBB->predecessors, curBB->id);
					dvmInsertGrowableList(blockList, (intptr_t) newBB);
				}
			}
		}/* 扫描基础块结束 */

		/* Now create a special block to host PC reconstruction code */
		/* 现在创建一个指定的基础块去重建本地代码 */
		curBB = dvmCompilerNewBB(kPCReconstruction, numBlocks++);
		dvmInsertGrowableList(blockList, (intptr_t) curBB);

		/* And one final block that publishes the PC and raise the exception */
		/* 增加一个开放给本地计算机并且跑出异常的最终的基础块 */
		curBB = dvmCompilerNewBB(kExceptionHandling, numBlocks++);
		dvmInsertGrowableList(blockList, (intptr_t) curBB);
		cUnit.puntBlock = curBB;

		/* 打印调试信息 */
		if (cUnit.printMe) {
			char* signature =
				dexProtoCopyMethodDescriptor(&desc->method->prototype);
			ALOGD("TRACEINFO (%d): 0x%08x %s%s.%s %#x %d of %d, %d blocks",
				compilationId,
				(intptr_t) desc->method->insns,
				desc->method->clazz->descriptor,
				desc->method->name,
				signature,
				desc->trace[0].info.frag.startOffset,
				traceSize,
				dexCode->insnsSize,
				numBlocks);
			free(signature);
		}

		/* 总共基本块的数量 */
		cUnit.numBlocks = numBlocks;

		/* Set the instruction set to use (NOTE: later components may change it) */
		/* 
		 * 设置指令集合
		 * dvmCompilerInstructionSet()这个函数是针对于不同的
		 * 硬件体系平台相对而言。每个平台都有不同的实现。
		 */
		cUnit.instructionSet = dvmCompilerInstructionSet();

		/* Inline transformation @ the MIR level */
		if (cUnit.hasInvoke && !(gDvmJit.disableOpt & (1 << kMethodInlining))) {
			dvmCompilerInlineMIR(&cUnit, info);
		}

		/* 当前使用函数使用寄存器的数量 */
		cUnit.numDalvikRegisters = cUnit.method->registersSize;

		/* Preparation for SSA conversion */
		/* 准备SSA转换 */
		dvmInitializeSSAConversion(&cUnit);

		/* 编译器无循环分析 */
		dvmCompilerNonLoopAnalysis(&cUnit);

#ifndef ARCH_IA32
		/* 在x86体系下需要初始化寄存器的分配 */
		dvmCompilerInitializeRegAlloc(&cUnit);  // Needs to happen after SSA naming
#endif

		/* 打印编译单元当前的信息 */
		if (cUnit.printMe) {
			dvmCompilerDumpCompilationUnit(&cUnit);
		}

#ifndef ARCH_IA32
		/* Allocate Registers using simple local allocation scheme */
		/* 分配寄存器的使用 */
		dvmCompilerLocalRegAlloc(&cUnit);

		/* Convert MIR to LIR, etc. */
		/* 转换MIR到LIR */
		dvmCompilerMIR2LIR(&cUnit);
#else /* ARCH_IA32 */
		/* Convert MIR to LIR, etc. */
		/* 转换MIR到LIR */
		dvmCompilerMIR2LIR(&cUnit, info);
#endif

		/* Convert LIR into machine code. Loop for recoverable retries */
		/* 转换LIR到机器代码 */
		do {
			/* 这里应该就是汇编代码 */
			dvmCompilerAssembleLIR(&cUnit, info);
			cUnit.assemblerRetries++;
			/* 调试标记开启或者汇编不成功则打印 */
			if (cUnit.printMe && cUnit.assemblerStatus != kSuccess)
				ALOGD("Assembler abort #%d on %d",cUnit.assemblerRetries,
					  cUnit.assemblerStatus);
		} while (cUnit.assemblerStatus == kRetryAll); /* 看来直到汇编成功为止 */

		/* 打印调试信息 */
		if (cUnit.printMe) {
			ALOGD("Trace Dalvik PC: %p", startCodePtr);
			dvmCompilerCodegenDump(&cUnit);
			ALOGD("End %s%s, %d Dalvik instructions",
				 desc->method->clazz->descriptor, desc->method->name,
				 cUnit.numInsts);
		}

		/* 
		 * 这里应该是当编译不成功时，进行的容错处理。
		 * 将指令数量减半，然后重新递归调用dvmCompilerTrace函数
		 */
		if (cUnit.assemblerStatus == kRetryHalve) {
			/* Reset the compiler resource pool before retry */
			/* 在重新尝试之前重新设置编译器资源池 */
			dvmCompilerArenaReset();

			/* Halve the instruction count and start from the top */
			/* 减半指令数量并且从顶端重新开始编译 */
			return dvmCompileTrace(desc, cUnit.numInsts / 2, info, bailPtr,
								   optHints);
		}

		/*
		 * If this trace uses class objects as constants,
		 * dvmJitInstallClassObjectPointers will switch the thread state
		 * to running and look up the class pointers using the descriptor/loader
		 * tuple stored in the callsite info structure. We need to make this window
		 * as short as possible since it is blocking GC.
		 */
		/*
		 * 如果这个trace使用类对象作为常量
		 * dvmJitInstallClassObjectPointers将交换线程状态到运行并且查找类指针使用描述符。
		 */
		if (cUnit.hasClassLiterals && info->codeAddress) {
			/* 
			 * 安装类对象指针
			 * dvmJitInstallClassObjectPointers()这个函数也是针对不同硬件平台而言的
			 */
			dvmJitInstallClassObjectPointers(&cUnit, (char *) info->codeAddress);
		}

		/*
		 * Since callsiteinfo is allocated from the arena, delay the reset until
		 * class pointers are resolved.
		 */
		/* 编译完成后重新设置所有编译资源池 */
		dvmCompilerArenaReset();

		assert(cUnit.assemblerStatus == kSuccess);
#if defined(WITH_JIT_TUNING)
		methodStats->nativeSize += cUnit.totalSize;
#endif

		return info->codeAddress != NULL;
	}
