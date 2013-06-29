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
#include "CompilerInternals.h"

/* Allocate a new basic block */
/**
 * @brief 分配一个指令基础块
 * @param blockType 指令块的类型
 * @param blockId 块的索引 
 * @return 返回一个BasicBlock的指针
 */ 
BasicBlock *dvmCompilerNewBB(BBType blockType, int blockId)
{
    BasicBlock *bb = (BasicBlock *)dvmCompilerNew(sizeof(BasicBlock), true);
    bb->blockType = blockType;
    bb->id = blockId;
    bb->predecessors = dvmCompilerAllocBitVector(blockId > 32 ? blockId : 32,
                                                 true /* expandable */);
    return bb;
}

/* Insert an MIR instruction to the end of a basic block */
/**
 * @brief 将一个MIR中间指令结构插入到指令基本块链表末尾
 * @param bb 指向一个BasicBlock链表的头
 * @param mir 指向一个MIR结构指针
 */
void dvmCompilerAppendMIR(BasicBlock *bb, MIR *mir)
{
    if (bb->firstMIRInsn == NULL) {
        assert(bb->lastMIRInsn == NULL);
        bb->lastMIRInsn = bb->firstMIRInsn = mir;
        mir->prev = mir->next = NULL;
    } else {
		/* 链表插入 */
        bb->lastMIRInsn->next = mir;
        mir->prev = bb->lastMIRInsn;
        mir->next = NULL;
        bb->lastMIRInsn = mir;
    }
}

/* Insert an MIR instruction to the head of a basic block */
/**
 * @brief 将一个MIR中间指令结构插入到指令基本块链表的头部
 * @param bb 指向一个基本块链表头
 * @param mir 指向一个MIR结构指针
 */
void dvmCompilerPrependMIR(BasicBlock *bb, MIR *mir)
{
    if (bb->firstMIRInsn == NULL) {
        assert(bb->lastMIRInsn == NULL);
        bb->lastMIRInsn = bb->firstMIRInsn = mir;
        mir->prev = mir->next = NULL;
    } else {
        bb->firstMIRInsn->prev = mir;
        mir->next = bb->firstMIRInsn;
        mir->prev = NULL;
        bb->firstMIRInsn = mir;
    }
}

/* Insert an MIR instruction after the specified MIR */
/**
 * @brief 插入一个MIR指令结果到一个指定的MIR结构之后
 * @param bb 指向基本块链表头
 * @param currentMIR 指定的MIR指针
 * @param newMIR 要插入的MIR指针
 */
void dvmCompilerInsertMIRAfter(BasicBlock *bb, MIR *currentMIR, MIR *newMIR)
{
    newMIR->prev = currentMIR;
    newMIR->next = currentMIR->next;
    currentMIR->next = newMIR;

    if (newMIR->next) {
        /* Is not the last MIR in the block */
        newMIR->next->prev = newMIR;
    } else {
        /* Is the last MIR in the block */
        bb->lastMIRInsn = newMIR;
    }
}

/*
 * Append an LIR instruction to the LIR list maintained by a compilation
 * unit
 */
void dvmCompilerAppendLIR(CompilationUnit *cUnit, LIR *lir)
{
    if (cUnit->firstLIRInsn == NULL) {
        assert(cUnit->lastLIRInsn == NULL);
        cUnit->lastLIRInsn = cUnit->firstLIRInsn = lir;
        lir->prev = lir->next = NULL;
    } else {
        cUnit->lastLIRInsn->next = lir;
        lir->prev = cUnit->lastLIRInsn;
        lir->next = NULL;
        cUnit->lastLIRInsn = lir;
    }
}

/*
 * Insert an LIR instruction before the current instruction, which cannot be the
 * first instruction.
 *
 * prevLIR <-> newLIR <-> currentLIR
 */
void dvmCompilerInsertLIRBefore(LIR *currentLIR, LIR *newLIR)
{
    assert(currentLIR->prev != NULL);
    LIR *prevLIR = currentLIR->prev;

    prevLIR->next = newLIR;
    newLIR->prev = prevLIR;
    newLIR->next = currentLIR;
    currentLIR->prev = newLIR;
}

/*
 * Insert an LIR instruction after the current instruction, which cannot be the
 * first instruction.
 *
 * currentLIR -> newLIR -> oldNext
 */
void dvmCompilerInsertLIRAfter(LIR *currentLIR, LIR *newLIR)
{
    newLIR->prev = currentLIR;
    newLIR->next = currentLIR->next;
    currentLIR->next = newLIR;
    newLIR->next->prev = newLIR;
}
