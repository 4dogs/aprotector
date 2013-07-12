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

/* Arena内存块 */
static ArenaMemBlock *arenaHead, *currentArena;
static int numArenaBlocks;	/* Arena块数量 */

/* Allocate the initial memory block for arena-based allocation */
/**
 * @brief 对arena内存区域的初始化
 * @retval 0 失败
 * @retval 1 成功
 */
bool dvmCompilerHeapInit(void)
{
    assert(arenaHead == NULL);
    arenaHead =
        (ArenaMemBlock *) malloc(sizeof(ArenaMemBlock) + ARENA_DEFAULT_SIZE);
    if (arenaHead == NULL) {
        ALOGE("No memory left to create compiler heap memory");
        return false;
    }
    arenaHead->blockSize = ARENA_DEFAULT_SIZE;
    currentArena = arenaHead;
    currentArena->bytesAllocated = 0;
    currentArena->next = NULL;
    numArenaBlocks = 1;

    return true;
}

/* Arena-based malloc for compilation tasks */
void * dvmCompilerNew(size_t size, bool zero)
{
    size = (size + 3) & ~3;
retry:
    /* Normal case - space is available in the current page */
    if (size + currentArena->bytesAllocated <= currentArena->blockSize) {
        void *ptr;
        ptr = &currentArena->ptr[currentArena->bytesAllocated];
        currentArena->bytesAllocated += size;
        if (zero) {
            memset(ptr, 0, size);
        }
        return ptr;
    } else {
        /*
         * See if there are previously allocated arena blocks before the last
         * reset
         */
        if (currentArena->next) {
            currentArena = currentArena->next;
            goto retry;
        }

        size_t blockSize = (size < ARENA_DEFAULT_SIZE) ?
                          ARENA_DEFAULT_SIZE : size;
        /* Time to allocate a new arena */
        ArenaMemBlock *newArena = (ArenaMemBlock *)
            malloc(sizeof(ArenaMemBlock) + blockSize);
        if (newArena == NULL) {
            ALOGE("Arena allocation failure");
            dvmAbort();
        }
        newArena->blockSize = blockSize;
        newArena->bytesAllocated = 0;
        newArena->next = NULL;
        currentArena->next = newArena;
        currentArena = newArena;
        numArenaBlocks++;
        if (numArenaBlocks > 10)
            ALOGI("Total arena pages for JIT: %d", numArenaBlocks);
        goto retry;
    }
    /* Should not reach here */
    dvmAbort();
}

/* Reclaim all the arena blocks allocated so far */
/**
 * @brief 回收所有arena块分配的内存
 */
void dvmCompilerArenaReset(void)
{
    ArenaMemBlock *block;

    for (block = arenaHead; block; block = block->next) {
        block->bytesAllocated = 0;
    }
    currentArena = arenaHead;
}

/* Growable List initialization */
/**
 * @brief 初始化一个动态链表
 * @param gList 链表的头
 * @param initLength 初始化的数量
 */
void dvmInitGrowableList(GrowableList *gList, size_t initLength)
{
    gList->numAllocated = initLength;
    gList->numUsed = 0;
    gList->elemList = (intptr_t *) dvmCompilerNew(sizeof(intptr_t) * initLength,
                                                  true);
}

/* Expand the capacity of a growable list */
/**
 * @brief 扩展动态数组列表
 * @param gList 动态数组指针
 */
static void expandGrowableList(GrowableList *gList)
{
    int newLength = gList->numAllocated;
    if (newLength < 128) {
        newLength <<= 1;
    } else {
        newLength += 128;
    }
    intptr_t *newArray =
        (intptr_t *) dvmCompilerNew(sizeof(intptr_t) * newLength, true);
    memcpy(newArray, gList->elemList, sizeof(intptr_t) * gList->numAllocated);
    gList->numAllocated = newLength;
    gList->elemList = newArray;
}

/* Insert a new element into the growable list */
/**
 * @brief 插入一个新的元素到数组中
 * @param gList 链表的头指针
 * @param elem 元素的指针
 */
void dvmInsertGrowableList(GrowableList *gList, intptr_t elem)
{
    assert(gList->numAllocated != 0);
    if (gList->numUsed == gList->numAllocated) {
		/* 扩展数组内存 */
        expandGrowableList(gList);
    }
	/* 增加元素 */
    gList->elemList[gList->numUsed++] = elem;
}

/**
 * @brief 动态数据项初始化
 * @param gList 动态数组指针
 * @param iterator 数组元素指针
 */
void dvmGrowableListIteratorInit(GrowableList *gList,
                                 GrowableListIterator *iterator)
{
    iterator->list = gList;
    iterator->idx = 0;
    iterator->size = gList->numUsed;
}

/**
 * @brief 返回下一个动态数组的元素
 */
intptr_t dvmGrowableListIteratorNext(GrowableListIterator *iterator)
{
    assert(iterator->size == iterator->list->numUsed);
    if (iterator->idx == iterator->size) return 0;
    return iterator->list->elemList[iterator->idx++];
}

/**
 * @brief 获取数组元素
 * @param gList 动态数组指针
 * @param idx 元素索引
 */
intptr_t dvmGrowableListGetElement(const GrowableList *gList, size_t idx)
{
    assert(idx < gList->numUsed);
    return gList->elemList[idx];
}

/* Debug Utility - dump a compilation unit */
/**
 * @brief 打印一个编译单元
 * @param cUnit 编译单元指针
 */
void dvmCompilerDumpCompilationUnit(CompilationUnit *cUnit)
{
    BasicBlock *bb;
    const char *blockTypeNames[] = {
        "Normal Chaining Cell",			/* 正常的链接单元 */
        "Hot Chaining Cell",			/* 热点链接单元 */
        "Singleton Chaining Cell",		/* Singleton链接单元 */
        "Predicted Chaining Cell",		/* Predicted链接单元 */
        "Backward Branch",				/* 向后分支 */
        "Chaining Cell Gap",			/* 链接单元Gap */
        "N/A",							/* 无效 */
        "Entry Block",					/* 入口块 */
        "Code Block",					/* 代码块 */
        "Exit Block",					/* 退出块 */
        "PC Reconstruction",			/* PC 重构区域 */
        "Exception Handling",			/* 异常处理 */
    };

    ALOGD("Compiling %s %s", cUnit->method->clazz->descriptor,
         cUnit->method->name);			/* 打印类信息 */
    ALOGD("%d insns", dvmGetMethodInsnsSize(cUnit->method));		/* 打印函数指令数量 */
    ALOGD("%d blocks in total", cUnit->numBlocks);					/* 打印基本块数量 */
    GrowableListIterator iterator;

    dvmGrowableListIteratorInit(&cUnit->blockList, &iterator);

	/* 遍历基本块 */
    while (true) {
        bb = (BasicBlock *) dvmGrowableListIteratorNext(&iterator);		/* 下一个基本块 */
        if (bb == NULL) break;
		/* 打印基本块信息 */
        ALOGD("Block %d (%s) (insn %04x - %04x%s)",
             bb->id,
             blockTypeNames[bb->blockType],
             bb->startOffset,
             bb->lastMIRInsn ? bb->lastMIRInsn->offset : bb->startOffset,
             bb->lastMIRInsn ? "" : " empty");
        if (bb->taken) {
            ALOGD("  Taken branch: block %d (%04x)",
                 bb->taken->id, bb->taken->startOffset);
        }
        if (bb->fallThrough) {
            ALOGD("  Fallthrough : block %d (%04x)",
                 bb->fallThrough->id, bb->fallThrough->startOffset);
        }
    }
}

/*
 * dvmHashForeach callback.
 */
/**
 * @brief dvmHashForeach回调函数
 */
static int dumpMethodStats(void *compilerMethodStats, void *totalMethodStats)
{
    CompilerMethodStats *methodStats =
        (CompilerMethodStats *) compilerMethodStats;
    CompilerMethodStats *totalStats =
        (CompilerMethodStats *) totalMethodStats;

    totalStats->dalvikSize += methodStats->dalvikSize;
    totalStats->compiledDalvikSize += methodStats->compiledDalvikSize;
    totalStats->nativeSize += methodStats->nativeSize;

    /* Enable the following when fine-tuning the JIT performance */
#if 0
    int limit = (methodStats->dalvikSize >> 2) * 3;

    /* If over 3/4 of the Dalvik code is compiled, print something */
    if (methodStats->compiledDalvikSize >= limit) {
        ALOGD("Method stats: %s%s, %d/%d (compiled/total Dalvik), %d (native)",
             methodStats->method->clazz->descriptor,
             methodStats->method->name,
             methodStats->compiledDalvikSize,
             methodStats->dalvikSize,
             methodStats->nativeSize);
    }
#endif
    return 0;
}

/*
 * Dump the current stats of the compiler, including number of bytes used in
 * the code cache, arena size, and work queue length, and various JIT stats.
 */
/**
 * @brief 打印编译器状态
 */
void dvmCompilerDumpStats(void)
{
    CompilerMethodStats totalMethodStats;

    memset(&totalMethodStats, 0, sizeof(CompilerMethodStats));
    ALOGD("%d compilations using %d + %d bytes",
         gDvmJit.numCompilations,
         gDvmJit.templateSize,
         gDvmJit.codeCacheByteUsed - gDvmJit.templateSize);
    ALOGD("Compiler arena uses %d blocks (%d bytes each)",
         numArenaBlocks, ARENA_DEFAULT_SIZE);
    ALOGD("Compiler work queue length is %d/%d", gDvmJit.compilerQueueLength,
         gDvmJit.compilerMaxQueued);
	/* 打印JIT状态 */
    dvmJitStats();
    dvmCompilerArchDump();
    if (gDvmJit.methodStatsTable) {
        dvmHashForeach(gDvmJit.methodStatsTable, dumpMethodStats,
                       &totalMethodStats);
        ALOGD("Code size stats: %d/%d (compiled/total Dalvik), %d (native)",
             totalMethodStats.compiledDalvikSize,
             totalMethodStats.dalvikSize,
             totalMethodStats.nativeSize);
    }
}

/*
 * Allocate a bit vector with enough space to hold at least the specified
 * number of bits.
 *
 * NOTE: this is the sister implementation of dvmAllocBitVector. In this version
 * memory is allocated from the compiler arena.
 */
/**
 * @brief 分配一个位向量的内存
 * @param startBits
 * @param expandable 可扩展
 * @return 位向量指针
 */
BitVector* dvmCompilerAllocBitVector(unsigned int startBits, bool expandable)
{
    BitVector* bv;
    unsigned int count;

    assert(sizeof(bv->storage[0]) == 4);        /* assuming 32-bit units */

    bv = (BitVector*) dvmCompilerNew(sizeof(BitVector), false);

    count = (startBits + 31) >> 5;

    bv->storageSize = count;
    bv->expandable = expandable;
    bv->storage = (u4*) dvmCompilerNew(count * sizeof(u4), true);
    return bv;
}

/*
 * Mark the specified bit as "set".
 *
 * Returns "false" if the bit is outside the range of the vector and we're
 * not allowed to expand.
 *
 * NOTE: this is the sister implementation of dvmSetBit. In this version
 * memory is allocated from the compiler arena.
 */
/**
 * @brief 标记指定位作为"set"
 * @param pBits 位向量
 * @param num 第几个block
 * @retval 0 失败
 * @retval 1 成功
 * @note 返回0如果位在向量范围以外并且这里设计的不允许被扩展。
 *	这个是dvmSetBit的扩展实现。在这个版本中内存在arena区域分配。
 */
bool dvmCompilerSetBit(BitVector *pBits, unsigned int num)
{
    if (num >= pBits->storageSize * sizeof(u4) * 8) {
        if (!pBits->expandable)
            dvmAbort();

        /* Round up to word boundaries for "num+1" bits */
        unsigned int newSize = (num + 1 + 31) >> 5;
        assert(newSize > pBits->storageSize);
        u4 *newStorage = (u4*)dvmCompilerNew(newSize * sizeof(u4), false);
        memcpy(newStorage, pBits->storage, pBits->storageSize * sizeof(u4));
        memset(&newStorage[pBits->storageSize], 0,
               (newSize - pBits->storageSize) * sizeof(u4));
        pBits->storage = newStorage;
        pBits->storageSize = newSize;
    }

    pBits->storage[num >> 5] |= 1 << (num & 0x1f);
    return true;
}

/*
 * Mark the specified bit as "unset".
 *
 * Returns "false" if the bit is outside the range of the vector and we're
 * not allowed to expand.
 *
 * NOTE: this is the sister implementation of dvmClearBit. In this version
 * memory is allocated from the compiler arena.
 */
/**
 * @brief 清除位
 */
bool dvmCompilerClearBit(BitVector *pBits, unsigned int num)
{
    if (num >= pBits->storageSize * sizeof(u4) * 8) {
        ALOGE("Trying to clear a bit that is not set in the vector yet!");
        dvmAbort();
    }

    pBits->storage[num >> 5] &= ~(1 << (num & 0x1f));
    return true;
}

/*
 * If set is true, mark all bits as 1. Otherwise mark all bits as 0.
 */
/**
 * @brief 标记所有位
 */
void dvmCompilerMarkAllBits(BitVector *pBits, bool set)
{
    int value = set ? -1 : 0;
    memset(pBits->storage, value, pBits->storageSize * (int)sizeof(u4));
}

/**
 * @brief 调试位向量
 */
void dvmDebugBitVector(char *msg, const BitVector *bv, int length)
{
    int i;

    ALOGE("%s", msg);
    for (i = 0; i < length; i++) {
        if (dvmIsBitSet(bv, i)) {
            ALOGE("    Bit %d is set", i);
        }
    }
}

/**
 * @brief 编译器异常
 */
void dvmCompilerAbort(CompilationUnit *cUnit)
{
    ALOGE("Jit: aborting trace compilation, reverting to interpreter");
    /* Force a traceback in debug builds */
    assert(0);
    /*
     * Abort translation and force to interpret-only for this trace
     * Matching setjmp in compiler thread work loop in Compiler.c.
     */
    longjmp(*cUnit->bailPtr, 1);
}

/**
 * @brief 打印基本块的位向量
 */
void dvmDumpBlockBitVector(const GrowableList *blocks, char *msg,
                           const BitVector *bv, int length)
{
    int i;

    ALOGE("%s", msg);
    for (i = 0; i < length; i++) {
        if (dvmIsBitSet(bv, i)) {
            BasicBlock *bb =
                (BasicBlock *) dvmGrowableListGetElement(blocks, i);
            char blockName[BLOCK_NAME_LEN];
            dvmGetBlockName(bb, blockName);
            ALOGE("Bit %d / %s is set", i, blockName);
        }
    }
}

/**
 * @brief 获取块名称
 * @param bb 块指针
 * @param name 名称
 */ 
void dvmGetBlockName(BasicBlock *bb, char *name)
{
    switch (bb->blockType) {
        case kEntryBlock:
            snprintf(name, BLOCK_NAME_LEN, "entry");
            break;
        case kExitBlock:
            snprintf(name, BLOCK_NAME_LEN, "exit");
            break;
        case kDalvikByteCode:
            snprintf(name, BLOCK_NAME_LEN, "block%04x", bb->startOffset);
            break;
        case kChainingCellNormal:
            snprintf(name, BLOCK_NAME_LEN, "chain%04x", bb->startOffset);
            break;
        case kExceptionHandling:
            snprintf(name, BLOCK_NAME_LEN, "exception%04x", bb->startOffset);
            break;
        default:
            snprintf(name, BLOCK_NAME_LEN, "??");
            break;
    }
}
