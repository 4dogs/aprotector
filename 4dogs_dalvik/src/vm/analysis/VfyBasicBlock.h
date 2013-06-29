/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
Basic block functions, as used by the verifier.  (The names were chosen
to avoid conflicts with similar structures used by the compiler.)

基本（程序）块，供校验器使用。（为避免命名冲突，选择编译器使用的相同结构。）                      
*/
#ifndef DALVIK_VFYBASICBLOCK_H_
#define DALVIK_VFYBASICBLOCK_H_

#include "PointerSet.h"

struct VerifierData;


/*
Structure representing a basic block.

This is used for liveness analysis, which is a reverse-flow algorithm,
so we need to mantain a list of predecessors for each block.

"liveRegs" indicates the set of registers that are live at the end of
the basic block (after the last instruction has executed).  Successor
blocks will compare their results with this to see if this block needs
to be re-evaluated.  Note that this is not the same as the contents of
the RegisterLine for the last instruction in the block (which reflects
the state *before* the instruction has executed).

该结构代表一个基本程序块。

被使用于生命周期分析，采用反流算法，
因此我们需要维护一个原始程序块列表。

“liveRegs”标识基本程序块末尾的寄存器集合（在最后一条指令执行后）。后续的
代码块将使用它比较他们的结果来看该代码块是否需要重新评估。注意，作为代码
块最后一条指令的RegisterLine的内容是不同的（反映了指令执行前的状态）。

NOTE TODO：什么是反流算法reverse-flow algorithm
*/
struct VfyBasicBlock {
	  /*
	  第一条指令的地址
	  */
    u4              firstAddr;      /* address of first instruction */
    /*
    最后一条指令的地址
    */
    u4              lastAddr;       /* address of last instruction */
    /*
		流向这里的基本校验块的原始引用
    */
    PointerSet*     predecessors;   /* set of basic blocks that can flow here */
    /*
    每个寄存器的生命周期状态，BitVector是扩展bitmap,用于跟踪资源。
    */
    BitVector*      liveRegs;       /* liveness for each register */
    /*
    输入设置被改变，必须重新评估
    */
    bool            changed;        /* input set has changed, must re-eval */
    /*
    代码块至少被访问了一次
    */
    bool            visited;        /* block has been visited at least once */
};

/*
Generate a list of basic blocks.

生成基本块(s)列表
*/
bool dvmComputeVfyBasicBlocks(struct VerifierData* vdata);

/*
Free storage allocated by dvmComputeVfyBasicBlocks.

释放通过dvmComputeVfyBasicBlocks已分配的空间。
*/
void dvmFreeVfyBasicBlocks(struct VerifierData* vdata);

#endif  // DALVIK_VFYBASICBLOCK_H_
