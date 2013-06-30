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
Dalvik classfile verification.

Dalvik class类文件校验
*/
#ifndef DALVIK_DEXVERIFY_H_
#define DALVIK_DEXVERIFY_H_

/*
Global verification mode.  These must be in order from least verification
to most.  If we're using "exact GC", we may need to perform some of
the verification steps anyway.

全局校验模式。这些模式必须符合从少到多的校验。如果使用“精确GC”？那么不论
以何种方式都需要执行一些校验步骤。
*/
enum DexClassVerifyMode {
    VERIFY_MODE_UNKNOWN = 0, /* 未知校验模式 */
    VERIFY_MODE_NONE, /* 非校验模式 */
    VERIFY_MODE_REMOTE, /* 远程校验模式 */
    VERIFY_MODE_ALL /* ALL校验模式 */
};

/* 
some verifier counters, for debugging 

一些调试方法的校验计数器
*/
struct VerifierStats {
	  /*
	  方法检查计数
	  */
    size_t methodsExamined;    /* number of methods examined */
		/*
		监控进入方法计数
		*/
    size_t monEnterMethods;    /* number of methods with monitor-enter */
    /*
    指令检查计数 
    
    NOTE TODO：第一次指令访问增量计数
    */
    size_t instrsExamined;     /* incr on first visit of instruction */
    /*    
    NOTE TODO：每次重复指令访问的增量计数
    */
    size_t instrsReexamined;   /* incr on each repeat visit of instruction */
    /*
    从更新寄存器到拷贝寄存器时调用
    
    拷贝寄存器计数
    */
    size_t copyRegCount;       /* calls from updateRegisters->copyRegisters */
    /*
    从更新寄存器到合并寄存器时调用
    
    合并寄存器计数
    */
    size_t mergeRegCount;      /* calls from updateRegisters->merge */
    /*
    从更新寄存器到合并、已改变的寄存器时调用
    
    合并已改变寄存器计数
    */
    size_t mergeRegChanged;    /* calls from updateRegisters->merge, changed */
    /*
    检索未初始化表的次数    
    */
    size_t uninitSearches;     /* times we've had to search the uninit table */
    /*
    最大RegisterLine表分配空间的大小
    */
    size_t biggestAlloc;       /* largest RegisterLine table alloc */
};

/*
Certain types of instructions can be GC points.  To support precise
GC, all such instructions must export the PC in the interpreter,
or the GC won't be able to identify the current PC for the thread.

NOTE TODO：
*/
#define VERIFY_GC_INST_MASK (kInstrCanBranch | kInstrCanSwitch |\
                             kInstrCanThrow | kInstrCanReturn)

/*
Verify a single class.

校验类
*/
bool dvmVerifyClass(ClassObject* clazz);

/*
Release the storage associated with a RegisterMap.

释放寄存器集合(Map)空间
*/
void dvmFreeRegisterMap(RegisterMap* pMap);

#endif  // DALVIK_DEXVERIFY_H_
