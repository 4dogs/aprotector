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
 * Dalvik classfile verification.  This file contains the verifier entry
 * points and the static constraint checks.
 */
#include "Dalvik.h"
#include "analysis/CodeVerify.h"
#include "libdex/DexCatch.h"


/* fwd */
static bool verifyMethod(Method* meth);
static bool verifyInstructions(VerifierData* vdata);


/*
Verify a class.

By the time we get here, the value of gDvm.classVerifyMode should already
have been factored in.  If you want to call into the verifier even
though verification is disabled, that's your business.

Returns "true" on success.

校验类

当调用到这个方法，gDvm.classVerifyMode类校验模式的值应该已经被做过处理。
虽然验证验证已被禁用，如果想要调用到校验器，做自己的处理实现。
*/
bool dvmVerifyClass(ClassObject* clazz)
{
    int i;
		
		/*
		根据类状态判断是否进过校验，不作双重校验
		*/
    if (dvmIsClassVerified(clazz)) {
        ALOGD("Ignoring duplicate verify attempt on %s", clazz->descriptor);
        return true;
    }

		/*
		校验类实例的所有直接方法
		*/
    for (i = 0; i < clazz->directMethodCount; i++) {
        if (!verifyMethod(&clazz->directMethods[i])) {
            LOG_VFY("Verifier rejected class %s", clazz->descriptor);
            return false;
        }
    }
		/*
		校验类实例的所有虚方法
		*/    
    for (i = 0; i < clazz->virtualMethodCount; i++) {
        if (!verifyMethod(&clazz->virtualMethods[i])) {
            LOG_VFY("Verifier rejected class %s", clazz->descriptor);
            return false;
        }
    }

    return true;
}


/*
Compute the width of the instruction at each address in the instruction
stream, and store it in vdata->insnFlags.  Addresses that are in the
middle of an instruction, or that are part of switch table data, are not
touched (so the caller should probably initialize "insnFlags" to zero).

The "newInstanceCount" and "monitorEnterCount" fields in vdata are
also set.

Performs some static checks, notably:
- opcode of first instruction begins at index 0
- only documented instructions may appear
- each instruction follows the last
- last byte of last instruction is at (code_length-1)

Logs an error and returns "false" on failure.

计算指令流中每个地址上指令的宽度，并且存储在 vdata->insnFlags。在指令中间的地址，
或者部分switch表数据的地址，不做处理（因此调用者应该正确初始化“insnFlags”到0）。

在vdata中的“newInstanceCount”和“monitorEnterCount”域也要设置值。

执行一些静态检查，值得注意的是：
- 第一条指令操作码从索引0开始
- 只有记录过的指令可以出现
- 每个指令跟在最后面	
- 最后一条指令的最后字节是在（code_length-1）

失败时记录错误并返回“false”。
*/
static bool computeWidthsAndCountOps(VerifierData* vdata)
{
    const Method* meth = vdata->method;
    InsnFlags* insnFlags = vdata->insnFlags;
    size_t insnCount = vdata->insnsSize;
    const u2* insns = meth->insns;
    bool result = false;
    int newInstanceCount = 0;
    int monitorEnterCount = 0;
    int i;

    for (i = 0; i < (int) insnCount; /**/) {
        size_t width = dexGetWidthFromInstruction(insns);
        if (width == 0) {
            LOG_VFY_METH(meth, "VFY: invalid instruction (0x%04x)", *insns);
            goto bail;
        } else if (width > 65535) {
            LOG_VFY_METH(meth,
                "VFY: warning: unusually large instr width (%d)", width);
        }
        /* CodeUnit代码单元（对应第一个问题）
        即使dex文件映射在内存和指令一一对应的实际字节码，可以这样说，进过解析转码后的字节码是操作码，
        之前的是代码单元。
        */
        Opcode opcode = dexOpcodeFromCodeUnit(*insns);
        if (opcode == OP_NEW_INSTANCE)
            newInstanceCount++;
        if (opcode == OP_MONITOR_ENTER)
            monitorEnterCount++;

        insnFlags[i] |= width;
        i += width;
        insns += width;
    }
    if (i != (int) vdata->insnsSize) {
        LOG_VFY_METH(meth, "VFY: code did not end where expected (%d vs. %d)",
            i, dvmGetMethodInsnsSize(meth));
        goto bail;
    }

    result = true;
    vdata->newInstanceCount = newInstanceCount;
    vdata->monitorEnterCount = monitorEnterCount;

bail:
    return result;
}

/*
Set the "in try" flags for all instructions protected by "try" statements.
Also sets the "branch target" flags for exception handlers.

Call this after widths have been set in "insnFlags".

Returns "false" if something in the exception table looks fishy, but
we're expecting the exception table to be somewhat sane.

对被“try”声明保护的所有指令的设置"in try"标识。同时为异常句柄设置“branch target(分支目标)”
标识。

在宽度被设置“inFlags”后调用。

返回“false”，如果异常表中出现可疑的东西，我们期望它能有点理智。
*/
static bool scanTryCatchBlocks(const Method* meth, InsnFlags* insnFlags)
{
    u4 insnsSize = dvmGetMethodInsnsSize(meth);
    const DexCode* pCode = dvmGetMethodCode(meth);
    u4 triesSize = pCode->triesSize;
    const DexTry* pTries;
    u4 idx;

    if (triesSize == 0) {
        return true;
    }

    pTries = dexGetTries(pCode);

    for (idx = 0; idx < triesSize; idx++) {
        const DexTry* pTry = &pTries[idx];
        u4 start = pTry->startAddr;
        u4 end = start + pTry->insnCount;
        u4 addr;

        if ((start >= end) || (start >= insnsSize) || (end > insnsSize)) {
            LOG_VFY_METH(meth,
                "VFY: bad exception entry: startAddr=%d endAddr=%d (size=%d)",
                start, end, insnsSize);
            return false;
        }

        if (dvmInsnGetWidth(insnFlags, start) == 0) {
            LOG_VFY_METH(meth,
                "VFY: 'try' block starts inside an instruction (%d)",
                start);
            return false;
        }

        for (addr = start; addr < end;
            addr += dvmInsnGetWidth(insnFlags, addr))
        {
            assert(dvmInsnGetWidth(insnFlags, addr) != 0);
            dvmInsnSetInTry(insnFlags, addr, true);
        }
    }

    /* Iterate over each of the handlers to verify target addresses. */
    u4 handlersSize = dexGetHandlersSize(pCode);
    u4 offset = dexGetFirstHandlerOffset(pCode);
    for (idx = 0; idx < handlersSize; idx++) {
        DexCatchIterator iterator;
        dexCatchIteratorInit(&iterator, pCode, offset);

        for (;;) {
            DexCatchHandler* handler = dexCatchIteratorNext(&iterator);
            u4 addr;

            if (handler == NULL) {
                break;
            }

            addr = handler->address;
            if (dvmInsnGetWidth(insnFlags, addr) == 0) {
                LOG_VFY_METH(meth,
                    "VFY: exception handler starts at bad address (%d)",
                    addr);
                return false;
            }

            dvmInsnSetBranchTarget(insnFlags, addr, true);
        }

        offset = dexCatchIteratorGetEndOffset(&iterator, pCode);
    }

    return true;
}

/*
Perform verification on a single method.

执行单个方法的校验

We do this in three passes:
 (1) Walk through all code units, determining instruction locations,
     widths, and other characteristics.
 (2) Walk through all code units, performing static checks on
     operands.
 (3) Iterate through the method, checking type safety and looking
     for code flow problems.

校验分3次处理：
 (1) 遍历所有代码单元，确定指令位置，宽度，和其它特征。
 (2) 遍历所有代码单元，对操作码执行静态检查。
 (3) 通过方法迭代，检查类型安全并且寻找代码流的问题。

Some checks may be bypassed depending on the verification mode.  We can't
turn this stuff off completely if we want to do "exact" GC.

一些检查可以避免，这取决于校验模式。我们不能完全关闭这些校验，如果想做“精确”的垃圾回收。

TODO: cite source?
Confirmed here:
- code array must not be empty
- (N/A) code_length must be less than 65536
Confirmed by computeWidthsAndCountOps():
- opcode of first instruction begins at index 0
- only documented instructions may appear
- each instruction follows the last
- last byte of last instruction is at (code_length-1)


*/
static bool verifyMethod(Method* meth)
{
    bool result = false;

    /*
    Verifier state blob.  Various values will be cached here so we
    can avoid expensive lookups and pass fewer arguments around.
    
    数据校验器数据结构体。不同的值将被缓存到这里，因此我们可以通过极少的参数进行更有效查找。
    
    可以缓存数据。数据结构参见于CodeVerify.h头文件。
    */
    VerifierData vdata;
#if 1   // ndef NDEBUG
    memset(&vdata, 0x99, sizeof(vdata));
#endif
    
    // 校验器数据初始化
    vdata.method = meth;
    vdata.insnsSize = dvmGetMethodInsnsSize(meth);
    vdata.insnRegCount = meth->registersSize;
    vdata.insnFlags = NULL;
    vdata.uninitMap = NULL;
    vdata.basicBlocks = NULL;

    /*
    If there aren't any instructions, make sure that's expected, then
    exit successfully.  Note: for native methods, meth->insns gets set
    to a native function pointer on first call, so don't use that as
    an indicator.
    
    如果没有任何指令，确保本地方法和抽象方法均可被访问，
    然后成功退出。
    */
    if (vdata.insnsSize == 0) {
        if (!dvmIsNativeMethod(meth) && !dvmIsAbstractMethod(meth)) {
            LOG_VFY_METH(meth,
                "VFY: zero-length code in concrete non-native method");
            goto bail;
        }

        goto success;
    }

    /*
    Sanity-check the register counts.  ins + locals = registers, so make
    sure that ins <= registers.
    
    校验寄存器个数。 指令寄存器ins + 本地寄存器locals = All，因此确保指令寄存器<= All。
    */
    if (meth->insSize > meth->registersSize) {
        LOG_VFY_METH(meth, "VFY: bad register counts (ins=%d regs=%d)",
            meth->insSize, meth->registersSize);
        goto bail;
    }

    /*
    Allocate and populate an array to hold instruction data.
    
    TODO: Consider keeping a reusable pre-allocated array sitting
    around for smaller methods.
    
    给指令分配空间
    */
    vdata.insnFlags = (InsnFlags*) calloc(vdata.insnsSize, sizeof(InsnFlags));
    if (vdata.insnFlags == NULL)
        goto bail;

    /*
    Compute the width of each instruction and store the result in insnFlags.
    Count up the #of occurrences of certain opcodes while we're at it.
    
    计算每条指令宽度并且存储 insnFlags 中的结果。
    */
    if (!computeWidthsAndCountOps(&vdata))
        goto bail;

    /*
    Allocate a map to hold the classes of uninitialized instances.
    
    分配一个map来持有未初始化的实例的类(s)
    */
    vdata.uninitMap = dvmCreateUninitInstanceMap(meth, vdata.insnFlags,
        vdata.newInstanceCount);
    if (vdata.uninitMap == NULL)
        goto bail;

    /*
    Set the "in try" flags for all instructions guarded by a "try" block.
    Also sets the "branch target" flag on exception handlers.
    
    对所有try块指令设置“in try”标识。
    同时在异常句柄处设置“branch target”标识。
    */
    if (!scanTryCatchBlocks(meth, vdata.insnFlags))
        goto bail;

    /*
    Perform static instruction verification.  Also sets the "branch
    target" flags.
    
    执行静态校验。同时设置“brach target”标识。
    */
    if (!verifyInstructions(&vdata))
        goto bail;

    /*
    Do code-flow analysis.
    
    We could probably skip this for a method with no registers, but
    that's so rare that there's little point in checking.
    
    做代码流分析
    
    也许可能会跳过一个没有寄存器的方法，但这种情况不见罕见，没有必要检查。
    */
    if (!dvmVerifyCodeFlow(&vdata)) {
        //ALOGD("+++ %s failed code flow", meth->name);
        goto bail;
    }

success:
    result = true;

bail:
    dvmFreeVfyBasicBlocks(&vdata);
    dvmFreeUninitInstanceMap(vdata.uninitMap);
    free(vdata.insnFlags);
    return result;
}


/*
Verify an array data table.  "curOffset" is the offset of the
fill-array-data instruction.

校验一个数组数据表。“curOffset”是fill-array-data指令的偏移。
*/
static bool checkArrayData(const Method* meth, u4 curOffset)
{
    const u4 insnCount = dvmGetMethodInsnsSize(meth);
    const u2* insns = meth->insns + curOffset;
    const u2* arrayData;
    u4 valueCount, valueWidth, tableSize;
    s4 offsetToArrayData;

    assert(curOffset < insnCount);

    /* 
    make sure the start of the array data table is in range 
    
    确保数组数据table的起始在范围之内。
    */
    offsetToArrayData = insns[1] | (((s4)insns[2]) << 16);
    if ((s4)curOffset + offsetToArrayData < 0 ||
        curOffset + offsetToArrayData + 2 >= insnCount)
    {
        LOG_VFY("VFY: invalid array data start: at %d, data offset %d, "
                "count %d",
            curOffset, offsetToArrayData, insnCount);
        return false;
    }

    /* 
    offset to array data table is a relative branch-style offset 
    
    数组数据table的偏移是一个相对branch-style偏移
    */
    arrayData = insns + offsetToArrayData;

    /* 
    make sure the table is 32-bit aligned 
    
    确保table是32位对齐。
    */
    if ((((u4) arrayData) & 0x03) != 0) {
        LOG_VFY("VFY: unaligned array data table: at %d, data offset %d",
            curOffset, offsetToArrayData);
        return false;
    }

    valueWidth = arrayData[1];
    valueCount = *(u4*)(&arrayData[2]);

    tableSize = 4 + (valueWidth * valueCount + 1) / 2;

    /* 
    make sure the end of the switch is in range 
    
    确保switch尾部在范围内
    */
    if (curOffset + offsetToArrayData + tableSize > insnCount) {
        LOG_VFY("VFY: invalid array data end: at %d, data offset %d, end %d, "
                "count %d",
            curOffset, offsetToArrayData,
            curOffset + offsetToArrayData + tableSize, insnCount);
        return false;
    }

    return true;
}

/*
Perform static checks on a "new-instance" instruction.  Specifically,
make sure the class reference isn't for an array class.

We don't need the actual class, just a pointer to the class name.

对“new-instance”指令执行静态检查。具体来说，确保类引用不是一个数组类。

不需要真实的类，只是类名指针就可以。
*/
static bool checkNewInstance(const DvmDex* pDvmDex, u4 idx)
{
    const char* classDescriptor;

    if (idx >= pDvmDex->pHeader->typeIdsSize) {
        LOG_VFY("VFY: bad type index %d (max %d)",
            idx, pDvmDex->pHeader->typeIdsSize);
        return false;
    }

    classDescriptor = dexStringByTypeIdx(pDvmDex->pDexFile, idx);
    if (classDescriptor[0] != 'L') {
        LOG_VFY("VFY: can't call new-instance on type '%s'",
            classDescriptor);
        return false;
    }

    return true;
}

/*
Perform static checks on a "new-array" instruction.  Specifically, make
sure they aren't creating an array of arrays that causes the number of
dimensions to exceed 255.

对“new-instance”指令执行静态检查。具体来说，确保不会创建数组的维数超过255的数组
*/
static bool checkNewArray(const DvmDex* pDvmDex, u4 idx)
{
    const char* classDescriptor;

    if (idx >= pDvmDex->pHeader->typeIdsSize) {
        LOG_VFY("VFY: bad type index %d (max %d)",
            idx, pDvmDex->pHeader->typeIdsSize);
        return false;
    }

    classDescriptor = dexStringByTypeIdx(pDvmDex->pDexFile, idx);

    int bracketCount = 0;
    const char* cp = classDescriptor;
    while (*cp++ == '[')
        bracketCount++;

    if (bracketCount == 0) {
        /* The given class must be an array type. */
        LOG_VFY("VFY: can't new-array class '%s' (not an array)",
            classDescriptor);
        return false;
    } else if (bracketCount > 255) {
        /* It is illegal to create an array of more than 255 dimensions. */
        LOG_VFY("VFY: can't new-array class '%s' (exceeds limit)",
            classDescriptor);
        return false;
    }

    return true;
}

/*
Perform static checks on an instruction that takes a class constant.
Ensure that the class index is in the valid range.

NOTE TODO：
*/
static bool checkTypeIndex(const DvmDex* pDvmDex, u4 idx)
{
    if (idx >= pDvmDex->pHeader->typeIdsSize) {
        LOG_VFY("VFY: bad type index %d (max %d)",
            idx, pDvmDex->pHeader->typeIdsSize);
        return false;
    }
    return true;
}

/*
Perform static checks on a field get or set instruction.  All we do
here is ensure that the field index is in the valid range.

对一个域的get和set指令做静态检查。
这里做的所有工作是为了确保字段索引在有效范围内。
*/
static bool checkFieldIndex(const DvmDex* pDvmDex, u4 idx)
{
    if (idx >= pDvmDex->pHeader->fieldIdsSize) {
        LOG_VFY("VFY: bad field index %d (max %d)",
            idx, pDvmDex->pHeader->fieldIdsSize);
        return false;
    }
    return true;
}

/*
Perform static checks on a method invocation instruction.  All we do
here is ensure that the method index is in the valid range.

对一个方法反射指令做静态检查。
这里做的所有工作是为了确保方法索引在有效范围内。
*/
static bool checkMethodIndex(const DvmDex* pDvmDex, u4 idx)
{
    if (idx >= pDvmDex->pHeader->methodIdsSize) {
        LOG_VFY("VFY: bad method index %d (max %d)",
            idx, pDvmDex->pHeader->methodIdsSize);
        return false;
    }
    return true;
}

/*
Ensure that the string index is in the valid range.

确保字符串索引在有效范围内。
*/
static bool checkStringIndex(const DvmDex* pDvmDex, u4 idx)
{
    if (idx >= pDvmDex->pHeader->stringIdsSize) {
        LOG_VFY("VFY: bad string index %d (max %d)",
            idx, pDvmDex->pHeader->stringIdsSize);
        return false;
    }
    return true;
}

/*
Ensure that the register index is valid for this method.

确保方法的寄存器索引有效。
*/
static bool checkRegisterIndex(const Method* meth, u4 idx)
{
    if (idx >= meth->registersSize) {
        LOG_VFY("VFY: register index out of range (%d >= %d)",
            idx, meth->registersSize);
        return false;
    }
    return true;
}

/*
Ensure that the wide register index is valid for this method.

确保方法的宽寄存器索引有效。
*/
static bool checkWideRegisterIndex(const Method* meth, u4 idx)
{
    if (idx+1 >= meth->registersSize) {
        LOG_VFY("VFY: wide register index out of range (%d+1 >= %d)",
            idx, meth->registersSize);
        return false;
    }
    return true;
}

/*
Check the register indices used in a "vararg" instruction, such as
invoke-virtual or filled-new-array.

检查用于“vararg”指令的寄存器标记，例如：invoke-virtual 或 filled-new-array

vA holds word count (0-5), args[] have values.

NOTE TODO：

There are some tests we don't do here, e.g. we don't try to verify
that invoking a method that takes a double is done with consecutive
registers.  This requires parsing the target method signature, which
we will be doing later on during the code flow analysis.

NOTE TODO：
*/
static bool checkVarargRegs(const Method* meth,
    const DecodedInstruction* pDecInsn)
{
    u2 registersSize = meth->registersSize;
    unsigned int idx;

    if (pDecInsn->vA > 5) {
        LOG_VFY("VFY: invalid arg count (%d) in non-range invoke)",
            pDecInsn->vA);
        return false;
    }

    for (idx = 0; idx < pDecInsn->vA; idx++) {
        if (pDecInsn->arg[idx] > registersSize) {
            LOG_VFY("VFY: invalid reg index (%d) in non-range invoke (> %d)",
                pDecInsn->arg[idx], registersSize);
            return false;
        }
    }

    return true;
}

/*
Check the register indices used in a "vararg/range" instruction, such as
invoke-virtual/range or filled-new-array/range.

vA holds word count, vC holds index of first reg.

检查寄存器索引

NOTE TODO：
*/
static bool checkVarargRangeRegs(const Method* meth,
    const DecodedInstruction* pDecInsn)
{
    u2 registersSize = meth->registersSize;

    /*
     * vA/vC are unsigned 8-bit/16-bit quantities for /range instructions,
     * so there's no risk of integer overflow when adding them here.
     */
    if (pDecInsn->vA + pDecInsn->vC > registersSize) {
        LOG_VFY("VFY: invalid reg index %d+%d in range invoke (> %d)",
            pDecInsn->vA, pDecInsn->vC, registersSize);
        return false;
    }

    return true;
}

/*
Verify a switch table.  "curOffset" is the offset of the switch
instruction.

Updates "insnFlags", setting the "branch target" flag.

校验一个分支table。“curOffset”是分支指令偏移。

更新“insnFlags”，设置“branch target“”标识。
*/
static bool checkSwitchTargets(const Method* meth, InsnFlags* insnFlags,
    u4 curOffset)
{
    const u4 insnCount = dvmGetMethodInsnsSize(meth);
    const u2* insns = meth->insns + curOffset;
    const u2* switchInsns;
    u2 expectedSignature;
    u4 switchCount, tableSize;
    s4 offsetToSwitch, offsetToKeys, offsetToTargets;
    s4 offset, absOffset;
    u4 targ;

    assert(curOffset < insnCount);

    /* make sure the start of the switch is in range */
    offsetToSwitch = insns[1] | ((s4) insns[2]) << 16;
    if ((s4) curOffset + offsetToSwitch < 0 ||
        curOffset + offsetToSwitch + 2 >= insnCount)
    {
        LOG_VFY("VFY: invalid switch start: at %d, switch offset %d, "
                "count %d",
            curOffset, offsetToSwitch, insnCount);
        return false;
    }

    /* offset to switch table is a relative branch-style offset */
    switchInsns = insns + offsetToSwitch;

    /* make sure the table is 32-bit aligned */
    if ((((u4) switchInsns) & 0x03) != 0) {
        LOG_VFY("VFY: unaligned switch table: at %d, switch offset %d",
            curOffset, offsetToSwitch);
        return false;
    }

    switchCount = switchInsns[1];

    if ((*insns & 0xff) == OP_PACKED_SWITCH) {
        /* 0=sig, 1=count, 2/3=firstKey */
        offsetToTargets = 4;
        offsetToKeys = -1;
        expectedSignature = kPackedSwitchSignature;
    } else {
        /* 0=sig, 1=count, 2..count*2 = keys */
        offsetToKeys = 2;
        offsetToTargets = 2 + 2*switchCount;
        expectedSignature = kSparseSwitchSignature;
    }
    tableSize = offsetToTargets + switchCount*2;

    if (switchInsns[0] != expectedSignature) {
        LOG_VFY("VFY: wrong signature for switch table (0x%04x, wanted 0x%04x)",
            switchInsns[0], expectedSignature);
        return false;
    }

    /* make sure the end of the switch is in range */
    if (curOffset + offsetToSwitch + tableSize > (u4) insnCount) {
        LOG_VFY("VFY: invalid switch end: at %d, switch offset %d, end %d, "
                "count %d",
            curOffset, offsetToSwitch, curOffset + offsetToSwitch + tableSize,
            insnCount);
        return false;
    }

    /* for a sparse switch, verify the keys are in ascending order */
    if (offsetToKeys > 0 && switchCount > 1) {
        s4 lastKey;

        lastKey = switchInsns[offsetToKeys] |
                  (switchInsns[offsetToKeys+1] << 16);
        for (targ = 1; targ < switchCount; targ++) {
            s4 key = (s4) switchInsns[offsetToKeys + targ*2] |
                    (s4) (switchInsns[offsetToKeys + targ*2 +1] << 16);
            if (key <= lastKey) {
                LOG_VFY("VFY: invalid packed switch: last key=%d, this=%d",
                    lastKey, key);
                return false;
            }

            lastKey = key;
        }
    }

    /* verify each switch target */
    for (targ = 0; targ < switchCount; targ++) {
        offset = (s4) switchInsns[offsetToTargets + targ*2] |
                (s4) (switchInsns[offsetToTargets + targ*2 +1] << 16);
        absOffset = curOffset + offset;

        if (absOffset < 0 || absOffset >= (s4)insnCount ||
            !dvmInsnIsOpcode(insnFlags, absOffset))
        {
            LOG_VFY("VFY: invalid switch target %d (-> %#x) at %#x[%d]",
                offset, absOffset, curOffset, targ);
            return false;
        }
        dvmInsnSetBranchTarget(insnFlags, absOffset, true);
    }

    return true;
}

/*
Verify that the target of a branch instruction is valid.

We don't expect code to jump directly into an exception handler, but
it's valid to do so as long as the target isn't a "move-exception"
instruction.  We verify that in a later stage.

The VM spec doesn't forbid an instruction from branching to itself,
but the Dalvik spec declares that only certain instructions can do so.

Updates "insnFlags", setting the "branch target" flag.

校验分支指令目标是否有效
*/
static bool checkBranchTarget(const Method* meth, InsnFlags* insnFlags,
    int curOffset, bool selfOkay)
{
    const int insnCount = dvmGetMethodInsnsSize(meth);
    s4 offset, absOffset;
    bool isConditional;

    if (!dvmGetBranchOffset(meth, insnFlags, curOffset, &offset,
            &isConditional))
        return false;

    if (!selfOkay && offset == 0) {
        LOG_VFY_METH(meth, "VFY: branch offset of zero not allowed at %#x",
            curOffset);
        return false;
    }

    /*
    Check for 32-bit overflow.  This isn't strictly necessary if we can
    depend on the VM to have identical "wrap-around" behavior, but
    it's unwise to depend on that.
    
		检查32位溢出。    
    */
    if (((s8) curOffset + (s8) offset) != (s8)(curOffset + offset)) {
        LOG_VFY_METH(meth, "VFY: branch target overflow %#x +%d",
            curOffset, offset);
        return false;
    }
    absOffset = curOffset + offset;
    if (absOffset < 0 || absOffset >= insnCount ||
        !dvmInsnIsOpcode(insnFlags, absOffset))
    {
        LOG_VFY_METH(meth,
            "VFY: invalid branch target %d (-> %#x) at %#x",
            offset, absOffset, curOffset);
        return false;
    }
    dvmInsnSetBranchTarget(insnFlags, absOffset, true);

    return true;
}


/*
Perform static verification on instructions.

As a side effect, this sets the "branch target" flags in InsnFlags.

"(CF)" items are handled during code-flow analysis.

v3 4.10.1
- target of each jump and branch instruction must be valid
- targets of switch statements must be valid
- operands referencing constant pool entries must be valid
- (CF) operands of getfield, putfield, getstatic, putstatic must be valid
- (new) verify operands of "quick" field ops
- (CF) operands of method invocation instructions must be valid
- (new) verify operands of "quick" method invoke ops
- (CF) only invoke-direct can call a method starting with '<'
- (CF) <clinit> must never be called explicitly
- operands of instanceof, checkcast, new (and variants) must be valid
- new-array[-type] limited to 255 dimensions
- can't use "new" on an array class
- (?) limit dimensions in multi-array creation
- local variable load/store register values must be in valid range

v3 4.11.1.2
- branches must be within the bounds of the code array
- targets of all control-flow instructions are the start of an instruction
- register accesses fall within range of allocated registers
- (N/A) access to constant pool must be of appropriate type
- code does not end in the middle of an instruction
- execution cannot fall off the end of the code
- (earlier) for each exception handler, the "try" area must begin and
  end at the start of an instruction (end can be at the end of the code)
- (earlier) for each exception handler, the handler must start at a valid
  instruction
  
执行指令的静态检查。
 */
static bool verifyInstructions(VerifierData* vdata)
{
    const Method* meth = vdata->method;
    const DvmDex* pDvmDex = meth->clazz->pDvmDex;
    InsnFlags* insnFlags = vdata->insnFlags;
    const u2* insns = meth->insns;
    unsigned int codeOffset;

    /* the start of the method is a "branch target" */
    /* 方法起始是一个分支目标 */    
    dvmInsnSetBranchTarget(insnFlags, 0, true);

    for (codeOffset = 0; codeOffset < vdata->insnsSize; /**/) {
        /*
        Pull the instruction apart.
        
        将指令分开。
        */
        int width = dvmInsnGetWidth(insnFlags, codeOffset);
        DecodedInstruction decInsn;
        bool okay = true;

        dexDecodeInstruction(meth->insns + codeOffset, &decInsn);

        /*
        Check register, type, class, field, method, and string indices
        for out-of-range values.  Do additional checks on branch targets
        and some special cases like new-instance and new-array.
        
        检查寄存器，类型，类，域，方法，字符串索引下标越界。
        在分支目标上做额外检查和一些特殊的情况，如：new-instance 和 new-array。
        */
        switch (decInsn.opcode) {
        case OP_NOP:
        case OP_RETURN_VOID:
            /* nothing to check */
            /* 不做任何检查 */            
            break;
        case OP_MOVE_RESULT:
        case OP_MOVE_RESULT_OBJECT:
        case OP_MOVE_EXCEPTION:
        case OP_RETURN:
        case OP_RETURN_OBJECT:
        case OP_CONST_4:
        case OP_CONST_16:
        case OP_CONST:
        case OP_CONST_HIGH16:
        case OP_MONITOR_ENTER:
        case OP_MONITOR_EXIT:
        case OP_THROW:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            break;
        case OP_MOVE_RESULT_WIDE:
        case OP_RETURN_WIDE:
        case OP_CONST_WIDE_16:
        case OP_CONST_WIDE_32:
        case OP_CONST_WIDE:
        case OP_CONST_WIDE_HIGH16:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            break;
        case OP_GOTO:
        case OP_GOTO_16:
            okay &= checkBranchTarget(meth, insnFlags, codeOffset, false);
            break;
        case OP_GOTO_32:
            okay &= checkBranchTarget(meth, insnFlags, codeOffset, true);
            break;
        case OP_MOVE:
        case OP_MOVE_FROM16:
        case OP_MOVE_16:
        case OP_MOVE_OBJECT:
        case OP_MOVE_OBJECT_FROM16:
        case OP_MOVE_OBJECT_16:
        case OP_ARRAY_LENGTH:
        case OP_NEG_INT:
        case OP_NOT_INT:
        case OP_NEG_FLOAT:
        case OP_INT_TO_FLOAT:
        case OP_FLOAT_TO_INT:
        case OP_INT_TO_BYTE:
        case OP_INT_TO_CHAR:
        case OP_INT_TO_SHORT:
        case OP_ADD_INT_2ADDR:
        case OP_SUB_INT_2ADDR:
        case OP_MUL_INT_2ADDR:
        case OP_DIV_INT_2ADDR:
        case OP_REM_INT_2ADDR:
        case OP_AND_INT_2ADDR:
        case OP_OR_INT_2ADDR:
        case OP_XOR_INT_2ADDR:
        case OP_SHL_INT_2ADDR:
        case OP_SHR_INT_2ADDR:
        case OP_USHR_INT_2ADDR:
        case OP_ADD_FLOAT_2ADDR:
        case OP_SUB_FLOAT_2ADDR:
        case OP_MUL_FLOAT_2ADDR:
        case OP_DIV_FLOAT_2ADDR:
        case OP_REM_FLOAT_2ADDR:
        case OP_ADD_INT_LIT16:
        case OP_RSUB_INT:
        case OP_MUL_INT_LIT16:
        case OP_DIV_INT_LIT16:
        case OP_REM_INT_LIT16:
        case OP_AND_INT_LIT16:
        case OP_OR_INT_LIT16:
        case OP_XOR_INT_LIT16:
        case OP_ADD_INT_LIT8:
        case OP_RSUB_INT_LIT8:
        case OP_MUL_INT_LIT8:
        case OP_DIV_INT_LIT8:
        case OP_REM_INT_LIT8:
        case OP_AND_INT_LIT8:
        case OP_OR_INT_LIT8:
        case OP_XOR_INT_LIT8:
        case OP_SHL_INT_LIT8:
        case OP_SHR_INT_LIT8:
        case OP_USHR_INT_LIT8:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            break;
        case OP_INT_TO_LONG:
        case OP_INT_TO_DOUBLE:
        case OP_FLOAT_TO_LONG:
        case OP_FLOAT_TO_DOUBLE:
        case OP_SHL_LONG_2ADDR:
        case OP_SHR_LONG_2ADDR:
        case OP_USHR_LONG_2ADDR:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            break;
        case OP_LONG_TO_INT:
        case OP_LONG_TO_FLOAT:
        case OP_DOUBLE_TO_INT:
        case OP_DOUBLE_TO_FLOAT:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkWideRegisterIndex(meth, decInsn.vB);
            break;
        case OP_MOVE_WIDE:
        case OP_MOVE_WIDE_FROM16:
        case OP_MOVE_WIDE_16:
        case OP_DOUBLE_TO_LONG:
        case OP_LONG_TO_DOUBLE:
        case OP_NEG_DOUBLE:
        case OP_NEG_LONG:
        case OP_NOT_LONG:
        case OP_ADD_LONG_2ADDR:
        case OP_SUB_LONG_2ADDR:
        case OP_MUL_LONG_2ADDR:
        case OP_DIV_LONG_2ADDR:
        case OP_REM_LONG_2ADDR:
        case OP_AND_LONG_2ADDR:
        case OP_OR_LONG_2ADDR:
        case OP_XOR_LONG_2ADDR:
        case OP_ADD_DOUBLE_2ADDR:
        case OP_SUB_DOUBLE_2ADDR:
        case OP_MUL_DOUBLE_2ADDR:
        case OP_DIV_DOUBLE_2ADDR:
        case OP_REM_DOUBLE_2ADDR:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            okay &= checkWideRegisterIndex(meth, decInsn.vB);
            break;
        case OP_CONST_STRING:
        case OP_CONST_STRING_JUMBO:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkStringIndex(pDvmDex, decInsn.vB);
            break;
        case OP_CONST_CLASS:
        case OP_CHECK_CAST:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkTypeIndex(pDvmDex, decInsn.vB);
            break;
        case OP_INSTANCE_OF:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            okay &= checkTypeIndex(pDvmDex, decInsn.vC);
            break;
        case OP_NEW_INSTANCE:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkNewInstance(pDvmDex, decInsn.vB);
            break;
        case OP_NEW_ARRAY:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            okay &= checkNewArray(pDvmDex, decInsn.vC);
            break;
        case OP_FILL_ARRAY_DATA:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkArrayData(meth, codeOffset);
            break;
        case OP_PACKED_SWITCH:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkSwitchTargets(meth, insnFlags, codeOffset);
            break;
        case OP_SPARSE_SWITCH:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkSwitchTargets(meth, insnFlags, codeOffset);
            break;
        case OP_CMPL_FLOAT:
        case OP_CMPG_FLOAT:
        case OP_AGET:
        case OP_AGET_OBJECT:
        case OP_AGET_BOOLEAN:
        case OP_AGET_BYTE:
        case OP_AGET_CHAR:
        case OP_AGET_SHORT:
        case OP_APUT:
        case OP_APUT_OBJECT:
        case OP_APUT_BOOLEAN:
        case OP_APUT_BYTE:
        case OP_APUT_CHAR:
        case OP_APUT_SHORT:
        case OP_ADD_INT:
        case OP_SUB_INT:
        case OP_MUL_INT:
        case OP_DIV_INT:
        case OP_REM_INT:
        case OP_AND_INT:
        case OP_OR_INT:
        case OP_XOR_INT:
        case OP_SHL_INT:
        case OP_SHR_INT:
        case OP_USHR_INT:
        case OP_ADD_FLOAT:
        case OP_SUB_FLOAT:
        case OP_MUL_FLOAT:
        case OP_DIV_FLOAT:
        case OP_REM_FLOAT:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            okay &= checkRegisterIndex(meth, decInsn.vC);
            break;
        case OP_AGET_WIDE:
        case OP_APUT_WIDE:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            okay &= checkRegisterIndex(meth, decInsn.vC);
            break;
        case OP_CMPL_DOUBLE:
        case OP_CMPG_DOUBLE:
        case OP_CMP_LONG:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkWideRegisterIndex(meth, decInsn.vB);
            okay &= checkWideRegisterIndex(meth, decInsn.vC);
            break;
        case OP_ADD_DOUBLE:
        case OP_SUB_DOUBLE:
        case OP_MUL_DOUBLE:
        case OP_DIV_DOUBLE:
        case OP_REM_DOUBLE:
        case OP_ADD_LONG:
        case OP_SUB_LONG:
        case OP_MUL_LONG:
        case OP_DIV_LONG:
        case OP_REM_LONG:
        case OP_AND_LONG:
        case OP_OR_LONG:
        case OP_XOR_LONG:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            okay &= checkWideRegisterIndex(meth, decInsn.vB);
            okay &= checkWideRegisterIndex(meth, decInsn.vC);
            break;
        case OP_SHL_LONG:
        case OP_SHR_LONG:
        case OP_USHR_LONG:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            okay &= checkWideRegisterIndex(meth, decInsn.vB);
            okay &= checkRegisterIndex(meth, decInsn.vC);
            break;
        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            okay &= checkBranchTarget(meth, insnFlags, codeOffset, false);
            break;
        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkBranchTarget(meth, insnFlags, codeOffset, false);
            break;
        case OP_IGET:
        case OP_IGET_OBJECT:
        case OP_IGET_BOOLEAN:
        case OP_IGET_BYTE:
        case OP_IGET_CHAR:
        case OP_IGET_SHORT:
        case OP_IPUT:
        case OP_IPUT_OBJECT:
        case OP_IPUT_BOOLEAN:
        case OP_IPUT_BYTE:
        case OP_IPUT_CHAR:
        case OP_IPUT_SHORT:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            okay &= checkFieldIndex(pDvmDex, decInsn.vC);
            break;
        case OP_IGET_WIDE:
        case OP_IPUT_WIDE:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            okay &= checkRegisterIndex(meth, decInsn.vB);
            okay &= checkFieldIndex(pDvmDex, decInsn.vC);
            break;
        case OP_SGET:
        case OP_SGET_OBJECT:
        case OP_SGET_BOOLEAN:
        case OP_SGET_BYTE:
        case OP_SGET_CHAR:
        case OP_SGET_SHORT:
        case OP_SPUT:
        case OP_SPUT_OBJECT:
        case OP_SPUT_BOOLEAN:
        case OP_SPUT_BYTE:
        case OP_SPUT_CHAR:
        case OP_SPUT_SHORT:
            okay &= checkRegisterIndex(meth, decInsn.vA);
            okay &= checkFieldIndex(pDvmDex, decInsn.vB);
            break;
        case OP_SGET_WIDE:
        case OP_SPUT_WIDE:
            okay &= checkWideRegisterIndex(meth, decInsn.vA);
            okay &= checkFieldIndex(pDvmDex, decInsn.vB);
            break;
        case OP_FILLED_NEW_ARRAY:
            /* decoder uses B, not C, for type ref */
            okay &= checkTypeIndex(pDvmDex, decInsn.vB);
            okay &= checkVarargRegs(meth, &decInsn);
            break;
        case OP_FILLED_NEW_ARRAY_RANGE:
            okay &= checkTypeIndex(pDvmDex, decInsn.vB);
            okay &= checkVarargRangeRegs(meth, &decInsn);
            break;
        case OP_INVOKE_VIRTUAL:
        case OP_INVOKE_SUPER:
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_STATIC:
        case OP_INVOKE_INTERFACE:
            /* decoder uses B, not C, for type ref */
            okay &= checkMethodIndex(pDvmDex, decInsn.vB);
            okay &= checkVarargRegs(meth, &decInsn);
            break;
        case OP_INVOKE_VIRTUAL_RANGE:
        case OP_INVOKE_SUPER_RANGE:
        case OP_INVOKE_DIRECT_RANGE:
        case OP_INVOKE_STATIC_RANGE:
        case OP_INVOKE_INTERFACE_RANGE:
            okay &= checkMethodIndex(pDvmDex, decInsn.vB);
            okay &= checkVarargRangeRegs(meth, &decInsn);
            break;

        /* verifier/optimizer output; we should never see these */
        case OP_IGET_VOLATILE:
        case OP_IPUT_VOLATILE:
        case OP_SGET_VOLATILE:
        case OP_SPUT_VOLATILE:
        case OP_IGET_OBJECT_VOLATILE:
        case OP_IPUT_OBJECT_VOLATILE:
        case OP_SGET_OBJECT_VOLATILE:
        case OP_SPUT_OBJECT_VOLATILE:
        case OP_IGET_WIDE_VOLATILE:
        case OP_IPUT_WIDE_VOLATILE:
        case OP_SGET_WIDE_VOLATILE:
        case OP_SPUT_WIDE_VOLATILE:
        case OP_BREAKPOINT:
        case OP_THROW_VERIFICATION_ERROR:
        case OP_EXECUTE_INLINE:
        case OP_EXECUTE_INLINE_RANGE:
        case OP_INVOKE_OBJECT_INIT_RANGE:
        case OP_RETURN_VOID_BARRIER:
        case OP_IGET_QUICK:
        case OP_IGET_WIDE_QUICK:
        case OP_IGET_OBJECT_QUICK:
        case OP_IPUT_QUICK:
        case OP_IPUT_WIDE_QUICK:
        case OP_IPUT_OBJECT_QUICK:
        case OP_INVOKE_VIRTUAL_QUICK:
        case OP_INVOKE_VIRTUAL_QUICK_RANGE:
        case OP_INVOKE_SUPER_QUICK:
        case OP_INVOKE_SUPER_QUICK_RANGE:
        case OP_UNUSED_3E:
        case OP_UNUSED_3F:
        case OP_UNUSED_40:
        case OP_UNUSED_41:
        case OP_UNUSED_42:
        case OP_UNUSED_43:
        case OP_UNUSED_73:
        case OP_UNUSED_79:
        case OP_UNUSED_7A:
        case OP_UNUSED_FF:
            ALOGE("VFY: unexpected opcode %04x", decInsn.opcode);
            okay = false;
            break;

        /*
         * DO NOT add a "default" clause here.  Without it the compiler will
         * complain if an instruction is missing (which is desirable).
         */
        }

        if (!okay) {
            LOG_VFY_METH(meth, "VFY:  rejecting opcode 0x%02x at 0x%04x",
                decInsn.opcode, codeOffset);
            return false;
        }

        OpcodeFlags opFlags = dexGetFlagsFromOpcode(decInsn.opcode);
        if ((opFlags & VERIFY_GC_INST_MASK) != 0) {
            /*
             * This instruction is a GC point.  If space is a concern,
             * the set of GC points could be reduced by eliminating
             * foward branches.
             *
             * TODO: we could also scan the targets of a "switch" statement,
             * and if none of them branch backward we could ignore that
             * instruction as well.
             */
            dvmInsnSetGcPoint(insnFlags, codeOffset, true);
        }

        assert(width > 0);
        codeOffset += width;
        insns += width;
    }

    /* make sure the last instruction ends at the end of the insn area */
    if (codeOffset != vdata->insnsSize) {
        LOG_VFY_METH(meth,
            "VFY: code did not end when expected (end at %d, count %d)",
            codeOffset, vdata->insnsSize);
        return false;
    }

    return true;
}
