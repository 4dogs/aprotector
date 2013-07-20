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
The VM wraps some additional data structures around the DexFile.  These
are defined here.

VM封装的一些和DEX文件相关的数据结构，定义在这里。
*/
#ifndef DALVIK_DVMDEX_H_
#define DALVIK_DVMDEX_H_

#include "libdex/DexFile.h"

/* extern */
struct ClassObject;
struct HashTable;
struct InstField;
struct Method;
struct StringObject;


/*
Some additional VM data structures that are associated with the DEX file.

一些和DEX文件相关的额外的虚拟机数据结构
*/
struct DvmDex {
    /* pointer to the DexFile we're associated with */
    DexFile*            pDexFile;

    /* clone of pDexFile->pHeader (it's used frequently enough) */
    const DexHeader*    pHeader;

    /* interned strings; parallel to "stringIds" */
    struct StringObject** pResStrings;

    /* resolved classes; parallel to "typeIds" */
    struct ClassObject** pResClasses;

    /* resolved methods; parallel to "methodIds" */
    struct Method**     pResMethods;

    /* resolved instance fields; parallel to "fieldIds" */
    /* (this holds both InstField and StaticField) */
    struct Field**      pResFields;

    /* interface method lookup cache */
    struct AtomicCache* pInterfaceCache;

    /* shared memory region with file contents */
    bool                isMappedReadOnly;
    MemMapping          memMap;

    /* lock ensuring mutual exclusion during updates */
    pthread_mutex_t     modLock;
};


/*
Given a file descriptor for an open "optimized" DEX file, map it into
memory and parse the contents.

On success, returns 0 and sets "*ppDvmDex" to a newly-allocated DvmDex.
On failure, returns a meaningful error code [currently just -1].

打开优化的DEX文件，映射到内存并且解析内容。

成功，返回0并且设置“ppDvmDex”到一个新分配的DvmDex。
失败，返回一个有意义的错误码[当前只是 -1]。

通过Fd打开DEX文件。
*/
int dvmDexFileOpenFromFd(int fd, DvmDex** ppDvmDex);

/*
Open a partial DEX file.  Only useful as part of the optimization process.

打开一部分DEX文件。只对优化过程的一部分有用。
*/
int dvmDexFileOpenPartial(const void* addr, int len, DvmDex** ppDvmDex);

/*
Free a DvmDex structure, along with any associated structures.

释放一个DvmDex结构，伴随一些相关结构。
*/
void dvmDexFileFree(DvmDex* pDvmDex);


/*
Change the 1- or 2-byte value at the specified address to a new value.  If
the location already has the new value, do nothing.

This does not make any synchronization guarantees.  The caller must
ensure exclusivity vs. other callers.

For the 2-byte call, the pointer should have 16-bit alignment.

Returns "true" on success.

在指定地址改变1- 或 2-byte值为新值。如果该位置已经存在新值，不作任何事情。

这里不走任何同步保证。调用者必须协调其它调用者，保证同步。
*/
bool dvmDexChangeDex1(DvmDex* pDvmDex, u1* addr, u1 newVal);
bool dvmDexChangeDex2(DvmDex* pDvmDex, u2* addr, u2 newVal);


/*
Return the requested item if it has been resolved, or NULL if it hasn't.

返回需要项，如果它已经处理过，如果没有则为NULL。
*/
INLINE struct StringObject* dvmDexGetResolvedString(const DvmDex* pDvmDex,
    u4 stringIdx)
{
    assert(stringIdx < pDvmDex->pHeader->stringIdsSize);
    return pDvmDex->pResStrings[stringIdx];
}
INLINE struct ClassObject* dvmDexGetResolvedClass(const DvmDex* pDvmDex,
    u4 classIdx)
{
    assert(classIdx < pDvmDex->pHeader->typeIdsSize);
    return pDvmDex->pResClasses[classIdx];
}
INLINE struct Method* dvmDexGetResolvedMethod(const DvmDex* pDvmDex,
    u4 methodIdx)
{
    assert(methodIdx < pDvmDex->pHeader->methodIdsSize);
    return pDvmDex->pResMethods[methodIdx];
}
INLINE struct Field* dvmDexGetResolvedField(const DvmDex* pDvmDex,
    u4 fieldIdx)
{
    assert(fieldIdx < pDvmDex->pHeader->fieldIdsSize);
    return pDvmDex->pResFields[fieldIdx];
}

/*
Update the resolved item table.  Resolution always produces the same
result, so we're not worried about atomicity here.

更新已处理过的table项。
*/
INLINE void dvmDexSetResolvedString(DvmDex* pDvmDex, u4 stringIdx,
    struct StringObject* str)
{
    assert(stringIdx < pDvmDex->pHeader->stringIdsSize);
    pDvmDex->pResStrings[stringIdx] = str;
}
INLINE void dvmDexSetResolvedClass(DvmDex* pDvmDex, u4 classIdx,
    struct ClassObject* clazz)
{
    assert(classIdx < pDvmDex->pHeader->typeIdsSize);
    pDvmDex->pResClasses[classIdx] = clazz;
}
INLINE void dvmDexSetResolvedMethod(DvmDex* pDvmDex, u4 methodIdx,
    struct Method* method)
{
    assert(methodIdx < pDvmDex->pHeader->methodIdsSize);
    pDvmDex->pResMethods[methodIdx] = method;
}
INLINE void dvmDexSetResolvedField(DvmDex* pDvmDex, u4 fieldIdx,
    struct Field* field)
{
    assert(fieldIdx < pDvmDex->pHeader->fieldIdsSize);
    pDvmDex->pResFields[fieldIdx] = field;
}

#endif  // DALVIK_DVMDEX_H_
