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
Maintain a table of references.  Used for internal local references,
JNI monitor references, and JNI pinned array references.

None of the table functions are synchronized.

包含一个引用表。使用内部本地引用，JNI监控引用，和JNI固定数组引用。

没有表函数是同步的。
*/
#ifndef DALVIK_REFERENCETABLE_H_
#define DALVIK_REFERENCETABLE_H_

/*
Table definition.

The expected common operations are adding a new entry and removing a
recently-added entry (usually the most-recently-added entry).

If "allocEntries" is not equal to "maxEntries", the table may expand when
entries are added, which means the memory may move.  If you want to keep
pointers into "table" rather than offsets, use a fixed-size table.

(This structure is still somewhat transparent; direct access to
table/nextEntry is allowed.)

表定义。

预期的一般操作包括添加新条目和去除最近添加的条目
（通常是最近添加的条目）。

如果“allocEntries”不等于“maxEntries”，table表可能扩展，当添加条目时，这意味着内存可以移动。如果我们
保持指针指向“table”表，而不是偏移，使用固定大小的table表。

这种结构依然是透明的；允许直接访问table/nextEntry。
*/
struct ReferenceTable {
    Object**        nextEntry;          /* top of the list */
    Object**        table;              /* bottom of the list */

    int             allocEntries;       /* #of entries we have space for */
    int             maxEntries;         /* max #of entries allowed */
};

/*
Initialize a ReferenceTable.

If "initialCount" != "maxCount", the table will expand as required.

Returns "false" if table allocation fails.

初始化一个引用表。

如果"initialCount" != "maxCount"，table表将随需要扩展。返回“false”，
如果table表分配空间失败。
*/
bool dvmInitReferenceTable(ReferenceTable* pRef, int initialCount,
    int maxCount);

/*
Clears out the contents of a ReferenceTable, freeing allocated storage.
Does not free "pRef".

You must call dvmInitReferenceTable() before you can re-use this table.

清除引用表内容，释放分配的空间存储。不释放“pRef”。

你必须在你可以重新使用这个table表前调用dvmInitReferenceTable()。
*/
void dvmClearReferenceTable(ReferenceTable* pRef);

/*
Return the #of entries currently stored in the ReferenceTable.

返回当前存储在ReferenceTable中的#of条目
*/
INLINE size_t dvmReferenceTableEntries(const ReferenceTable* pRef)
{
    return pRef->nextEntry - pRef->table;
}

/*
Returns "true" if the table is full.  The table is considered full if
we would need to expand it to add another entry.

如果talbe已经满了，返回“true”
*/
INLINE size_t dvmIsReferenceTableFull(const ReferenceTable* pRef)
{
    return dvmReferenceTableEntries(pRef) == (size_t)pRef->allocEntries;
}

/*
Add a new entry.  "obj" must be a valid non-NULL object reference
(though it's okay if it's not fully-formed, e.g. the result from
dvmMalloc doesn't have obj->clazz set).

Returns "false" if the table is full.

添加一个新的条目。“obj”必须是有效非空对象引用。

如果表已经满了，返回“false”。
*/
bool dvmAddToReferenceTable(ReferenceTable* pRef, Object* obj);

/*
Determine if "obj" is present in "pRef".  Stops searching when we hit
"bottom".  To include the entire table, pass in "pRef->table" as the
bottom.

Returns NULL if "obj" was not found.

判断"obj"是否代表“pRef”。停止检索，当到达table表底部。

NOTE TODO：
*/
Object** dvmFindInReferenceTable(const ReferenceTable* pRef, Object** bottom,
    Object* obj);

/*
Remove an existing entry.

We stop searching for a match after examining the element at "bottom".
This is useful when entries are associated with a stack frame.

Returns "false" if the entry was not found.

删除一个存在的条目。

在检查底部元素后停止检索匹配。

返回“false”，如果条目没有找到。
*/
bool dvmRemoveFromReferenceTable(ReferenceTable* pRef, Object** bottom,
    Object* obj);

/*
Dump the contents of a reference table to the log file.

The caller should lock any external sync before calling.

Dump引用表内容到日志文件。

调用者应该在调用前进行外部同步锁。
*/
void dvmDumpReferenceTable(const ReferenceTable* pRef, const char* descr);

/*
Internal function, shared with IndirectRefTable.

内部函数，共享IndirectRefTable。
*/
void dvmDumpReferenceTableContents(Object* const* refs, size_t count,
    const char* descr);

#endif  // DALVIK_REFERENCETABLE_H_
