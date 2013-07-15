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
 * Garbage-collecting memory allocator.
 */
#include "Dalvik.h"
#include "alloc/Heap.h"
#include "alloc/HeapInternal.h"
#include "alloc/HeapSource.h"

/*
 * Initialize the GC universe.
 *
 * We're currently using a memory-mapped arena to keep things off of the
 * main heap.  This needs to be replaced with something real.
 */

/*
 *breif:初始化几个gc线程同步原语，再调用dvmHeapStartup初始化GC内存堆(即java内存堆).
*/
bool dvmGcStartup()
{
    dvmInitMutex(&gDvm.gcHeapLock);
    pthread_cond_init(&gDvm.gcHeapCond, NULL);
    return dvmHeapStartup();
}

/*
 * Post-zygote heap initialization, including starting
 * the HeapWorker thread.
 */

/*
 *breif:虚拟机初始化的时候会调用，最终调用的是dvmHeapSourceStartupAfterZygote.
 *
*/
bool dvmGcStartupAfterZygote()
{
    return dvmHeapStartupAfterZygote();
}

/*
 * Shutdown the threads internal to the garbage collector.
 */

/*
 *breif:关闭垃圾回收线程.内部调用是dvmHeapSourceThreadShutdown->gcDaemonShutdown.
*/
void dvmGcThreadShutdown()
{
    dvmHeapThreadShutdown();
}

/*
 * Shut the GC down.
 */

/*
 *breif:关闭释放垃圾回收堆.
*/
void dvmGcShutdown()
{
    //TODO: grab and destroy the lock
    dvmHeapShutdown();
}

/*
 * Do any last-minute preparation before we call fork() for the first time.
 */

/*
 *breif:在第一次掉用fork之前，在主堆上创建一块新的 zygote heap.
*/
bool dvmGcPreZygoteFork()
{
    return dvmHeapSourceStartupBeforeFork();
}

/*
 *breif:通过调用java的函数，启动Daemons类内存回收.
*/
bool dvmGcStartupClasses()
{
    ClassObject *klass = dvmFindSystemClass("Ljava/lang/Daemons;");
    if (klass == NULL) {
        return false;
    }
    Method *method = dvmFindDirectMethodByDescriptor(klass, "start", "()V");
    if (method == NULL) {
        return false;
    }
    Thread *self = dvmThreadSelf();
    assert(self != NULL);
    JValue unusedResult;
    dvmCallMethod(self, method, NULL, &unusedResult);
    return true;
}

/*
 * Create a "stock instance" of an exception class.
 */

/*
 *breif:创建一个异常类的存储实例，先通过descriptor搜索到类，然后分配一个Object内存，初始化异常类并与object关联.
 *param[descriptor]:类描述.
 *param[msg]:输出信息.
 *return:异常类的实例object.
*/
static Object* createStockException(const char* descriptor, const char* msg)
{
    Thread* self = dvmThreadSelf();
    StringObject* msgStr = NULL;
    ClassObject* clazz;
    Method* init;
    Object* obj;

    /* find class, initialize if necessary */
    clazz = dvmFindSystemClass(descriptor);
    if (clazz == NULL) {
        ALOGE("Unable to find %s", descriptor);
        return NULL;
    }

    init = dvmFindDirectMethodByDescriptor(clazz, "<init>",
            "(Ljava/lang/String;)V");
    if (init == NULL) {
        ALOGE("Unable to find String-arg constructor for %s", descriptor);
        return NULL;
    }

    obj = dvmAllocObject(clazz, ALLOC_DEFAULT);
    if (obj == NULL)
        return NULL;

    if (msg == NULL) {
        msgStr = NULL;
    } else {
        msgStr = dvmCreateStringFromCstr(msg);
        if (msgStr == NULL) {
            ALOGW("Could not allocate message string \"%s\"", msg);
            dvmReleaseTrackedAlloc(obj, self);
            return NULL;
        }
    }

    JValue unused;
    dvmCallMethod(self, init, obj, &unused, msgStr);
    if (dvmCheckException(self)) {
        dvmReleaseTrackedAlloc((Object*) msgStr, self);
        dvmReleaseTrackedAlloc(obj, self);
        return NULL;
    }

    dvmReleaseTrackedAlloc((Object*) msgStr, self);     // okay if msgStr NULL
    return obj;
}

/*
 * Create some "stock" exceptions.  These can be thrown when the system is
 * too screwed up to allocate and initialize anything, or when we don't
 * need a meaningful stack trace.
 *
 * We can't do this during the initial startup because we need to execute
 * the constructors.
 */

/*
 *breif:当系统分配内存或初始化失败时，需要抛出异常.这里创建了一些处理异常的object.
*/
bool dvmCreateStockExceptions()
{
    /*
     * Pre-allocate some throwables.  These need to be explicitly added
     * to the GC's root set (see dvmHeapMarkRootSet()).
     */
    gDvm.outOfMemoryObj = createStockException("Ljava/lang/OutOfMemoryError;",
        "[memory exhausted]");
    dvmReleaseTrackedAlloc(gDvm.outOfMemoryObj, NULL);
    gDvm.internalErrorObj = createStockException("Ljava/lang/InternalError;",
        "[pre-allocated]");
    dvmReleaseTrackedAlloc(gDvm.internalErrorObj, NULL);
    gDvm.noClassDefFoundErrorObj =
        createStockException("Ljava/lang/NoClassDefFoundError;",
            "[generic]");
    dvmReleaseTrackedAlloc(gDvm.noClassDefFoundErrorObj, NULL);

    if (gDvm.outOfMemoryObj == NULL || gDvm.internalErrorObj == NULL ||
        gDvm.noClassDefFoundErrorObj == NULL)
    {
        ALOGW("Unable to create stock exceptions");
        return false;
    }

    return true;
}


/*
 * Create an instance of the specified class.
 *
 * Returns NULL and throws an exception on failure.
 */

/*
 *breif:创建指定类的实例对象，内部调用dvmMalloc分配objectSize大小的内存，成功后，调用对象的构造函数初始化实例.
 *param[clazz]:类对象.
 *param[flags]:分配内存的标识.
 *return:返回一个Object类型的指针.
*/
Object* dvmAllocObject(ClassObject* clazz, int flags)
{
    Object* newObj;

    assert(clazz != NULL);
    assert(dvmIsClassInitialized(clazz) || dvmIsClassInitializing(clazz));

    /* allocate on GC heap; memory is zeroed out */
    newObj = (Object*)dvmMalloc(clazz->objectSize, flags);
    if (newObj != NULL) {
        DVM_OBJECT_INIT(newObj, clazz);
        dvmTrackAllocation(clazz, clazz->objectSize);   /* notify DDMS */
    }

    return newObj;
}

/*
 * Create a copy of an object, for Object.clone().
 *
 * We use the size actually allocated, rather than obj->clazz->objectSize,
 * because the latter doesn't work for array objects.
 */

/*
 *breif:创建object的一份拷贝.包括array object.
 *param[obj]:对象.
 *param[flags]:dvmMalloc的参数.
*/
Object* dvmCloneObject(Object* obj, int flags)
{
    assert(dvmIsValidObject(obj));
    ClassObject* clazz = obj->clazz;

    /* Class.java shouldn't let us get here (java.lang.Class is final
     * and does not implement Clonable), but make extra sure.
     * A memcpy() clone will wreak havoc on a ClassObject's "innards".
     */
    assert(!dvmIsTheClassClass(clazz));

    size_t size;
    if (IS_CLASS_FLAG_SET(clazz, CLASS_ISARRAY)) {
        size = dvmArrayObjectSize((ArrayObject *)obj);
    } else {
        size = clazz->objectSize;
    }

    Object* copy = (Object*)dvmMalloc(size, flags);
    if (copy == NULL)
        return NULL;

    DVM_OBJECT_INIT(copy, clazz);
    size_t offset = sizeof(Object);
    /* Copy instance data.  We assume memcpy copies by words. */
    memcpy((char*)copy + offset, (char*)obj + offset, size - offset);

    /* Mark the clone as finalizable if appropriate. */
    if (IS_CLASS_FLAG_SET(clazz, CLASS_ISFINALIZABLE)) {
        dvmSetFinalizable(copy);
    }

    dvmTrackAllocation(clazz, size);    /* notify DDMS */

    return copy;
}


/*
 * Track an object that was allocated internally and isn't yet part of the
 * VM root set.
 *
 * We could do this per-thread or globally.  If it's global we don't have
 * to do the thread lookup but we do have to synchronize access to the list.
 *
 * "obj" must not be NULL.
 *
 * NOTE: "obj" is not a fully-formed object; in particular, obj->clazz will
 * usually be NULL since we're being called from dvmMalloc().
 */

/*
 *breif:跟踪不是vm根集的对象分配.
 *param[obj]:对象.
 *param[self]:线程对象.
*/
void dvmAddTrackedAlloc(Object* obj, Thread* self)
{
    if (self == NULL)
        self = dvmThreadSelf();

    assert(obj != NULL);
    assert(self != NULL);
    if (!dvmAddToReferenceTable(&self->internalLocalRefTable, obj)) {
        ALOGE("threadid=%d: unable to add %p to internal ref table",
            self->threadId, obj);
        dvmDumpThread(self, false);
        dvmAbort();
    }
}

/*
 * Stop tracking an object.
 *
 * We allow attempts to delete NULL "obj" so that callers don't have to wrap
 * calls with "if != NULL".
 */

/*
 *breif:停止跟踪对象内存分配.
 *param[obj]:对象.
 *param[self]:线程对象.
*/
void dvmReleaseTrackedAlloc(Object* obj, Thread* self)
{
    if (obj == NULL)
        return;

    if (self == NULL)
        self = dvmThreadSelf();
    assert(self != NULL);

    if (!dvmRemoveFromReferenceTable(&self->internalLocalRefTable,
            self->internalLocalRefTable.table, obj))
    {
        ALOGE("threadid=%d: failed to remove %p from internal ref table",
            self->threadId, obj);
        dvmAbort();
    }
}


/*
 * Explicitly initiate garbage collection.
 */

/*
 *breif:启动垃圾回收.
*/
void dvmCollectGarbage()
{
    if (gDvm.disableExplicitGc) {
        return;
    }
    dvmLockHeap();
    dvmWaitForConcurrentGcToComplete();
    dvmCollectGarbageInternal(GC_EXPLICIT);
    dvmUnlockHeap();
}

struct CountContext {
    const ClassObject *clazz;
    size_t count;
};

/*
 *breif:计算class的实例的回调函数，若obj->clazz == arg->clazz 则 arg->count++.
*/
static void countInstancesOfClassCallback(Object *obj, void *arg)
{
    CountContext *ctx = (CountContext *)arg;
    assert(ctx != NULL);
    if (obj->clazz == ctx->clazz) {
        ctx->count += 1;
    }
}

/*
 *breif:计算class实例.
 *param[clazz]:要计算的类对象.
 *return:返回class实例的计数.
*/
size_t dvmCountInstancesOfClass(const ClassObject *clazz)
{
    CountContext ctx = { clazz, 0 };
    dvmLockHeap();
    HeapBitmap *bitmap = dvmHeapSourceGetLiveBits();
    dvmHeapBitmapWalk(bitmap, countInstancesOfClassCallback, &ctx);
    dvmUnlockHeap();
    return ctx.count;
}

/*
 *breif:计算可分配类实例的回调函数.
 *param[obj]:类对象.
 *param[arg]:CountContext类型的值.
*/
static void countAssignableInstancesOfClassCallback(Object *obj, void *arg)
{
    CountContext *ctx = (CountContext *)arg;
    assert(ctx != NULL);
    if (obj->clazz != NULL && dvmInstanceof(obj->clazz, ctx->clazz)) {
        ctx->count += 1;
    }
}

/*
 *breif:计算可调整类实例计数.
 *param[clazz]:类对象.
 *return:返回计数.
*/
size_t dvmCountAssignableInstancesOfClass(const ClassObject *clazz)
{
    CountContext ctx = { clazz, 0 };
    dvmLockHeap();
    HeapBitmap *bitmap = dvmHeapSourceGetLiveBits();
    dvmHeapBitmapWalk(bitmap, countAssignableInstancesOfClassCallback, &ctx);
    dvmUnlockHeap();
    return ctx.count;
}


/*
 *breif:判断是否是堆内的地址.
 *param[address]:堆地址.
*/
bool dvmIsHeapAddress(void *address)
{
    return address != NULL && (((uintptr_t) address & (8-1)) == 0);
}

/*
 *breif:无具体实现.
*/
bool dvmIsNonMovingObject(const Object* object)
{
    return true;
}
