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
 * Link between JDWP and the VM.  The code here only runs as a result of
 * requests from the debugger, so speed is not essential.  Maintaining
 * isolation of the JDWP code should make it easier to maintain and reuse.
 *
 * Collecting all debugger-related pieces here will also allow us to #ifdef
 * the JDWP code out of release builds.
 */

/*
 *在JDWP与VM之间建立联系.这里的代码只是调试器请求的结果，所以速度没要求.
*/
#include "Dalvik.h"

/*
Notes on garbage collection and object registration

JDWP does not allow the debugger to assume that objects passed to it
will not be garbage collected.  It specifies explicit commands (e.g.
ObjectReference.DisableCollection) to allow the debugger to manage
object lifetime.  It does, however, require that the VM not re-use an
object ID unless an explicit "dispose" call has been made, and if the
VM asks for a now-collected object we must return INVALID_OBJECT.

JDWP also requires that, while the VM is suspended, no garbage collection
occur.  The JDWP docs suggest that this is obvious, because no threads
can be running.  Unfortunately it's not entirely clear how to deal
with situations where the debugger itself allocates strings or executes
code as part of displaying variables.  The easiest way to enforce this,
short of disabling GC whenever the debugger is connected, is to ensure
that the debugger thread can't cause a GC: it has to expand the heap or
fail to allocate.  (Might want to make that "is debugger thread AND all
other threads are suspended" to avoid unnecessary heap expansion by a
poorly-timed JDWP request.)

We use an "object registry" so that we can separate our internal
representation from what we show the debugger.  This allows us to
return a registry table index instead of a pointer or handle.

There are various approaches we can take to achieve correct behavior:

(1) Disable garbage collection entirely while the debugger is attached.
This is very easy, but doesn't allow extended debugging sessions on
small devices.

(2) Keep a list of all object references requested by or sent to the
debugger, and include the list in the GC root set.  This ensures that
objects the debugger might care about don't go away.  This is straightforward,
but it can cause us to hold on to large objects and prevent finalizers from
being executed.

(3) Keep a list of what amount to weak object references.  This way we
don't interfere with the GC, and can support JDWP requests like
"ObjectReference.IsCollected".

The current implementation is #2.  The set should be reasonably small and
performance isn't critical, so a simple expanding array can be used.


Notes on threads:

The VM has a Thread struct associated with every active thread.  The
ThreadId we pass to the debugger is the ObjectId for the java/lang/Thread
object, so to retrieve the VM's Thread struct we have to scan through the
list looking for a match.

When a thread goes away, we lock the list and free the struct.  To
avoid having the thread list updated or Thread structs freed out from
under us, we want to acquire and hold the thread list lock while we're
performing operations on Threads.  Exceptions to this rule are noted in
a couple of places.

We can speed this up a bit by adding a Thread struct pointer to the
java/lang/Thread object, and ensuring that both are discarded at the
same time.
*/

/*
vm有一个活动线程有关的结构,我们传递给调试器的ThreadId是java/lang/Thread 的ObjectId.所以要获取虚拟机线程的结构需要遍历链表查找匹配项.
当线程结束时,将锁定链表并释放线程结构.我们需要维护一个线程链表锁来同步线程链表的更新与线程结构的释放.
向java/lang/Thread 对象添加一个Thread struct的指针.
*/

#define THREAD_GROUP_ALL ((ObjectId) 0x12345)   // magic, internal-only value

#define kSlot0Sub   1000    // Eclipse workaround

/*
 * System init.  We don't allocate the registry until first use.
 * Make sure we do this before initializing JDWP.
 */

/*
 *breif:由系统初始化.直到第一次使用才分配一个哈希表注册调试器.初始化前要先初始化JDWP.
*/
bool dvmDebuggerStartup()
{
    if (!dvmBreakpointStartup())
        return false;

    gDvm.dbgRegistry = dvmHashTableCreate(1000, NULL);
    return (gDvm.dbgRegistry != NULL);
}

/*
 * Free registry storage.
 */

/*
 *breif:释放注册的哈希表.
*/
void dvmDebuggerShutdown()
{
    dvmHashTableFree(gDvm.dbgRegistry);
    gDvm.dbgRegistry = NULL;
    dvmBreakpointShutdown();
}


/*
 * Pass these through to the VM functions.  Allows extended checking
 * (e.g. "errorcheck" mutexes).  If nothing else we can assert() success.
 */

/*
 *breif:一些调试相关函数.互斥操作,条件变量的同步操作进行调试.
*/
void dvmDbgInitMutex(pthread_mutex_t* pMutex)
{
    dvmInitMutex(pMutex);
}
void dvmDbgLockMutex(pthread_mutex_t* pMutex)
{
    dvmLockMutex(pMutex);
}
void dvmDbgUnlockMutex(pthread_mutex_t* pMutex)
{
    dvmUnlockMutex(pMutex);
}
void dvmDbgInitCond(pthread_cond_t* pCond)
{
    pthread_cond_init(pCond, NULL);
}
void dvmDbgCondWait(pthread_cond_t* pCond, pthread_mutex_t* pMutex)
{
    int cc __attribute__ ((__unused__)) = pthread_cond_wait(pCond, pMutex);
    assert(cc == 0);
}
void dvmDbgCondSignal(pthread_cond_t* pCond)
{
    int cc __attribute__ ((__unused__)) = pthread_cond_signal(pCond);
    assert(cc == 0);
}
void dvmDbgCondBroadcast(pthread_cond_t* pCond)
{
    int cc __attribute__ ((__unused__)) = pthread_cond_broadcast(pCond);
    assert(cc == 0);
}


/* keep track of type, in case we need to distinguish them someday */

/*
跟踪的调试类型，留给以后用.
*/
enum RegistryType {
    kObjectId = 0xc1, kRefTypeId
};

/*
 * Hash function for object IDs.  Since objects are at least 8 bytes, and
 * could someday be allocated on 16-byte boundaries, we don't want to use
 * the low 4 bits in our hash.
 */

/*
 *breif:hash函数的对象id.低4字节不使用.
 *param[val]:应该是hash id
 *return:应该是对象id.
*/
static inline u4 registryHash(u4 val)
{
    return val >> 4;
}

/*
 * (This is a dvmHashTableLookup() callback.)
 */

/*
 *breif:这是dvmHashTableLookup的回调函数.用于比较操作.
 *param[obj1]:对象1.
 *param[obj2]:对象2.
*/
static int registryCompare(const void* obj1, const void* obj2)
{
    return (int) obj1 - (int) obj2;
}


/*
 * Determine if an id is already in the list.
 *
 * If the list doesn't yet exist, this creates it.
 *
 * Lock the registry before calling here.
 */

/*
 *breif:判断对象id是否已经在链表里.如果不存在，则创建.操作前应该锁定.
 *param[id]:对象id.
*/


#ifndef NDEBUG
static bool lookupId(ObjectId id)
{
    void* found;

    found = dvmHashTableLookup(gDvm.dbgRegistry, registryHash((u4) id),
                (void*)(u4) id, registryCompare, false);
    if (found == NULL)
        return false;
    assert(found == (void*)(u4) id);
    return true;
}
#endif

/*
 * Register an object, if it hasn't already been.
 *
 * This is used for both ObjectId and RefTypeId.  In theory we don't have
 * to register RefTypeIds unless we're worried about classes unloading.
 *
 * Null references must be represented as zero, or the debugger will get
 * very confused.
 */

/*
 *breif:如果对象不存在则注册对象.在注册的hash表中搜索对象,若hash表中没有对象则添加.
 *param[obj]:对象.
 *param[type]:注册类型.
 *param[reg]:是否注册.
 *return:返回对象id.
*/
static ObjectId registerObject(const Object* obj, RegistryType type, bool reg)
{
    ObjectId id;

    if (obj == NULL)
        return 0;

    assert((u4) obj != 0xcccccccc);
    assert((u4) obj > 0x100);

    id = (ObjectId)(u4)obj | ((u8) type) << 32;
    if (!reg)
        return id;

    dvmHashTableLock(gDvm.dbgRegistry);
    if (!gDvm.debuggerConnected) {
        /* debugger has detached while we were doing stuff? */
        ALOGI("ignoring registerObject request in thread=%d",
            dvmThreadSelf()->threadId);
        //dvmAbort();
        goto bail;
    }

    dvmHashTableLookup(gDvm.dbgRegistry, registryHash((u4) id),
                (void*)(u4) id, registryCompare, true);

bail:
    dvmHashTableUnlock(gDvm.dbgRegistry);
    return id;
}

/*
 * Verify that an object has been registered.  If it hasn't, the debugger
 * is asking for something we didn't send it, which means something
 * somewhere is broken.
 *
 * If speed is an issue we can encode the registry index in the high
 * four bytes.  We could also just hard-wire this to "true".
 *
 * Note this actually takes both ObjectId and RefTypeId.
 */

/*
 *breif:验证对象是否注册.
 *param[id]:对象id.
 *param[type]:注册类型.
*/
#ifndef NDEBUG
static bool objectIsRegistered(ObjectId id, RegistryType type)
{
    UNUSED_PARAMETER(type);

    if (id == 0)        // null reference?
        return true;

    dvmHashTableLock(gDvm.dbgRegistry);
    bool result = lookupId(id);
    dvmHashTableUnlock(gDvm.dbgRegistry);
    return result;
}
#endif

/*
 * Convert to/from a RefTypeId.
 *
 * These are rarely NULL, but can be (e.g. java/lang/Object's superclass).
 */

/*
 *breif:RefTypeId 与 ClassObject的相互转换.
*/
static RefTypeId classObjectToRefTypeId(ClassObject* clazz)
{
    return (RefTypeId) registerObject((Object*) clazz, kRefTypeId, true);
}
#if 0
static RefTypeId classObjectToRefTypeIdNoReg(ClassObject* clazz)
{
    return (RefTypeId) registerObject((Object*) clazz, kRefTypeId, false);
}
#endif
static ClassObject* refTypeIdToClassObject(RefTypeId id)
{
    assert(objectIsRegistered(id, kRefTypeId) || !gDvm.debuggerConnected);
    return (ClassObject*)(u4) id;
}

/*
 * Convert to/from an ObjectId.
 */

/*
 *breif:Object 与 ObjectId之间转换.
*/
static ObjectId objectToObjectId(const Object* obj)
{
    return registerObject(obj, kObjectId, true);
}
static ObjectId objectToObjectIdNoReg(const Object* obj)
{
    return registerObject(obj, kObjectId, false);
}
static Object* objectIdToObject(ObjectId id)
{
    assert(objectIsRegistered(id, kObjectId) || !gDvm.debuggerConnected);
    return (Object*)(u4) id;
}

/*
 * Register an object ID that might not have been registered previously.
 *
 * Normally this wouldn't happen -- the conversion to an ObjectId would
 * have added the object to the registry -- but in some cases (e.g.
 * throwing exceptions) we really want to do the registration late.
 */

/*
 *breif:注册先前没有注册过的对象.通常是不会发生的，除非有类似异常的情况导致我们推迟注册.
*/
void dvmDbgRegisterObjectId(ObjectId id)
{
    Object* obj = (Object*)(u4) id;
    ALOGV("+++ registering %p (%s)", obj, obj->clazz->descriptor);
    registerObject(obj, kObjectId, true);
}

/*
 * Convert to/from a MethodId.
 *
 * These IDs are only guaranteed unique within a class, so they could be
 * an enumeration index.  For now we just use the Method*.
 */

/*
 *breif:Method 与 MethodId之间的转换.
*/
static MethodId methodToMethodId(const Method* meth)
{
    return (MethodId)(u4) meth;
}
static Method* methodIdToMethod(RefTypeId refTypeId, MethodId id)
{
    // TODO? verify "id" is actually a method in "refTypeId"
    return (Method*)(u4) id;
}

/*
 * Convert to/from a FieldId.
 *
 * These IDs are only guaranteed unique within a class, so they could be
 * an enumeration index.  For now we just use the Field*.
 */

/*
 *breif: FieldId 与 field之间的转换.
*/
static FieldId fieldToFieldId(const Field* field)
{
    return (FieldId)(u4) field;
}
static Field* fieldIdToField(RefTypeId refTypeId, FieldId id)
{
    // TODO? verify "id" is actually a field in "refTypeId"
    return (Field*)(u4) id;
}

/*
 * Convert to/from a FrameId.
 *
 * We just return a pointer to the stack frame.
 */

/*
 *breif: FrameId 与 frame之间的转换.
*/
static FrameId frameToFrameId(const void* frame)
{
    return (FrameId)(u4) frame;
}
static u4* frameIdToFrame(FrameId id)
{
    return (u4*)(u4) id;
}


/*
 * Get the invocation request state.
 */

/*
 *breif:获取调用请求状态.实际是Thread结构里的invokeReq成员.
*/
DebugInvokeReq* dvmDbgGetInvokeReq()
{
    return &dvmThreadSelf()->invokeReq;
}

/*
 * Enable the object registry, but don't enable debugging features yet.
 *
 * Only called from the JDWP handler thread.
 */

/*
 *breif:有JDWP线程调用,启用对象注册,但不启用调试功能.
*/
void dvmDbgConnected()
{
    assert(!gDvm.debuggerConnected);

    ALOGV("JDWP has attached");
    assert(dvmHashTableNumEntries(gDvm.dbgRegistry) == 0);
    gDvm.debuggerConnected = true;
}

/*
 * Enable all debugging features, including scans for breakpoints.
 *
 * This is a no-op if we're already active.
 *
 * Only called from the JDWP handler thread.
 */

/*
 *breif:JDWP线程调用.启用所有调试功能,包括断点扫描.
*/
void dvmDbgActive()
{
    if (gDvm.debuggerActive)
        return;

    ALOGI("Debugger is active");
    dvmInitBreakpoints();
    gDvm.debuggerActive = true;
    dvmEnableAllSubMode(kSubModeDebuggerActive);
#if defined(WITH_JIT)
    dvmCompilerUpdateGlobalState();
#endif
}

/*
 * Disable debugging features.
 *
 * Set "debuggerConnected" to false, which disables use of the object
 * registry.
 *
 * Only called from the JDWP handler thread.
 */

/*
 *breif:由JDWP线程调用.禁用所有调试功能.并禁用注册功能.
*/
void dvmDbgDisconnected()
{
    assert(gDvm.debuggerConnected);

    gDvm.debuggerActive = false;
    dvmDisableAllSubMode(kSubModeDebuggerActive);
#if defined(WITH_JIT)
    dvmCompilerUpdateGlobalState();
#endif

    dvmHashTableLock(gDvm.dbgRegistry);
    gDvm.debuggerConnected = false;

    ALOGD("Debugger has detached; object registry had %d entries",
        dvmHashTableNumEntries(gDvm.dbgRegistry));
    //int i;
    //for (i = 0; i < gDvm.dbgRegistryNext; i++)
    //    LOGVV("%4d: 0x%llx", i, gDvm.dbgRegistryTable[i]);

    dvmHashTableClear(gDvm.dbgRegistry);
    dvmHashTableUnlock(gDvm.dbgRegistry);
}

/*
 * Returns "true" if a debugger is connected.
 *
 * Does not return "true" if it's just a DDM server.
 */

/*
 *breif:如果调试器已经链接则返回true.相反情况是一个ddm服务.
*/
bool dvmDbgIsDebuggerConnected()
{
    return gDvm.debuggerActive;
}

/*
 * Get time since last debugger activity.  Used when figuring out if the
 * debugger has finished configuring us.
 */

/*
 *breif:获取活动调试器的最后时间.
*/
s8 dvmDbgLastDebuggerActivity()
{
    return dvmJdwpLastDebuggerActivity(gDvm.jdwpState);
}

/*
 * JDWP thread is running, don't allow GC.
 */

/*
 *breif:JDWP线程正在运行.禁用GC(内存回收).
*/
int dvmDbgThreadRunning()
{
    ThreadStatus oldStatus = dvmChangeStatus(NULL, THREAD_RUNNING);
    return static_cast<int>(oldStatus);
}

/*
 * JDWP thread is idle, allow GC.
 */

/*
 *breif:JDWP线程空闲时,允许GC.
*/
int dvmDbgThreadWaiting()
{
    ThreadStatus oldStatus = dvmChangeStatus(NULL, THREAD_VMWAIT);
    return static_cast<int>(oldStatus);
}

/*
 * Restore state returned by Running/Waiting calls.
 */

/*
 *breif:更改线程状态.
 *param[status]:线程状态.
*/
int dvmDbgThreadContinuing(int status)
{
    ThreadStatus newStatus = static_cast<ThreadStatus>(status);
    ThreadStatus oldStatus = dvmChangeStatus(NULL, newStatus);
    return static_cast<int>(oldStatus);
}

/*
 * The debugger wants us to exit.
 */

/*
 *breif:调试器退出.
 *param[status]:系统退出代码.
*/
void dvmDbgExit(int status)
{
    // TODO? invoke System.exit() to perform exit processing; ends up
    // in System.exitInternal(), which can call JNI exit hook
    ALOGI("GC lifetime allocation: %d bytes", gDvm.allocProf.allocCount);
    if (CALC_CACHE_STATS) {
        dvmDumpAtomicCacheStats(gDvm.instanceofCache);
        dvmDumpBootClassPath();
    }
    exit(status);
}


/*
 * ===========================================================================
 *      Class, Object, Array
 * ===========================================================================
 */

/*
 * Get the class's type descriptor from a reference type ID.
 */

/*
 *breif:从引用类型ID获取类的描述.
 *param[id]:引用类型ID.
*/
const char* dvmDbgGetClassDescriptor(RefTypeId id)
{
    ClassObject* clazz;

    clazz = refTypeIdToClassObject(id);
    return clazz->descriptor;
}

/*
 * Convert a RefTypeId to an ObjectId.
 */

/*
 *breif:将RefTypeId转化为ObjectId.
*/
ObjectId dvmDbgGetClassObject(RefTypeId id)
{
    ClassObject* clazz = refTypeIdToClassObject(id);
    return objectToObjectId((Object*) clazz);
}

/*
 * Return the superclass of a class (will be NULL for java/lang/Object).
 */

/*
 *breif:获取一个类的超类类型ID.
 *param[id]:类型ID.
*/
RefTypeId dvmDbgGetSuperclass(RefTypeId id)
{
    ClassObject* clazz = refTypeIdToClassObject(id);
    return classObjectToRefTypeId(clazz->super);
}

/*
 * Return a class's defining class loader.
 */

/*
 *breif:返回类的类加载器的类型ID.
 *param[id]:类型ID.
*/
RefTypeId dvmDbgGetClassLoader(RefTypeId id)
{
    ClassObject* clazz = refTypeIdToClassObject(id);
    return objectToObjectId(clazz->classLoader);
}

/*
 * Return a class's access flags.
 */

/*
 *breif:获取类的访问标志.
*/
u4 dvmDbgGetAccessFlags(RefTypeId id)
{
    ClassObject* clazz = refTypeIdToClassObject(id);
    return clazz->accessFlags & JAVA_FLAGS_MASK;
}

/*
 * Is this class an interface?
 */

/*
 *breif:判断类是否是接口.
*/
bool dvmDbgIsInterface(RefTypeId id)
{
    ClassObject* clazz = refTypeIdToClassObject(id);
    return dvmIsInterfaceClass(clazz);
}

/*
 * dvmHashForeach callback
 */

/*
 *breif:dvmHashForeach的回调函数.
 *param[vclazz]:类对象.
 *param[varg]:参数.
*/
static int copyRefType(void* vclazz, void* varg)
{
    RefTypeId** pRefType = (RefTypeId**)varg;
    **pRefType = classObjectToRefTypeId((ClassObject*) vclazz);
    (*pRefType)++;
    return 0;
}

/*
 * Get the complete list of reference classes (i.e. all classes except
 * the primitive types).
 *
 * Returns a newly-allocated buffer full of RefTypeId values.
 */

/*
 *breif:获取参考类的完整列表.
*/
void dvmDbgGetClassList(u4* pNumClasses, RefTypeId** pClassRefBuf)
{
    RefTypeId* pRefType;

    dvmHashTableLock(gDvm.loadedClasses);
    *pNumClasses = dvmHashTableNumEntries(gDvm.loadedClasses);
    pRefType = *pClassRefBuf =
        (RefTypeId*)malloc(sizeof(RefTypeId) * *pNumClasses);

    if (dvmHashForeach(gDvm.loadedClasses, copyRefType, &pRefType) != 0) {
        ALOGW("Warning: problem getting class list");
        /* not really expecting this to happen */
    } else {
        assert(pRefType - *pClassRefBuf == (int) *pNumClasses);
    }

    dvmHashTableUnlock(gDvm.loadedClasses);
}

/*
 * Get the list of reference classes "visible" to the specified class
 * loader.  A class is visible to a class loader if the ClassLoader object
 * is the defining loader or is listed as an initiating loader.
 *
 * Returns a newly-allocated buffer full of RefTypeId values.
 */

/*
 *breif:获取指定的类加载器的类列表.
 *param[classLoaderId]:类加载器ID
 *param[pNumClasses]:输出参数类数目.
 *param[pClassRefBuf]:输出参数.    
*/
void dvmDbgGetVisibleClassList(ObjectId classLoaderId, u4* pNumClasses,
    RefTypeId** pClassRefBuf)
{
    Object* classLoader;
    int numClasses = 0, maxClasses;

    classLoader = objectIdToObject(classLoaderId);
    // I don't think classLoader can be NULL, but the spec doesn't say

    LOGVV("GetVisibleList: comparing to %p", classLoader);

    dvmHashTableLock(gDvm.loadedClasses);

    /* over-allocate the return buffer */
    maxClasses = dvmHashTableNumEntries(gDvm.loadedClasses);
    *pClassRefBuf = (RefTypeId*)malloc(sizeof(RefTypeId) * maxClasses);

    /*
     * Run through the list, looking for matches.
     */
    HashIter iter;
    for (dvmHashIterBegin(gDvm.loadedClasses, &iter); !dvmHashIterDone(&iter);
        dvmHashIterNext(&iter))
    {
        ClassObject* clazz = (ClassObject*) dvmHashIterData(&iter);

        if (clazz->classLoader == classLoader ||
            dvmLoaderInInitiatingList(clazz, classLoader))
        {
            LOGVV("  match '%s'", clazz->descriptor);
            (*pClassRefBuf)[numClasses++] = classObjectToRefTypeId(clazz);
        }
    }
    *pNumClasses = numClasses;

    dvmHashTableUnlock(gDvm.loadedClasses);
}

/*
 * Get the "JNI signature" for a class, e.g. "Ljava/lang/String;".
 *
 * Our class descriptors are in the correct format, so we just return that.
 */

/*
 *breif:返回类的"JNI signature".
 *param[clazz]:类对象.
 *return:返回类表述.
*/
static const char* jniSignature(ClassObject* clazz)
{
    return clazz->descriptor;
}

/*
 * Get information about a class.
 *
 * If "pSignature" is not NULL, *pSignature gets the "JNI signature" of
 * the class.
 */

/*
 *breif:获取类的信息.
 *param[classId]:(in)类ID.
 *param[pTypeTag]:(out)类是数组还是接口还是类等信息.
 *param[pStatus]:(out)类是否初始化了等信息.
 *param[pSignature]:(out)若内存不为空则返回类描述.
*/
void dvmDbgGetClassInfo(RefTypeId classId, u1* pTypeTag, u4* pStatus,
    const char** pSignature)
{
    ClassObject* clazz = refTypeIdToClassObject(classId);

    if (clazz->descriptor[0] == '[') {
        /* generated array class */
        *pStatus = CS_VERIFIED | CS_PREPARED;
        *pTypeTag = TT_ARRAY;
    } else {
        if (clazz->status == CLASS_ERROR)
            *pStatus = CS_ERROR;
        else
            *pStatus = CS_VERIFIED | CS_PREPARED | CS_INITIALIZED;
        if (dvmIsInterfaceClass(clazz))
            *pTypeTag = TT_INTERFACE;
        else
            *pTypeTag = TT_CLASS;
    }
    if (pSignature != NULL)
        *pSignature = jniSignature(clazz);
}

/*
 * Search the list of loaded classes for a match.
 */

/*
 *breif:搜索匹配列表的加载类.
 *param[classDescriptor]:类描述.
 *param[pRefTypeId]:引用类型ID.
*/
bool dvmDbgFindLoadedClassBySignature(const char* classDescriptor,
        RefTypeId* pRefTypeId)
{
    ClassObject* clazz;

    clazz = dvmFindLoadedClass(classDescriptor);
    if (clazz != NULL) {
        *pRefTypeId = classObjectToRefTypeId(clazz);
        return true;
    } else
        return false;
}


/*
 * Get an object's class and "type tag".
 */

/*
 *breif:获取对象的类与类型标记.
 *param[objectId]:对象ID.
 *param[pRefTypeTag]:类型标记.
 *param[pRefTypeId]:类型引用ID.
*/
void dvmDbgGetObjectType(ObjectId objectId, u1* pRefTypeTag,
    RefTypeId* pRefTypeId)
{
    Object* obj = objectIdToObject(objectId);

    if (dvmIsArrayClass(obj->clazz))
        *pRefTypeTag = TT_ARRAY;
    else if (dvmIsInterfaceClass(obj->clazz))
        *pRefTypeTag = TT_INTERFACE;
    else
        *pRefTypeTag = TT_CLASS;
    *pRefTypeId = classObjectToRefTypeId(obj->clazz);
}

/*
 * Get a class object's "type tag".
 */

/*
 *breif:获取类的类型.
*/
u1 dvmDbgGetClassObjectType(RefTypeId refTypeId)
{
    ClassObject* clazz = refTypeIdToClassObject(refTypeId);

    if (dvmIsArrayClass(clazz))
        return TT_ARRAY;
    else if (dvmIsInterfaceClass(clazz))
        return TT_INTERFACE;
    else
        return TT_CLASS;
}

/*
 * Get a class' signature.
 */

/*
 *breif:获取类的描述信息.
*/
const char* dvmDbgGetSignature(RefTypeId refTypeId)
{
    ClassObject* clazz;

    clazz = refTypeIdToClassObject(refTypeId);
    assert(clazz != NULL);

    return jniSignature(clazz);
}

/*
 * Get class' source file.
 *
 * Returns a newly-allocated string.
 */

/*
 *breif:获取类的源文件.返回字符串是重新分配的内存.
*/
const char* dvmDbgGetSourceFile(RefTypeId refTypeId)
{
    ClassObject* clazz;

    clazz = refTypeIdToClassObject(refTypeId);
    assert(clazz != NULL);

    return clazz->sourceFile;
}

/*
 * Get an object's type name.  (For log message display only.)
 */

/*
 *breif:获取对象的类型名称.
*/
const char* dvmDbgGetObjectTypeName(ObjectId objectId)
{
    if (objectId == 0)
        return "(null)";

    Object* obj = objectIdToObject(objectId);
    return jniSignature(obj->clazz);
}

/*
 * Determine whether or not a tag represents a primitive type.
 */

/*
 *breif:确定一个标签是否代表一个原始类型.
*/
static bool isTagPrimitive(u1 tag)
{
    switch (tag) {
    case JT_BYTE:
    case JT_CHAR:
    case JT_FLOAT:
    case JT_DOUBLE:
    case JT_INT:
    case JT_LONG:
    case JT_SHORT:
    case JT_VOID:
    case JT_BOOLEAN:
        return true;
    case JT_ARRAY:
    case JT_OBJECT:
    case JT_STRING:
    case JT_CLASS_OBJECT:
    case JT_THREAD:
    case JT_THREAD_GROUP:
    case JT_CLASS_LOADER:
        return false;
    default:
        ALOGE("ERROR: unhandled tag '%c'", tag);
        assert(false);
        return false;
    }
}

/*
 * Determine the best tag type given an object's class.
 */

/*
 *breif:获取类的标签.
*/
static u1 tagFromClass(ClassObject* clazz)
{
    if (dvmIsArrayClass(clazz))
        return JT_ARRAY;

    if (clazz == gDvm.classJavaLangString) {
        return JT_STRING;
    } else if (dvmIsTheClassClass(clazz)) {
        return JT_CLASS_OBJECT;
    } else if (dvmInstanceof(clazz, gDvm.classJavaLangThread)) {
        return JT_THREAD;
    } else if (dvmInstanceof(clazz, gDvm.classJavaLangThreadGroup)) {
        return JT_THREAD_GROUP;
    } else if (dvmInstanceof(clazz, gDvm.classJavaLangClassLoader)) {
        return JT_CLASS_LOADER;
    } else {
        return JT_OBJECT;
    }
}

/*
 * Return a basic tag value based solely on a type descriptor.
 *
 * The ASCII value maps directly to the JDWP tag constants, so we don't
 * need to do much here.  This does not return the fancier tags like
 * JT_THREAD.
 */

/*
 *breif:从类型描述中获取标记.
*/
static u1 basicTagFromDescriptor(const char* descriptor)
{
    return descriptor[0];
}

/*
 * Objects declared to hold Object might actually hold a more specific
 * type.  The debugger may take a special interest in these (e.g. it
 * wants to display the contents of Strings), so we want to return an
 * appropriate tag.
 *
 * Null objects are tagged JT_OBJECT.
 */

/*
 *breif:从对象返回类标记.
*/
static u1 tagFromObject(const Object* obj)
{
    if (obj == NULL)
        return JT_OBJECT;
    return tagFromClass(obj->clazz);
}

/*
 * Determine the tag for an object.
 *
 * "objectId" may be 0 (i.e. NULL reference).
 */

/*
 *breif:确定一个对象的标签.
*/
u1 dvmDbgGetObjectTag(ObjectId objectId)
{
    return tagFromObject(objectIdToObject(objectId));
}

/*
 * Get the widths of the specified JDWP.Tag value.
 */

/*
 *breif:获取JDWP类型标签的长度.
*/
int dvmDbgGetTagWidth(int tag)
{
    switch (tag) {
    case JT_VOID:
        return 0;
    case JT_BYTE:
    case JT_BOOLEAN:
        return 1;
    case JT_CHAR:
    case JT_SHORT:
        return 2;
    case JT_FLOAT:
    case JT_INT:
        return 4;
    case JT_ARRAY:
    case JT_OBJECT:
    case JT_STRING:
    case JT_THREAD:
    case JT_THREAD_GROUP:
    case JT_CLASS_LOADER:
    case JT_CLASS_OBJECT:
        return sizeof(ObjectId);
    case JT_DOUBLE:
    case JT_LONG:
        return 8;
    default:
        ALOGE("ERROR: unhandled tag '%c'", tag);
        assert(false);
        return -1;
    }
}


/*
 * Return the length of the specified array.
 */

/*
 *breif:获取指定数组的长度.
*/
int dvmDbgGetArrayLength(ObjectId arrayId)
{
    ArrayObject* arrayObj = (ArrayObject*) objectIdToObject(arrayId);
    assert(dvmIsArray(arrayObj));
    return arrayObj->length;
}

/*
 * Return a tag indicating the general type of elements in the array.
 */

/*
 *breif:从数组中获取标记.
*/
u1 dvmDbgGetArrayElementTag(ObjectId arrayId)
{
    ArrayObject* arrayObj = (ArrayObject*) objectIdToObject(arrayId);

    ClassObject* arrayClass = arrayObj->clazz;
    u1 tag = basicTagFromDescriptor(arrayClass->descriptor + 1);
    if (!isTagPrimitive(tag)) {
        /* try to refine it */
        tag = tagFromClass(arrayClass->elementClass);
    }

    return tag;
}

/*
 * Copy a series of values with the specified width, changing the byte
 * ordering to big-endian.
 */

/*
 *breif:复制值，并改变为大端方式存储.
*/
static void copyValuesToBE(u1* out, const u1* in, int count, int width)
{
    int i;

    switch (width) {
    case 1:
        memcpy(out, in, count);
        break;
    case 2:
        for (i = 0; i < count; i++)
            *(((u2*) out)+i) = get2BE(in + i*2);
        break;
    case 4:
        for (i = 0; i < count; i++)
            *(((u4*) out)+i) = get4BE(in + i*4);
        break;
    case 8:
        for (i = 0; i < count; i++)
            *(((u8*) out)+i) = get8BE(in + i*8);
        break;
    default:
        assert(false);
    }
}

/*
 * Copy a series of values with the specified width, changing the
 * byte order from big-endian.
 */

/*
 *breif:复制值，并改变其为大端.
*/
static void copyValuesFromBE(u1* out, const u1* in, int count, int width)
{
    int i;

    switch (width) {
    case 1:
        memcpy(out, in, count);
        break;
    case 2:
        for (i = 0; i < count; i++)
            set2BE(out + i*2, *((u2*)in + i));
        break;
    case 4:
        for (i = 0; i < count; i++)
            set4BE(out + i*4, *((u4*)in + i));
        break;
    case 8:
        for (i = 0; i < count; i++)
            set8BE(out + i*8, *((u8*)in + i));
        break;
    default:
        assert(false);
    }
}

/*
 * Output a piece of an array to the reply buffer.
 *
 * Returns "false" if something looks fishy.
 */

/*
 *breif:将数组输出到reply缓存.
*/
bool dvmDbgOutputArray(ObjectId arrayId, int firstIndex, int count,
    ExpandBuf* pReply)
{
    ArrayObject* arrayObj = (ArrayObject*) objectIdToObject(arrayId);
    const u1* data = (const u1*)arrayObj->contents;
    u1 tag;

    assert(dvmIsArray(arrayObj));

    if (firstIndex + count > (int)arrayObj->length) {
        ALOGW("Request for index=%d + count=%d excceds length=%d",
            firstIndex, count, arrayObj->length);
        return false;
    }

    tag = basicTagFromDescriptor(arrayObj->clazz->descriptor + 1);

    if (isTagPrimitive(tag)) {
        int width = dvmDbgGetTagWidth(tag);
        u1* outBuf;

        outBuf = expandBufAddSpace(pReply, count * width);

        copyValuesToBE(outBuf, data + firstIndex*width, count, width);
    } else {
        Object** pObjects;
        int i;

        pObjects = (Object**) data;
        pObjects += firstIndex;

        ALOGV("    --> copying %d object IDs", count);
        //assert(tag == JT_OBJECT);     // could be object or "refined" type

        for (i = 0; i < count; i++, pObjects++) {
            u1 thisTag;
            if (*pObjects != NULL)
                thisTag = tagFromObject(*pObjects);
            else
                thisTag = tag;
            expandBufAdd1(pReply, thisTag);
            expandBufAddObjectId(pReply, objectToObjectId(*pObjects));
        }
    }

    return true;
}

/*
 * Set a range of elements in an array from the data in "buf".
 */

/*
 *breif:从"buf"中读取元素到"arrayId"的数组.
*/
bool dvmDbgSetArrayElements(ObjectId arrayId, int firstIndex, int count,
    const u1* buf)
{
    ArrayObject* arrayObj = (ArrayObject*) objectIdToObject(arrayId);
    u1* data = (u1*)arrayObj->contents;
    u1 tag;

    assert(dvmIsArray(arrayObj));

    if (firstIndex + count > (int)arrayObj->length) {
        ALOGW("Attempt to set index=%d + count=%d excceds length=%d",
            firstIndex, count, arrayObj->length);
        return false;
    }

    tag = basicTagFromDescriptor(arrayObj->clazz->descriptor + 1);

    if (isTagPrimitive(tag)) {
        int width = dvmDbgGetTagWidth(tag);

        ALOGV("    --> setting %d '%c' width=%d", count, tag, width);

        copyValuesFromBE(data + firstIndex*width, buf, count, width);
    } else {
        Object** pObjects;
        int i;

        pObjects = (Object**) data;
        pObjects += firstIndex;

        ALOGV("    --> setting %d objects", count);

        /* should do array type check here */
        for (i = 0; i < count; i++) {
            ObjectId id = dvmReadObjectId(&buf);
            *pObjects++ = objectIdToObject(id);
        }
    }

    return true;
}

/*
 * Create a new string.
 *
 * The only place the reference will be held in the VM is in our registry.
 */

/*
 *breif:创建一个字符串.
*/
ObjectId dvmDbgCreateString(const char* str)
{
    StringObject* strObj;

    strObj = dvmCreateStringFromCstr(str);
    dvmReleaseTrackedAlloc((Object*) strObj, NULL);
    return objectToObjectId((Object*) strObj);
}

/*
 * Allocate a new object of the specified type.
 *
 * Add it to the registry to prevent it from being GCed.
 */

/*
 *breif:按指定的类型分配一个对象.
*/
ObjectId dvmDbgCreateObject(RefTypeId classId)
{
    ClassObject* clazz = refTypeIdToClassObject(classId);
    Object* newObj = dvmAllocObject(clazz, ALLOC_DEFAULT);
    dvmReleaseTrackedAlloc(newObj, NULL);
    return objectToObjectId(newObj);
}

/*
 * Allocate a new array object of the specified type and length.  The
 * type is the array type, not the element type.
 *
 * Add it to the registry to prevent it from being GCed.
 */

/*
 *breif:按指定的类型与长度分配一个对象数组.
*/
ObjectId dvmDbgCreateArrayObject(RefTypeId arrayTypeId, u4 length)
{
    ClassObject* clazz = refTypeIdToClassObject(arrayTypeId);
    Object* newObj = (Object*) dvmAllocArrayByClass(clazz, length, ALLOC_DEFAULT);
    dvmReleaseTrackedAlloc(newObj, NULL);
    return objectToObjectId(newObj);
}

/*
 * Determine if "instClassId" is an instance of "classId".
 */

/*
 *breif:判断"instClassId"是不是"classId"的一个实力.
*/
bool dvmDbgMatchType(RefTypeId instClassId, RefTypeId classId)
{
    ClassObject* instClazz = refTypeIdToClassObject(instClassId);
    ClassObject* clazz = refTypeIdToClassObject(classId);

    return dvmInstanceof(instClazz, clazz);
}


/*
 * ===========================================================================
 *      Method and Field
 * ===========================================================================
 */

/*
 * Get the method name from a MethodId.
 */

/*
 *breif:通过方法ID获取方法名.
*/
const char* dvmDbgGetMethodName(RefTypeId refTypeId, MethodId id)
{
    Method* meth;

    meth = methodIdToMethod(refTypeId, id);
    return meth->name;
}

/*
 * Augment the access flags for synthetic methods and fields by setting
 * the (as described by the spec) "0xf0000000 bit".  Also, strip out any
 * flags not specified by the Java programming language.
 */

/*
 *breif:设置访问标志.
*/
static u4 augmentedAccessFlags(u4 accessFlags)
{
    accessFlags &= JAVA_FLAGS_MASK;

    if ((accessFlags & ACC_SYNTHETIC) != 0) {
        return accessFlags | 0xf0000000;
    } else {
        return accessFlags;
    }
}

/*
 * For ReferenceType.Fields and ReferenceType.FieldsWithGeneric:
 * output all fields declared by the class.  Inherited fields are
 * not included.
 */

/*
 *breif:将ClassObject内的所有sField 与 iField内容输出到"pReply".
*/
void dvmDbgOutputAllFields(RefTypeId refTypeId, bool withGeneric,
    ExpandBuf* pReply)
{
    ClassObject* clazz = refTypeIdToClassObject(refTypeId);
    assert(clazz != NULL);

    u4 declared = clazz->sfieldCount + clazz->ifieldCount;
    expandBufAdd4BE(pReply, declared);

    for (int i = 0; i < clazz->sfieldCount; i++) {
        Field* field = &clazz->sfields[i];
        expandBufAddFieldId(pReply, fieldToFieldId(field));
        expandBufAddUtf8String(pReply, (const u1*) field->name);
        expandBufAddUtf8String(pReply, (const u1*) field->signature);
        if (withGeneric) {
            static const u1 genericSignature[1] = "";
            expandBufAddUtf8String(pReply, genericSignature);
        }
        expandBufAdd4BE(pReply, augmentedAccessFlags(field->accessFlags));
    }
    for (int i = 0; i < clazz->ifieldCount; i++) {
        Field* field = &clazz->ifields[i];
        expandBufAddFieldId(pReply, fieldToFieldId(field));
        expandBufAddUtf8String(pReply, (const u1*) field->name);
        expandBufAddUtf8String(pReply, (const u1*) field->signature);
        if (withGeneric) {
            static const u1 genericSignature[1] = "";
            expandBufAddUtf8String(pReply, genericSignature);
        }
        expandBufAdd4BE(pReply, augmentedAccessFlags(field->accessFlags));
    }
}

/*
 * For ReferenceType.Methods and ReferenceType.MethodsWithGeneric:
 * output all methods declared by the class.  Inherited methods are
 * not included.
 */

/*
 *breif:将class里的directMethod与virtualMethod输出到pReply里.
*/
void dvmDbgOutputAllMethods(RefTypeId refTypeId, bool withGeneric,
    ExpandBuf* pReply)
{
    DexStringCache stringCache;
    static const u1 genericSignature[1] = "";
    ClassObject* clazz;
    Method* meth;
    u4 declared;
    int i;

    dexStringCacheInit(&stringCache);

    clazz = refTypeIdToClassObject(refTypeId);
    assert(clazz != NULL);

    declared = clazz->directMethodCount + clazz->virtualMethodCount;
    expandBufAdd4BE(pReply, declared);

    for (i = 0; i < clazz->directMethodCount; i++) {
        meth = &clazz->directMethods[i];

        expandBufAddMethodId(pReply, methodToMethodId(meth));
        expandBufAddUtf8String(pReply, (const u1*) meth->name);

        expandBufAddUtf8String(pReply,
            (const u1*) dexProtoGetMethodDescriptor(&meth->prototype,
                    &stringCache));

        if (withGeneric)
            expandBufAddUtf8String(pReply, genericSignature);
        expandBufAdd4BE(pReply, augmentedAccessFlags(meth->accessFlags));
    }
    for (i = 0; i < clazz->virtualMethodCount; i++) {
        meth = &clazz->virtualMethods[i];

        expandBufAddMethodId(pReply, methodToMethodId(meth));
        expandBufAddUtf8String(pReply, (const u1*) meth->name);

        expandBufAddUtf8String(pReply,
            (const u1*) dexProtoGetMethodDescriptor(&meth->prototype,
                    &stringCache));

        if (withGeneric)
            expandBufAddUtf8String(pReply, genericSignature);
        expandBufAdd4BE(pReply, augmentedAccessFlags(meth->accessFlags));
    }

    dexStringCacheRelease(&stringCache);
}

/*
 * Output all interfaces directly implemented by the class.
 */

/*
 *breif:输出接口实现类.
*/
void dvmDbgOutputAllInterfaces(RefTypeId refTypeId, ExpandBuf* pReply)
{
    ClassObject* clazz;
    int i, count;

    clazz = refTypeIdToClassObject(refTypeId);
    assert(clazz != NULL);

    count = clazz->interfaceCount;
    expandBufAdd4BE(pReply, count);
    for (i = 0; i < count; i++) {
        ClassObject* iface = clazz->interfaces[i];
        expandBufAddRefTypeId(pReply, classObjectToRefTypeId(iface));
    }
}

struct DebugCallbackContext {
    int numItems;
    ExpandBuf* pReply;
    // used by locals table
    bool withGeneric;
};

/*
 *breif:将行号与地址存放到cnxt.
*/
static int lineTablePositionsCb(void *cnxt, u4 address, u4 lineNum)
{
    DebugCallbackContext *pContext = (DebugCallbackContext *)cnxt;

    expandBufAdd8BE(pContext->pReply, address);
    expandBufAdd4BE(pContext->pReply, lineNum);
    pContext->numItems++;

    return 0;
}

/*
 * For Method.LineTable: output the line table.
 *
 * Note we operate in Dalvik's 16-bit units rather than bytes.
 */

/*
 *breif:输出线性表.
*/
void dvmDbgOutputLineTable(RefTypeId refTypeId, MethodId methodId,
    ExpandBuf* pReply)
{
    Method* method;
    u8 start, end;
    DebugCallbackContext context;

    memset (&context, 0, sizeof(DebugCallbackContext));

    method = methodIdToMethod(refTypeId, methodId);
    if (dvmIsNativeMethod(method)) {
        start = (u8) -1;
        end = (u8) -1;
    } else {
        start = 0;
        end = dvmGetMethodInsnsSize(method);
    }

    expandBufAdd8BE(pReply, start);
    expandBufAdd8BE(pReply, end);

    // Add numLines later
    size_t numLinesOffset = expandBufGetLength(pReply);
    expandBufAdd4BE(pReply, 0);

    context.pReply = pReply;

    dexDecodeDebugInfo(method->clazz->pDvmDex->pDexFile,
        dvmGetMethodCode(method),
        method->clazz->descriptor,
        method->prototype.protoIdx,
        method->accessFlags,
        lineTablePositionsCb, NULL, &context);

    set4BE(expandBufGetBuffer(pReply) + numLinesOffset, context.numItems);
}

/*
 * Eclipse appears to expect that the "this" reference is in slot zero.
 * If it's not, the "variables" display will show two copies of "this",
 * possibly because it gets "this" from SF.ThisObject and then displays
 * all locals with nonzero slot numbers.
 *
 * So, we remap the item in slot 0 to 1000, and remap "this" to zero.  On
 * SF.GetValues / SF.SetValues we map them back.
 */

/*
 *breif:Eclipse相关.
*/
static int tweakSlot(int slot, const char* name)
{
    int newSlot = slot;

    if (strcmp(name, "this") == 0)      // only remap "this" ptr
        newSlot = 0;
    else if (slot == 0)                 // always remap slot 0
        newSlot = kSlot0Sub;

    ALOGV("untweak: %d to %d", slot, newSlot);
    return newSlot;
}

/*
 * Reverse Eclipse hack.
 */

/*
 *breif:eclipse相关.
*/
static int untweakSlot(int slot, const void* framePtr)
{
    int newSlot = slot;

    if (slot == kSlot0Sub) {
        newSlot = 0;
    } else if (slot == 0) {
        const StackSaveArea* saveArea = SAVEAREA_FROM_FP(framePtr);
        const Method* method = saveArea->method;
        newSlot = method->registersSize - method->insSize;
    }

    ALOGV("untweak: %d to %d", slot, newSlot);
    return newSlot;
}


/*
 *breif:变量表.
*/
static void variableTableCb (void *cnxt, u2 reg, u4 startAddress,
        u4 endAddress, const char *name, const char *descriptor,
        const char *signature)
{
    DebugCallbackContext *pContext = (DebugCallbackContext *)cnxt;

    reg = (u2) tweakSlot(reg, name);

    ALOGV("    %2d: %d(%d) '%s' '%s' slot=%d",
        pContext->numItems, startAddress, endAddress - startAddress,
        name, descriptor, reg);

    expandBufAdd8BE(pContext->pReply, startAddress);
    expandBufAddUtf8String(pContext->pReply, (const u1*)name);
    expandBufAddUtf8String(pContext->pReply, (const u1*)descriptor);
    if (pContext->withGeneric) {
        expandBufAddUtf8String(pContext->pReply, (const u1*) signature);
    }
    expandBufAdd4BE(pContext->pReply, endAddress - startAddress);
    expandBufAdd4BE(pContext->pReply, reg);

    pContext->numItems++;
}

/*
 * For Method.VariableTable[WithGeneric]: output information about local
 * variables for the specified method.
 */

/*
 *breif:输出有关本地变量指定的方法.
*/
void dvmDbgOutputVariableTable(RefTypeId refTypeId, MethodId methodId,
    bool withGeneric, ExpandBuf* pReply)
{
    Method* method;
    DebugCallbackContext context;

    memset (&context, 0, sizeof(DebugCallbackContext));

    method = methodIdToMethod(refTypeId, methodId);

    expandBufAdd4BE(pReply, method->insSize);

    // Add numLocals later
    size_t numLocalsOffset = expandBufGetLength(pReply);
    expandBufAdd4BE(pReply, 0);

    context.pReply = pReply;
    context.withGeneric = withGeneric;
    dexDecodeDebugInfo(method->clazz->pDvmDex->pDexFile,
        dvmGetMethodCode(method),
        method->clazz->descriptor,
        method->prototype.protoIdx,
        method->accessFlags,
        NULL, variableTableCb, &context);

    set4BE(expandBufGetBuffer(pReply) + numLocalsOffset, context.numItems);
}

/*
 * Get the basic tag for an instance field.
 */

/*
 *breif:获取一个实例字段的标签.
*/
u1 dvmDbgGetFieldBasicTag(ObjectId objId, FieldId fieldId)
{
    Object* obj = objectIdToObject(objId);
    RefTypeId classId = classObjectToRefTypeId(obj->clazz);
    const Field* field = fieldIdToField(classId, fieldId);
    return basicTagFromDescriptor(field->signature);
}

/*
 * Get the basic tag for a static field.
 */

/*
 *breif:获取静态字段的基本标签.
*/
u1 dvmDbgGetStaticFieldBasicTag(RefTypeId refTypeId, FieldId fieldId)
{
    const Field* field = fieldIdToField(refTypeId, fieldId);
    return basicTagFromDescriptor(field->signature);
}


/*
 * Copy the value of a static field into the output buffer, preceded
 * by an appropriate tag.  The tag is based on the value held by the
 * field, not the field's type.
 */

/*
 *breif:获取字段的值.
*/
void dvmDbgGetFieldValue(ObjectId objectId, FieldId fieldId, ExpandBuf* pReply)
{
    Object* obj = objectIdToObject(objectId);
    RefTypeId classId = classObjectToRefTypeId(obj->clazz);
    InstField* ifield = (InstField*) fieldIdToField(classId, fieldId);
    u1 tag = basicTagFromDescriptor(ifield->signature);

    if (tag == JT_ARRAY || tag == JT_OBJECT) {
        Object* objVal = dvmGetFieldObject(obj, ifield->byteOffset);
        tag = tagFromObject(objVal);
        expandBufAdd1(pReply, tag);
        expandBufAddObjectId(pReply, objectToObjectId(objVal));
        ALOGV("    --> ifieldId %x --> tag '%c' %p", fieldId, tag, objVal);
    } else {
        ALOGV("    --> ifieldId %x --> tag '%c'", fieldId, tag);
        expandBufAdd1(pReply, tag);

        switch (tag) {
        case JT_BOOLEAN:
            expandBufAdd1(pReply, dvmGetFieldBoolean(obj, ifield->byteOffset));
            break;
        case JT_BYTE:
            expandBufAdd1(pReply, dvmGetFieldByte(obj, ifield->byteOffset));
            break;
        case JT_SHORT:
            expandBufAdd2BE(pReply, dvmGetFieldShort(obj, ifield->byteOffset));
            break;
        case JT_CHAR:
            expandBufAdd2BE(pReply, dvmGetFieldChar(obj, ifield->byteOffset));
            break;
        case JT_INT:
        case JT_FLOAT:
            expandBufAdd4BE(pReply, dvmGetFieldInt(obj, ifield->byteOffset));
            break;
        case JT_LONG:
        case JT_DOUBLE:
            expandBufAdd8BE(pReply, dvmGetFieldLong(obj, ifield->byteOffset));
            break;
        default:
            ALOGE("ERROR: unhandled field type '%s'", ifield->signature);
            assert(false);
            break;
        }
    }
}

/*
 * Set the value of the specified field.
 */

/*
 *breif:向特定的字段设置值.
*/
void dvmDbgSetFieldValue(ObjectId objectId, FieldId fieldId, u8 value,
    int width)
{
    Object* obj = objectIdToObject(objectId);
    RefTypeId classId = classObjectToRefTypeId(obj->clazz);
    InstField* field = (InstField*) fieldIdToField(classId, fieldId);

    switch (field->signature[0]) {
    case JT_BOOLEAN:
        assert(width == 1);
        dvmSetFieldBoolean(obj, field->byteOffset, value != 0);
        break;
    case JT_BYTE:
        assert(width == 1);
        dvmSetFieldInt(obj, field->byteOffset, value);
        break;
    case JT_SHORT:
    case JT_CHAR:
        assert(width == 2);
        dvmSetFieldInt(obj, field->byteOffset, value);
        break;
    case JT_INT:
    case JT_FLOAT:
        assert(width == 4);
        dvmSetFieldInt(obj, field->byteOffset, value);
        break;
    case JT_ARRAY:
    case JT_OBJECT:
        assert(width == sizeof(ObjectId));
        dvmSetFieldObject(obj, field->byteOffset, objectIdToObject(value));
        break;
    case JT_DOUBLE:
    case JT_LONG:
        assert(width == 8);
        dvmSetFieldLong(obj, field->byteOffset, value);
        break;
    default:
        ALOGE("ERROR: unhandled class type '%s'", field->signature);
        assert(false);
        break;
    }
}

/*
 * Copy the value of a static field into the output buffer, preceded
 * by an appropriate tag.  The tag is based on the value held by the
 * field, not the field's type.
 */

/*
 *breif:获取静态字段的值.
*/
void dvmDbgGetStaticFieldValue(RefTypeId refTypeId, FieldId fieldId,
    ExpandBuf* pReply)
{
    StaticField* sfield = (StaticField*) fieldIdToField(refTypeId, fieldId);
    u1 tag = basicTagFromDescriptor(sfield->signature);

    if (tag == JT_ARRAY || tag == JT_OBJECT) {
        Object* objVal = dvmGetStaticFieldObject(sfield);
        tag = tagFromObject(objVal);
        expandBufAdd1(pReply, tag);
        expandBufAddObjectId(pReply, objectToObjectId(objVal));
        ALOGV("    --> sfieldId %x --> tag '%c' %p", fieldId, tag, objVal);
    } else {
        JValue value;

        ALOGV("    --> sfieldId %x --> tag '%c'", fieldId, tag);
        expandBufAdd1(pReply, tag);

        switch (tag) {
        case JT_BOOLEAN:
            expandBufAdd1(pReply, dvmGetStaticFieldBoolean(sfield));
            break;
        case JT_BYTE:
            expandBufAdd1(pReply, dvmGetStaticFieldByte(sfield));
            break;
        case JT_SHORT:
            expandBufAdd2BE(pReply, dvmGetStaticFieldShort(sfield));
            break;
        case JT_CHAR:
            expandBufAdd2BE(pReply, dvmGetStaticFieldChar(sfield));
            break;
        case JT_INT:
            expandBufAdd4BE(pReply, dvmGetStaticFieldInt(sfield));
            break;
        case JT_FLOAT:
            value.f = dvmGetStaticFieldFloat(sfield);
            expandBufAdd4BE(pReply, value.i);
            break;
        case JT_LONG:
            expandBufAdd8BE(pReply, dvmGetStaticFieldLong(sfield));
            break;
        case JT_DOUBLE:
            value.d = dvmGetStaticFieldDouble(sfield);
            expandBufAdd8BE(pReply, value.j);
            break;
        default:
            ALOGE("ERROR: unhandled field type '%s'", sfield->signature);
            assert(false);
            break;
        }
    }
}

/*
 * Set the value of a static field.
 */

/*
 *breif:向静态字段设置值.
*/
void dvmDbgSetStaticFieldValue(RefTypeId refTypeId, FieldId fieldId,
    u8 rawValue, int width)
{
    StaticField* sfield = (StaticField*) fieldIdToField(refTypeId, fieldId);
    Object* objVal;
    JValue value;

    value.j = rawValue;

    switch (sfield->signature[0]) {
    case JT_BOOLEAN:
        assert(width == 1);
        dvmSetStaticFieldBoolean(sfield, value.z);
        break;
    case JT_BYTE:
        assert(width == 1);
        dvmSetStaticFieldByte(sfield, value.b);
        break;
    case JT_SHORT:
        assert(width == 2);
        dvmSetStaticFieldShort(sfield, value.s);
        break;
    case JT_CHAR:
        assert(width == 2);
        dvmSetStaticFieldChar(sfield, value.c);
        break;
    case JT_INT:
        assert(width == 4);
        dvmSetStaticFieldInt(sfield, value.i);
        break;
    case JT_FLOAT:
        assert(width == 4);
        dvmSetStaticFieldFloat(sfield, value.f);
        break;
    case JT_ARRAY:
    case JT_OBJECT:
        assert(width == sizeof(ObjectId));
        objVal = objectIdToObject(rawValue);
        dvmSetStaticFieldObject(sfield, objVal);
        break;
    case JT_LONG:
        assert(width == 8);
        dvmSetStaticFieldLong(sfield, value.j);
        break;
    case JT_DOUBLE:
        assert(width == 8);
        dvmSetStaticFieldDouble(sfield, value.d);
        break;
    default:
        ALOGE("ERROR: unhandled class type '%s'", sfield->signature);
        assert(false);
        break;
    }
}

/*
 * Convert a string object to a UTF-8 string.
 *
 * Returns a newly-allocated string.
 */

/*
 *breif:返回一个新分配的字符串.
*/
char* dvmDbgStringToUtf8(ObjectId strId)
{
    StringObject* strObj = (StringObject*) objectIdToObject(strId);

    return dvmCreateCstrFromString(strObj);
}


/*
 * ===========================================================================
 *      Thread and ThreadGroup
 * ===========================================================================
 */

/*
 * Convert a thread object to a Thread ptr.
 *
 * This currently requires running through the list of threads and finding
 * a match.
 *
 * IMPORTANT: grab gDvm.threadListLock before calling here.
 */

/*
 *breif:将线程对象设置为线程指针.需要遍历线程对象表.
*/
static Thread* threadObjToThread(Object* threadObj)
{
    Thread* thread;

    for (thread = gDvm.threadList; thread != NULL; thread = thread->next) {
        if (thread->threadObj == threadObj)
            break;
    }

    return thread;
}

/*
 * Get the status and suspend state of a thread.
 */

/*
 *breif:获取线程状态并且挂起线程.
*/
bool dvmDbgGetThreadStatus(ObjectId threadId, u4* pThreadStatus,
    u4* pSuspendStatus)
{
    Object* threadObj;
    Thread* thread;
    bool result = false;

    threadObj = objectIdToObject(threadId);
    assert(threadObj != NULL);

    /* lock the thread list, so the thread doesn't vanish while we work */
    dvmLockThreadList(NULL);

    thread = threadObjToThread(threadObj);
    if (thread == NULL)
        goto bail;

    switch (thread->status) {
    case THREAD_ZOMBIE:         *pThreadStatus = TS_ZOMBIE;     break;
    case THREAD_RUNNING:        *pThreadStatus = TS_RUNNING;    break;
    case THREAD_TIMED_WAIT:     *pThreadStatus = TS_SLEEPING;   break;
    case THREAD_MONITOR:        *pThreadStatus = TS_MONITOR;    break;
    case THREAD_WAIT:           *pThreadStatus = TS_WAIT;       break;
    case THREAD_INITIALIZING:   *pThreadStatus = TS_ZOMBIE;     break;
    case THREAD_STARTING:       *pThreadStatus = TS_ZOMBIE;     break;
    case THREAD_NATIVE:         *pThreadStatus = TS_RUNNING;    break;
    case THREAD_VMWAIT:         *pThreadStatus = TS_WAIT;       break;
    case THREAD_SUSPENDED:      *pThreadStatus = TS_RUNNING;    break;
    default:
        assert(false);
        *pThreadStatus = THREAD_ZOMBIE;
        break;
    }

    if (dvmIsSuspended(thread))
        *pSuspendStatus = SUSPEND_STATUS_SUSPENDED;
    else
        *pSuspendStatus = 0;

    result = true;

bail:
    dvmUnlockThreadList();
    return result;
}

/*
 * Get the thread's suspend count.
 */

/*
 *breif:获取线程的挂起计数.
*/
u4 dvmDbgGetThreadSuspendCount(ObjectId threadId)
{
    Object* threadObj;
    Thread* thread;
    u4 result = 0;

    threadObj = objectIdToObject(threadId);
    assert(threadObj != NULL);

    /* lock the thread list, so the thread doesn't vanish while we work */
    dvmLockThreadList(NULL);

    thread = threadObjToThread(threadObj);
    if (thread == NULL)
        goto bail;

    result = thread->suspendCount;

bail:
    dvmUnlockThreadList();
    return result;
}

/*
 * Determine whether or not a thread exists in the VM's thread list.
 *
 * Returns "true" if the thread exists.
 */

/*
 *breif:判断指定线程ID的线程是否在虚拟机的线程链表里.
*/
bool dvmDbgThreadExists(ObjectId threadId)
{
    Object* threadObj;
    Thread* thread;
    bool result;

    threadObj = objectIdToObject(threadId);
    assert(threadObj != NULL);

    /* lock the thread list, so the thread doesn't vanish while we work */
    dvmLockThreadList(NULL);

    thread = threadObjToThread(threadObj);
    if (thread == NULL)
        result = false;
    else
        result = true;

    dvmUnlockThreadList();
    return result;
}

/*
 * Determine whether or not a thread is suspended.
 *
 * Returns "false" if the thread is running or doesn't exist.
 */

/*
 *breif:判断线程是否挂起.
*/
bool dvmDbgIsSuspended(ObjectId threadId)
{
    Object* threadObj;
    Thread* thread;
    bool result = false;

    threadObj = objectIdToObject(threadId);
    assert(threadObj != NULL);

    /* lock the thread list, so the thread doesn't vanish while we work */
    dvmLockThreadList(NULL);

    thread = threadObjToThread(threadObj);
    if (thread == NULL)
        goto bail;

    result = dvmIsSuspended(thread);

bail:
    dvmUnlockThreadList();
    return result;
}

/*
 * Return the ObjectId for the "system" thread group.
 */

/*
 *breif:获取 "system"组的线程对象ID.
*/
ObjectId dvmDbgGetSystemThreadGroupId()
{
    Object* groupObj = dvmGetSystemThreadGroup();
    return objectToObjectId(groupObj);
}

/*
 * Return the ObjectId for the "main" thread group.
 */

/*
 *breif:获取组为"main"的线程对象.
*/
ObjectId dvmDbgGetMainThreadGroupId()
{
    Object* groupObj = dvmGetMainThreadGroup();
    return objectToObjectId(groupObj);
}

/*
 * Get the name of a thread.
 *
 * Returns a newly-allocated string.
 */

/*
 *breif:返回一个新分配的字符串存储线程名字.
*/
char* dvmDbgGetThreadName(ObjectId threadId)
{
    Object* threadObj;
    StringObject* nameStr;
    char* str;
    char* result;

    threadObj = objectIdToObject(threadId);
    assert(threadObj != NULL);

    nameStr = (StringObject*) dvmGetFieldObject(threadObj,
                                                gDvm.offJavaLangThread_name);
    str = dvmCreateCstrFromString(nameStr);
    result = (char*) malloc(strlen(str) + 20);

    /* lock the thread list, so the thread doesn't vanish while we work */
    dvmLockThreadList(NULL);
    Thread* thread = threadObjToThread(threadObj);
    if (thread != NULL)
        sprintf(result, "<%d> %s", thread->threadId, str);
    else
        sprintf(result, "%s", str);
    dvmUnlockThreadList();

    free(str);
    return result;
}

/*
 * Get a thread's group.
 */

/*
 *breif:获取一个线程的组.
*/
ObjectId dvmDbgGetThreadGroup(ObjectId threadId)
{
    Object* threadObj;
    Object* group;

    threadObj = objectIdToObject(threadId);
    assert(threadObj != NULL);

    group = dvmGetFieldObject(threadObj, gDvm.offJavaLangThread_group);
    return objectToObjectId(group);
}


/*
 * Get the name of a thread group.
 *
 * Returns a newly-allocated string.
 */

/*
 *breif:通过线程组ID获取线程组名称.
*/
char* dvmDbgGetThreadGroupName(ObjectId threadGroupId)
{
    Object* threadGroup;
    StringObject* nameStr;

    threadGroup = objectIdToObject(threadGroupId);
    assert(threadGroup != NULL);

    nameStr = (StringObject*)
        dvmGetFieldObject(threadGroup, gDvm.offJavaLangThreadGroup_name);
    return dvmCreateCstrFromString(nameStr);
}

/*
 * Get the parent of a thread group.
 *
 * Returns a newly-allocated string.
 */

/*
 *breif:获取线程组的父组.
*/
ObjectId dvmDbgGetThreadGroupParent(ObjectId threadGroupId)
{
    Object* threadGroup;
    Object* parent;

    threadGroup = objectIdToObject(threadGroupId);
    assert(threadGroup != NULL);

    parent = dvmGetFieldObject(threadGroup, gDvm.offJavaLangThreadGroup_parent);
    return objectToObjectId(parent);
}

/*
 * Get the list of threads in the thread group.
 *
 * We do this by running through the full list of threads and returning
 * the ones that have the ThreadGroup object as their owner.
 *
 * If threadGroupId is set to "kAllThreads", we ignore the group field and
 * return all threads.
 *
 * The caller must free "*ppThreadIds".
 */

/*
 *breif:获取线程组的所有线程.
*/
void dvmDbgGetThreadGroupThreads(ObjectId threadGroupId,
    ObjectId** ppThreadIds, u4* pThreadCount)
{
    Object* targetThreadGroup = NULL;
    Thread* thread;
    int count;

    if (threadGroupId != THREAD_GROUP_ALL) {
        targetThreadGroup = objectIdToObject(threadGroupId);
        assert(targetThreadGroup != NULL);
    }

    dvmLockThreadList(NULL);

    thread = gDvm.threadList;
    count = 0;
    for (thread = gDvm.threadList; thread != NULL; thread = thread->next) {
        Object* group;

        /* Skip over the JDWP support thread.  Some debuggers
         * get bent out of shape when they can't suspend and
         * query all threads, so it's easier if we just don't
         * tell them about us.
         */
        if (thread->handle == dvmJdwpGetDebugThread(gDvm.jdwpState))
            continue;

        /* This thread is currently being created, and isn't ready
         * to be seen by the debugger yet.
         */
        if (thread->threadObj == NULL)
            continue;

        group = dvmGetFieldObject(thread->threadObj,
                    gDvm.offJavaLangThread_group);
        if (threadGroupId == THREAD_GROUP_ALL || group == targetThreadGroup)
            count++;
    }

    *pThreadCount = count;

    if (count == 0) {
        *ppThreadIds = NULL;
    } else {
        ObjectId* ptr;
        ptr = *ppThreadIds = (ObjectId*) malloc(sizeof(ObjectId) * count);

        for (thread = gDvm.threadList; thread != NULL; thread = thread->next) {
            Object* group;

            /* Skip over the JDWP support thread.  Some debuggers
             * get bent out of shape when they can't suspend and
             * query all threads, so it's easier if we just don't
             * tell them about us.
             */
            if (thread->handle == dvmJdwpGetDebugThread(gDvm.jdwpState))
                continue;

            /* This thread is currently being created, and isn't ready
             * to be seen by the debugger yet.
             */
            if (thread->threadObj == NULL)
                continue;

            group = dvmGetFieldObject(thread->threadObj,
                        gDvm.offJavaLangThread_group);
            if (threadGroupId == THREAD_GROUP_ALL || group == targetThreadGroup)
            {
                *ptr++ = objectToObjectId(thread->threadObj);
                count--;
            }
        }

        assert(count == 0);
    }

    dvmUnlockThreadList();
}

/*
 * Get all threads.
 *
 * The caller must free "*ppThreadIds".
 */

/*
 *breif:获取所有线程.
*/
void dvmDbgGetAllThreads(ObjectId** ppThreadIds, u4* pThreadCount)
{
    dvmDbgGetThreadGroupThreads(THREAD_GROUP_ALL, ppThreadIds, pThreadCount);
}


/*
 * Count up the #of frames on the thread's stack.
 *
 * Returns -1 on failure.
 */

/*
 *breif:获取线程堆栈侦.
*/
int dvmDbgGetThreadFrameCount(ObjectId threadId)
{
    Object* threadObj;
    Thread* thread;
    int count = -1;

    threadObj = objectIdToObject(threadId);

    dvmLockThreadList(NULL);
    thread = threadObjToThread(threadObj);
    if (thread != NULL) {
        count = dvmComputeExactFrameDepth(thread->interpSave.curFrame);
    }
    dvmUnlockThreadList();

    return count;
}

/*
 * Get info for frame N from the specified thread's stack.
 */

/*
 *breif:从指定的线程帧获取信息.
*/
bool dvmDbgGetThreadFrame(ObjectId threadId, int num, FrameId* pFrameId,
    JdwpLocation* pLoc)
{
    Object* threadObj;
    Thread* thread;
    void* framePtr;
    int count;

    threadObj = objectIdToObject(threadId);

    dvmLockThreadList(NULL);

    thread = threadObjToThread(threadObj);
    if (thread == NULL)
        goto bail;

    framePtr = thread->interpSave.curFrame;
    count = 0;
    while (framePtr != NULL) {
        const StackSaveArea* saveArea = SAVEAREA_FROM_FP(framePtr);
        const Method* method = saveArea->method;

        if (!dvmIsBreakFrame((u4*)framePtr)) {
            if (count == num) {
                *pFrameId = frameToFrameId(framePtr);
                if (dvmIsInterfaceClass(method->clazz))
                    pLoc->typeTag = TT_INTERFACE;
                else
                    pLoc->typeTag = TT_CLASS;
                pLoc->classId = classObjectToRefTypeId(method->clazz);
                pLoc->methodId = methodToMethodId(method);
                if (dvmIsNativeMethod(method))
                    pLoc->idx = (u8)-1;
                else
                    pLoc->idx = saveArea->xtra.currentPc - method->insns;
                dvmUnlockThreadList();
                return true;
            }

            count++;
        }

        framePtr = saveArea->prevFrame;
    }

bail:
    dvmUnlockThreadList();
    return false;
}

/*
 * Get the ThreadId for the current thread.
 */

/*
 *breif:获取当前线程的ID.
*/
ObjectId dvmDbgGetThreadSelfId()
{
    Thread* self = dvmThreadSelf();
    return objectToObjectId(self->threadObj);
}

/*
 * Suspend the VM.
 */

/*
 *breif:将虚拟机所有线程挂起.
*/
void dvmDbgSuspendVM(bool isEvent)
{
    dvmSuspendAllThreads(isEvent ? SUSPEND_FOR_DEBUG_EVENT : SUSPEND_FOR_DEBUG);
}

/*
 * Resume the VM.
 */

/*
 *breif:恢复虚拟机.
*/
void dvmDbgResumeVM()
{
    dvmResumeAllThreads(SUSPEND_FOR_DEBUG);
}

/*
 * Suspend one thread (not ourselves).
 */

/*
 *breif:挂起一个线程.
*/
void dvmDbgSuspendThread(ObjectId threadId)
{
    Object* threadObj = objectIdToObject(threadId);
    Thread* thread;

    dvmLockThreadList(NULL);

    thread = threadObjToThread(threadObj);
    if (thread == NULL) {
        /* can happen if our ThreadDeath notify crosses in the mail */
        ALOGW("WARNING: threadid=%llx obj=%p no match", threadId, threadObj);
    } else {
        dvmSuspendThread(thread);
    }

    dvmUnlockThreadList();
}

/*
 * Resume one thread (not ourselves).
 */

/*
 *breif:恢复一个线程.
*/
void dvmDbgResumeThread(ObjectId threadId)
{
    Object* threadObj = objectIdToObject(threadId);
    Thread* thread;

    dvmLockThreadList(NULL);

    thread = threadObjToThread(threadObj);
    if (thread == NULL) {
        ALOGW("WARNING: threadid=%llx obj=%p no match", threadId, threadObj);
    } else {
        dvmResumeThread(thread);
    }

    dvmUnlockThreadList();
}

/*
 * Suspend ourselves after sending an event to the debugger.
 */

/*
 *breif:挂起自身线程并向调试器发送事件.
*/
void dvmDbgSuspendSelf()
{
    dvmSuspendSelf(true);
}

/*
 * Get the "this" object for the specified frame.
 */

/*
 *breif:从指定的帧获取对象.
*/
static Object* getThisObject(const u4* framePtr)
{
    const StackSaveArea* saveArea = SAVEAREA_FROM_FP(framePtr);
    const Method* method = saveArea->method;
    int argOffset = method->registersSize - method->insSize;
    Object* thisObj;

    if (method == NULL) {
        /* this is a "break" frame? */
        assert(false);
        return NULL;
    }

    LOGVV("  Pulling this object for frame at %p", framePtr);
    LOGVV("    Method='%s' native=%d static=%d this=%p",
        method->name, dvmIsNativeMethod(method),
        dvmIsStaticMethod(method), (Object*) framePtr[argOffset]);

    /*
     * No "this" pointer for statics.  No args on the interp stack for
     * native methods invoked directly from the VM.
     */
    if (dvmIsNativeMethod(method) || dvmIsStaticMethod(method))
        thisObj = NULL;
    else
        thisObj = (Object*) framePtr[argOffset];

    if (thisObj != NULL && !dvmIsHeapAddress(thisObj)) {
        ALOGW("Debugger: invalid 'this' pointer %p in %s.%s; returning NULL",
            framePtr, method->clazz->descriptor, method->name);
        thisObj = NULL;
    }

    return thisObj;
}

/*
 * Return the "this" object for the specified frame.  The thread must be
 * suspended.
 */

/*
 *breif:挂起线程,然后从指定的帧获取对象.
*/
bool dvmDbgGetThisObject(ObjectId threadId, FrameId frameId, ObjectId* pThisId)
{
    const u4* framePtr = frameIdToFrame(frameId);
    Object* thisObj;

    UNUSED_PARAMETER(threadId);

    thisObj = getThisObject(framePtr);

    *pThisId = objectToObjectId(thisObj);
    return true;
}

/*
 * Copy the value of a method argument or local variable into the
 * specified buffer.  The value will be preceeded with the tag.
 *
 * The debugger includes the tags in the request.  Object tags may
 * be updated with a more refined type.
 */

/*
 *breif:获取方法参数或者局部变量的值.
*/
void dvmDbgGetLocalValue(ObjectId threadId, FrameId frameId, int slot,
    u1 tag, u1* buf, int expectedLen)
{
    const u4* framePtr = frameIdToFrame(frameId);
    Object* objVal;
    u4 intVal;
    u8 longVal;

    UNUSED_PARAMETER(threadId);

    slot = untweakSlot(slot, framePtr);     // Eclipse workaround

    switch (tag) {
    case JT_BOOLEAN:
        assert(expectedLen == 1);
        intVal = framePtr[slot];
        set1(buf+1, intVal != 0);
        break;
    case JT_BYTE:
        assert(expectedLen == 1);
        intVal = framePtr[slot];
        set1(buf+1, intVal);
        break;
    case JT_SHORT:
    case JT_CHAR:
        assert(expectedLen == 2);
        intVal = framePtr[slot];
        set2BE(buf+1, intVal);
        break;
    case JT_INT:
    case JT_FLOAT:
        assert(expectedLen == 4);
        intVal = framePtr[slot];
        set4BE(buf+1, intVal);
        break;
    case JT_ARRAY:
        assert(expectedLen == sizeof(ObjectId));
        {
            /* convert to "ObjectId" */
            objVal = (Object*)framePtr[slot];
            if (objVal != NULL && !dvmIsHeapAddress(objVal)) {
                ALOGW("JDWP: slot %d expected to hold array, %p invalid",
                    slot, objVal);
                dvmAbort();         // DEBUG: make it obvious
                objVal = NULL;
                tag = JT_OBJECT;    // JT_ARRAY not expected for NULL ref
            }
            dvmSetObjectId(buf+1, objectToObjectId(objVal));
        }
        break;
    case JT_OBJECT:
        assert(expectedLen == sizeof(ObjectId));
        {
            /* convert to "ObjectId" */
            objVal = (Object*)framePtr[slot];

            if (objVal != NULL && !dvmIsHeapAddress(objVal)) {
                ALOGW("JDWP: slot %d expected to hold object, %p invalid",
                    slot, objVal);
                dvmAbort();         // DEBUG: make it obvious
                objVal = NULL;
            }
            tag = tagFromObject(objVal);
            dvmSetObjectId(buf+1, objectToObjectId(objVal));
        }
        break;
    case JT_DOUBLE:
    case JT_LONG:
        assert(expectedLen == 8);
        memcpy(&longVal, &framePtr[slot], 8);
        set8BE(buf+1, longVal);
        break;
    default:
        ALOGE("ERROR: unhandled tag '%c'", tag);
        assert(false);
        break;
    }

    /* prepend tag, which may have been updated */
    set1(buf, tag);
}

/*
 * Copy a new value into an argument or local variable.
 */

/*
 *breif:复制一个新的值到参数或局部变量.
*/
void dvmDbgSetLocalValue(ObjectId threadId, FrameId frameId, int slot, u1 tag,
    u8 value, int width)
{
    u4* framePtr = frameIdToFrame(frameId);

    UNUSED_PARAMETER(threadId);

    slot = untweakSlot(slot, framePtr);     // Eclipse workaround

    switch (tag) {
    case JT_BOOLEAN:
        assert(width == 1);
        framePtr[slot] = (u4)value;
        break;
    case JT_BYTE:
        assert(width == 1);
        framePtr[slot] = (u4)value;
        break;
    case JT_SHORT:
    case JT_CHAR:
        assert(width == 2);
        framePtr[slot] = (u4)value;
        break;
    case JT_INT:
    case JT_FLOAT:
        assert(width == 4);
        framePtr[slot] = (u4)value;
        break;
    case JT_STRING:
        /* The debugger calls VirtualMachine.CreateString to create a new
         * string, then uses this to set the object reference, when you
         * edit a String object */
    case JT_ARRAY:
    case JT_OBJECT:
        assert(width == sizeof(ObjectId));
        framePtr[slot] = (u4) objectIdToObject(value);
        break;
    case JT_DOUBLE:
    case JT_LONG:
        assert(width == 8);
        memcpy(&framePtr[slot], &value, 8);
        break;
    case JT_VOID:
    case JT_CLASS_OBJECT:
    case JT_THREAD:
    case JT_THREAD_GROUP:
    case JT_CLASS_LOADER:
        /* not expecting these from debugger; fall through to failure */
    default:
        ALOGE("ERROR: unhandled tag '%c'", tag);
        assert(false);
        break;
    }
}


/*
 * ===========================================================================
 *      Debugger notification
 * ===========================================================================
 */

/*
 * Tell JDWP that a breakpoint address has been reached.
 *
 * "pcOffset" will be -1 for native methods.
 * "thisPtr" will be NULL for static methods.
 */

/*
 *breif:告诉JDWP已经到了一个断点地址.
*/
void dvmDbgPostLocationEvent(const Method* method, int pcOffset,
    Object* thisPtr, int eventFlags)
{
    JdwpLocation loc;

    if (dvmIsInterfaceClass(method->clazz))
        loc.typeTag = TT_INTERFACE;
    else
        loc.typeTag = TT_CLASS;
    loc.classId = classObjectToRefTypeId(method->clazz);
    loc.methodId = methodToMethodId(method);
    loc.idx = pcOffset;

    /*
     * Note we use "NoReg" so we don't keep track of references that are
     * never actually sent to the debugger.  The "thisPtr" is only used to
     * compare against registered events.
     */

    if (dvmJdwpPostLocationEvent(gDvm.jdwpState, &loc,
            objectToObjectIdNoReg(thisPtr), eventFlags))
    {
        classObjectToRefTypeId(method->clazz);
        objectToObjectId(thisPtr);
    }
}

/*
 * Tell JDWP that an exception has occurred.
 */

/*
 *breif:告诉JDWP产生异常.
*/
void dvmDbgPostException(void* throwFp, int throwRelPc, void* catchFp,
    int catchRelPc, Object* exception)
{
    JdwpLocation throwLoc, catchLoc;
    const Method* throwMeth;
    const Method* catchMeth;

    throwMeth = SAVEAREA_FROM_FP(throwFp)->method;
    if (dvmIsInterfaceClass(throwMeth->clazz))
        throwLoc.typeTag = TT_INTERFACE;
    else
        throwLoc.typeTag = TT_CLASS;
    throwLoc.classId = classObjectToRefTypeId(throwMeth->clazz);
    throwLoc.methodId = methodToMethodId(throwMeth);
    throwLoc.idx = throwRelPc;

    if (catchRelPc < 0) {
        memset(&catchLoc, 0, sizeof(catchLoc));
    } else {
        catchMeth = SAVEAREA_FROM_FP(catchFp)->method;
        if (dvmIsInterfaceClass(catchMeth->clazz))
            catchLoc.typeTag = TT_INTERFACE;
        else
            catchLoc.typeTag = TT_CLASS;
        catchLoc.classId = classObjectToRefTypeId(catchMeth->clazz);
        catchLoc.methodId = methodToMethodId(catchMeth);
        catchLoc.idx = catchRelPc;
    }

    /* need this for InstanceOnly filters */
    Object* thisObj = getThisObject((u4*)throwFp);

    /*
     * Hand the event to the JDWP exception handler.  Note we're using the
     * "NoReg" objectID on the exception, which is not strictly correct --
     * the exception object WILL be passed up to the debugger if the
     * debugger is interested in the event.  We do this because the current
     * implementation of the debugger object registry never throws anything
     * away, and some people were experiencing a fatal build up of exception
     * objects when dealing with certain libraries.
     */
    dvmJdwpPostException(gDvm.jdwpState, &throwLoc,
        objectToObjectIdNoReg(exception),
        classObjectToRefTypeId(exception->clazz), &catchLoc,
        objectToObjectId(thisObj));
}

/*
 * Tell JDWP and/or DDMS that a thread has started.
 */

/*
 *breif:告诉JDWP或DDMS有线程启动.
*/
void dvmDbgPostThreadStart(Thread* thread)
{
    if (gDvm.debuggerActive) {
        dvmJdwpPostThreadChange(gDvm.jdwpState,
            objectToObjectId(thread->threadObj), true);
    }
    if (gDvm.ddmThreadNotification)
        dvmDdmSendThreadNotification(thread, true);
}

/*
 * Tell JDWP and/or DDMS that a thread has gone away.
 */

/*
 *breif:通知JDWP或者DDMS线程结束.
*/
void dvmDbgPostThreadDeath(Thread* thread)
{
    if (gDvm.debuggerActive) {
        dvmJdwpPostThreadChange(gDvm.jdwpState,
            objectToObjectId(thread->threadObj), false);
    }
    if (gDvm.ddmThreadNotification)
        dvmDdmSendThreadNotification(thread, false);
}

/*
 * Tell JDWP that a new class has been prepared.
 */

/*
 *breif:通知JDWP新的类构造.
*/
void dvmDbgPostClassPrepare(ClassObject* clazz)
{
    const char* signature;
    int tag;

    if (dvmIsInterfaceClass(clazz))
        tag = TT_INTERFACE;
    else
        tag = TT_CLASS;

    // TODO - we currently always send both "verified" and "prepared" since
    // debuggers seem to like that.  There might be some advantage to honesty,
    // since the class may not yet be verified.
    signature = jniSignature(clazz);
    dvmJdwpPostClassPrepare(gDvm.jdwpState, tag, classObjectToRefTypeId(clazz),
        signature, CS_VERIFIED | CS_PREPARED);
}

/*
 * The JDWP event mechanism has registered an event with a LocationOnly
 * mod.  Tell the interpreter to call us if we hit the specified
 * address.
 */

/*
 *breif:JDWP事件机制注册的本地事件
*/
bool dvmDbgWatchLocation(const JdwpLocation* pLoc)
{
    Method* method = methodIdToMethod(pLoc->classId, pLoc->methodId);
    assert(!dvmIsNativeMethod(method));
    dvmAddBreakAddr(method, pLoc->idx);
    return true;        /* assume success */
}

/*
 * An event with a LocationOnly mod has been removed.
 */

/*
 *breif:LocationOnly mod 事件移除.
*/
void dvmDbgUnwatchLocation(const JdwpLocation* pLoc)
{
    Method* method = methodIdToMethod(pLoc->classId, pLoc->methodId);
    assert(!dvmIsNativeMethod(method));
    dvmClearBreakAddr(method, pLoc->idx);
}

/*
 * The JDWP event mechanism has registered a single-step event.  Tell
 * the interpreter about it.
 */

/*
 *breif:JDWP注册的单步事件.
*/
bool dvmDbgConfigureStep(ObjectId threadId, JdwpStepSize size,
    JdwpStepDepth depth)
{
    Object* threadObj;
    Thread* thread;
    bool result = false;

    threadObj = objectIdToObject(threadId);
    assert(threadObj != NULL);

    /*
     * Get a pointer to the Thread struct for this ID.  The pointer will
     * be used strictly for comparisons against the current thread pointer
     * after the setup is complete, so we can safely release the lock.
     */
    dvmLockThreadList(NULL);
    thread = threadObjToThread(threadObj);

    if (thread == NULL) {
        ALOGE("Thread for single-step not found");
        goto bail;
    }
    if (!dvmIsSuspended(thread)) {
        ALOGE("Thread for single-step not suspended");
        assert(!"non-susp step");      // I want to know if this can happen
        goto bail;
    }

    assert(dvmIsSuspended(thread));
    if (!dvmAddSingleStep(thread, size, depth))
        goto bail;

    result = true;

bail:
    dvmUnlockThreadList();
    return result;
}

/*
 * A single-step event has been removed.
 */

/*
 *breif:单步事件移除.
*/
void dvmDbgUnconfigureStep(ObjectId threadId)
{
    UNUSED_PARAMETER(threadId);

    /* right now it's global, so don't need to find Thread */
    dvmClearSingleStep(NULL);
}

/*
 * Invoke a method in a thread that has been stopped on a breakpoint or
 * other debugger event.  (This function is called from the JDWP thread.)
 *
 * Note that access control is not enforced, per spec.
 */

/*
 *breif:处理一个断点中断或者调试事件触发的方法.
*/
JdwpError dvmDbgInvokeMethod(ObjectId threadId, ObjectId objectId,
    RefTypeId classId, MethodId methodId, u4 numArgs, ObjectId* argArray,
    u4 options, u1* pResultTag, u8* pResultValue, ObjectId* pExceptObj)
{
    Object* threadObj = objectIdToObject(threadId);

    dvmLockThreadList(NULL);

    Thread* targetThread = threadObjToThread(threadObj);
    if (targetThread == NULL) {
        dvmUnlockThreadList();
        return ERR_INVALID_THREAD;       /* thread does not exist */
    }
    if (!targetThread->invokeReq.ready) {
        dvmUnlockThreadList();
        return ERR_INVALID_THREAD;       /* thread not stopped by event */
    }

    /*
     * We currently have a bug where we don't successfully resume the
     * target thread if the suspend count is too deep.  We're expected to
     * require one "resume" for each "suspend", but when asked to execute
     * a method we have to resume fully and then re-suspend it back to the
     * same level.  (The easiest way to cause this is to type "suspend"
     * multiple times in jdb.)
     *
     * It's unclear what this means when the event specifies "resume all"
     * and some threads are suspended more deeply than others.  This is
     * a rare problem, so for now we just prevent it from hanging forever
     * by rejecting the method invocation request.  Without this, we will
     * be stuck waiting on a suspended thread.
     */
    if (targetThread->suspendCount > 1) {
        ALOGW("threadid=%d: suspend count on threadid=%d is %d, too deep "
             "for method exec",
            dvmThreadSelf()->threadId, targetThread->threadId,
            targetThread->suspendCount);
        dvmUnlockThreadList();
        return ERR_THREAD_SUSPENDED;     /* probably not expected here */
    }

    /*
     * TODO: ought to screen the various IDs, and verify that the argument
     * list is valid.
     */

    targetThread->invokeReq.obj = objectIdToObject(objectId);
    targetThread->invokeReq.thread = threadObj;
    targetThread->invokeReq.clazz = refTypeIdToClassObject(classId);
    targetThread->invokeReq.method = methodIdToMethod(classId, methodId);
    targetThread->invokeReq.numArgs = numArgs;
    targetThread->invokeReq.argArray = argArray;
    targetThread->invokeReq.options = options;
    targetThread->invokeReq.invokeNeeded = true;

    /*
     * This is a bit risky -- if the thread goes away we're sitting high
     * and dry -- but we must release this before the dvmResumeAllThreads
     * call, and it's unwise to hold it during dvmWaitForSuspend.
     */
    dvmUnlockThreadList();

    /*
     * We change our (JDWP thread) status, which should be THREAD_RUNNING,
     * so the VM can suspend for a GC if the invoke request causes us to
     * run out of memory.  It's also a good idea to change it before locking
     * the invokeReq mutex, although that should never be held for long.
     */
    Thread* self = dvmThreadSelf();
    ThreadStatus oldStatus = dvmChangeStatus(self, THREAD_VMWAIT);

    ALOGV("    Transferring control to event thread");
    dvmLockMutex(&targetThread->invokeReq.lock);

    if ((options & INVOKE_SINGLE_THREADED) == 0) {
        ALOGV("      Resuming all threads");
        dvmResumeAllThreads(SUSPEND_FOR_DEBUG_EVENT);
    } else {
        ALOGV("      Resuming event thread only");
        dvmResumeThread(targetThread);
    }

    /*
     * Wait for the request to finish executing.
     */
    while (targetThread->invokeReq.invokeNeeded) {
        pthread_cond_wait(&targetThread->invokeReq.cv,
                          &targetThread->invokeReq.lock);
    }
    dvmUnlockMutex(&targetThread->invokeReq.lock);
    ALOGV("    Control has returned from event thread");

    /* wait for thread to re-suspend itself */
    dvmWaitForSuspend(targetThread);

    /*
     * Done waiting, switch back to RUNNING.
     */
    dvmChangeStatus(self, oldStatus);

    /*
     * Suspend the threads.  We waited for the target thread to suspend
     * itself, so all we need to do is suspend the others.
     *
     * The suspendAllThreads() call will double-suspend the event thread,
     * so we want to resume the target thread once to keep the books straight.
     */
    if ((options & INVOKE_SINGLE_THREADED) == 0) {
        ALOGV("      Suspending all threads");
        dvmSuspendAllThreads(SUSPEND_FOR_DEBUG_EVENT);
        ALOGV("      Resuming event thread to balance the count");
        dvmResumeThread(targetThread);
    }

    /*
     * Set up the result.
     */
    *pResultTag = targetThread->invokeReq.resultTag;
    if (isTagPrimitive(targetThread->invokeReq.resultTag))
        *pResultValue = targetThread->invokeReq.resultValue.j;
    else {
        Object* tmpObj = (Object*)targetThread->invokeReq.resultValue.l;
        *pResultValue = objectToObjectId(tmpObj);
    }
    *pExceptObj = targetThread->invokeReq.exceptObj;
    return targetThread->invokeReq.err;
}

/*
 * Return a basic tag value for the return type.
 */

/*
 *breif:返回一个类型的标签.
*/
static u1 getReturnTypeBasicTag(const Method* method)
{
    const char* descriptor = dexProtoGetReturnType(&method->prototype);
    return basicTagFromDescriptor(descriptor);
}

/*
 * Execute the method described by "*pReq".
 *
 * We're currently in VMWAIT, because we're stopped on a breakpoint.  We
 * want to switch to RUNNING while we execute.
 */

/*
 *breif:执行 pReq 指向的方法.
*/
void dvmDbgExecuteMethod(DebugInvokeReq* pReq)
{
    Thread* self = dvmThreadSelf();
    const Method* meth;
    Object* oldExcept;
    ThreadStatus oldStatus;

    /*
     * We can be called while an exception is pending in the VM.  We need
     * to preserve that across the method invocation.
     */
    oldExcept = dvmGetException(self);
    if (oldExcept != NULL) {
        dvmAddTrackedAlloc(oldExcept, self);
        dvmClearException(self);
    }

    oldStatus = dvmChangeStatus(self, THREAD_RUNNING);

    /*
     * Translate the method through the vtable, unless we're calling a
     * direct method or the debugger wants to suppress it.
     */
    if ((pReq->options & INVOKE_NONVIRTUAL) != 0 || pReq->obj == NULL ||
        dvmIsDirectMethod(pReq->method))
    {
        meth = pReq->method;
    } else {
        meth = dvmGetVirtualizedMethod(pReq->clazz, pReq->method);
    }
    assert(meth != NULL);

    assert(sizeof(jvalue) == sizeof(u8));

    IF_ALOGV() {
        char* desc = dexProtoCopyMethodDescriptor(&meth->prototype);
        ALOGV("JDWP invoking method %p/%p %s.%s:%s",
            pReq->method, meth, meth->clazz->descriptor, meth->name, desc);
        free(desc);
    }

    dvmCallMethodA(self, meth, pReq->obj, false, &pReq->resultValue,
        (jvalue*)pReq->argArray);
    pReq->exceptObj = objectToObjectId(dvmGetException(self));
    pReq->resultTag = getReturnTypeBasicTag(meth);
    if (pReq->exceptObj != 0) {
        Object* exc = dvmGetException(self);
        ALOGD("  JDWP invocation returning with exceptObj=%p (%s)",
            exc, exc->clazz->descriptor);
        //dvmLogExceptionStackTrace();
        dvmClearException(self);
        /*
         * Nothing should try to use this, but it looks like something is.
         * Make it null to be safe.
         */
        pReq->resultValue.j = 0; /*0xadadadad;*/
    } else if (pReq->resultTag == JT_OBJECT) {
        /* if no exception thrown, examine object result more closely */
        u1 newTag = tagFromObject((Object*)pReq->resultValue.l);
        if (newTag != pReq->resultTag) {
            LOGVV("  JDWP promoted result from %d to %d",
                pReq->resultTag, newTag);
            pReq->resultTag = newTag;
        }

        /*
         * Register the object.  We don't actually need an ObjectId yet,
         * but we do need to be sure that the GC won't move or discard the
         * object when we switch out of RUNNING.  The ObjectId conversion
         * will add the object to the "do not touch" list.
         *
         * We can't use the "tracked allocation" mechanism here because
         * the object is going to be handed off to a different thread.
         */
        objectToObjectId((Object*)pReq->resultValue.l);
    }

    if (oldExcept != NULL) {
        dvmSetException(self, oldExcept);
        dvmReleaseTrackedAlloc(oldExcept, self);
    }
    dvmChangeStatus(self, oldStatus);
}

// for dvmAddressSetForLine
struct AddressSetContext {
    bool lastAddressValid;
    u4 lastAddress;
    u4 lineNum;
    AddressSet *pSet;
};

// for dvmAddressSetForLine

/*
 *breif:dvmAddressSetForLine相关.
*/
static int addressSetCb (void *cnxt, u4 address, u4 lineNum)
{
    AddressSetContext *pContext = (AddressSetContext *)cnxt;

    if (lineNum == pContext->lineNum) {
        if (!pContext->lastAddressValid) {
            // Everything from this address until the next line change is ours
            pContext->lastAddress = address;
            pContext->lastAddressValid = true;
        }
        // else, If we're already in a valid range for this lineNum,
        // just keep going (shouldn't really happen)
    } else if (pContext->lastAddressValid) { // and the line number is new
        u4 i;
        // Add everything from the last entry up until here to the set
        for (i = pContext->lastAddress; i < address; i++) {
            dvmAddressSetSet(pContext->pSet, i);
        }

        pContext->lastAddressValid = false;
    }

    // there may be multiple entries for a line
    return 0;
}
/*
 * Build up a set of bytecode addresses associated with a line number
 */

/*
 *breif:建立字节码地址关联的行号.
*/
const AddressSet *dvmAddressSetForLine(const Method* method, int line)
{
    AddressSet *result;
    const DexFile *pDexFile = method->clazz->pDvmDex->pDexFile;
    u4 insnsSize = dvmGetMethodInsnsSize(method);
    AddressSetContext context;

    result = (AddressSet*)calloc(1, sizeof(AddressSet) + (insnsSize/8) + 1);
    result->setSize = insnsSize;

    memset(&context, 0, sizeof(context));
    context.pSet = result;
    context.lineNum = line;
    context.lastAddressValid = false;

    dexDecodeDebugInfo(pDexFile, dvmGetMethodCode(method),
        method->clazz->descriptor,
        method->prototype.protoIdx,
        method->accessFlags,
        addressSetCb, NULL, &context);

    // If the line number was the last in the position table...
    if (context.lastAddressValid) {
        u4 i;
        for (i = context.lastAddress; i < insnsSize; i++) {
            dvmAddressSetSet(result, i);
        }
    }

    return result;
}


/*
 * ===========================================================================
 *      Dalvik Debug Monitor support
 * ===========================================================================
 */

/*
 * We have received a DDM packet over JDWP.  Hand it off to the VM.
 */

/*
 *breif:受到DDM发送的包.
*/
bool dvmDbgDdmHandlePacket(const u1* buf, int dataLen, u1** pReplyBuf,
    int* pReplyLen)
{
    return dvmDdmHandlePacket(buf, dataLen, pReplyBuf, pReplyLen);
}

/*
 * First DDM packet has arrived over JDWP.  Notify the press.
 */

/*
 *breif:第一个DDM包到达JDWP.
*/
void dvmDbgDdmConnected()
{
    dvmDdmConnected();
}

/*
 * JDWP connection has dropped.
 */

/*
 *breif:中断JDWP.
*/
void dvmDbgDdmDisconnected()
{
    dvmDdmDisconnected();
}

/*
 * Send up a JDWP event packet with a DDM chunk in it.
 */

/*
 *breif:发送包含DDM块的JDWP事件包.
*/
void dvmDbgDdmSendChunk(int type, size_t len, const u1* buf)
{
    assert(buf != NULL);
    struct iovec vec[1] = { {(void*)buf, len} };
    dvmDbgDdmSendChunkV(type, vec, 1);
}

/*
 * Send up a JDWP event packet with a DDM chunk in it.  The chunk is
 * concatenated from multiple source buffers.
 */

/*
 *breif:发送包含DDM块的JDWP事件包.发自多个源.
*/
void dvmDbgDdmSendChunkV(int type, const struct iovec* iov, int iovcnt)
{
    if (gDvm.jdwpState == NULL) {
        ALOGV("Debugger thread not active, ignoring DDM send (t=0x%08x)",
            type);
        return;
    }

    dvmJdwpDdmSendChunkV(gDvm.jdwpState, type, iov, iovcnt);
}
