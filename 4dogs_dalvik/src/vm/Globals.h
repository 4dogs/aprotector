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
 * Variables with library scope.
 *
 * Prefer this over scattered static and global variables -- it's easier to
 * view the state in a debugger, it makes clean shutdown simpler, we can
 * trivially dump the state into a crash log, and it dodges most naming
 * collisions that will arise when we are embedded in a larger program.
 *
 * If we want multiple VMs per process, this can get stuffed into TLS (or
 * accessed through a Thread field).  May need to pass it around for some
 * of the early initialization functions.
 */
#ifndef DALVIK_GLOBALS_H_
#define DALVIK_GLOBALS_H_

#include <string>
#include <vector>

#include <stdarg.h>
#include <pthread.h>

/* private structures */
struct GcHeap;
struct BreakpointSet;
struct InlineSub;

/*
 * One of these for each -ea/-da/-esa/-dsa on the command line.
 */
struct AssertionControl {
    char*   pkgOrClass;         /* package/class string, or NULL for esa/dsa */
    int     pkgOrClassLen;      /* string length, for quick compare */
    bool    enable;             /* enable or disable */
    bool    isPackage;          /* string ended with "..."? */
};

/*
 * Register map generation mode.  Only applicable when generateRegisterMaps
 * is enabled.  (The "disabled" state is not folded into this because
 * there are callers like dexopt that want to enable/disable without
 * specifying the configuration details.)
 *
 * "TypePrecise" is slower and requires additional storage for the register
 * maps, but allows type-precise GC.  "LivePrecise" is even slower and
 * requires additional heap during processing, but allows live-precise GC.
 */
enum RegisterMapMode {
    kRegisterMapModeUnknown = 0,
    kRegisterMapModeTypePrecise,
    kRegisterMapModeLivePrecise
};

/*
 * Profiler clock source.
 */
enum ProfilerClockSource {
    kProfilerClockSourceThreadCpu,
    kProfilerClockSourceWall,
    kProfilerClockSourceDual,
};

/*
 * All fields are initialized to zero.
 *
 * Storage allocated here must be freed by a subsystem shutdown function.
 */
struct DvmGlobals {
    /*
     * Some options from the command line or environment.
     */
    char*       bootClassPathStr;
    char*       classPathStr;

    size_t      heapStartingSize;
    size_t      heapMaximumSize;
    size_t      heapGrowthLimit;
    double      heapTargetUtilization;
    size_t      heapMinFree;
    size_t      heapMaxFree;
    size_t      stackSize;
    size_t      mainThreadStackSize;

    bool        verboseGc;
    bool        verboseJni;
    bool        verboseClass;
    bool        verboseShutdown;

    bool        jdwpAllowed;        // debugging allowed for this process?
    bool        jdwpConfigured;     // has debugging info been provided?
    JdwpTransportType jdwpTransport;
    bool        jdwpServer;
    char*       jdwpHost;
    int         jdwpPort;
    bool        jdwpSuspend;

    ProfilerClockSource profilerClockSource;

    /*
     * Lock profiling threshold value in milliseconds.  Acquires that
     * exceed threshold are logged.  Acquires within the threshold are
     * logged with a probability of $\frac{time}{threshold}$ .  If the
     * threshold is unset no additional logging occurs.
     */
    u4          lockProfThreshold;

    int         (*vfprintfHook)(FILE*, const char*, va_list);
    void        (*exitHook)(int);
    void        (*abortHook)(void);
    bool        (*isSensitiveThreadHook)(void);

    int         jniGrefLimit;       // 0 means no limit
    char*       jniTrace;
    bool        reduceSignals;
    bool        noQuitHandler;
    bool        verifyDexChecksum;
    char*       stackTraceFile;     // for SIGQUIT-inspired output

    bool        logStdio;

    DexOptimizerMode    dexOptMode;
    DexClassVerifyMode  classVerifyMode;

    bool        generateRegisterMaps;
    RegisterMapMode     registerMapMode;

    bool        monitorVerification;

    bool        dexOptForSmp;

    /*
     * GC option flags.
     */
    bool        preciseGc;
    bool        preVerify;
    bool        postVerify;
    bool        concurrentMarkSweep;
    bool        verifyCardTable;
    bool        disableExplicitGc;

    int         assertionCtrlCount;
    AssertionControl*   assertionCtrl;

    ExecutionMode   executionMode;

    bool        commonInit; /* whether common stubs are generated */
    bool        constInit; /* whether global constants are initialized */

    /*
     * VM init management.
     */
    bool        initializing;
    bool        optimizing;

    /*
     * java.lang.System properties set from the command line with -D.
     * This is effectively a set, where later entries override earlier
     * ones.
     */
    std::vector<std::string>* properties;

    /*
     * Where the VM goes to find system classes.
     */
    ClassPathEntry* bootClassPath;
    /* used by the DEX optimizer to load classes from an unfinished DEX */
    DvmDex*     bootClassPathOptExtra;
    bool        optimizingBootstrapClass;

    /*
     * Loaded classes, hashed by class name.  Each entry is a ClassObject*,
     * allocated in GC space.
     */
    HashTable*  loadedClasses;

    /*
     * Value for the next class serial number to be assigned.  This is
     * incremented as we load classes.  Failed loads and races may result
     * in some numbers being skipped, and the serial number is not
     * guaranteed to start at 1, so the current value should not be used
     * as a count of loaded classes.
     */
    volatile int classSerialNumber;

    /*
     * Classes with a low classSerialNumber are probably in the zygote, and
     * their InitiatingLoaderList is not used, to promote sharing. The list is
     * kept here instead.
     */
    InitiatingLoaderList* initiatingLoaderList;

    /*
     * Interned strings.
     */

    /* A mutex that guards access to the interned string tables. */
    pthread_mutex_t internLock;

    /* Hash table of strings interned by the user. */
    HashTable*  internedStrings;

    /* Hash table of strings interned by the class loader. */
    HashTable*  literalStrings;

    /*
     * Classes constructed directly by the vm.
     */

    /* the class Class */
    ClassObject* classJavaLangClass;

    /* synthetic classes representing primitive types */
    ClassObject* typeVoid;
    ClassObject* typeBoolean;
    ClassObject* typeByte;
    ClassObject* typeShort;
    ClassObject* typeChar;
    ClassObject* typeInt;
    ClassObject* typeLong;
    ClassObject* typeFloat;
    ClassObject* typeDouble;

    /* synthetic classes for arrays of primitives */
    ClassObject* classArrayBoolean;
    ClassObject* classArrayByte;
    ClassObject* classArrayShort;
    ClassObject* classArrayChar;
    ClassObject* classArrayInt;
    ClassObject* classArrayLong;
    ClassObject* classArrayFloat;
    ClassObject* classArrayDouble;

    /*
     * Quick lookups for popular classes used internally.
     */
    ClassObject* classJavaLangClassArray;
    ClassObject* classJavaLangClassLoader;
    ClassObject* classJavaLangObject;
    ClassObject* classJavaLangObjectArray;
    ClassObject* classJavaLangString;
    ClassObject* classJavaLangThread;
    ClassObject* classJavaLangVMThread;
    ClassObject* classJavaLangThreadGroup;
    ClassObject* classJavaLangStackTraceElement;
    ClassObject* classJavaLangStackTraceElementArray;
    ClassObject* classJavaLangAnnotationAnnotationArray;
    ClassObject* classJavaLangAnnotationAnnotationArrayArray;
    ClassObject* classJavaLangReflectAccessibleObject;
    ClassObject* classJavaLangReflectConstructor;
    ClassObject* classJavaLangReflectConstructorArray;
    ClassObject* classJavaLangReflectField;
    ClassObject* classJavaLangReflectFieldArray;
    ClassObject* classJavaLangReflectMethod;
    ClassObject* classJavaLangReflectMethodArray;
    ClassObject* classJavaLangReflectProxy;
    ClassObject* classJavaNioReadWriteDirectByteBuffer;
    ClassObject* classOrgApacheHarmonyLangAnnotationAnnotationFactory;
    ClassObject* classOrgApacheHarmonyLangAnnotationAnnotationMember;
    ClassObject* classOrgApacheHarmonyLangAnnotationAnnotationMemberArray;
    ClassObject* classOrgApacheHarmonyDalvikDdmcChunk;
    ClassObject* classOrgApacheHarmonyDalvikDdmcDdmServer;
    ClassObject* classJavaLangRefFinalizerReference;

    /*
     * classes representing exception types. The names here don't include
     * packages, just to keep the use sites a bit less verbose. All are
     * in java.lang, except where noted.
     */
    ClassObject* exAbstractMethodError;
    ClassObject* exArithmeticException;
    ClassObject* exArrayIndexOutOfBoundsException;
    ClassObject* exArrayStoreException;
    ClassObject* exClassCastException;
    ClassObject* exClassCircularityError;
    ClassObject* exClassFormatError;
    ClassObject* exClassNotFoundException;
    ClassObject* exError;
    ClassObject* exExceptionInInitializerError;
    ClassObject* exFileNotFoundException; /* in java.io */
    ClassObject* exIOException;           /* in java.io */
    ClassObject* exIllegalAccessError;
    ClassObject* exIllegalAccessException;
    ClassObject* exIllegalArgumentException;
    ClassObject* exIllegalMonitorStateException;
    ClassObject* exIllegalStateException;
    ClassObject* exIllegalThreadStateException;
    ClassObject* exIncompatibleClassChangeError;
    ClassObject* exInstantiationError;
    ClassObject* exInstantiationException;
    ClassObject* exInternalError;
    ClassObject* exInterruptedException;
    ClassObject* exLinkageError;
    ClassObject* exNegativeArraySizeException;
    ClassObject* exNoClassDefFoundError;
    ClassObject* exNoSuchFieldError;
    ClassObject* exNoSuchFieldException;
    ClassObject* exNoSuchMethodError;
    ClassObject* exNullPointerException;
    ClassObject* exOutOfMemoryError;
    ClassObject* exRuntimeException;
    ClassObject* exStackOverflowError;
    ClassObject* exStaleDexCacheError;    /* in dalvik.system */
    ClassObject* exStringIndexOutOfBoundsException;
    ClassObject* exThrowable;
    ClassObject* exTypeNotPresentException;
    ClassObject* exUnsatisfiedLinkError;
    ClassObject* exUnsupportedOperationException;
    ClassObject* exVerifyError;
    ClassObject* exVirtualMachineError;

    /* method offsets - Object */
    int         voffJavaLangObject_equals;
    int         voffJavaLangObject_hashCode;
    int         voffJavaLangObject_toString;

    /* field offsets - String */
    int         offJavaLangString_value;
    int         offJavaLangString_count;
    int         offJavaLangString_offset;
    int         offJavaLangString_hashCode;

    /* field offsets - Thread */
    int         offJavaLangThread_vmThread;
    int         offJavaLangThread_group;
    int         offJavaLangThread_daemon;
    int         offJavaLangThread_name;
    int         offJavaLangThread_priority;
    int         offJavaLangThread_uncaughtHandler;
    int         offJavaLangThread_contextClassLoader;

    /* method offsets - Thread */
    int         voffJavaLangThread_run;

    /* field offsets - ThreadGroup */
    int         offJavaLangThreadGroup_name;
    int         offJavaLangThreadGroup_parent;

    /* field offsets - VMThread */
    int         offJavaLangVMThread_thread;
    int         offJavaLangVMThread_vmData;

    /* method offsets - ThreadGroup */
    int         voffJavaLangThreadGroup_removeThread;

    /* field offsets - Throwable */
    int         offJavaLangThrowable_stackState;
    int         offJavaLangThrowable_cause;

    /* method offsets - ClassLoader */
    int         voffJavaLangClassLoader_loadClass;

    /* direct method pointers - ClassLoader */
    Method*     methJavaLangClassLoader_getSystemClassLoader;

    /* field offsets - java.lang.reflect.* */
    int         offJavaLangReflectConstructor_slot;
    int         offJavaLangReflectConstructor_declClass;
    int         offJavaLangReflectField_slot;
    int         offJavaLangReflectField_declClass;
    int         offJavaLangReflectMethod_slot;
    int         offJavaLangReflectMethod_declClass;

    /* field offsets - java.lang.ref.Reference */
    int         offJavaLangRefReference_referent;
    int         offJavaLangRefReference_queue;
    int         offJavaLangRefReference_queueNext;
    int         offJavaLangRefReference_pendingNext;

    /* field offsets - java.lang.ref.FinalizerReference */
    int offJavaLangRefFinalizerReference_zombie;

    /* method pointers - java.lang.ref.ReferenceQueue */
    Method* methJavaLangRefReferenceQueueAdd;

    /* method pointers - java.lang.ref.FinalizerReference */
    Method* methJavaLangRefFinalizerReferenceAdd;

    /* constructor method pointers; no vtable involved, so use Method* */
    Method*     methJavaLangStackTraceElement_init;
    Method*     methJavaLangReflectConstructor_init;
    Method*     methJavaLangReflectField_init;
    Method*     methJavaLangReflectMethod_init;
    Method*     methOrgApacheHarmonyLangAnnotationAnnotationMember_init;

    /* static method pointers - android.lang.annotation.* */
    Method*
        methOrgApacheHarmonyLangAnnotationAnnotationFactory_createAnnotation;

    /* direct method pointers - java.lang.reflect.Proxy */
    Method*     methJavaLangReflectProxy_constructorPrototype;

    /* field offsets - java.lang.reflect.Proxy */
    int         offJavaLangReflectProxy_h;

    /* field offsets - java.io.FileDescriptor */
    int         offJavaIoFileDescriptor_descriptor;

    /* direct method pointers - dalvik.system.NativeStart */
    Method*     methDalvikSystemNativeStart_main;
    Method*     methDalvikSystemNativeStart_run;

    /* assorted direct buffer helpers */
    Method*     methJavaNioReadWriteDirectByteBuffer_init;
    int         offJavaNioBuffer_capacity;
    int         offJavaNioBuffer_effectiveDirectAddress;

    /* direct method pointers - org.apache.harmony.dalvik.ddmc.DdmServer */
    Method*     methDalvikDdmcServer_dispatch;
    Method*     methDalvikDdmcServer_broadcast;

    /* field offsets - org.apache.harmony.dalvik.ddmc.Chunk */
    int         offDalvikDdmcChunk_type;
    int         offDalvikDdmcChunk_data;
    int         offDalvikDdmcChunk_offset;
    int         offDalvikDdmcChunk_length;

    /*
     * Thread list.  This always has at least one element in it (main),
     * and main is always the first entry.
     *
     * The threadListLock is used for several things, including the thread
     * start condition variable.  Generally speaking, you must hold the
     * threadListLock when:
     *  - adding/removing items from the list
     *  - waiting on or signaling threadStartCond
     *  - examining the Thread struct for another thread (this is to avoid
     *    one thread freeing the Thread struct while another thread is
     *    perusing it)
     */
     /*
     * 线程列表(存放了虚拟机的各个线程信息)，其中至少有一个main线程。
     * 以下三种情况会用到threadListLock
     * - 从链表中添加或者删除条目
     * - 等待或者响应threadStartCond
     * - 另外一个线程检查列表中某个线程结构体的时候
     */
    Thread*     threadList;
    pthread_mutex_t threadListLock;

    pthread_cond_t threadStartCond;

    /*
     * The thread code grabs this before suspending all threads.  There
     * are a few things that can cause a "suspend all":
     *  (1) the GC is starting;
     *  (2) the debugger has sent a "suspend all" request;
     *  (3) a thread has hit a breakpoint or exception that the debugger
     *      has marked as a "suspend all" event;
     *  (4) the SignalCatcher caught a signal that requires suspension.
     *  (5) (if implemented) the JIT needs to perform a heavyweight
     *      rearrangement of the translation cache or JitTable.
     *
     * Because we use "safe point" self-suspension, it is never safe to
     * do a blocking "lock" call on this mutex -- if it has been acquired,
     * somebody is probably trying to put you to sleep.  The leading '_' is
     * intended as a reminder that this lock is special.
     */
    pthread_mutex_t _threadSuspendLock;

    /*
     * Guards Thread->suspendCount for all threads, and
     * provides the lock for the condition variable that all suspended threads
     * sleep on (threadSuspendCountCond).
     *
     * This has to be separate from threadListLock because of the way
     * threads put themselves to sleep.
     */
    pthread_mutex_t threadSuspendCountLock;

    /*
     * Suspended threads sleep on this.  They should sleep on the condition
     * variable until their "suspend count" is zero.
     *
     * Paired with "threadSuspendCountLock".
     */
    pthread_cond_t  threadSuspendCountCond;

    /*
     * Sum of all threads' suspendCount fields. Guarded by
     * threadSuspendCountLock.
     */
    int  sumThreadSuspendCount;

    /*
     * MUTEX ORDERING: when locking multiple mutexes, always grab them in
     * this order to avoid deadlock:
     *
     *  (1) _threadSuspendLock      (use lockThreadSuspend())
     *  (2) threadListLock          (use dvmLockThreadList())
     *  (3) threadSuspendCountLock  (use lockThreadSuspendCount())
     */


    /*
     * Thread ID bitmap.  We want threads to have small integer IDs so
     * we can use them in "thin locks".
     */
    BitVector*  threadIdMap;

    /*
     * Manage exit conditions.  The VM exits when all non-daemon threads
     * have exited.  If the main thread returns early, we need to sleep
     * on a condition variable.
     */
    int         nonDaemonThreadCount;   /* must hold threadListLock to access */
    pthread_cond_t  vmExitCond;

    /*
     * The set of DEX files loaded by custom class loaders.
     */
    HashTable*  userDexFiles;

    /*
     * JNI global reference table.
     */
    IndirectRefTable jniGlobalRefTable;
    IndirectRefTable jniWeakGlobalRefTable;
    pthread_mutex_t jniGlobalRefLock;
    pthread_mutex_t jniWeakGlobalRefLock;
    int         jniGlobalRefHiMark;
    int         jniGlobalRefLoMark;

    /*
     * JNI pinned object table (used for primitive arrays).
     */
    ReferenceTable  jniPinRefTable;
    pthread_mutex_t jniPinRefLock;

    /*
     * Native shared library table.
     */
    HashTable*  nativeLibs;

    /*
     * GC heap lock.  Functions like gcMalloc() acquire this before making
     * any changes to the heap.  It is held throughout garbage collection.
     */
    pthread_mutex_t gcHeapLock;

    /*
     * Condition variable to queue threads waiting to retry an
     * allocation.  Signaled after a concurrent GC is completed.
     */
    pthread_cond_t gcHeapCond;

    /* Opaque pointer representing the heap. */
    GcHeap*     gcHeap;

    /* The card table base, modified as needed for marking cards. */
    u1*         biasedCardTableBase;

    /*
     * Pre-allocated throwables.
     */
    Object*     outOfMemoryObj;
    Object*     internalErrorObj;
    Object*     noClassDefFoundErrorObj;

    /* Monitor list, so we can free them */
    /*volatile*/ Monitor* monitorList;

    /* Monitor for Thread.sleep() implementation */
    Monitor*    threadSleepMon;

    /* set when we create a second heap inside the zygote */
    bool        newZygoteHeapAllocated;

    /*
     * TLS keys.
     */
    pthread_key_t pthreadKeySelf;       /* Thread*, for dvmThreadSelf */

    /*
     * Cache results of "A instanceof B".
     */
    AtomicCache* instanceofCache;

    /* inline substitution table, used during optimization */
    InlineSub*          inlineSubs;

    /*
     * Bootstrap class loader linear allocator.
     */
    LinearAllocHdr* pBootLoaderAlloc;

    /*
     * Compute some stats on loaded classes.
     */
    int         numLoadedClasses;
    int         numDeclaredMethods;
    int         numDeclaredInstFields;
    int         numDeclaredStaticFields;

    /* when using a native debugger, set this to suppress watchdog timers */
    bool        nativeDebuggerActive;

    /*
     * JDWP debugger support.
     *
     * Note: Each thread will normally determine whether the debugger is active
     * for it by referring to its subMode flags.  "debuggerActive" here should be
     * seen as "debugger is making requests of 1 or more threads".
     */
    bool        debuggerConnected;      /* debugger or DDMS is connected */
    bool        debuggerActive;         /* debugger is making requests */
    JdwpState*  jdwpState;

    /*
     * Registry of objects known to the debugger.
     */
    HashTable*  dbgRegistry;

    /*
     * Debugger breakpoint table.
     */
    BreakpointSet*  breakpointSet;

    /*
     * Single-step control struct.  We currently only allow one thread to
     * be single-stepping at a time, which is all that really makes sense,
     * but it's possible we may need to expand this to be per-thread.
     */
    StepControl stepControl;

    /*
     * DDM features embedded in the VM.
     */
    bool        ddmThreadNotification;

    /*
     * Zygote (partially-started process) support
     */
    bool        zygote;

    /*
     * Used for tracking allocations that we report to DDMS.  When the feature
     * is enabled (through a DDMS request) the "allocRecords" pointer becomes
     * non-NULL.
     */
    pthread_mutex_t allocTrackerLock;
    AllocRecord*    allocRecords;
    int             allocRecordHead;        /* most-recently-added entry */
    int             allocRecordCount;       /* #of valid entries */

    /*
     * When a profiler is enabled, this is incremented.  Distinct profilers
     * include "dmtrace" method tracing, emulator method tracing, and
     * possibly instruction counting.
     *
     * The purpose of this is to have a single value that shows whether any
     * profiling is going on.  Individual thread will normally check their
     * thread-private subMode flags to take any profiling action.
     */
    volatile int activeProfilers;

    /*
     * State for method-trace profiling.
     */
    MethodTraceState methodTrace;
    Method*     methodTraceGcMethod;
    Method*     methodTraceClassPrepMethod;

    /*
     * State for emulator tracing.
     */
    void*       emulatorTracePage;
    int         emulatorTraceEnableCount;

    /*
     * Global state for memory allocation profiling.
     */
    AllocProfState allocProf;

    /*
     * Pointers to the original methods for things that have been inlined.
     * This makes it easy for us to output method entry/exit records for
     * the method calls we're not actually making.  (Used by method
     * profiling.)
     */
    Method**    inlinedMethods;

    /*
     * Dalvik instruction counts (kNumPackedOpcodes entries).
     */
    int*        executedInstrCounts;
    int         instructionCountEnableCount;

    /*
     * Signal catcher thread (for SIGQUIT).
     */
    pthread_t   signalCatcherHandle;
    bool        haltSignalCatcher;

    /*
     * Stdout/stderr conversion thread.
     */
    bool            haltStdioConverter;
    bool            stdioConverterReady;
    pthread_t       stdioConverterHandle;
    pthread_mutex_t stdioConverterLock;
    pthread_cond_t  stdioConverterCond;
    int             stdoutPipe[2];
    int             stderrPipe[2];

    /*
     * pid of the system_server process. We track it so that when system server
     * crashes the Zygote process will be killed and restarted.
     */
    pid_t systemServerPid;

    int kernelGroupScheduling;

//#define COUNT_PRECISE_METHODS
#ifdef COUNT_PRECISE_METHODS
    PointerSet* preciseMethods;
#endif

    /* some RegisterMap statistics, useful during development */
    void*       registerMapStats;

#ifdef VERIFIER_STATS
    VerifierStats verifierStats;
#endif

    /* String pointed here will be deposited on the stack frame of dvmAbort */
    const char *lastMessage;
};

extern struct DvmGlobals gDvm;

/*
 * JIT鐨勫叏灞�缁撴瀯澹版槑
 */
#if defined(WITH_JIT)

/* Trace profiling modes.  Ordering matters - off states before on states */
/* Trace profiling妯″紡 */
enum TraceProfilingModes {
	/* 涓嶈繘琛宲rofiling */
    kTraceProfilingDisabled = 0,      // Not profiling
	/* 鍛ㄦ湡鎬х殑杩涜profiling, off闃舵 */
    kTraceProfilingPeriodicOff = 1,   // Periodic profiling, off phase
	/* 鎬绘槸杩涜profiling */
    kTraceProfilingContinuous = 2,    // Always profiling
	/* 鍛ㄦ湡鎬х殑杩涜profiling, on闃舵 */
    kTraceProfilingPeriodicOn = 3     // Periodic profiling, on phase
};

/*
 * Exiting the compiled code w/o chaining will incur overhead to look up the
 * target in the code cache which is extra work only when JIT is enabled. So
 * we want to monitor it closely to make sure we don't have performance bugs.
 */
enum NoChainExits {
    kInlineCacheMiss = 0,
    kCallsiteInterpreted,
    kSwitchOverflow,
    kHeavyweightMonitor,
    kNoChainExitLast,
};

/*
 * JIT-specific global state
 */
/**
 * @brief Jit鐨勫叏灞�鏁版嵁缁撴瀯
 */
struct DvmJitGlobals {
    /*
     * Guards writes to Dalvik PC (dPC), translated code address (codeAddr) and
     * chain fields within the JIT hash table.  Note carefully the access
     * mechanism.
     * Only writes are guarded, and the guarded fields must be updated in a
     * specific order using atomic operations.  Further, once a field is
     * written it cannot be changed without halting all threads.
     *
     * The write order is:
     *    1) codeAddr
     *    2) dPC
     *    3) chain [if necessary]
     *
     * This mutex also guards both read and write of curJitTableEntries.
     */
	/*
	 * 鍐欏叆鐨勯『搴忥細
	 *	1) codeAddr
	 *	2) dPC
	 *	3) chain [濡傛灉蹇呰鐨勫寲]
	 * 杩欎釜mutex涔熷璇诲啓curJitTableEntries杩涜璇诲啓淇濇姢
	 */
    pthread_mutex_t tableLock;

    /* The JIT hash table.  Note that for access speed, copies of this pointer
     * are stored in each thread. */
	/* JIT HASH琛ㄣ�備负浜嗗揩閫熺殑杩涜璁块棶锛屾瘡鏉＄嚎绋嬮兘瀛樺湪杩欎釜琛ㄧ殑涓�浠芥嫹璐� */
    struct JitEntry *pJitEntryTable;

    /* Array of compilation trigger threshold counters */
	/* 缂栬瘧鐨勮Е鍙戦榾鍊艰鏁板櫒闃熷垪  */
    unsigned char *pProfTable;

    /* Trace profiling counters */
	/* Trace profiling 璁℃暟鍣� */
    struct JitTraceProfCounters *pJitTraceProfCounters;

    /* Copy of pProfTable used for temporarily disabling the Jit */
	/* pProfTable鐨勪竴浠芥嫹璐濆湪涓存椂鍏抽棴JIT鏃朵娇鐢� */
    unsigned char *pProfTableCopy;

    /* Size of JIT hash table in entries.  Must be a power of 2 */
	/* JIT HASH琛ㄧ殑闋呮暟銆傚繀椤绘槸2鐨凬娆℃柟 */
    unsigned int jitTableSize;

    /* Mask used in hash function for JitTable.  Should be jitTableSize-1 */
	/* 鍦↗itTable涓殑hash鍑芥暟鐨勬帺鐮併�傚簲璇ヨ璁剧疆涓簀itTableSize-1 */
    unsigned int jitTableMask;

    /* How many entries in the JitEntryTable are in use */
	/* 鏈夊灏慗itEntryTable闋呰浣跨敤 */
    unsigned int jitTableEntriesUsed;

    /* Bytes allocated for the code cache */
	/* 浠ｇ爜缂撳啿鐨勬暟閲� */
    unsigned int codeCacheSize;

    /* Trigger for trace selection */
	/* 瑙﹀彂閫夊畾trace鐨勯榾鍊� */
    unsigned short threshold;

    /* JIT Compiler Control */
	/* JIT缂栬瘧鍣ㄦ帶鍒� */
    bool               haltCompilerThread;			/* 鍏抽棴缂栬瘧鍣ㄧ嚎绋� */
    bool               blockingMode;				/* 闃诲妯″紡 */
    bool               methodTraceSupport;			/* 鍑芥暟Trace鏀寔 */
    bool               genSuspendPoll;				/* 浜х敓鎸傝捣 */
    Thread*            compilerThread;				/* 缂栬瘧鍣ㄧ嚎绋� */
    pthread_t          compilerHandle;				/* 缂栬瘧鍣ㄧ嚎绋嬪彞鏌� */
    pthread_mutex_t    compilerLock;				/* 缂栬瘧鍣ㄧ嚎绋嬮攣 */
    pthread_mutex_t    compilerICPatchLock;
    pthread_cond_t     compilerQueueActivity;		/* 缂栬瘧鍣ㄩ槦鍒楁縺娲� */
    pthread_cond_t     compilerQueueEmpty;			/* 缂栬瘧鍣ㄩ槦鍒楃┖ */
    volatile int       compilerQueueLength;			/* 缂栬瘧鍣ㄩ槦鍒楅暱搴� */
    int                compilerHighWater;
    int                compilerWorkEnqueueIndex;	/* 缂栬瘧鍣ㄥ叆鍒楃储寮� */
    int                compilerWorkDequeueIndex;	/* 缂栬瘧鍣ㄥ嚭鍒楃储寮� */
    int                compilerICPatchIndex;

    /* JIT internal stats */
	/* JIT 鍐呴儴鐘舵�� */
    int                compilerMaxQueued;			/* 缂栬瘧鍣ㄧ殑鏈�澶ч槦鍒� */
    int                translationChains;			/* 杞崲閾� */

    /* Compiled code cache */
	/* 浠ョ紪璇戠殑浠ｇ爜缂撳啿 */
    void* codeCache;

    /*
     * This is used to store the base address of an in-flight compilation whose
     * class object pointers have been calculated to populate literal pool.
     * Once the compiler thread has changed its status to VM_WAIT, we cannot
     * guarantee whether GC has happened before the code address has been
     * installed to the JIT table. Because of that, this field can only
     * been cleared/overwritten by the compiler thread if it is in the
     * THREAD_RUNNING state or in a safe point.
     */
    void *inflightBaseAddr;

    /* Translation cache version (protected by compilerLock */
	/* 杞崲缂撳啿鐗堟湰锛堣compilerLock鎵�淇濇姢 */
    int cacheVersion;

    /* Bytes used by the code templates */
	/* 浠ｇ爜妯℃澘鐨勪娇鐢ㄩ噺 */
    unsigned int templateSize;

    /* Bytes already used in the code cache */
	/* 鍦ㄤ唬鐮佺紦鍐插尯涓凡缁忎娇鐢ㄧ殑瀛楄妭鏁� */
    unsigned int codeCacheByteUsed;

    /* Number of installed compilations in the cache */
	/* 宸茬粡鍦ㄧ紦瀛樹腑缂栬瘧鐨勬暟閲� */
    unsigned int numCompilations;

    /* Flag to indicate that the code cache is full */
	/* 浠ｇ爜缂撳啿鍖烘槸鍚﹀凡缁忔弧浜� */
    bool codeCacheFull;

    /* Page size  - 1 */
	/* 椤靛ぇ灏� - 1 */
    unsigned int pageSizeMask;

    /* Lock to change the protection type of the code cache */
	/* 鍦ㄥ缂栬瘧浠ｇ爜缂撳啿鏃朵娇鐢ㄧ殑mutex */
    pthread_mutex_t    codeCacheProtectionLock;

    /* Number of times that the code cache has been reset */
	/* 浠ｇ爜缂撳啿鍖洪噸璁炬椂闂存鏁� */
    int numCodeCacheReset;

    /* Number of times that the code cache reset request has been delayed */
	/* 浠ｇ爜缂撳啿鍖洪噸璁惧欢杩熸鏁� */
    int numCodeCacheResetDelayed;

    /* true/false: compile/reject opcodes specified in the -Xjitop list */
	/* true/false: 缂栬瘧/涓㈠純 opcodes瀵逛簬鎸囧畾鐨� -Xjitop鍒楄〃 */
    bool includeSelectedOp;

    /* true/false: compile/reject methods specified in the -Xjitmethod list */
	/* true/false: 缂栬瘧/涓㈠純 鏂规硶閫氳繃鎸囧畾鐨勫弬鏁� -Xjitmethod鍒楄〃 */
    bool includeSelectedMethod;

    /* true/false: compile/reject traces with offset specified in the -Xjitoffset list */
	/* true/false: 缂栬瘧/涓㈠純 traces妯″紡瀵逛簬浣跨敤 -Xjitoffset鍒楄〃涓殑鍋忕Щ */
    bool includeSelectedOffset;

    /* Disable JIT for selected opcodes - one bit for each opcode */
	/* 鍏抽棴  JIT 瀵逛簬閫変腑鐨刼pcodes锛屾瘡涓綅瀵瑰簲涓�涓狾PCODE */
    char opList[(kNumPackedOpcodes+7)/8];

    /* Disable JIT for selected methods */
	/* 鍏抽棴 JIT 瀵逛簬閫夊畾鐨勫嚱鏁� */
    HashTable *methodTable;

    /* Disable JIT for selected classes */
	/* 鍏抽棴 JIT 瀵逛簬閫夊畾鐨勭被 */
    HashTable *classTable;

    /* Disable JIT for selected offsets */
	/* 
	 * 鍏抽棴 JIT涓洪�変腑鐨勫亸绉�
	 * 杩欎釜琛ㄩ噷鐨勬暟鎹垚瀵瑰嚭鐜�
	 * 姣忛爡閮芥槸涓�涓寖鍥碵浣庡亸绉伙紝楂樺亸绉籡
	 * 鍦ㄧ紪璇戣繃绋嬩腑姣斿锛屽鏋滃湪杩欎釜鑼冨洿鍐呮墠杩涜缂栬瘧
	 */
    unsigned int pcTable[COMPILER_PC_OFFSET_SIZE];	/* 鍋忕Щ琛� */
    int num_entries_pcTable;						/* 鍋忕Щ鏁伴噺 */

    /* Flag to dump all compiled code */
	/* 璋冭瘯浣跨敤锛屾墦鍗扮紪璇戠姸鎬� */
    bool printMe;

    /* Flag to dump compiled binary code in bytes */
	/* 鎵撳嵃缂栬瘧鍚庣殑2杩涘埗浠ｇ爜 */
    bool printBinary;

    /* Per-process debug flag toggled when receiving a SIGUSR2 */
	/* 棰勫鐞嗚皟璇曟爣璇嗗紑鍏冲綋鎺ユ敹鍒颁竴涓猄IGUSR2淇″彿 */
    bool receivedSIGUSR2;

    /* Trace profiling mode */
	/* Trace profiling妯″紡 */
    TraceProfilingModes profileMode;

    /* Periodic trace profiling countdown timer */
	/* 鍛ㄦ湡鎬race profiling 鍊掕鏃惰鏃跺櫒 */
    int profileCountdown;

    /* Vector to disable selected optimizations */
	/* 鍏抽棴閫夊畾鐨勪紭鍖� */
    int disableOpt;

    /* Table to track the overall and trace statistics of hot methods */
	/* 璺熻釜鐑偣鍑芥暟鐨則race缁熻淇℃伅HASH琛� */
    HashTable*  methodStatsTable;

    /* Filter method compilation blacklist with call-graph information */
	/* 閫氳繃璋冪敤鍥炬鏌ヨ繃婊ゆ帀鐨勫嚱鏁� */
    bool checkCallGraph;

    /* New translation chain has been set up */
	/* 鏂扮殑杞崲閾捐璁剧疆 */
    volatile bool hasNewChain;

#if defined(WITH_SELF_VERIFICATION)
    /* Spin when error is detected, volatile so GDB can reset it */
    volatile bool selfVerificationSpin;
#endif

    /* Framework or stand-alone? */
	/* Framework鐙珛杩愯锛� */
    bool runningInAndroidFramework;

    /* Framework callback happened? */
	/* 宸茬粡寮�鍚疐ramework鍥炶皟 */
    bool alreadyEnabledViaFramework;

    /* Framework requests to disable the JIT for good */
	/* 鍏抽棴JIT */
    bool disableJit;

#if defined(SIGNATURE_BREAKPOINT)
    /* Signature breakpoint */
    u4 signatureBreakpointSize;         // # of words
    u4 *signatureBreakpoint;            // Signature content
#endif

#if defined(WITH_JIT_TUNING)
    /* Performance tuning counters */
	/* 鎬ц兘鐩戣璁℃暟锛岀敤浜庢祴璇曠▼搴� */
    int                addrLookupsFound;
    int                addrLookupsNotFound;
    int                noChainExit[kNoChainExitLast];
    int                normalExit;
    int                puntExit;
    int                invokeMonomorphic;
    int                invokePolymorphic;
    int                invokeNative;
    int                invokeMonoGetterInlined;
    int                invokeMonoSetterInlined;
    int                invokePolyGetterInlined;
    int                invokePolySetterInlined;
    int                returnOp;
    int                icPatchInit;
    int                icPatchLockFree;
    int                icPatchQueued;
    int                icPatchRejected;
    int                icPatchDropped;
    int                codeCachePatches;
    int                numCompilerThreadBlockGC;
    u8                 jitTime;
    u8                 compilerThreadBlockGCStart;
    u8                 compilerThreadBlockGCTime;
    u8                 maxCompilerThreadBlockGCTime;
#endif

#if defined(ARCH_IA32)
	/* 浼樺寲绾у埆 */
    JitOptLevel        optLevel;
#endif

    /* Place arrays at the end to ease the display in gdb sessions */

    /* Work order queue for compilations */
	/* 缂栬瘧璁㈠崟搴忓垪 */
    CompilerWorkOrder compilerWorkQueue[COMPILER_WORK_QUEUE_SIZE];

    /* Work order queue for predicted chain patching */
    ICPatchWorkOrder compilerICPatchQueue[COMPILER_IC_PATCH_QUEUE_SIZE];
};

/* 鏁翠釜铏氭嫙鏈轰腑鍞竴鐨勫叏灞�JIT瀹炰緥 */
extern struct DvmJitGlobals gDvmJit;

#if defined(WITH_JIT_TUNING)
extern int gDvmICHitCount;
#endif

#endif

struct DvmJniGlobals {
    bool useCheckJni;
    bool warnOnly;
    bool forceCopy;

    // Provide backwards compatibility for pre-ICS apps on ICS.
    bool workAroundAppJniBugs;

    // Debugging help for third-party developers. Similar to -Xjnitrace.
    bool logThirdPartyJni;

    // We only support a single JavaVM per process.
    JavaVM*     jniVm;
};

extern struct DvmJniGlobals gDvmJni;

#endif  // DALVIK_GLOBALS_H_
