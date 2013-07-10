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
/**
 * @brief dalvik虚拟机的全局设定
 * @note 
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
     * ?߳??б?(?????????????ĸ????߳???Ϣ)????????????һ??main?̡߳?
     * ???????????????õ?threadListLock
     * - ??��???????ӻ???ɾ????Ŀ
     * - ?ȴ???????ӦthreadStartCond
     * - ????һ???̼߳????б???ĳ???߳̽ṹ????ʱ??
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
 * JIT的全局结构声明
 */
#if defined(WITH_JIT)

/* Trace profiling modes.  Ordering matters - off states before on states */
/* Trace profiling模式 */
enum TraceProfilingModes {
	/* 不进行profiling */
    kTraceProfilingDisabled = 0,      // Not profiling
	/* 周期性的进行profiling, off阶段 */
    kTraceProfilingPeriodicOff = 1,   // Periodic profiling, off phase
	/* 总是进行profiling */
    kTraceProfilingContinuous = 2,    // Always profiling
	/* 周期性的进行profiling, on阶段 */
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
 * @brief Jit的全局数据结构
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
	 * 写入的顺序：
	 *	1) codeAddr
	 *	2) dPC
	 *	3) chain [如果必要的化]
	 * 这个mutex也对读写curJitTableEntries进行读写保护
	 */
    pthread_mutex_t tableLock;

    /* The JIT hash table.  Note that for access speed, copies of this pointer
     * are stored in each thread. */
	/* JIT HASH表。为了快速的进行访问，每条线程都存在这个表的一份拷贝 */
    struct JitEntry *pJitEntryTable;

    /* Array of compilation trigger threshold counters */
	/* 编译的触发阀值计数器队列  */
    unsigned char *pProfTable;

    /* Trace profiling counters */
	/* Trace profiling 计数器 */
    struct JitTraceProfCounters *pJitTraceProfCounters;

    /* Copy of pProfTable used for temporarily disabling the Jit */
	/* pProfTable的一份拷贝在临时关闭JIT时使用 */
    unsigned char *pProfTableCopy;

    /* Size of JIT hash table in entries.  Must be a power of 2 */
	/* JIT HASH表的項数。必须是2的N次方 */
    unsigned int jitTableSize;

    /* Mask used in hash function for JitTable.  Should be jitTableSize-1 */
	/* 在JitTable中的hash函数的掩码。应该被设置为jitTableSize-1 */
    unsigned int jitTableMask;

    /* How many entries in the JitEntryTable are in use */
	/* 有多少JitEntryTable項被使用 */
    unsigned int jitTableEntriesUsed;

    /* Bytes allocated for the code cache */
	/* 代码缓冲的数量 */
    unsigned int codeCacheSize;

    /* Trigger for trace selection */
	/* 触发选定trace的阀值 */
    unsigned short threshold;

    /* JIT Compiler Control */
	/* JIT编译器控制 */
    bool               haltCompilerThread;			/* 关闭编译器线程 */
    bool               blockingMode;				/* 阻塞模式 */
    bool               methodTraceSupport;			/* 函数Trace支持 */
    bool               genSuspendPoll;				/* 产生挂起 */
    Thread*            compilerThread;				/* 编译器线程 */
    pthread_t          compilerHandle;				/* 编译器线程句柄 */
    pthread_mutex_t    compilerLock;				/* 编译器线程锁 */
    pthread_mutex_t    compilerICPatchLock;
    pthread_cond_t     compilerQueueActivity;		/* 编译器队列激活 */
    pthread_cond_t     compilerQueueEmpty;			/* 编译器队列空 */
    volatile int       compilerQueueLength;			/* 编译器队列长度 */
    int                compilerHighWater;
    int                compilerWorkEnqueueIndex;	/* 编译器入列索引 */
    int                compilerWorkDequeueIndex;	/* 编译器出列索引 */
    int                compilerICPatchIndex;

    /* JIT internal stats */
	/* JIT 内部状态 */
    int                compilerMaxQueued;			/* 编译器的最大队列 */
    int                translationChains;			/* 转换链 */

    /* Compiled code cache */
	/* 以编译的代码缓冲 */
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
	/* 转换缓冲版本（被compilerLock所保护 */
    int cacheVersion;

    /* Bytes used by the code templates */
	/* 代码模板的使用量 */
    unsigned int templateSize;

    /* Bytes already used in the code cache */
	/* 在代码缓冲区中已经使用的字节数 */
    unsigned int codeCacheByteUsed;

    /* Number of installed compilations in the cache */
	/* 已经在缓存中编译的数量 */
    unsigned int numCompilations;

    /* Flag to indicate that the code cache is full */
	/* 代码缓冲区是否已经满了 */
    bool codeCacheFull;

    /* Page size  - 1 */
	/* 页大小 - 1 */
    unsigned int pageSizeMask;

    /* Lock to change the protection type of the code cache */
	/* 在对编译代码缓冲时使用的mutex */
    pthread_mutex_t    codeCacheProtectionLock;

    /* Number of times that the code cache has been reset */
	/* 代码缓冲区重设时间次数 */
    int numCodeCacheReset;

    /* Number of times that the code cache reset request has been delayed */
	/* 代码缓冲区重设延迟次数 */
    int numCodeCacheResetDelayed;

    /* true/false: compile/reject opcodes specified in the -Xjitop list */
	/* true/false: 编译/丢弃 opcodes对于指定的 -Xjitop列表 */
    bool includeSelectedOp;

    /* true/false: compile/reject methods specified in the -Xjitmethod list */
	/* true/false: 编译/丢弃 方法通过指定的参数 -Xjitmethod列表 */
	/* true:编译,false:丢弃 */
    bool includeSelectedMethod;

    /* true/false: compile/reject traces with offset specified in the -Xjitoffset list */
	/* true/false: 编译/丢弃 traces模式对于使用 -Xjitoffset列表中的偏移 */
    bool includeSelectedOffset;

    /* Disable JIT for selected opcodes - one bit for each opcode */
	/* 关闭  JIT 对于选中的opcodes，每个位对应一个OPCODE */
    char opList[(kNumPackedOpcodes+7)/8];

    /* Disable JIT for selected methods */
	/* 关闭 JIT 对于选定的函数 */
    HashTable *methodTable;

    /* Disable JIT for selected classes */
	/* 关闭 JIT 对于选定的类 */
    HashTable *classTable;

    /* Disable JIT for selected offsets */
	/* 
	 * 关闭 JIT为选中的偏移
	 * 这个表里的数据成对出现
	 * 每項都是一个范围[低偏移，高偏移]
	 * 在编译过程中比对，如果在这个范围内才进行编译
	 */
    unsigned int pcTable[COMPILER_PC_OFFSET_SIZE];	/* 偏移表 */
    int num_entries_pcTable;						/* 偏移数量 */

    /* Flag to dump all compiled code */
	/* 调试使用，打印编译状态 */
    bool printMe;

    /* Flag to dump compiled binary code in bytes */
	/* 打印编译后的2进制代码 */
    bool printBinary;

    /* Per-process debug flag toggled when receiving a SIGUSR2 */
	/* 预处理调试标识开关当接收到一个SIGUSR2信号 */
    bool receivedSIGUSR2;

    /* Trace profiling mode */
	/* Trace profiling模式 */
    TraceProfilingModes profileMode;

    /* Periodic trace profiling countdown timer */
	/* 周期性trace profiling 倒计时计时器 */
    int profileCountdown;

    /* Vector to disable selected optimizations */
	/* 关闭选定的优化 */
    int disableOpt;

    /* Table to track the overall and trace statistics of hot methods */
	/* 跟踪热点函数的trace统计信息HASH表 */
    HashTable*  methodStatsTable;

    /* Filter method compilation blacklist with call-graph information */
	/* 通过调用图检查过滤掉的函数 */
    bool checkCallGraph;

    /* New translation chain has been set up */
	/* 新的转换链被设置 */
    volatile bool hasNewChain;

#if defined(WITH_SELF_VERIFICATION)
    /* Spin when error is detected, volatile so GDB can reset it */
    volatile bool selfVerificationSpin;
#endif

    /* Framework or stand-alone? */
	/* Framework独立运行？ */
    bool runningInAndroidFramework;

    /* Framework callback happened? */
	/* 已经开启Framework回调 */
    bool alreadyEnabledViaFramework;

    /* Framework requests to disable the JIT for good */
	/* 关闭JIT */
    bool disableJit;

#if defined(SIGNATURE_BREAKPOINT)
    /* Signature breakpoint */
    u4 signatureBreakpointSize;         // # of words
    u4 *signatureBreakpoint;            // Signature content
#endif

#if defined(WITH_JIT_TUNING)
    /* Performance tuning counters */
	/* 性能监视计数，用于测试程序 */
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
	/* 优化级别 */
    JitOptLevel        optLevel;
#endif

    /* Place arrays at the end to ease the display in gdb sessions */

    /* Work order queue for compilations */
	/* 编译订单序列 */
    CompilerWorkOrder compilerWorkQueue[COMPILER_WORK_QUEUE_SIZE];

    /* Work order queue for predicted chain patching */
    ICPatchWorkOrder compilerICPatchQueue[COMPILER_IC_PATCH_QUEUE_SIZE];
};

/* 整个虚拟机中唯一的全局JIT实例 */
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
