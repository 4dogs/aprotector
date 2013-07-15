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
 * Declaration of the fundamental Object type and refinements thereof, plus
 * some functions for manipulating them.
 */
#ifndef DALVIK_OO_OBJECT_H_
#define DALVIK_OO_OBJECT_H_

#include <stddef.h>
#include "Atomic.h"

/* fwd decl */
struct DataObject;
struct InitiatingLoaderList;
struct ClassObject;
struct StringObject;
struct ArrayObject;
struct Method;
struct ExceptionEntry;
struct LineNumEntry;
struct StaticField;
struct InstField;
struct Field;
struct RegisterMap;

/*
 * Native function pointer type.
 *
 * "args[0]" holds the "this" pointer for virtual methods.
 *
 * The "Bridge" form is a super-set of the "Native" form; in many places
 * they are used interchangeably.  Currently, all functions have all
 * arguments passed in, but some functions only care about the first two.
 * Passing extra arguments to a C function is (mostly) harmless.
 */
typedef void (*DalvikBridgeFunc)(const u4* args, JValue* pResult,
    const Method* method, struct Thread* self);
typedef void (*DalvikNativeFunc)(const u4* args, JValue* pResult);


/* vm-internal access flags and related definitions */
/* 虚拟机内部访问标志及相关的定义 */
enum AccessFlags {
    ACC_MIRANDA         = 0x8000,       // method (internal to VM)
    JAVA_FLAGS_MASK     = 0xffff,       // bits set from Java sources (low 16)
};

/* Use the top 16 bits of the access flags field for
 * other class flags.  Code should use the *CLASS_FLAG*()
 * macros to set/get these flags.
 */
/**/
enum ClassFlags {
   /* Class或它的超类覆写了finalize()*/
    CLASS_ISFINALIZABLE        = (1<<31), // class/ancestor overrides finalize()
    /* Class是一个数组*/
    CLASS_ISARRAY              = (1<<30), // class is a "[*"
    /* Class是一个对象数组*/
    CLASS_ISOBJECTARRAY        = (1<<29), // class is a "[L*" or "[[*"
    CLASS_ISCLASS              = (1<<28), // class is *the* class Class

     /* Class是一个引用*/
    CLASS_ISREFERENCE          = (1<<27), // class is a soft/weak/phantom ref
                                          // only ISREFERENCE is set --> soft
     /* Class是一个弱引用*/
    CLASS_ISWEAKREFERENCE      = (1<<26), // class is a weak reference
    /*
   *(每个类都有一个特殊的方法finalizer，它不能被直接调用，而被JVM在适当的时候调用，通常用来处理一些清理资源的工作，因此称为收尾机制。)
   */
    CLASS_ISFINALIZERREFERENCE = (1<<25), // class is a finalizer reference
    CLASS_ISPHANTOMREFERENCE   = (1<<24), // class is a phantom reference

    /* Class定义在多个dex文件中 */
    CLASS_MULTIPLE_DEFS        = (1<<23), // DEX verifier: defs in multiple DEXs

    /* unlike the others, these can be present in the optimized DEX file */
    /* Class是被优化过的 */
    CLASS_ISOPTIMIZED          = (1<<17), // class may contain opt instrs
    /* Class已经预校验 */
    CLASS_ISPREVERIFIED        = (1<<16), // class has been pre-verified
};

/* bits we can reasonably expect to see set in a DEX access flags field */
#define EXPECTED_FILE_FLAGS \
    (ACC_CLASS_MASK | CLASS_ISPREVERIFIED | CLASS_ISOPTIMIZED)

/*
 * Get/set class flags.
 */
#define SET_CLASS_FLAG(clazz, flag) \
    do { (clazz)->accessFlags |= (flag); } while (0)

#define CLEAR_CLASS_FLAG(clazz, flag) \
    do { (clazz)->accessFlags &= ~(flag); } while (0)

#define IS_CLASS_FLAG_SET(clazz, flag) \
    (((clazz)->accessFlags & (flag)) != 0)

#define GET_CLASS_FLAG_GROUP(clazz, flags) \
    ((u4)((clazz)->accessFlags & (flags)))

/*
 * Use the top 16 bits of the access flags field for other method flags.
 * Code should use the *METHOD_FLAG*() macros to set/get these flags.
 */
enum MethodFlags {
    METHOD_ISWRITABLE       = (1<<31),  // the method's code is writable
};

/*
 * Get/set method flags.
 */
#define SET_METHOD_FLAG(method, flag) \
    do { (method)->accessFlags |= (flag); } while (0)

#define CLEAR_METHOD_FLAG(method, flag) \
    do { (method)->accessFlags &= ~(flag); } while (0)

#define IS_METHOD_FLAG_SET(method, flag) \
    (((method)->accessFlags & (flag)) != 0)

#define GET_METHOD_FLAG_GROUP(method, flags) \
    ((u4)((method)->accessFlags & (flags)))

/* current state of the class, increasing as we progress */
/* 类的一些状态，用来表明类的当前执行状态*/
enum ClassStatus {
    CLASS_ERROR         = -1,

    CLASS_NOTREADY      = 0,
    CLASS_IDX           = 1,    /* loaded, DEX idx in super or ifaces */
    CLASS_LOADED        = 2,    /* DEX idx values resolved */ /* 加载 */
    CLASS_RESOLVED      = 3,    /* part of linking */  /* 解析 */
    CLASS_VERIFYING     = 4,    /* in the process of being verified */  /*  校验过程中 */
    CLASS_VERIFIED      = 5,    /* logically part of linking; done pre-init */ /* 校验完成，预初始化 */
    CLASS_INITIALIZING  = 6,    /* class init in progress */  /* 初始化中 */
    CLASS_INITIALIZED   = 7,    /* ready to go */ /*初始化完成 */
};

/*
 * Definitions for packing refOffsets in ClassObject.
 */
/*
 * A magic value for refOffsets. Ignore the bits and walk the super
 * chain when this is the value.
 * [This is an unlikely "natural" value, since it would be 30 non-ref instance
 * fields followed by 2 ref instance fields.]
 */
#define CLASS_WALK_SUPER ((unsigned int)(3))
#define CLASS_SMALLEST_OFFSET (sizeof(struct Object))
#define CLASS_BITS_PER_WORD (sizeof(unsigned long int) * 8)
#define CLASS_OFFSET_ALIGNMENT 4
#define CLASS_HIGH_BIT ((unsigned int)1 << (CLASS_BITS_PER_WORD - 1))
/*
 * Given an offset, return the bit number which would encode that offset.
 * Local use only.
 */
#define _CLASS_BIT_NUMBER_FROM_OFFSET(byteOffset) \
    (((unsigned int)(byteOffset) - CLASS_SMALLEST_OFFSET) / \
     CLASS_OFFSET_ALIGNMENT)
/*
 * Is the given offset too large to be encoded?
 */
#define CLASS_CAN_ENCODE_OFFSET(byteOffset) \
    (_CLASS_BIT_NUMBER_FROM_OFFSET(byteOffset) < CLASS_BITS_PER_WORD)
/*
 * Return a single bit, encoding the offset.
 * Undefined if the offset is too large, as defined above.
 */
#define CLASS_BIT_FROM_OFFSET(byteOffset) \
    (CLASS_HIGH_BIT >> _CLASS_BIT_NUMBER_FROM_OFFSET(byteOffset))
/*
 * Return an offset, given a bit number as returned from CLZ.
 */
#define CLASS_OFFSET_FROM_CLZ(rshift) \
    (((int)(rshift) * CLASS_OFFSET_ALIGNMENT) + CLASS_SMALLEST_OFFSET)


/*
 * Used for iftable in ClassObject.
 */
/*
 * 用于ClassObject的iftable列表中
 */
struct InterfaceEntry {
    /* pointer to interface class */
    ClassObject*    clazz;   //表示接口的ClassObject对象

    /*
     * Index into array of vtable offsets.  This points into the ifviPool,
     * which holds the vtables for all interfaces declared by this class.
     */
    int*            methodIndexArray; //指向在vtable中对应方法的位置偏移的索引数组ifviPool中的位置偏移的索引数组
};



/*
 * There are three types of objects:
 *  Class objects - an instance of java.lang.Class
 *  Array objects - an object created with a "new array" instruction
 *  Data objects - an object that is neither of the above
 *
 * We also define String objects.  At present they're equivalent to
 * DataObject, but that may change.  (Either way, they make some of the
 * code more obvious.)
 *
 * All objects have an Object header followed by type-specific data.
 */
struct Object {
    /* ptr to class object */
    ClassObject*    clazz;   //类型对象

    /*
     * A word containing either a "thin" lock or a "fat" monitor.  See
     * the comments in Sync.c for a description of its layout.
     */
    /*
   * 锁对象，只要是实例对象都有对应的锁，某个线程获得对它的锁以后，如果其它线程要获得它的锁，
   * 只有等这个线程释放了它的锁，才能真正获得锁
   */
    u4              lock;
};

/*
 * Properly initialize an Object.
 * void DVM_OBJECT_INIT(Object *obj, ClassObject *clazz_)
 */
#define DVM_OBJECT_INIT(obj, clazz_) \
    dvmSetFieldObject(obj, OFFSETOF_MEMBER(Object, clazz), clazz_)

/*
 * Data objects have an Object header followed by their instance data.
 */
struct DataObject : Object {
    /* variable #of u4 slots; u8 uses 2 slots */
   /* u4类型项的变量数;u8使用两项*/
    u4              instanceData[1];
};

/*
 * Strings are used frequently enough that we may want to give them their
 * own unique type.
 *
 * Using a dedicated type object to access the instance data provides a
 * performance advantage but makes the java/lang/String.java implementation
 * fragile.
 *
 * Currently this is just equal to DataObject, and we pull the fields out
 * like we do for any other object.
 */
struct StringObject : Object {
    /* variable #of u4 slots; u8 uses 2 slots */
   /* u4类型项的变量数;u8使用两项*/
    u4              instanceData[1];

    /** Returns this string's length in characters. */
    int length() const;

    /**
     * Returns this string's length in bytes when encoded as modified UTF-8.
     * Does not include a terminating NUL byte.
     */
    int utfLength() const;

    /** Returns this string's char[] as an ArrayObject. */
    ArrayObject* array() const;

    /** Returns this string's char[] as a u2*. */
    const u2* chars() const;
};


/*
 * Array objects have these additional fields.
 *
 * We don't currently store the size of each element.  Usually it's implied
 * by the instruction.  If necessary, the width can be derived from
 * the first char of obj->clazz->descriptor.
 */
struct ArrayObject : Object {
    /* number of elements; immutable after init */
   /* 元素个数，初始化后不会改变*/
    u4              length;

    /*
     * Array contents; actual size is (length * sizeof(type)).  This is
     * declared as u8 so that the compiler inserts any necessary padding
     * (e.g. for EABI); the actual allocation may be smaller than 8 bytes.
     */
    /*数组的内容，大小为length*sizeof(type)，总长度必须是8字节对齐的,实际分配的大小可能小于8字节*/
    u8              contents[1];
};

/*
 * For classes created early and thus probably in the zygote, the
 * InitiatingLoaderList is kept in gDvm. Later classes use the structure in
 * Object Class. This helps keep zygote pages shared.
 */
struct InitiatingLoaderList {
    /* a list of initiating loader Objects; grown and initialized on demand */
    Object**  initiatingLoaders;
    /* count of loaders in the above list */
    int       initiatingLoaderCount;
};

/*
 * Generic field header.  We pass this around when we want a generic Field
 * pointer (e.g. for reflection stuff).  Testing the accessFlags for
 * ACC_STATIC allows a proper up-cast.
 */
/*字段结构体*/
struct Field {
   /* 字段所属的类*/
    ClassObject*    clazz;          /* class in which the field is declared */
   /* 变量名称*/
    const char*     name;
   /* 变量的签名比如"I", "[C", "Landroid/os/Debug;"等 */
    const char*     signature;      /* e.g. "I", "[C", "Landroid/os/Debug;" */
  /* 访问标志,可以是ACC_PUBLIC、ACC_PRIVATE.... */
    u4              accessFlags;
};

/*
 * Static field.
 */
/*静态字段结构体*/
struct StaticField : Field {
   /* 对于原始类型直接由DEX设置*/
    JValue          value;          /* initially set from DEX for primitives */  
};

/*
 * Instance field.
 */
/*实例字段结构体*/
struct InstField : Field {
    /*
     * This field indicates the byte offset from the beginning of the
     * (Object *) to the actual instance data; e.g., byteOffset==0 is
     * the same as the object pointer (bug!), and byteOffset==4 is 4
     * bytes farther.
     */
    /*从Object*地址处开始的偏移位置*/
    int             byteOffset;
};

/*
 * This defines the amount of space we leave for field slots in the
 * java.lang.Class definition.  If we alter the class to have more than
 * this many fields, the VM will abort at startup.
 */
#define CLASS_FIELD_SLOTS   4

/*
 * Class objects have many additional fields.  This is used for both
 * classes and interfaces, including synthesized classes (arrays and
 * primitive types).
 *
 * Class objects are unusual in that they have some fields allocated with
 * the system malloc (or LinearAlloc), rather than on the GC heap.  This is
 * handy during initialization, but does require special handling when
 * discarding java.lang.Class objects.
 *
 * The separation of methods (direct vs. virtual) and fields (class vs.
 * instance) used in Dalvik works out pretty well.  The only time it's
 * annoying is when enumerating or searching for things with reflection.
 */
/*
 * ClassObject - 类加载后的表现形式
 *
 */
struct ClassObject : Object {
    /* leave space for instance data; we could access fields directly if we
       freeze the definition of java/lang/Class */
    /* 为实例数据留出4字间的空间*/
    u4              instanceData[CLASS_FIELD_SLOTS];

    /* UTF-8 descriptor for the class; from constant pool, or on heap
       if generated ("[C") */
    /* UTF-8的描述字符串 */
    const char*     descriptor;
   /* 另一个描述字符串，貌似在反射机制的代理类用到 */
    char*           descriptorAlloc;

    /* access flags; low 16 bits are defined by VM spec */
    /* 访问标志 ,对于外部类而言,可以是ACC_PUBLIC、ACC_FINAL.....*/
    u4              accessFlags;

    /* VM-unique class serial number, nonzero, set very early */
    /* VM特有的类序列码,非零的 */
    u4              serialNumber;

    /* DexFile from which we came; needed to resolve constant pool entries */
    /* (will be NULL for VM-generated, e.g. arrays and primitive classes) */
   /*指向对应的DexFile，当从常量池中查询信息时用到，如果虚拟机自己生成的类,比如数组和原始类等则为空*/
    DvmDex*         pDvmDex;

    /* state of class initialization */
    /* 类初始化的一些状态 ,比如CLASS_NOTREADY、CLASS_LOADED....*/
    ClassStatus     status;

    /* if class verify fails, we must return same error on subsequent tries */
    /* 如果类校验失败，我们必须返回相同的错误供后续尝试 */
    ClassObject*    verifyErrorClass;

    /* threadId, used to check for recursive <clinit> invocation */
    /*初始化时的线程id,用于在嵌套调用时作检查*/
      u4              initThreadId;

    /*
     * Total object size; used when allocating storage on gc heap.  (For
     * interfaces and abstract classes this will be zero.)
     */
     /*
   * 这个类型所对应的对象的大小，用于在堆上分配内存时使用.如果是接口或抽象类，这个值是0
   */
    size_t          objectSize;

    /* arrays only: class object for base element, for instanceof/checkcast
       (for String[][][], this will be String) */
    /*
   * 数组元素的类型，仅当这个类型为数组类型时有效.用于instanceof操作符或强制类型
   * 转换时使用，比如:String[][][]类型的这个值就是String类型
   */
    ClassObject*    elementClass;

    /* arrays only: number of dimensions, e.g. int[][] is 2 */
   /*
  * 数组的维数，仅当这个类型为数组时才有效，比如int[][]的值为2
  */
    int             arrayDim;

    /* primitive type index, or PRIM_NOT (-1); set for generated prim classes */
   /* 原始类型的下标，用于虚拟机生成的原始类型，非原始类型时为PRIM_NOT (-1) */
    PrimitiveType   primitiveType;

    /* superclass, or NULL if this is java.lang.Object */
   /* 超类的类型，如果是java.lang.Object的话这个值为NULL  */
    ClassObject*    super;

    /* defining class loader, or NULL for the "bootstrap" system loader */
   /*这个类的定义加载器，如果类型为“bootstrap”的系统类加载器则为NULL*/
    Object*         classLoader;

    /* initiating class loader list */
    /* NOTE: for classes with low serialNumber, these are unused, and the
       values are kept in a table in gDvm. */
    /*需要初始化这个类的加载器的列表，即这个类的初始化加载器的列表*/
    InitiatingLoaderList initiatingLoaderList;

    /* array of interfaces this class implements directly */
    /* 此类所实现的接口数 */
    int             interfaceCount;
    /* 此类直接实现的接口列表 */
    ClassObject**   interfaces;

    /* static, private, and <init> methods */
    /* 所谓的direct方法即static,private和方法条数 */
    int             directMethodCount;
   /* direct方法列表*/
    Method*         directMethods;

    /* virtual methods defined in this class; invoked through vtable */
    /* 本类定义的虚方法数 */
    int             virtualMethodCount;
   /*本类定义的虚方法，所谓虚方法就是通过虚方法表vtable来调用的方法 */
    Method*         virtualMethods;

    /*
     * Virtual method table (vtable), for use by "invoke-virtual".  The
     * vtable from the superclass is copied in, and virtual methods from
     * our class either replace those from the super or are appended.
     */
     /* 虚方法表中的方法数 */
    int             vtableCount;
   /* 
  * 虚方法表,通过invokevirtual来调用.首先从超类完全复制过来虚表,
  * 然后我们在部分得替换它或者扩展它
  */
    Method**        vtable;

    /*
     * Interface table (iftable), one entry per interface supported by
     * this class.  That means one entry for each interface we support
     * directly, indirectly via superclass, or indirectly via
     * superinterface.  This will be null if neither we nor our superclass
     * implement any interfaces.
     *
     * Why we need this: given "class Foo implements Face", declare
     * "Face faceObj = new Foo()".  Invoke faceObj.blah(), where "blah" is
     * part of the Face interface.  We can't easily use a single vtable.
     *
     * For every interface a concrete class implements, we create a list of
     * virtualMethod indices for the methods in the interface.
     */
     /*类实现的接口数*/
    int             iftableCount;
   /* 
  * 类的接口表，每个接口一个表项.不管是由类直接实现的接口,还是由超类
  * 间接实现的接口.如果一个接口都未实现那么这个表就为NULL
  */
    InterfaceEntry* iftable;

    /*
     * The interface vtable indices for iftable get stored here.  By placing
     * them all in a single pool for each class that implements interfaces,
     * we decrease the number of allocations.
     */
     /*在vtable中对应方法的位置偏移的索引数组中的元素个数*/
    int             ifviPoolCount;
   /* 指向在vtable中对应方法的位置偏移的索引数组*/
    int*            ifviPool;

    /* instance fields
     *
     * These describe the layout of the contents of a DataObject-compatible
     * Object.  Note that only the fields directly defined by this class
     * are listed in ifields;  fields defined by a superclass are listed
     * in the superclass's ClassObject.ifields.
     *
     * All instance fields that refer to objects are guaranteed to be
     * at the beginning of the field list.  ifieldRefCount specifies
     * the number of reference fields.
     */
     /*实例变量的个数*/
    int             ifieldCount;
    /*实例变量中引用的个数*/
    int             ifieldRefCount; // number of fields that are object refs 相关字段的数量
    /*实例变量数组 */
    InstField*      ifields;

    /* bitmap of offsets of ifields */
    u4 refOffsets;

    /* source file name, if known */
   /*源文件的文件名*/
    const char*     sourceFile;

    /* static fields */
   /*静态变量个数*/
    int             sfieldCount;
    StaticField     sfields[0]; /* MUST be last item */
};

/*
 * A method.  We create one of these for every method in every class
 * we load, so try to keep the size to a minimum.
 * 对于类里面的每个函数，都要给他创建这么一个结构体，用来描述这个函数
 *
 * Much of this comes from and could be accessed in the data held in shared
 * memory.  We hold it all together here for speed.  Everything but the
 * pointers could be held in a shared table generated by the optimizer;
 * if we're willing to convert them to offsets and take the performance
 * hit (e.g. "meth->insns" becomes "baseAddr + meth->insnsOffset") we
 * could move everything but "nativeFunc".
 * 本来这个结构体里面的某些成员的数据是可以放在共享内存里面的
 * 但是为了省去读取这么一个操作，为了提高速度，就都放在各自的成员处了
 */
struct Method {
    /* the class we are a part of  当前的方法隶属于那个类对象*/
    ClassObject*    clazz;

    /* access flags; low 16 bits are defined by spec (could be u2?) 该方法的访问标记，低16位是空的，实际上可以用u2就满足了 */
    u4              accessFlags;

    /*
     * For concrete virtual methods, this is the offset of the method
     * in "vtable".
     * 对于实际的虚函数，这个index代表该函数在虚表中的偏移
     * For abstract methods in an interface class, this is the offset
     * of the method in "iftable[n]->methodIndexArray".
     * 对于接口类中的抽象方法，它代表函数在iftable[n]->methodIndexArray中的偏移
     */
    u2             methodIndex;

    /*
     * Method bounds; not needed for an abstract method.
     * 对于一个函数，下面的三个字段描述边界的大小，但是对于抽象函数不需要这些。
     * For a native method, we compute the size of the argument list, and
     * set "insSize" and "registerSize" equal to it.
     * 对于本地方法的话，设置的时候要注意，计算参数列表的整体大小
     * 然后把registersSize和insSize都设置成这个整体大小(对于其他函数的话，应该是registersSize = insSize + locals)
     * 在一个标准的栈帧中一般需要这么几个东西: 参数空间+ 局部变量空间 + 输出结果空间
     */
    u2              registersSize;  /* ins + locals */
    u2              outsSize;
    u2              insSize;

    /* method name, e.g. "<init>" or "eatLunch"  方法的名字*/
    const char*     name;

    /*
     * Method prototype descriptor string (return and argument types).
     * 一个方法的原型(返回值的类型和参数类型)
     * 问题是这个值怎么能同时代表返回值和参数的类型呢?
     * TODO: This currently must specify the DexFile as well as the proto_ids
     * index, because generated Proxy classes don't have a DexFile.  We can
     * remove the DexFile* and reduce the size of this struct if we generate
     * a DEX for proxies.
     */
    DexProto        prototype;

    /* short-form method descriptor string  关于一个函数的短描述字符串*/
    const char*     shorty;

    /*
     * The remaining items are not used for abstract or native methods.
     * (JNI is currently hijacking "insns" as a function pointer, set
     * after the first call.  For internal-native this stays null.)
     * 从这里开始往下的字段不适用于抽象和本地方法
     * 对于JNI的相关调用的话，这里做了个技巧，就是在第一次调用后，insns会被设置为方法指针
     */

    /* the actual code 
    * 存放实际的该函数的指令
    * 这里是个指针，实际存放的指令是在dex文件映射到的对应内存区域。
    */
    const u2*       insns;          /* instructions, in memory-mapped .dex */

    /* JNI: cached argument and return-type hints 
    * 这个字段主要是工jni调用来使用的，用来表明参数和返回值类型
    */
    int             jniArgInfo;

    /*
     * JNI: native method ptr; could be actual function or a JNI bridge.  We
     * don't currently discriminate between DalvikBridgeFunc and
     * DalvikNativeFunc; the former takes an argument superset (i.e. two
     * extra args) which will be ignored.  If necessary we can use
     * insns==NULL to detect JNI bridge vs. internal native.
     */
    /*本地方法指针。可以是真正的函数也可以是JNI桥。
   *当前我们并不区分DalvikBridgeFunc和DalvikNativeFunc，前者的参数是个超集(有额外的两个参数，它们会被忽略)。
   *必要的话我们可以使用insns==NULL来判断是JNI桥还是内部本地函数
   */ 

    DalvikBridgeFunc nativeFunc;

    /*
     * JNI: true if this static non-synchronized native method (that has no
     * reference arguments) needs a JNIEnv* and jclass/jobject. Libcore
     * uses this.
     */
    bool fastJni;

    /*
     * JNI: true if this method has no reference arguments. This lets the JNI
     * bridge avoid scanning the shorty for direct pointers that need to be
     * converted to local references.
     *
     * TODO: replace this with a list of indexes of the reference arguments.
     */
    bool noRef;

    /*
     * JNI: true if we should log entry and exit. This is the only way
     * developers can log the local references that are passed into their code.
     * Used for debugging JNI problems in third-party code.
     */
    bool shouldTrace;

    /*
     * Register map data, if available.  This will point into the DEX file
     * if the data was computed during pre-verification, or into the
     * linear alloc area if not.
     */
    const RegisterMap* registerMap;

    /* set if method was called during method profiling */
    bool            inProfile;
};


/*
 * Find a method within a class.  The superclass is not searched.
 */
Method* dvmFindDirectMethodByDescriptor(const ClassObject* clazz,
    const char* methodName, const char* signature);
Method* dvmFindVirtualMethodByDescriptor(const ClassObject* clazz,
    const char* methodName, const char* signature);
Method* dvmFindVirtualMethodByName(const ClassObject* clazz,
    const char* methodName);
Method* dvmFindDirectMethod(const ClassObject* clazz, const char* methodName,
    const DexProto* proto);
Method* dvmFindVirtualMethod(const ClassObject* clazz, const char* methodName,
    const DexProto* proto);


/*
 * Find a method within a class hierarchy.
 */
Method* dvmFindDirectMethodHierByDescriptor(const ClassObject* clazz,
    const char* methodName, const char* descriptor);
Method* dvmFindVirtualMethodHierByDescriptor(const ClassObject* clazz,
    const char* methodName, const char* signature);
Method* dvmFindDirectMethodHier(const ClassObject* clazz,
    const char* methodName, const DexProto* proto);
Method* dvmFindVirtualMethodHier(const ClassObject* clazz,
    const char* methodName, const DexProto* proto);
Method* dvmFindMethodHier(const ClassObject* clazz, const char* methodName,
    const DexProto* proto);

/*
 * Find a method in an interface hierarchy.
 */
Method* dvmFindInterfaceMethodHierByDescriptor(const ClassObject* iface,
    const char* methodName, const char* descriptor);
Method* dvmFindInterfaceMethodHier(const ClassObject* iface,
    const char* methodName, const DexProto* proto);

/*
 * Find the implementation of "meth" in "clazz".
 *
 * Returns NULL and throws an exception if not found.
 */
const Method* dvmGetVirtualizedMethod(const ClassObject* clazz,
    const Method* meth);

/*
 * Get the source file associated with a method.
 */
extern "C" const char* dvmGetMethodSourceFile(const Method* meth);

/*
 * Find a field within a class.  The superclass is not searched.
 */
InstField* dvmFindInstanceField(const ClassObject* clazz,
    const char* fieldName, const char* signature);
StaticField* dvmFindStaticField(const ClassObject* clazz,
    const char* fieldName, const char* signature);

/*
 * Find a field in a class/interface hierarchy.
 */
InstField* dvmFindInstanceFieldHier(const ClassObject* clazz,
    const char* fieldName, const char* signature);
StaticField* dvmFindStaticFieldHier(const ClassObject* clazz,
    const char* fieldName, const char* signature);
Field* dvmFindFieldHier(const ClassObject* clazz, const char* fieldName,
    const char* signature);

/*
 * Find a field and return the byte offset from the object pointer.  Only
 * searches the specified class, not the superclass.
 *
 * Returns -1 on failure.
 */
INLINE int dvmFindFieldOffset(const ClassObject* clazz,
    const char* fieldName, const char* signature)
{
    InstField* pField = dvmFindInstanceField(clazz, fieldName, signature);
    if (pField == NULL)
        return -1;
    else
        return pField->byteOffset;
}

/*
 * Helpers.
 */
 // 判断一个方法的属性(public，private，staticynchronized，DeclaredSynchronized)
INLINE bool dvmIsPublicMethod(const Method* method) {
    return (method->accessFlags & ACC_PUBLIC) != 0;
}
INLINE bool dvmIsPrivateMethod(const Method* method) {
    return (method->accessFlags & ACC_PRIVATE) != 0;
}
INLINE bool dvmIsStaticMethod(const Method* method) {
    return (method->accessFlags & ACC_STATIC) != 0;
}
INLINE bool dvmIsSynchronizedMethod(const Method* method) {
    return (method->accessFlags & ACC_SYNCHRONIZED) != 0;
}
INLINE bool dvmIsDeclaredSynchronizedMethod(const Method* method) {
    return (method->accessFlags & ACC_DECLARED_SYNCHRONIZED) != 0;
}
INLINE bool dvmIsFinalMethod(const Method* method) {
    return (method->accessFlags & ACC_FINAL) != 0;
}
INLINE bool dvmIsNativeMethod(const Method* method) {
    return (method->accessFlags & ACC_NATIVE) != 0;
}
INLINE bool dvmIsAbstractMethod(const Method* method) {
    return (method->accessFlags & ACC_ABSTRACT) != 0;
}
INLINE bool dvmIsSyntheticMethod(const Method* method) {
    return (method->accessFlags & ACC_SYNTHETIC) != 0;
}
INLINE bool dvmIsMirandaMethod(const Method* method) {
    return (method->accessFlags & ACC_MIRANDA) != 0;
}
INLINE bool dvmIsConstructorMethod(const Method* method) {
    return *method->name == '<';
}
/*
* Dalvik puts private, static, and constructors into non-virtual table 
* 这里提出一个直接调用的概念，实际上并没有什么直接调用
* 只是dalvik认为私有的或者静态的或者构造函数都是直接调用函数
* dalvik 要将他们放入非虚表中
*/
INLINE bool dvmIsDirectMethod(const Method* method) {
    return dvmIsPrivateMethod(method) ||
           dvmIsStaticMethod(method) ||
           dvmIsConstructorMethod(method);
}
/* Get whether the given method has associated bytecode. This is the
 * case for methods which are neither native nor abstract. 
 * 确定一个方法是否有字节码，因为本地方法和抽象方法没有字节码可执行
 */
INLINE bool dvmIsBytecodeMethod(const Method* method) {
    return (method->accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) == 0;
}

INLINE bool dvmIsProtectedField(const Field* field) {
    return (field->accessFlags & ACC_PROTECTED) != 0;
}
INLINE bool dvmIsStaticField(const Field* field) {
    return (field->accessFlags & ACC_STATIC) != 0;
}
INLINE bool dvmIsFinalField(const Field* field) {
    return (field->accessFlags & ACC_FINAL) != 0;
}
INLINE bool dvmIsVolatileField(const Field* field) {
    return (field->accessFlags & ACC_VOLATILE) != 0;
}

INLINE bool dvmIsInterfaceClass(const ClassObject* clazz) {
    return (clazz->accessFlags & ACC_INTERFACE) != 0;
}
INLINE bool dvmIsPublicClass(const ClassObject* clazz) {
    return (clazz->accessFlags & ACC_PUBLIC) != 0;
}
INLINE bool dvmIsFinalClass(const ClassObject* clazz) {
    return (clazz->accessFlags & ACC_FINAL) != 0;
}
INLINE bool dvmIsAbstractClass(const ClassObject* clazz) {
    return (clazz->accessFlags & ACC_ABSTRACT) != 0;
}
INLINE bool dvmIsAnnotationClass(const ClassObject* clazz) {
    return (clazz->accessFlags & ACC_ANNOTATION) != 0;
}
INLINE bool dvmIsPrimitiveClass(const ClassObject* clazz) {
    return clazz->primitiveType != PRIM_NOT;
}

/* linked, here meaning prepared and resolved */
/* 类是否已经被解析 */
INLINE bool dvmIsClassLinked(const ClassObject* clazz) {
    return clazz->status >= CLASS_RESOLVED;
}
/* has class been verified? */
/* 类是否完成校验 */
INLINE bool dvmIsClassVerified(const ClassObject* clazz) {
    return clazz->status >= CLASS_VERIFIED;
}

/*
 * Return whether the given object is an instance of Class.
 */
INLINE bool dvmIsClassObject(const Object* obj) {
    assert(obj != NULL);
    assert(obj->clazz != NULL);
    return IS_CLASS_FLAG_SET(obj->clazz, CLASS_ISCLASS);
}

/*
 * Return whether the given object is the class Class (that is, the
 * unique class which is an instance of itself).
 */
INLINE bool dvmIsTheClassClass(const ClassObject* clazz) {
    assert(clazz != NULL);
    return IS_CLASS_FLAG_SET(clazz, CLASS_ISCLASS);
}

/*
 * Get the associated code struct for a method. This returns NULL
 * for non-bytecode methods.
 * 返回一个方法所关联的描述性结构体
 */
INLINE const DexCode* dvmGetMethodCode(const Method* meth) {
    if (dvmIsBytecodeMethod(meth)) {
        /*
         * The insns field for a bytecode method actually points at
         * &(DexCode.insns), so we can subtract back to get at the
         * DexCode in front.
         */
        return (const DexCode*)
            (((const u1*) meth->insns) - offsetof(DexCode, insns));
    } else {
        return NULL;
    }
}

/*
 * Get the size of the insns associated with a method. This returns 0
 * for non-bytecode methods.
 * 获取一个方法所关联的指令的大小
 */
INLINE u4 dvmGetMethodInsnsSize(const Method* meth) {
    const DexCode* pCode = dvmGetMethodCode(meth);
    return (pCode == NULL) ? 0 : pCode->insnsSize;
}

/* debugging */
void dvmDumpObject(const Object* obj);

#endif  // DALVIK_OO_OBJECT_H_
