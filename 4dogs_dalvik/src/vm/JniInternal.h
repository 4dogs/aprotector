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
JNI innards, common to the regular and "checked" interfaces.

JNI�ڲ�ͨ�ù�����Ѽ��Ľӿڡ�
*/
#ifndef DALVIK_JNIINTERNAL_H_
#define DALVIK_JNIINTERNAL_H_

#include "jni.h"

/*
system init/shutdown 

ϵͳ��ʼ��/�ر�
*/
bool dvmJniStartup(void);
void dvmJniShutdown(void);

/*
Our data structures for JNIEnv and JavaVM.

Native code thinks it has a pointer to a pointer.  We know better.

JNIEnv��JavaVM�����ݽṹ��
*/
struct JavaVMExt;

struct JNIEnvExt {
    const struct JNINativeInterface* funcTable;     /* must be first */

    const struct JNINativeInterface* baseFuncTable;

    u4      envThreadId;
    Thread* self;

    /* if nonzero, we are in a "critical" JNI call */
    int     critical;

    struct JNIEnvExt* prev;
    struct JNIEnvExt* next;
};

struct JavaVMExt {
    const struct JNIInvokeInterface* funcTable;     /* must be first */

    const struct JNIInvokeInterface* baseFuncTable;

    /* 
    head of list of JNIEnvs associated with this VM 
    
    ��VM��ص�JNIEnvs�б�ͷ
    */
    JNIEnvExt*      envList;
    pthread_mutex_t envListLock;
};

/*
Native function return type; used by dvmPlatformInvoke().

This is part of Method.jniArgInfo, and must fit in 3 bits.
Note: Assembly code in arch/<arch>/Call<arch>.S relies on
the enum values defined here.

���غ����������ͣ�ͨ��dvmPlatformInvoke()ʹ�á�

����Method.jniArgInfo�Ĳ��֣����ұ���ǡ��3bits��
*/
enum DalvikJniReturnType {
    DALVIK_JNI_RETURN_VOID = 0,     /* must be zero */
    DALVIK_JNI_RETURN_FLOAT = 1,
    DALVIK_JNI_RETURN_DOUBLE = 2,
    DALVIK_JNI_RETURN_S8 = 3,
    DALVIK_JNI_RETURN_S4 = 4,
    DALVIK_JNI_RETURN_S2 = 5,
    DALVIK_JNI_RETURN_U2 = 6,
    DALVIK_JNI_RETURN_S1 = 7
};

/*


NOTE TODO��
*/
#define DALVIK_JNI_NO_ARG_INFO  0x80000000
#define DALVIK_JNI_RETURN_MASK  0x70000000
#define DALVIK_JNI_RETURN_SHIFT 28
#define DALVIK_JNI_COUNT_MASK   0x0f000000
#define DALVIK_JNI_COUNT_SHIFT  24


/*
Pop the JNI local stack when we return from a native method.  "saveArea"
points to the StackSaveArea for the method we're leaving.

(This may be implemented directly in assembly in mterp, so changes here
may only affect the portable interpreter.)

����һ�����ط�������ʱ������JNI����ջ����saveArea��ָ��StackSaveArea��

NOTE TODO��
*/
INLINE void dvmPopJniLocals(Thread* self, StackSaveArea* saveArea)
{
    self->jniLocalRefTable.segmentState.all = saveArea->xtra.localRefCookie;
}

/*
Set the envThreadId field.

�����߳�ID�������̡߳�
*/
INLINE void dvmSetJniEnvThreadId(JNIEnv* pEnv, Thread* self)
{
    ((JNIEnvExt*)pEnv)->envThreadId = self->threadId;
    ((JNIEnvExt*)pEnv)->self = self;
}

void dvmCallJNIMethod(const u4* args, JValue* pResult,
    const Method* method, Thread* self);
void dvmCheckCallJNIMethod(const u4* args, JValue* pResult,
    const Method* method, Thread* self);

/*
Configure "method" to use the JNI bridge to call "func".

���á�method��ʹ��JNI��ȥ���á�func����
*/
void dvmUseJNIBridge(Method* method, void* func);


/*
Enable the "checked" versions.

���checked���汾��
*/
void dvmUseCheckedJniEnv(JNIEnvExt* pEnv);
void dvmUseCheckedJniVm(JavaVMExt* pVm);
void dvmLateEnableCheckedJni(void);

/*
Decode a local, global, or weak-global reference.

����һ�����ء�ȫ�֡�����-ȫ�����á�
*/
Object* dvmDecodeIndirectRef(Thread* self, jobject jobj);

/*
Verify that a reference passed in from native code is valid.  Returns
an indication of local/global/invalid.

У��ӱ��ش��봫�ݵ���������Ч�ġ�����һ�� ����/ȫ��/��Ч ��ʶ��
*/
jobjectRefType dvmGetJNIRefType(Thread* self, jobject jobj);

/*
Get the last method called on the interp stack.  This is the method
"responsible" for calling into JNI.

��ȡ�ڽ���ջ�����ķ������á�
*/
const Method* dvmGetCurrentJNIMethod(void);

/*
Create/destroy a JNIEnv for the current thread.

����/����һ����ǰ�̵߳�JNIEnv��
*/ 
JNIEnv* dvmCreateJNIEnv(Thread* self);
void dvmDestroyJNIEnv(JNIEnv* env);

/*
Find the JNIEnv associated with the current thread.

���ҵ�ǰ�߳���ص�JNIEnv��
*/
JNIEnvExt* dvmGetJNIEnvForThread(void);

/*
Release all MonitorEnter-acquired locks that are still held.  Called at
DetachCurrentThread time.

�ͷ������Գ���MonitorEnter-acquired������DetachCurrentThreadʱ���á�
*/
void dvmReleaseJniMonitors(Thread* self);

/*
Dump the contents of the JNI reference tables to the log file.

DumpJNI���ñ����ݵ���־�ļ���

The local ref tables associated with other threads are not included.

������������������صı������ñ�
*/
void dvmDumpJniReferenceTables(void);

#endif  // DALVIK_JNIINTERNAL_H_
