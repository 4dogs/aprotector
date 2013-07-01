/*
 * Handler function table, one entry per opcode.
 */
#undef H
#define H(_op) (const void*) dvmMterp_##_op
DEFINE_GOTO_TABLE(gDvmMterpHandlers)

#undef H
#define H(_op) #_op
DEFINE_GOTO_TABLE(gDvmMterpHandlerNames)

#include <setjmp.h>

/*
 * C mterp entry point.  This just calls the various C fallbacks, making
 * this a slow but portable interpeter.
 *
 * This is only used for the "allstubs" variant.
 * c 类型的多平台解释器入口点
 */
void dvmMterpStdRun(Thread* self)
{
    jmp_buf jmpBuf;

    // 当有异常或者其他错误发生时会跳到这片区域去
    self->interpSave.bailPtr = &jmpBuf;

    /* 
    * We exit via a longjmp 
    * setjmp 和longjmp是配套使用的，他们是c语言特有的异常处理机制的一部分
    * setjmp(jmp_buf j)它表示“使用变量j记录现在的位置。函数返回零
    * longjmp(jmp_buf j,int i)它表示“回到j所记录的位置，让它看上去像是从原来的setjmp()函数返回一样。但是函数返回i，使代码知道它实际上是通过longjmp()返回的。
    */
    if (setjmp(jmpBuf)) {
        LOGVV("mterp threadid=%d returning", dvmThreadSelf()->threadId);
        return;
    }

    /* run until somebody longjmp()s out */
    /*这里进入一个while循环，循环的执行指令*/
    while (true) {
        typedef void (*Handler)(Thread* self);

        u2 inst = /*self->interpSave.*/pc[0];
        /*
         * In mterp, dvmCheckBefore is handled via the altHandlerTable,
         * while in the portable interpreter it is part of the handler
         * FINISH code.  For allstubs, we must do an explicit check
         * in the interpretation loop.
         */
        if (self->interpBreak.ctl.subMode) {
            dvmCheckBefore(pc, fp, self);
        }
        Handler handler = (Handler) gDvmMterpHandlers[inst & 0xff];
        (void) gDvmMterpHandlerNames;   /* avoid gcc "defined but not used" */
        LOGVV("handler %p %s",
            handler, (const char*) gDvmMterpHandlerNames[inst & 0xff]);
        (*handler)(self);
    }
}

/*
 * C mterp exit point.  Call here to bail out of the interpreter.
 */
void dvmMterpStdBail(Thread* self)
{
    jmp_buf* pJmpBuf = (jmp_buf*) self->interpSave.bailPtr;
    longjmp(*pJmpBuf, 1);
}
