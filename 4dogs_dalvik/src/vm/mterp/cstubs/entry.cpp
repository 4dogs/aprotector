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
 * c ���͵Ķ�ƽ̨��������ڵ�
 */
void dvmMterpStdRun(Thread* self)
{
    jmp_buf jmpBuf;

    // �����쳣��������������ʱ��������Ƭ����ȥ
    self->interpSave.bailPtr = &jmpBuf;

    /* 
    * We exit via a longjmp 
    * setjmp ��longjmp������ʹ�õģ�������c�������е��쳣������Ƶ�һ����
    * setjmp(jmp_buf j)����ʾ��ʹ�ñ���j��¼���ڵ�λ�á�����������
    * longjmp(jmp_buf j,int i)����ʾ���ص�j����¼��λ�ã���������ȥ���Ǵ�ԭ����setjmp()��������һ�������Ǻ�������i��ʹ����֪����ʵ������ͨ��longjmp()���صġ�
    */
    if (setjmp(jmpBuf)) {
        LOGVV("mterp threadid=%d returning", dvmThreadSelf()->threadId);
        return;
    }

    /* run until somebody longjmp()s out */
    /*�������һ��whileѭ����ѭ����ִ��ָ��*/
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
