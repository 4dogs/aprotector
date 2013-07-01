/*
 * Main interpreter loop.
 *
 * This was written with an ARM implementation in mind.
 * portable���͵Ľ������Ľ���ѭ�����
 */
void dvmInterpretPortable(Thread* self)
{
#if defined(EASY_GDB)
    // ��������Ƿ�����ԣ�������ջ֡�ĵ�ַ
    StackSaveArea* debugSaveArea = SAVEAREA_FROM_FP(self->interpSave.curFrame);
#endif
    DvmDex* methodClassDex;     // curMethod->clazz->pDvmDex
    JValue retval;

    /* core state */
    const Method* curMethod;    // method we're interpreting ��ǰ����Ҫ���͵ķ���
    const u2* pc;               // program counter ���������
    u4* fp;                     // frame pointer ָ֡��
    u2 inst;                    // current instruction ��ǰָ��

	
    /* instruction decoding */
    u4 ref;                     // 16 or 32-bit quantity fetched directly
    u2 vsrc1, vsrc2, vdst;      // usually used for register indexes
    
    /* method call setup */
    const Method* methodToCall;
    bool methodCallRange;

    /* 
    * static computed goto table
    * ��̬����õ���ת��
    * ʵ���Ͼ��Ƕ���õ�һ�����
    * �þ�̬��ת����libdex��dexopcode.h�ж���
    * [��Ҫע����壺�ñ�ֻ�ṩ����cʵ�ֵĽ�������ʹ��]
    * �⿪�����������
    *  static const void* handlerTable[0x100] = {                      \
    *    H(OP_NOP),                                                            \
    *    H(OP_MOVE),                                                           \
    *    ....
    *  }
    * ���������opcode-gen������߶�̬���ɵģ�����˵�����������ʲô�����ɵģ���Ҫ�ο��ù��ߵ�ʵ��
    *
    * # define H(_op)             &&op_##_op
    * ʵ�����������������&&op_OP_NOP �����ĵ�ַ
    */
    DEFINE_GOTO_TABLE(handlerTable);

    /* copy state in 
    * ��ʼ��һЩ״ֵ̬
    */
    curMethod = self->interpSave.method;
    pc = self->interpSave.pc;
    fp = self->interpSave.curFrame;
    retval = self->interpSave.retval;   /* only need for kInterpEntryReturn? */

    methodClassDex = curMethod->clazz->pDvmDex; //��ȡdex��ص�����(������Ҫ�ο�vm\DvmDex.cpp��������ʵ��)

    LOGVV("threadid=%d: %s.%s pc=%#x fp=%p",
        self->threadId, curMethod->clazz->descriptor, curMethod->name,
        pc - curMethod->insns, fp);

    /*
     * Handle any ongoing profiling and prep for debugging.
     * ������Ҫ�Ƿ�����ԣ�����������һ�����巽���Ľ���
     */
    if (self->interpBreak.ctl.subMode != 0) {
        TRACE_METHOD_ENTER(self, curMethod);
        self->debugIsMethodEntry = true;   // Always true on startup
    }
    /*
     * DEBUG: scramble this to ensure we're not relying on it.
     */
    methodToCall = (const Method*) -1;

#if 0
    if (self->debugIsMethodEntry) {
        ILOGD("|-- Now interpreting %s.%s", curMethod->clazz->descriptor,
                curMethod->name);
        DUMP_REGS(curMethod, self->interpSave.curFrame, false);
    }
#endif

    //�����￪ʼ����ȡָ�ִ�У����صĽ׶�
    // ������ʵ���Ͻ�����һ��do - while��ѭ����ֱ��ִ����Ϸ���
    FINISH(0);                  /* fetch and execute first instruction */
    //�������¾�û�ж����ˣ�����Ҳû��} ��˵����ط����滹�ж���
    //��������ļ��еĴ��붼�ǽ���Ҫͨ�������ļ�����ƴ�ӵ����յĽ����������ļ��е�
    //���Կ����֪���������Ǿ�����ֽ���Ľ�������
    //�������һ��ֻ�Ǵӵ�һ��ָ�ʼ�����ϵĵ���pcָ��ֱ���ҵ�Ҫ���͵ķ�����������ָ��
    

/*--- start of opcodes ---*/
