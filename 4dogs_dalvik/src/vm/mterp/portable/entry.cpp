/*
 * Main interpreter loop.
 *
 * This was written with an ARM implementation in mind.
 * portableÀàÐÍµÄ½âÊÍÆ÷µÄ½âÊÍÑ­»·Èë¿Ú
 */
void dvmInterpretPortable(Thread* self)
{
#if defined(EASY_GDB)
    // ÕâÀï½ö½öÊÇ·½±ãµ÷ÊÔ£¬±£´æÏÂÕ»Ö¡µÄµØÖ·
    StackSaveArea* debugSaveArea = SAVEAREA_FROM_FP(self->interpSave.curFrame);
#endif
    DvmDex* methodClassDex;     // curMethod->clazz->pDvmDex
    JValue retval;

    /* core state */
    const Method* curMethod;    // method we're interpreting µ±Ç°ÎÒÃÇÒª½âÊÍµÄ·½·¨
    const u2* pc;               // program counter ³ÌÐò¼ÆÊýÆ÷
    u4* fp;                     // frame pointer Ö¡Ö¸Õë
    u2 inst;                    // current instruction µ±Ç°Ö¸Áî

	
    /* instruction decoding */
    u4 ref;                     // 16 or 32-bit quantity fetched directly
    u2 vsrc1, vsrc2, vdst;      // usually used for register indexes
    
    /* method call setup */
    const Method* methodToCall;
    bool methodCallRange;

    /* 
    * static computed goto table
    * ¾²Ì¬¼ÆËãºÃµÄÌø×ª±í
    * Êµ¼ÊÉÏ¾ÍÊÇ¶¨ÒåºÃµÄÒ»¸öÊý×
    * ¸Ã¾²Ì¬Ìø×ª±íÔÚlibdexµÄdexopcode.hÖÐ¶¨Òå
    * [ÐèÒª×¢ÒâµÄÊå£º¸Ã±íÖ»Ìá¹©¸ø´¿cÊµÏÖµÄ½âÊÍÆ÷À´Ê¹ÓÃ]
    * ½â¿ªºêºóÊÇÕâÑùµÄ
    *  static const void* handlerTable[0x100] = {                      \
    *    H(OP_NOP),                                                            \
    *    H(OP_MOVE),                                                           \
    *    ....
    *  }
    * Õâ¸ö±íÊÇÓÉopcode-genÕâ¸ö¹¤¾ß¶¯Ì¬Éú³ÉµÄ£¬¾ßÌåËµÕâ¸ö¹¤¾ßÒÀ¾ÝÊ²Ã´À´Éú³ÉµÄ£¬ÐèÒª²Î¿´¸Ã¹¤¾ßµÄÊµÏÖ
    *
    * # define H(_op)             &&op_##_op
    * Êµ¼ÊÉÏÕâ¸ö±íÀïÃæ´æ·ÅÁË&&op_OP_NOP ÕâÑùµÄµØÖ·
    */
    DEFINE_GOTO_TABLE(handlerTable);

    /* copy state in 
    * ³õÊ¼»¯Ò»Ð©×´Ì¬Öµ
    */
    curMethod = self->interpSave.method;
    pc = self->interpSave.pc;
    fp = self->interpSave.curFrame;
    retval = self->interpSave.retval;   /* only need for kInterpEntryReturn? */

    methodClassDex = curMethod->clazz->pDvmDex; //»ñÈ¡dexÏà¹ØµÄÊý¾Ý(ÕâÀïÐèÒª²Î¿¼vm\DvmDex.cppÀïÃæµÄÏà¹ØÊµÏÖ)

    LOGVV("threadid=%d: %s.%s pc=%#x fp=%p",
        self->threadId, curMethod->clazz->descriptor, curMethod->name,
        pc - curMethod->insns, fp);

    /*
     * Handle any ongoing profiling and prep for debugging.
     * ÏÂÃæÖ÷ÒªÊÇ·½±ãµ÷ÊÔ£¬±íÃ÷½øÈëÁËÒ»¸ö¾ßÌå·½·¨µÄ½âÎö
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

    //´ÓÕâÀï¿ªÊ¼½øÈëÈ¡Ö¸Áî£¬Ö´ÐÐ£¬·µ»ØµÄ½×¶Î
    // ´ÓÕâÀïÊµ¼ÊÉÏ½øÈëÁËÒ»¸ödo - whileµÄÑ­»·£¬Ö±µ½Ö´ÐÐÍê±Ï·µ»Ø
    FINISH(0);                  /* fetch and execute first instruction */
    //ÕâÀïÍùÏÂ¾ÍÃ»ÓÐ¶«Î÷ÁË£¬µ«ÊÇÒ²Ã»ÓÐ} £¬ËµÕâ¸öµØ·½ºóÃæ»¹ÓÐ¶«Î÷
    //ÓÉÓÚÕâ¸öÎÄ¼þÖÐµÄ´úÂë¶¼ÊÇ½«À´ÒªÍ¨¹ýÅäÖÃÎÄ¼þ¸´ÖÆÆ´½Óµ½×îÖÕµÄ½âÊÍÆ÷´úÂëÎÄ¼þÖÐµÄ
    //ËùÒÔ¿ÉÏë¶øÖªÕâÀïºóÃæ¾ÍÊÇ¾ßÌåµÄ×Ö½ÚÂëµÄ½âÊÍÀý³Ì
    //ÉÏÃæµÄÕâÒ»¾äÖ»ÊÇ´ÓµÚÒ»ÌõÖ¸Áî¿ªÊ¼£¬²»¶ÏµÄµ÷ÕûpcÖ¸Ïò£¬Ö±µ½ÕÒµ½Òª½âÊÍµÄ·½·¨Ëù°üº¬µÄÖ¸Áî
    

/*--- start of opcodes ---*/
