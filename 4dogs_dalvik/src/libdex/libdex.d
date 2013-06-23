CmdUtils.o: CmdUtils.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 ZipArchive.h SysUtil.h CmdUtils.h
DexCatch.o: DexCatch.cpp DexCatch.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h Leb128.h
DexClass.o: DexClass.cpp DexClass.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h Leb128.h
DexDataMap.o: DexDataMap.cpp DexDataMap.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
DexDebugInfo.o: DexDebugInfo.cpp DexDebugInfo.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h DexProto.h Leb128.h
DexFile.o: DexFile.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 DexOptData.h ../libdex/DexFile.h DexProto.h DexCatch.h Leb128.h sha1.h \
 ZipArchive.h SysUtil.h
DexInlines.o: DexInlines.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 DexCatch.h Leb128.h DexClass.h DexDataMap.h DexUtf.h DexOpcodes.h \
 DexProto.h InstrUtils.h ZipArchive.h SysUtil.h
DexOpcodes.o: DexOpcodes.cpp DexOpcodes.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
DexOptData.o: DexOptData.cpp DexOptData.h ../libdex/DexFile.h \
 ../vm/Common.h ../libdex/SysUtil.h
DexProto.o: DexProto.cpp DexProto.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
DexSwapVerify.o: DexSwapVerify.cpp DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h DexClass.h Leb128.h DexDataMap.h DexProto.h DexUtf.h
DexUtf.o: DexUtf.cpp DexUtf.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
InstrUtils.o: InstrUtils.cpp InstrUtils.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h DexOpcodes.h
Leb128.o: Leb128.cpp Leb128.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
OptInvocation.o: OptInvocation.cpp ../vm/DalvikVersion.h OptInvocation.h \
 DexFile.h ../vm/Common.h ../libdex/SysUtil.h
sha1.o: sha1.cpp sha1.h DexFile.h ../vm/Common.h ../libdex/SysUtil.h
SysUtil.o: SysUtil.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 SysUtil.h
ZipArchive.o: ZipArchive.cpp ZipArchive.h SysUtil.h DexFile.h \
 ../vm/Common.h ../libdex/SysUtil.h
