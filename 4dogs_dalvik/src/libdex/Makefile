OUTPUT := ../../lib/
ARFLAGS := cr
CPPFLAGS := -I.. -I../support -I../support/safe-iop -I/usr/include/i386-linux-gnu -Wno-deprecated
CXX := gcc
RM := -rm
RMFLAGS := -rf

OBJECTS = \
	CmdUtils.o \
	DexCatch.o \
	DexClass.o \
	DexDataMap.o \
	DexDebugInfo.o \
	DexFile.o \
	DexInlines.o \
	DexOptData.o \
	DexOpcodes.o \
	DexProto.o \
	DexSwapVerify.o \
	DexUtf.o \
	InstrUtils.o \
	Leb128.o \
	OptInvocation.o \
	sha1.o \
	SysUtil.o \
	ZipArchive.o

libdex.a: $(OBJECTS)
	$(AR) $(ARFLAGS) $(OUTPUT)$@ $<

CmdUtils.o: CmdUtils.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 ZipArchive.h SysUtil.h CmdUtils.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexCatch.o: DexCatch.cpp DexCatch.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h Leb128.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexClass.o: DexClass.cpp DexClass.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h Leb128.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexDataMap.o: DexDataMap.cpp DexDataMap.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexDebugInfo.o: DexDebugInfo.cpp DexDebugInfo.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h DexProto.h Leb128.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexFile.o: DexFile.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 DexOptData.h ../libdex/DexFile.h DexProto.h DexCatch.h Leb128.h sha1.h \
 ZipArchive.h SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexInlines.o: DexInlines.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 DexCatch.h Leb128.h DexClass.h DexDataMap.h DexUtf.h DexOpcodes.h \
 DexProto.h InstrUtils.h ZipArchive.h SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexOpcodes.o: DexOpcodes.cpp DexOpcodes.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexOptData.o: DexOptData.cpp DexOptData.h ../libdex/DexFile.h \
 ../vm/Common.h ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexProto.o: DexProto.cpp DexProto.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexSwapVerify.o: DexSwapVerify.cpp DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h DexClass.h Leb128.h DexDataMap.h DexProto.h DexUtf.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
DexUtf.o: DexUtf.cpp DexUtf.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
InstrUtils.o: InstrUtils.cpp InstrUtils.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h DexOpcodes.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
Leb128.o: Leb128.cpp Leb128.h DexFile.h ../vm/Common.h \
 ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
OptInvocation.o: OptInvocation.cpp ../vm/DalvikVersion.h OptInvocation.h \
 DexFile.h ../vm/Common.h ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
sha1.o: sha1.cpp sha1.h DexFile.h ../vm/Common.h ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
SysUtil.o: SysUtil.cpp DexFile.h ../vm/Common.h ../libdex/SysUtil.h \
 SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
ZipArchive.o: ZipArchive.cpp ZipArchive.h SysUtil.h DexFile.h \
 ../vm/Common.h ../libdex/SysUtil.h
	$(CXX) -o $(OUTPUT)$@ $(CPPFLAGS) -c $<
