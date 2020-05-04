ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

ifeq ($(wildcard ../../mk/PcapPlusPlus.mk),)
  $(error PcapPlusPlus.mk not found! Please run configure script first)
endif

include ../../mk/PcapPlusPlus.mk

ifeq ($(wildcard ../../3rdParty/MemPlumber/Makefile.defs),)
  $(error MemPlumber/Makefile.defs not found!)
endif

include ../../3rdParty/MemPlumber/Makefile.defs

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

COMMON_DEBUG_LIB_DIR := -L../../Common++/Lib/Debug

ENDIAN_PORTABLE_INCLUDE := $(PCAPPLUSPLUS_HOME)/3rdParty/EndianPortable/include

PCPP_TEST_FRAMEWORK := ../PcppTestFramework

PCAPPP_INCLUDES += -I$(MEMPLUMBER_INCLUDES) -I$(ENDIAN_PORTABLE_INCLUDE) -I$(PCPP_TEST_FRAMEWORK)

Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@$(CXX) $(PCAPPP_INCLUDES) $(PCAPPP_BUILD_FLAGS) -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"


UNAME := $(shell uname)
CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

all: dependents Packet++Test

start:
	@echo '==> Building target: $(CUR_TARGET)'

create-directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Bin

dependents:
	@cd $(PCAPPLUSPLUS_HOME) && $(MAKE) libs

Packet++Test: start create-directories $(OBJS_FILENAMES)
	@cd $(MEMPLUMBER_HOME) && $(MAKE) memplumber_sources
	@$(CXX) $(COMMON_DEBUG_LIB_DIR) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/Packet++Test$(BIN_EXT)" $(OBJS_FILENAMES) $(MEMPLUMBER_OBJS_FILENAMES) $(PCAPPP_LIBS)
	@$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '

clean:
	@cd $(MEMPLUMBER_HOME) && $(MAKE) clean
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Bin/*
	@echo 'Clean finished: $(CUR_TARGET)'
