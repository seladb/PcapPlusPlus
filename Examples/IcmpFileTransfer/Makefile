ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif
ifeq ($(wildcard ../../mk/PcapPlusPlus.mk),)
  $(error PcapPlusPlus.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk
include ../../mk/PcapPlusPlus.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@$(G++) $(PCAPPP_INCLUDES) -O0 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"


UNAME := $(shell uname)
CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

all: dependents IcmpFileTransfer-pitcher IcmpFileTransfer-catcher

start:
	@echo '==> Building target: $(CUR_TARGET)'

create-directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Bin

dependents:
	@cd $(PCAPPLUSPLUS_HOME) && $(MAKE) libs

IcmpFileTransfer-pitcher: start create-directories $(OBJS_FILENAMES)
	@$(G++) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/IcmpFileTransfer-pitcher$(BIN_EXT)" Obj/Common.o Obj/IcmpFileTransfer-pitcher.o $(PCAPPP_LIBS)
	@$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '

IcmpFileTransfer-catcher: start create-directories $(OBJS_FILENAMES)
	@$(G++) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/IcmpFileTransfer-catcher$(BIN_EXT)" Obj/Common.o  Obj/IcmpFileTransfer-catcher.o $(PCAPPP_LIBS)
	@$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '

clean:
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Bin/*
	@echo 'Clean finished: $(CUR_TARGET)'
