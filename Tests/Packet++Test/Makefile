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

COMMON_DEBUG_LIB_DIR := -L../../Common++/Lib/Debug

DEBUG_NEW_HOME := ../../3rdParty/debug-new
DEBUG_NEW_SOURCES := $(wildcard $(DEBUG_NEW_HOME)/*.cpp)
DEBUG_NEW_OBJS_FILENAMES := $(patsubst %.cpp,$(DEBUG_NEW_HOME)/%.o,$(DEBUG_NEW_SOURCES))
PCAPPP_INCLUDES += -I$(DEBUG_NEW_HOME)

Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@$(G++) $(PCAPPP_INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"


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
	@cd $(DEBUG_NEW_HOME) && $(MAKE) debug_new_sources
	@$(G++) $(COMMON_DEBUG_LIB_DIR) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/Packet++Test$(BIN_EXT)" $(OBJS_FILENAMES) $(DEBUG_NEW_OBJS_FILENAMES) $(PCAPPP_LIBS) 
	@$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '

clean:
	@cd $(DEBUG_NEW_HOME) && $(MAKE) clean
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Bin/*
	@echo 'Clean finished: $(CUR_TARGET)'
