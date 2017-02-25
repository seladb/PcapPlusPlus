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

DEBUG_NEW_HOME := ../../3rdParty/debug-new
DEBUG_NEW_SOURCES := $(wildcard $(DEBUG_NEW_HOME)/*.cpp)
DEBUG_NEW_OBJS_FILENAMES := $(patsubst %.cpp,$(DEBUG_NEW_HOME)/%.o,$(DEBUG_NEW_SOURCES))
PCAPPP_INCLUDES += -I$(DEBUG_NEW_HOME)

ifdef WIN32
DEPS := -DHAVE_STRUCT_TIMESPEC
endif
ifdef LINUX
DEPS := -DLINUX
endif
ifdef PF_RING_HOME
DEPS += -DUSE_PF_RING
endif
ifdef USE_DPDK
DEPS += -DUSE_DPDK
endif
ifdef MAC_OS_X
DEPS := -DMAC_OS_X
endif

COMMON_DEBUG_LIB_DIR := -L../../Common++/Lib/Debug

Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(DEPS) $(PCAPPP_INCLUDES) $(PCAPPP_BUILD_FLAGS) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
	

UNAME := $(shell uname)

# All Target
all: dependents Pcap++Test

create-directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Bin

dependents:
	cd $(PCAPPLUSPLUS_HOME) && $(MAKE) libs
	
# Tool invocations
Pcap++Test: create-directories $(OBJS_FILENAMES)
	cd $(DEBUG_NEW_HOME) && $(MAKE) debug_new_sources
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(COMMON_DEBUG_LIB_DIR) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/Pcap++Test$(BIN_EXT)" $(OBJS_FILENAMES) $(DEBUG_NEW_OBJS_FILENAMES) $(PCAPPP_LIBS)
	$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean:
	cd $(DEBUG_NEW_HOME) && $(MAKE) clean
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Bin/*
	@echo 'Clean finished'
