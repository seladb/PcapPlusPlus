ifeq ($(wildcard ../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../mk/platform.mk

SOURCES := $(wildcard src/*.cpp)
OBJS_FILENAMES := $(patsubst src/%.cpp,Obj/%.o,$(SOURCES))

COMMONPP_HOME := ../Common++
PACKETPP_HOME := ../Packet++
LIGHT_PCAPNG_PCPP_HOME := ../3rdParty/LightPcapNg
LIGHT_PCAPNG_HOME := $(LIGHT_PCAPNG_PCPP_HOME)/LightPcapNg

LIGHT_PCAPNG_SOURCES := $(wildcard $(LIGHT_PCAPNG_HOME)/src/*.c)
LIGHT_PCAPNG_OBJS_FILENAMES := $(patsubst $(LIGHT_PCAPNG_HOME)/src/%.c,$(LIGHT_PCAPNG_PCPP_HOME)/Obj/%.o,$(LIGHT_PCAPNG_SOURCES))

ifdef WIN32
DEPS := -DWPCAP -DHAVE_REMOTE -DHAVE_STRUCT_TIMESPEC
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

INCLUDES := -I"./src" \
			-I"./header" \
			-I"$(COMMONPP_HOME)/header" \
			-I"$(PACKETPP_HOME)/header" \
			-I"$(LIGHT_PCAPNG_HOME)/include"
			
ifdef WIN32
INCLUDES += -I$(MINGW_HOME)/include/ddk \
			-I$(WINPCAP_HOME)/Include
endif
ifdef LINUX
INCLUDES += -I/usr/include/netinet
endif
ifdef PF_RING_HOME
INCLUDES += -I$(PF_RING_HOME)/userland/lib -I$(PF_RING_HOME)/kernel
endif
ifdef USE_DPDK
INCLUDES += -I"$(RTE_SDK)/$(RTE_TARGET)/include"
endif


ifdef USE_DPDK
FLAGS := -msse -msse2 -msse3 -mssse3
endif		
	
Obj/%.o: src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(DEPS) $(INCLUDES) $(FLAGS) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

# All Target
all: Pcap++.lib

create-directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Lib

# Tool invocations
Pcap++.lib: create-directories $(OBJS_FILENAMES)
	cd $(LIGHT_PCAPNG_PCPP_HOME) && $(MAKE) light_pcapng_sources
	@echo 'Building target: $@'
	@echo 'Invoking: GCC Archiver'
	$(AR) -r  "Lib/$(LIB_PREFIX)Pcap++$(LIB_EXT)" $(OBJS_FILENAMES) $(LIGHT_PCAPNG_OBJS_FILENAMES)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean:
	cd $(LIGHT_PCAPNG_PCPP_HOME) && $(MAKE) clean
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Lib/*
	@echo 'Clean finished'
