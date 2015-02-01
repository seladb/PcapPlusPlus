-include ../mk/platform.mk

SOURCES := $(wildcard src/*.cpp)
OBJS_FILENAMES := $(patsubst src/%.cpp,Obj/%.o,$(SOURCES))

COMMONPP_HOME := ../Common++
PACKETPP_HOME := ../Packet++

ifdef WIN32
DEPS := -DWPCAP -DHAVE_REMOTE
endif
ifdef PF_RING_HOME
DEPS := -DUSE_PF_RING
endif

INCLUDES := -I"./src" \
			-I"./header" \
			-I"$(COMMONPP_HOME)/header" \
			-I"$(PACKETPP_HOME)/header"
			
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
			
Obj/%.o: src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(DEPS) $(INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

# All Target
all: Pcap++.lib

create-directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Lib

# Tool invocations
Pcap++.lib: create-directories $(OBJS_FILENAMES)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC Archiver'
	$(AR) -r  "Lib/$(LIB_PREFIX)Pcap++$(LIB_EXT)" $(OBJS_FILENAMES)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean:
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Lib/*
	@echo 'Clean finished'