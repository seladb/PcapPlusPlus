-include ../mk/platform.mk

SOURCES := $(wildcard ./src/*.cpp)
OBJS_FILENAMES := $(patsubst ./src/%.cpp,%.o,$(SOURCES))
OBJS := $(patsubst ./src/%.cpp,./Obj/%.o,$(SOURCES))

COMMONPP_HOME := ../Common++
PACKETPP_HOME := ../Packet++

ifdef WIN32
DEPS := -DWPCAP -DHAVE_REMOTE
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
			
$(OBJS_FILENAMES):
	@echo 'Building file: $(@:%.o=./src/%.cpp)'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(DEPS) $(INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=./Obj/%.d)" -MT"$(@:%.o=./Obj/%.d)" -o "./Obj/$@" "$(@:%.o=./src/%.cpp)"
	@echo 'Finished building: $(@:%.o=./src/%.cpp)'
	@echo ' '

# All Target
all: Pcap++.lib

# Tool invocations
Pcap++.lib: $(OBJS_FILENAMES)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC Archiver'
	$(AR) -r  "Lib/$(LIB_PREFIX)Pcap++$(LIB_EXT)" $(OBJS)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean:
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Lib/*
	@echo 'Clean finished'