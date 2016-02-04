-include ../mk/platform.mk
-include ../mk/PcapPlusPlus.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

COMMON_DEBUG_LIB := ../Common++/Lib/Debug
PACKET_LIB := ../Packet++/Lib
PCAP_LIB := ../Pcap++/Lib

Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(PCAPPP_INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


UNAME := $(shell uname)

# All Target
all: Packet++Test

create-directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Bin

dependents:
	cd $(PCAPPLUSPLUS_HOME) && $(MAKE) libs

# Tool invocations
Packet++Test: create-directories dependents $(OBJS_FILENAMES)
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(PCAPPP_BUILD_FLAGS) -L$(COMMON_DEBUG_LIB) -L$(PACKET_LIB) -L$(PCAP_LIB) -o "./Bin/Packet++Test$(BIN_EXT)" $(OBJS_FILENAMES) $(PCAPPP_LIBS) 
	$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean:
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Bin/*
	@echo 'Clean finished'
