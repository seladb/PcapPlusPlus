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
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(PCAPPP_INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


UNAME := $(shell uname)

# All Target
all: dependents Pcap++Examples.PacketParsing

create-directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Bin

dependents:
	cd $(PCAPPLUSPLUS_HOME) && $(MAKE) libs

# Tool invocations
Pcap++Examples.PacketParsing: create-directories $(OBJS_FILENAMES)
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/Pcap++Examples.PacketParsing$(BIN_EXT)" $(OBJS_FILENAMES) $(PCAPPP_LIBS)
	$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean:
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Bin/*
	@echo 'Clean finished'
