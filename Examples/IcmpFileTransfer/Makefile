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
	$(G++) $(PCAPPP_INCLUDES) -O0 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


UNAME := $(shell uname)

# All Target
all: dependents IcmpFileTransfer-pitcher IcmpFileTransfer-catcher

create-directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Bin

dependents:
	cd $(PCAPPLUSPLUS_HOME) && $(MAKE) libs

# Tool invocations
IcmpFileTransfer-pitcher: create-directories $(OBJS_FILENAMES)
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/IcmpFileTransfer-pitcher$(BIN_EXT)" Obj/Common.o Obj/IcmpFileTransfer-pitcher.o $(PCAPPP_LIBS)
	$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '

IcmpFileTransfer-catcher: create-directories $(OBJS_FILENAMES)
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/IcmpFileTransfer-catcher$(BIN_EXT)" Obj/Common.o  Obj/IcmpFileTransfer-catcher.o $(PCAPPP_LIBS)
	$(PCAPPP_POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '


# Other Targets
clean:
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Bin/*
	@echo 'Clean finished'
