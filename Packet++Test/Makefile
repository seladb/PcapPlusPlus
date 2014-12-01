-include ../mk/platform.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

COMMONPP_HOME := ../Common++
PACKTPP_HOME := ../Packet++

ifdef WIN32
DEPS := -DWPCAP -DHAVE_REMOTE
endif

INCLUDES := -I$(PACKTPP_HOME)/header -I../Packet++Test -I$(COMMONPP_HOME)/header
ifdef WIN32
INCLUDES += -I$(WINPCAP_HOME)/Include
endif
ifdef LINUX
INCLUDES += -I/usr/include/netinet
endif
		
		
Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(DEPS) $(INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
	
LIBS_DIR := -L$(PACKTPP_HOME)/Lib -L$(COMMONPP_HOME)/Lib
ifdef WIN32
LIBS_DIR += -L$(WINPCAP_HOME)/lib \
		-L$(MINGW_HOME)/lib
endif

LIBS := -lPacket++ -lCommon++
ifdef WIN32
LIBS += -lwpcap -lpthread -lws2_32
endif
ifdef LINUX
LIBS += -lpcap -lpthread
endif

POST_BUILD :=
ifdef WIN32
POST_BUILD += $(CP) $(MINGW_HOME)/bin/pthreadGC2.dll ./Bin
endif

UNAME := $(shell uname)

# All Target
all: Packet++Test

create-directories:
	@mkdir -p Obj
	@mkdir -p Bin

dependents:
	-cd $(COMMONPP_HOME) && $(MAKE) all
	-cd $(PACKTPP_HOME) && $(MAKE) all

dependents-clean:
	-cd $(COMMONPP_HOME) && $(MAKE) clean
	-cd $(PACKTPP_HOME) && $(MAKE) clean
	
# Tool invocations
Packet++Test: create-directories $(OBJS_FILENAMES) dependents
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(LIBS_DIR) -static-libgcc -static-libstdc++ -o "./Bin/Packet++Test$(BIN_EXT)" $(OBJS_FILENAMES) $(USER_OBJS) $(LIBS)
	$(POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean: dependents-clean
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Bin/*
	@echo 'Clean finished'