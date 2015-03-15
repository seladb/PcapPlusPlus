-include ../mk/platform.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

COMMONPP_HOME := ../Common++
PACKETPP_HOME := ../Packet++
PCAPP_HOME := ../Pcap++

ifdef WIN32
DEPS := -DWPCAP -DHAVE_REMOTE
endif
ifdef PF_RING_HOME
DEPS := -DUSE_PF_RING
endif

INCLUDES := -I$(PCAPP_HOME)/header -I$(PACKETPP_HOME)/header -I$(COMMONPP_HOME)/header -I../Pcap++Test
ifdef WIN32
INCLUDES += -I$(WINPCAP_HOME)/Include
endif
ifdef LINUX
INCLUDES += -I/usr/include/netinet
endif
ifdef PF_RING_HOME
INCLUDES += -I$(PF_RING_HOME)/userland/lib -I$(PF_RING_HOME)/kernel
endif		
		
Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(DEPS) $(INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
	
LIBS_DIR := -L$(PCAPP_HOME)/Lib -L$(PACKETPP_HOME)/Lib -L$(COMMONPP_HOME)/Lib
ifdef WIN32
LIBS_DIR += -L$(WINPCAP_HOME)/lib \
		-L$(MINGW_HOME)/lib
endif
ifdef PF_RING_HOME
LIBS_DIR += -L$(PF_RING_HOME)/userland/lib
endif

LIBS := -lPcap++ -lPacket++ -lCommon++
ifdef WIN32
LIBS += -lwpcap -lPacket -lpthread -lws2_32
endif
ifdef LINUX
LIBS += -lpcap -lpthread
endif
ifdef PF_RING_HOME
LIBS += -Wl,-Bstatic -lpfring -lnuma -lrt
endif

POST_BUILD :=
ifdef WIN32
POST_BUILD += $(CP) $(MINGW_HOME)/bin/pthreadGC2.dll ./Bin
endif

UNAME := $(shell uname)

# All Target
all: Pcap++Test

create-directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Bin

dependents:
	cd $(COMMONPP_HOME) && $(MAKE) all
	cd $(PACKETPP_HOME) && $(MAKE) all
	cd $(PCAPP_HOME) && $(MAKE) all

dependents-clean:
	cd $(COMMONPP_HOME) && $(MAKE) clean
	cd $(PACKETPP_HOME) && $(MAKE) clean
	cd $(PCAPP_HOME) && $(MAKE) clean
	
# Tool invocations
Pcap++Test: create-directories $(OBJS_FILENAMES) dependents
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(LIBS_DIR) -static-libgcc -static-libstdc++ -o "./Bin/Pcap++Test$(BIN_EXT)" $(OBJS_FILENAMES) $(USER_OBJS) $(LIBS)
	$(POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean: dependents-clean
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Bin/*
	@echo 'Clean finished'