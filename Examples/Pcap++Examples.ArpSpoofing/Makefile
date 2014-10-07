-include ../../mk/platform.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,%.o,$(SOURCES))
OBJS := $(patsubst %.cpp,./Obj/%.o,$(SOURCES))

COMMONPP_HOME := ../../Common++
PACKETPP_HOME := ../../Packet++
PCAPP_HOME := ../../Pcap++

ifdef WIN32
DEPS := -DWPCAP -DHAVE_REMOTE
endif

INCLUDES := -I$(PCAPP_HOME)/header -I$(PACKETPP_HOME)/header -I$(COMMONPP_HOME)/header
ifdef WIN32
INCLUDES += -I$(WINPCAP_HOME)/Include
endif
ifdef LINUX
INCLUDES += -I/usr/include/netinet
endif
		
		
$(OBJS_FILENAMES):
	@echo 'Building file: $(@:%.o=%.cpp)'
	@echo 'Invoking: GCC C++ Compiler'
	$(G++) $(DEPS) $(INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=./Obj/%.d)" -MT"$(@:%.o=./Obj/%.d)" -o "./Obj/$@" "$(@:%.o=%.cpp)"
	@echo 'Finished building: $(@:%.o=%.cpp)'
	@echo ' '

LIBS_DIR := -L$(PCAPP_HOME)/Lib -L$(PACKETPP_HOME)/Lib -L$(COMMONPP_HOME)/Lib
ifdef WIN32
LIBS_DIR += -L$(WINPCAP_HOME)/lib \
		-L$(MINGW_HOME)/lib
endif

LIBS := -lPcap++ -lPacket++ -lCommon++
ifdef WIN32
LIBS += -lwpcap -lPacket -lpthread -lws2_32
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
all: Pcap++Examples.ArpSpoofing

dependents:
	-cd $(COMMONPP_HOME) && $(MAKE) all
	-cd $(PACKETPP_HOME) && $(MAKE) all
	-cd $(PCAPP_HOME) && $(MAKE) all

dependents-clean:
	-cd $(COMMONPP_HOME) && $(MAKE) clean
	-cd $(PACKETPP_HOME) && $(MAKE) clean
	-cd $(PCAPP_HOME) && $(MAKE) clean
	
# Tool invocations
Pcap++Examples.ArpSpoofing: $(OBJS_FILENAMES) dependents
	@echo uname is: $(UNAME)
	@echo 'Building target: $@'
	@echo 'Invoking C++ Linker'
	$(G++) $(LIBS_DIR) -static-libgcc -static-libstdc++ -o "./Bin/Pcap++Examples.ArpSpoofing$(BIN_EXT)" $(OBJS) $(USER_OBJS) $(LIBS)
	$(POST_BUILD)
	@echo 'Finished successfully building target: $@'
	@echo ' '

# Other Targets
clean: dependents-clean
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Bin/*
	@echo 'Clean finished'