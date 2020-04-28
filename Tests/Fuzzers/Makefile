include ../../mk/platform.mk
include ../../mk/PcapPlusPlus.mk

PCAPPP_BUILD_DIR := ../../Dist
PCAPPP_INCLUDES += -I$(PCAPPP_BUILD_DIR)/header
PCAPPP_LIBS_DIR += -L$(PCAPPP_BUILD_DIR)
PCAPPP_LIBS += -lPcap++ -lPacket++ -lCommon++ -lpthread


CUR_TARGET := $(notdir $(shell pwd))


all:
	@echo '==> Building target: $(CUR_TARGET)'
	@mkdir -p Bin
	@$(CXX) $(PCAPPP_BUILD_FLAGS) $(LIB_FUZZING_ENGINE) $(PCAPPP_LIBS_DIR) $(PCAPPP_INCLUDES) -o Bin/FuzzTarget FuzzTarget.cpp $(PCAPPP_LIBS)
	@echo 'Finished successfully building: $(CUR_TARGET)'

clean:
	 @$(RM) -rf Bin
	 @echo 'Clean finished: $(CUR_TARGET)'
