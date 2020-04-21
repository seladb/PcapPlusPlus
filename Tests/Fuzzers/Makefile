PCAPPP_BUILD_DIR := ../../Dist
PCAPPP_INCLUDES := -I$(PCAPPP_BUILD_DIR)/header
PCAPPP_LIBS_DIR := -L$(PCAPPP_BUILD_DIR)
PCAPPP_LIBS := -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread

include ../../mk/platform.mk

CUR_TARGET := $(notdir $(shell pwd))

all:
	@mkdir -p Bin
	@clang++ -O0 -g -fsanitize=fuzzer,address $(PCAPPP_LIBS_DIR) $(PCAPPP_INCLUDES) -o Bin/fuzz_target fuzz_target.cc $(PCAPPP_LIBS)

clean:
	 @$(RM) -rf fuzz_target
	 @echo 'Clean finished: $(CUR_TARGET)'
