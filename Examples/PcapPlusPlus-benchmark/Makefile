include ../../mk/platform.mk
include ../../mk/PcapPlusPlus.mk

all:
	$(G++) $(PCAPPP_INCLUDES) -std=c++0x -c -o benchmark.o benchmark.cpp
	$(G++) $(PCAPPP_LIBS_DIR) -static-libstdc++ -o benchmark benchmark.o $(PCAPPP_LIBS)
	$(PCAPPP_POST_BUILD)

clean:
	$(RM) benchmark.o
	$(RM) benchmark
