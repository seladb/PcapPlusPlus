include /usr/local/etc/PcapPlusPlus.mk

all:
	g++ $(PCAPPP_INCLUDES) -O2 -std=c++0x -c -o benchmark.o benchmark.cpp
	g++ $(PCAPPP_LIBS_DIR) -o benchmark benchmark.o $(PCAPPP_LIBS)

clean:
	rm benchmark.o
	rm benchmark
