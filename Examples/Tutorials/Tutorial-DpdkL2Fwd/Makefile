include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) -c $(PCAPPP_INCLUDES) -c -o WorkerThread.o WorkerThread.cpp
	g++ $(PCAPPP_BUILD_FLAGS) -c $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o Tutorial-DpdkL2Fwd WorkerThread.o main.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm main.o
	rm WorkerThread.o
	rm Tutorial-DpdkL2Fwd
