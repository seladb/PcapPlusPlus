-include ../../Dist/mk/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o ArpSpoofing main.o $(PCAPPP_LIBS)
	$(PCAPPP_POST_BUILD)

# Clean Target
clean:
	rm main.o
	rm ArpSpoofing
