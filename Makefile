-include mk/platform.mk

COMMONPP_HOME 	:=	Common++
PACKETPP_HOME 	:=	Packet++
PCAPPP_HOME 	:=	Pcap++
PACKETPP_TEST	:=	Packet++Test
PCAPPP_TEST		:=	Pcap++Test
EXAMPLE_PARSE	:=	Examples/Pcap++Examples.PacketParsing
EXAMPLE_STREAMS	:=	Examples/Pcap++Examples.BreakPcapFileToStreams
EXAMPLE_ARPSPOOF := Examples/Pcap++Examples.ArpSpoofing

UNAME := $(shell uname)

# capPlusPlus libs only
libs:
	$(RM) -rf Dist
	cd $(COMMONPP_HOME)		&& $(MAKE) all
	cd $(PACKETPP_HOME)		&& $(MAKE) all
	cd $(PCAPPP_HOME)		&& $(MAKE) all
	$(MKDIR) -p Dist
	$(MKDIR) -p Dist/header
	$(MKDIR) -p Dist/examples
	$(CP) $(COMMONPP_HOME)/Lib/* ./Dist
	$(CP) $(PACKETPP_HOME)/Lib/* ./Dist
	$(CP) $(PCAPPP_HOME)/Lib/* ./Dist
	$(CP) $(COMMONPP_HOME)/header/* ./Dist/header
	$(CP) $(PACKETPP_HOME)/header/* ./Dist/header
	$(CP) $(PCAPPP_HOME)/header/* ./Dist/header
	@echo 'Finished successfully building PcapPlusPlus libs'

# All Target
all: libs
	cd $(PACKETPP_TEST)		&& $(MAKE) all
	cd $(PCAPPP_TEST)		&& $(MAKE) all
	cd $(EXAMPLE_PARSE)		&& $(MAKE) all
	cd $(EXAMPLE_STREAMS)		&& $(MAKE) all
	cd $(EXAMPLE_ARPSPOOF)		&& $(MAKE) all
	$(CP) $(EXAMPLE_PARSE)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PARSE)/UdpPacket.dat ./Dist/examples
	$(CP) $(EXAMPLE_STREAMS)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_STREAMS)/example.pcap ./Dist/examples
	$(CP) $(EXAMPLE_ARPSPOOF)/Bin/* ./Dist/examples
	@echo 'Finished successfully building PcapPlusPlus'

# Clean
clean:
	cd $(COMMONPP_HOME)		&& $(MAKE) clean
	cd $(PACKETPP_HOME)		&& $(MAKE) clean
	cd $(PCAPPP_HOME)		&& $(MAKE) clean
	cd $(PACKETPP_TEST)		&& $(MAKE) clean
	cd $(PCAPPP_TEST)		&& $(MAKE) clean
	cd $(EXAMPLE_PARSE)		&& $(MAKE) clean
	cd $(EXAMPLE_STREAMS)	&& $(MAKE) clean
	cd $(EXAMPLE_ARPSPOOF)	&& $(MAKE) clean
	$(RM) -rf Dist
	@echo 'Finished successfully cleaning PcapPlusPlus'
