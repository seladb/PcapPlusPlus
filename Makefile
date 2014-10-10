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

# All Target
all:
	-cd $(COMMONPP_HOME)	&& $(MAKE) all
	-cd $(PACKETPP_HOME)	&& $(MAKE) all
	-cd $(PCAPPP_HOME)		&& $(MAKE) all
	-cd $(PACKETPP_TEST)	&& $(MAKE) all
	-cd $(PCAPPP_TEST)		&& $(MAKE) all
	-cd $(EXAMPLE_PARSE)	&& $(MAKE) all
	-cd $(EXAMPLE_STREAMS)	&& $(MAKE) all
	-cd $(EXAMPLE_ARPSPOOF)	&& $(MAKE) all

# Clean
clean:
	-cd $(COMMONPP_HOME)	&& $(MAKE) clean
	-cd $(PACKETPP_HOME)	&& $(MAKE) clean
	-cd $(PCAPPP_HOME)		&& $(MAKE) clean
	-cd $(PACKETPP_TEST)	&& $(MAKE) clean
	-cd $(PCAPPP_TEST)		&& $(MAKE) clean
	-cd $(EXAMPLE_PARSE)	&& $(MAKE) clean
	-cd $(EXAMPLE_STREAMS)	&& $(MAKE) clean
	-cd $(EXAMPLE_ARPSPOOF)	&& $(MAKE) clean
