-include mk/platform.mk

COMMONPP_HOME        := Common++
PACKETPP_HOME        := Packet++
PCAPPP_HOME          := Pcap++
PACKETPP_TEST        := Packet++Test
PCAPPP_TEST          := Pcap++Test
EXAMPLE_PARSE        := Examples/Pcap++Examples.PacketParsing
EXAMPLE_STREAMS      := Examples/Pcap++Examples.BreakPcapFileToStreams
EXAMPLE_ARPSPOOF     := Examples/ArpSpoofing
EXAMPLE_ARPING       := Examples/Arping
EXAMPLE_DPDK1        := Examples/DpdkExample-FilterTraffic
EXAMPLE_DNSSPOOF     := Examples/DnsSpoofing
EXAMPLE_DNSRESOLVER  := Examples/DNSResolver
EXAMPLE_HTTPANALYZE  := Examples/HttpAnalyzer
EXAMPLE_PF_RING1     := Examples/PfRingExample-FilterTraffic
EXAMPLE_PCAP_PRINT   := Examples/PcapPrinter
EXAMPLE_SSLANALYZER  := Examples/SSLAnalyzer


UNAME := $(shell uname)

# capPlusPlus libs only
libs:
	$(RM) -rf Dist
	cd $(COMMONPP_HOME)             && $(MAKE) all
	cd $(PACKETPP_HOME)             && $(MAKE) all
	cd $(PCAPPP_HOME)               && $(MAKE) all
	$(MKDIR) -p Dist
	$(MKDIR) -p Dist/header
	$(CP) $(COMMONPP_HOME)/Lib/Release/* ./Dist
	$(CP) $(PACKETPP_HOME)/Lib/* ./Dist
	$(CP) $(PCAPPP_HOME)/Lib/* ./Dist
	$(CP) $(COMMONPP_HOME)/header/* ./Dist/header
	$(CP) $(PACKETPP_HOME)/header/* ./Dist/header
	$(CP) $(PCAPPP_HOME)/header/* ./Dist/header
	@echo 'Finished successfully building PcapPlusPlus libs'

# All Target
all: libs
	cd $(PACKETPP_TEST)             && $(MAKE) Packet++Test
	cd $(PCAPPP_TEST)               && $(MAKE) Pcap++Test
	cd $(EXAMPLE_PARSE)             && $(MAKE) Pcap++Examples.PacketParsing
	cd $(EXAMPLE_STREAMS)           && $(MAKE) Pcap++Examples.BreakPcapFileToStreams
	cd $(EXAMPLE_ARPSPOOF)          && $(MAKE) ArpSpoofing
	cd $(EXAMPLE_ARPING)            && $(MAKE) Arping
	cd $(EXAMPLE_DNSSPOOF)          && $(MAKE) DnsSpoofing
	cd $(EXAMPLE_DNSRESOLVER)       && $(MAKE) DNSResolver
	cd $(EXAMPLE_HTTPANALYZE)       && $(MAKE) HttpAnalyzer
	cd $(EXAMPLE_PCAP_PRINT)		&& $(MAKE) PcapPrinter
	cd $(EXAMPLE_SSLANALYZER)		&& $(MAKE) SSLAnalyzer
ifdef USE_DPDK
	cd $(EXAMPLE_DPDK1)             && $(MAKE) DpdkTrafficFilter
endif
ifdef PF_RING_HOME
	cd $(EXAMPLE_PF_RING1)          && $(MAKE) PfRingTrafficFilter
endif
	$(MKDIR) -p Dist/examples
	$(MKDIR) -p Dist/mk
	$(CP) $(EXAMPLE_PARSE)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PARSE)/UdpPacket.dat ./Dist/examples
	$(CP) $(EXAMPLE_STREAMS)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_STREAMS)/example.pcap ./Dist/examples
	$(CP) $(EXAMPLE_ARPSPOOF)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_ARPING)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_DNSSPOOF)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_DNSRESOLVER)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_HTTPANALYZE)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PCAP_PRINT)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_SSLANALYZER)/Bin/* ./Dist/examples
ifdef USE_DPDK
	$(CP) $(EXAMPLE_DPDK1)/Bin/* ./Dist/examples
endif
ifdef PF_RING_HOME
	$(CP) $(EXAMPLE_PF_RING1)/Bin/* ./Dist/examples
endif
	$(CP) mk/platform.mk ./Dist/mk
	$(CP) mk/PcapPlusPlus.mk ./Dist/mk
	@echo 'Finished successfully building PcapPlusPlus'

# Clean
clean:
	cd $(COMMONPP_HOME)             && $(MAKE) clean
	cd $(PACKETPP_HOME)             && $(MAKE) clean
	cd $(PCAPPP_HOME)               && $(MAKE) clean
	cd $(PACKETPP_TEST)             && $(MAKE) clean
	cd $(PCAPPP_TEST)               && $(MAKE) clean
	cd $(EXAMPLE_PARSE)             && $(MAKE) clean
	cd $(EXAMPLE_STREAMS)           && $(MAKE) clean
	cd $(EXAMPLE_ARPSPOOF)          && $(MAKE) clean
	cd $(EXAMPLE_ARPING)            && $(MAKE) clean
	cd $(EXAMPLE_DNSSPOOF)          && $(MAKE) clean
	cd $(EXAMPLE_DNSRESOLVER)       && $(MAKE) clean
	cd $(EXAMPLE_HTTPANALYZE)       && $(MAKE) clean
	cd $(EXAMPLE_PCAP_PRINT)        && $(MAKE) clean
	cd $(EXAMPLE_SSLANALYZER)       && $(MAKE) clean	
ifdef USE_DPDK
	cd $(EXAMPLE_DPDK1)             && $(MAKE) clean
endif
ifdef PF_RING_HOME
	cd $(EXAMPLE_PF_RING1)          && $(MAKE) clean
endif

	$(RM) -rf Dist
	@echo 'Finished successfully cleaning PcapPlusPlus'
