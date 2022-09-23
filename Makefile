ifeq ($(wildcard mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include mk/platform.mk

COMMONPP_HOME        := Common++
PACKETPP_HOME        := Packet++
PCAPPP_HOME          := Pcap++
PACKETPP_TEST        := Tests/Packet++Test
PCAPPP_TEST          := Tests/Pcap++Test
FUZZERS_HOME         := Tests/Fuzzers
EXAMPLE_ARPSPOOF     := Examples/ArpSpoofing
EXAMPLE_ARPING       := Examples/Arping
EXAMPLE_DPDK1        := Examples/DpdkExample-FilterTraffic
EXAMPLE_DNSSPOOF     := Examples/DnsSpoofing
EXAMPLE_DNSRESOLVER  := Examples/DNSResolver
EXAMPLE_HTTPANALYZE  := Examples/HttpAnalyzer
EXAMPLE_PF_RING1     := Examples/PfRingExample-FilterTraffic
EXAMPLE_PCAP_PRINT   := Examples/PcapPrinter
EXAMPLE_SSLANALYZER  := Examples/SSLAnalyzer
EXAMPLE_PCAPSPLITTER := Examples/PcapSplitter
EXAMPLE_PCAPSEARCH   := Examples/PcapSearch
EXAMPLE_ICMP_FT      := Examples/IcmpFileTransfer
EXAMPLE_TCP_REASM    := Examples/TcpReassembly
EXAMPLE_IP_FRAG      := Examples/IPFragUtil
EXAMPLE_IP_DEFRAG    := Examples/IPDefragUtil
EXAMPLE_TLS_FP       := Examples/TLSFingerprinting
EXAMPLE_DPDK2        := Examples/DpdkBridge
EXAMPLE_KNI_PONG     := Examples/KniPong
EXAMPLE_UDP_REASM	:= Examples/UdpReassembly
EXAMPLE_GRE_REASM	:= Examples/GreReassembly
EXAMPLE_RIP_REASM	:= Examples/RipReassembly
EXAMPLE_OSPF_REASM	:= Examples/OspfReassembly
EXAMPLE_L2TP_REASM	:= Examples/L2tpReassembly


UNAME := $(shell uname)


.SILENT:

all: libs
	@cd $(PACKETPP_TEST)             && $(MAKE) Packet++Test
	@cd $(PCAPPP_TEST)               && $(MAKE) Pcap++Test
	@cd $(EXAMPLE_ARPSPOOF)          && $(MAKE) ArpSpoofing
	@cd $(EXAMPLE_ARPING)            && $(MAKE) Arping
	@cd $(EXAMPLE_DNSSPOOF)          && $(MAKE) DnsSpoofing
	@cd $(EXAMPLE_DNSRESOLVER)       && $(MAKE) DNSResolver
	@cd $(EXAMPLE_HTTPANALYZE)       && $(MAKE) HttpAnalyzer
	@cd $(EXAMPLE_PCAP_PRINT)        && $(MAKE) PcapPrinter
	@cd $(EXAMPLE_SSLANALYZER)       && $(MAKE) SSLAnalyzer
	@cd $(EXAMPLE_PCAPSPLITTER)      && $(MAKE) PcapSplitter
	@cd $(EXAMPLE_PCAPSEARCH)        && $(MAKE) PcapSearch
	@cd $(EXAMPLE_ICMP_FT)           && $(MAKE) IcmpFileTransfer-pitcher && $(MAKE) IcmpFileTransfer-catcher
	@cd $(EXAMPLE_TCP_REASM)         && $(MAKE) TcpReassembly
	@cd $(EXAMPLE_IP_FRAG)           && $(MAKE) IPFragUtil
	@cd $(EXAMPLE_IP_DEFRAG)         && $(MAKE) IPDefragUtil
	@cd $(EXAMPLE_TLS_FP)            && $(MAKE) TLSFingerprinting

	@cd $(EXAMPLE_UDP_REASM)         && $(MAKE) UdpReassembly
	@cd $(EXAMPLE_GRE_REASM)         && $(MAKE) GreReassembly
	@cd $(EXAMPLE_RIP_REASM)         && $(MAKE) RipReassembly
	@cd $(EXAMPLE_OSPF_REASM)         && $(MAKE) OspfReassembly
	@cd $(EXAMPLE_L2TP_REASM)         && $(MAKE) L2tpReassembly

ifdef USE_DPDK
	@cd $(EXAMPLE_DPDK1)             && $(MAKE) DpdkTrafficFilter
	@cd $(EXAMPLE_DPDK2)             && $(MAKE) DpdkBridge
	@cd $(EXAMPLE_KNI_PONG)          && $(MAKE) KniPong
endif
ifdef PF_RING_HOME
	@cd $(EXAMPLE_PF_RING1)          && $(MAKE) PfRingTrafficFilter
endif
	@$(MKDIR) -p Dist/examples
	$(CP) $(EXAMPLE_ARPSPOOF)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_ARPING)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_DNSSPOOF)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_DNSRESOLVER)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_HTTPANALYZE)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PCAP_PRINT)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_SSLANALYZER)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PCAPSPLITTER)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_PCAPSEARCH)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_ICMP_FT)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_TCP_REASM)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_IP_FRAG)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_IP_DEFRAG)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_TLS_FP)/Bin/* ./Dist/examples

	$(CP) $(EXAMPLE_UDP_REASM)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_GRE_REASM)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_RIP_REASM)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_OSPF_REASM)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_L2TP_REASM)/Bin/* ./Dist/examples

ifdef USE_DPDK
	$(CP) $(EXAMPLE_DPDK1)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_DPDK2)/Bin/* ./Dist/examples
	$(CP) $(EXAMPLE_KNI_PONG)/Bin/* ./Dist/examples
endif
ifdef PF_RING_HOME
	$(CP) $(EXAMPLE_PF_RING1)/Bin/* ./Dist/examples
endif
	@echo Finished successfully building PcapPlusPlus

# PcapPlusPlus libs only
libs:
	@$(RM) -rf Dist
	@cd $(COMMONPP_HOME)             && $(MAKE) all
	@cd $(PACKETPP_HOME)             && $(MAKE) all
	@cd $(PCAPPP_HOME)               && $(MAKE) all
	@$(MKDIR) -p Dist
	@$(MKDIR) -p Dist/header
	@$(CP) $(COMMONPP_HOME)/Lib/Release/* ./Dist
	@$(CP) $(PACKETPP_HOME)/Lib/* ./Dist
	@$(CP) $(PCAPPP_HOME)/Lib/* ./Dist
	@$(CP) $(COMMONPP_HOME)/header/* ./Dist/header
	@$(CP) $(PACKETPP_HOME)/header/* ./Dist/header
	@$(CP) $(PCAPPP_HOME)/header/* ./Dist/header
	@$(MKDIR) -p Dist/mk
	$(CP) mk/PcapPlusPlus.mk ./Dist/mk
	@echo Finished successfully building PcapPlusPlus libs
	@echo ' '

# PcapPlusPlus with fuzzers
fuzzers: libs
	@cd $(FUZZERS_HOME)              && $(MAKE)

# Clean
clean:
	@cd $(COMMONPP_HOME)             && $(MAKE) clean
	@cd $(PACKETPP_HOME)             && $(MAKE) clean
	@cd $(PCAPPP_HOME)               && $(MAKE) clean
	@cd $(PACKETPP_TEST)             && $(MAKE) clean
	@cd $(PCAPPP_TEST)               && $(MAKE) clean
	@cd $(EXAMPLE_ARPSPOOF)          && $(MAKE) clean
	@cd $(EXAMPLE_ARPING)            && $(MAKE) clean
	@cd $(EXAMPLE_DNSSPOOF)          && $(MAKE) clean
	@cd $(EXAMPLE_DNSRESOLVER)       && $(MAKE) clean
	@cd $(EXAMPLE_HTTPANALYZE)       && $(MAKE) clean
	@cd $(EXAMPLE_PCAP_PRINT)        && $(MAKE) clean
	@cd $(EXAMPLE_SSLANALYZER)       && $(MAKE) clean
	@cd $(EXAMPLE_PCAPSPLITTER)      && $(MAKE) clean
	@cd $(EXAMPLE_PCAPSEARCH)        && $(MAKE) clean
	@cd $(EXAMPLE_ICMP_FT)           && $(MAKE) clean
	@cd $(EXAMPLE_TCP_REASM)         && $(MAKE) clean
	@cd $(EXAMPLE_IP_FRAG)           && $(MAKE) clean
	@cd $(EXAMPLE_IP_DEFRAG)         && $(MAKE) clean
	@cd $(EXAMPLE_TLS_FP)            && $(MAKE) clean
	@cd $(FUZZERS_HOME)              && $(MAKE) clean

	@cd $(EXAMPLE_UDP_REASM)         && $(MAKE) clean
	@cd $(EXAMPLE_GRE_REASM)         && $(MAKE) clean
	@cd $(EXAMPLE_RIP_REASM)         && $(MAKE) clean
	@cd $(EXAMPLE_OSPF_REASM)         && $(MAKE) clean
	@cd $(EXAMPLE_L2TP_REASM)         && $(MAKE) clean

ifdef USE_DPDK
	@cd $(EXAMPLE_DPDK1)             && $(MAKE) clean
	@cd $(EXAMPLE_DPDK2)             && $(MAKE) clean
	@cd $(EXAMPLE_KNI_PONG)          && $(MAKE) clean
endif
ifdef PF_RING_HOME
	@cd $(EXAMPLE_PF_RING1)          && $(MAKE) clean
endif

	@$(RM) -rf Dist
	@echo Finished successfully cleaning PcapPlusPlus

ifndef WIN32
INSTALL_DIR=Dist

# Install
install: | $(INSTALL_DIR)
	@cd Dist && ../mk/$(INSTALL_SCRIPT)
	@echo 'Installation complete!'

# Uninstall
uninstall: | $(INSTALL_DIR)
	@cd Dist && ../mk/$(UNINSTALL_SCRIPT)
	@echo 'Uninstallation complete!'

$(INSTALL_DIR):
	@echo 'Please run make all first' && exit 1

endif
