#include <Logger.h>
#include <Packet.h>
#include <PcapFileDevice.h>

#include <benchmark/benchmark.h>

#include <iostream>
#include <string>
#include <unordered_map>

static std::string pcapFileName = "pcap_examples/example_copy.pcap";

static void BM_PcapFileRead(benchmark::State &state)
{
	// Open the pcap file for reading
	pcpp::PcapFileReaderDevice reader(pcapFileName);
	if (!reader.open())
	{
		state.SkipWithError("Cannot open pcap file for reading");
		return;
	}

	size_t totalBytes = 0;
	size_t totalPackets = 0;
	pcpp::RawPacket rawPacket;
	for (auto _ : state)
	{
		if (!reader.getNextPacket(rawPacket))
		{
			// If the rawPacket is empty there should be an error
			if (totalBytes == 0)
			{
				state.SkipWithError("Cannot read packet");
				break;
			}
			else // If the rawPacket is not empty, it means the file is over
			{
				state.PauseTiming();
				reader.close();
				reader.open();
				state.ResumeTiming();
			}
		}

		++totalPackets;
		totalBytes += rawPacket.getRawDataLen();
	}

	state.SetBytesProcessed(totalBytes);
	state.SetItemsProcessed(totalPackets);
}
BENCHMARK(BM_PcapFileRead);

static void BM_PcapPacketParsing(benchmark::State &state)
{
	std::unordered_map<pcpp::ProtocolType, std::string> layerTypeStrings = {
		{pcpp::UnknownProtocol, "Unknown"},
		{pcpp::Ethernet, "Ethernet"},
		{pcpp::IPv4, "IPv4"},
		{pcpp::IPv6, "IPv6"},
		{pcpp::TCP, "TCP"},
		{pcpp::UDP, "UDP"},
		{pcpp::HTTPRequest, "HTTPRequest"},
		{pcpp::HTTPResponse, "HTTPResponse"},
		{pcpp::ARP, "ARP"},
		{pcpp::VLAN, "VLAN"},
		{pcpp::ICMP, "ICMP"},
		{pcpp::PPPoESession, "PPPoESession"},
		{pcpp::PPPoEDiscovery, "PPPoEDiscovery"},
		{pcpp::DNS, "DNS"},
		{pcpp::MPLS, "MPLS"},
		{pcpp::GREv0, "GREv0"},
		{pcpp::GREv1, "GREv1"},
		{pcpp::PPP_PPTP, "PPP_PPTP"},
		{pcpp::SSL, "SSL"},
		{pcpp::SLL, "SLL"},
		{pcpp::DHCP, "DHCP"},
		{pcpp::NULL_LOOPBACK, "NULL_LOOPBACK"},
		{pcpp::IGMPv1, "IGMPv1"},
		{pcpp::IGMPv2, "IGMPv2"},
		{pcpp::IGMPv3, "IGMPv3"},
		{pcpp::GenericPayload, "GenericPayload"},
		{pcpp::VXLAN, "VXLAN"},
		{pcpp::SIPRequest, "SIPRequest"},
		{pcpp::SIPResponse, "SIPResponse"},
		{pcpp::SDP, "SDP"},
		{pcpp::PacketTrailer, "PacketTrailer"},
		{pcpp::Radius, "Radius"},
		{pcpp::GTPv1, "GTPv1"},
		{pcpp::EthernetDot3, "EthernetDot3"},
		{pcpp::BGP, "BGP"},
		{pcpp::SSH, "SSH"},
		{pcpp::AuthenticationHeader, "AuthenticationHeader"},
		{pcpp::ESP, "ESP"},
		{pcpp::DHCPv6, "DHCPv6"},
		{pcpp::NTP, "NTP"},
		{pcpp::Telnet, "Telnet"},
		{pcpp::FTP, "FTP"},
		{pcpp::ICMPv6, "ICMPv6"},
		{pcpp::STP, "STP"},
		{pcpp::LLC, "LLC"},
		{pcpp::SomeIP, "SomeIP"},
		{pcpp::WakeOnLan, "WakeOnLan"},
		{pcpp::NFLOG, "NFLOG"},
		{pcpp::TPKT, "TPKT"},
		{pcpp::VRRPv2, "VRRPv2"},
		{pcpp::VRRPv3, "VRRPv3"},
		{pcpp::COTP, "COTP"},
		{pcpp::SLL2, "SLL2"},
		{pcpp::S7COMM, "S7COMM"},
		{pcpp::SMTP, "SMTP"}};

	std::unordered_map<pcpp::OsiModelLayer, std::string> osiLayerStrings = {
		{pcpp::OsiModelLayer::OsiModelPhysicalLayer, "Physical"},
		{pcpp::OsiModelLayer::OsiModelDataLinkLayer, "DataLink"},
		{pcpp::OsiModelLayer::OsiModelNetworkLayer, "Network"},
		{pcpp::OsiModelLayer::OsiModelTransportLayer, "Transport"},
		{pcpp::OsiModelLayer::OsiModelSesionLayer, "Session"},
		{pcpp::OsiModelLayer::OsiModelPresentationLayer, "Presentation"},
		{pcpp::OsiModelLayer::OsiModelApplicationLayer, "Application"},
		{pcpp::OsiModelLayer::OsiModelLayerUnknown, "Unknown"}};

	std::unordered_map<pcpp::ProtocolType, size_t> layerTypes;
	for (const auto &element : layerTypeStrings)
	{
		layerTypes[element.first] = 0;
	}

	std::unordered_map<pcpp::OsiModelLayer, size_t> osiLayers;
	for (const auto &element : osiLayerStrings)
	{
		osiLayers[element.first] = 0;
	}

	// Open the pcap file for reading
	size_t totalBytes = 0;
	size_t totalPackets = 0;
	pcpp::PcapFileReaderDevice reader(pcapFileName);
	if (!reader.open())
	{
		state.SkipWithError("Cannot open pcap file for reading");
		return;
	}

	pcpp::RawPacket rawPacket;
	for (auto _ : state)
	{
		if (!reader.getNextPacket(rawPacket))
		{
			// If the rawPacket is empty there should be an error
			if (totalBytes == 0)
			{
				state.SkipWithError("Cannot read packet");
				break;
			}
			else // If the rawPacket is not empty, it means the file is over
			{
				state.PauseTiming();
				reader.close();
				reader.open();
				state.ResumeTiming();
			}
		}

		// Parse packet
		pcpp::Packet parsedPacket(&rawPacket);

		// Count protocol layers to simulate accessing
		for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL;
			 curLayer = curLayer->getNextLayer())
		{
			++layerTypes[curLayer->getProtocol()];
			++osiLayers[curLayer->getOsiModelLayer()];
		}

		++totalPackets;
		totalBytes += rawPacket.getRawDataLen();
	}

	state.SetBytesProcessed(totalBytes);
	state.SetItemsProcessed(totalPackets);
}
BENCHMARK(BM_PcapPacketParsing);

int main(int argc, char **argv)
{
	// Initialize the benchmark
	benchmark::Initialize(&argc, argv);

	// Parse command line arguments to find the pcap file name
	for (int idx = 1; idx < argc; ++idx)
	{
		if (strcmp(argv[idx], "--pcap-file") == 0)
		{
			if (idx == argc - 1)
			{
				std::cerr << "Please provide a pcap file name after --pcap-file" << std::endl;
				return 1;
			}

			pcapFileName = argv[idx + 1];
			break;
		}

		if (idx == argc - 1)
		{
			std::cout << "You can provide a pcap file after --pcap-file. Using default pcap file" << std::endl;
		}
	}
	benchmark::AddCustomContext("Pcap file", pcapFileName);

	// Run the benchmarks
	benchmark::RunSpecifiedBenchmarks();

	return 0;
}
