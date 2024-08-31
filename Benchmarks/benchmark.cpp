#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapPlusPlusVersion.h>

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

#include <benchmark/benchmark.h>

#include <iostream>
#include <string>
#include <unordered_map>

static std::string pcapFileName = "PcapExamples/example.pcap";

static void BM_PcapFileRead(benchmark::State& state)
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
			else  // If the rawPacket is not empty, it means the file is over
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

static void BM_PcapFileWrite(benchmark::State& state)
{
	// Open the pcap file for writing
	pcpp::PcapFileWriterDevice writer("PcapExamples/output.pcap");
	if (!writer.open())
	{
		state.SkipWithError("Cannot open pcap file for writing");
		return;
	}

	pcpp::Packet packet;
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:00:00:00:00:00"), pcpp::MacAddress("00:00:00:00:00:00"));
	pcpp::IPv4Layer ip4Layer(pcpp::IPv4Address("192.168.0.1"), pcpp::IPv4Address("192.168.0.2"));
	pcpp::TcpLayer tcpLayer(12345, 80);

	packet.addLayer(&ethLayer);
	packet.addLayer(&ip4Layer);
	packet.addLayer(&tcpLayer);
	packet.computeCalculateFields();

	size_t totalBytes = 0;
	size_t totalPackets = 0;
	for (auto _ : state)
	{
		// Write packet to file
		writer.writePacket(*(packet.getRawPacket()));

		// Count total bytes and packets
		++totalPackets;
		totalBytes += packet.getRawPacket()->getRawDataLen();
	}

	// Set statistics to the benchmark state
	state.SetBytesProcessed(totalBytes);
	state.SetItemsProcessed(totalPackets);
}
BENCHMARK(BM_PcapFileWrite);

static void BM_PacketParsing(benchmark::State& state)
{
	std::unordered_map<pcpp::ProtocolType, size_t> layerTypes;
	std::unordered_map<pcpp::OsiModelLayer, size_t> osiLayers;

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
			else  // If the rawPacket is not empty, it means the file is over
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
		for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL;
		     curLayer = curLayer->getNextLayer())
		{
			// Count protocol types. If the protocol type is not in the map, add it
			if (layerTypes.find(curLayer->getProtocol()) == layerTypes.end())
			{
				layerTypes[curLayer->getProtocol()] = 0;
			}
			++layerTypes[curLayer->getProtocol()];

			// Count OSI layers. If the OSI layer is not in the map, add it
			if (osiLayers.find(curLayer->getOsiModelLayer()) == osiLayers.end())
			{
				osiLayers[curLayer->getOsiModelLayer()] = 0;
			}
			++osiLayers[curLayer->getOsiModelLayer()];
		}

		// Count total bytes and packets
		++totalPackets;
		totalBytes += rawPacket.getRawDataLen();
	}

	// Set statistics to the benchmark state
	state.SetBytesProcessed(totalBytes);
	state.SetItemsProcessed(totalPackets);
}
BENCHMARK(BM_PacketParsing);

static void BM_PacketCrafting(benchmark::State& state)
{
	size_t totalBytes = 0;
	size_t totalPackets = 0;

	for (auto _ : state)
	{
		uint8_t randNum = static_cast<uint8_t>(rand() % 256);

		// Generate random MAC addresses
		pcpp::MacAddress srcMac(randNum, randNum, randNum, randNum, randNum, randNum);
		pcpp::MacAddress dstMac(randNum, randNum, randNum, randNum, randNum, randNum);

		// Craft packet
		std::unique_ptr<pcpp::EthLayer> ethLayer(new pcpp::EthLayer(srcMac, dstMac));

		std::unique_ptr<pcpp::IPv4Layer> ipv4Layer(nullptr);
		std::unique_ptr<pcpp::IPv6Layer> ipv6Layer(nullptr);

		std::unique_ptr<pcpp::TcpLayer> tcpLayer(nullptr);
		std::unique_ptr<pcpp::UdpLayer> udpLayer(nullptr);

		// Randomly choose between IPv4 and IPv6
		if (randNum % 2)
		{
			ipv4Layer.reset(new pcpp::IPv4Layer(randNum, randNum));
		}
		else
		{
			std::array<uint8_t, 16> srcIP = { randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum,
				                              randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum };
			std::array<uint8_t, 16> dstIP = { randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum,
				                              randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum };

			ipv6Layer.reset(new pcpp::IPv6Layer(srcIP, dstIP));
		}

		// Randomly choose between TCP and UDP
		if (randNum % 2)
		{
			tcpLayer.reset(new pcpp::TcpLayer(randNum % 65536, randNum % 65536));
		}
		else
		{
			udpLayer.reset(new pcpp::UdpLayer(randNum % 65536, randNum % 65536));
		}

		// Add layers to the packet
		pcpp::Packet packet;
		packet.addLayer(ethLayer.get());
		if (ipv4Layer)
		{
			packet.addLayer(ipv4Layer.get());
		}
		else
		{
			packet.addLayer(ipv6Layer.get());
		}

		if (tcpLayer)
		{
			packet.addLayer(tcpLayer.get());
		}
		else
		{
			packet.addLayer(udpLayer.get());
		}

		packet.computeCalculateFields();

		// Count total bytes and packets
		++totalPackets;
		totalBytes += packet.getRawPacket()->getRawDataLen();
	}

	// Set statistics to the benchmark state
	state.SetBytesProcessed(totalBytes);
	state.SetItemsProcessed(totalPackets);
}
BENCHMARK(BM_PacketCrafting);

int main(int argc, char** argv)
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
	benchmark::AddCustomContext("PcapPlusPlus version", pcpp::getPcapPlusPlusVersionFull());
	benchmark::AddCustomContext("Build info", pcpp::getBuildDateTime());
	benchmark::AddCustomContext("Git info", pcpp::getGitInfo());
	benchmark::AddCustomContext("Pcap file", pcapFileName);

	// Run the benchmarks
	benchmark::RunSpecifiedBenchmarks();

	return 0;
}
