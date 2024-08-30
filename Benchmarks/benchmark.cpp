#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapPlusPlusVersion.h>

#include <benchmark/benchmark.h>

#include <iostream>
#include <string>
#include <unordered_map>

static std::string pcapFileName = "PcapExamples/example_copy.pcap";

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

static void BM_PcapPacketParsing(benchmark::State& state)
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
BENCHMARK(BM_PcapPacketParsing);

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
