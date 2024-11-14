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

static std::string pcapFileName = "";

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
				return;
			}

			// Rewind the file if it reached the end
			state.PauseTiming();
			reader.close();
			reader.open();
			state.ResumeTiming();
			continue;
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
	pcpp::PcapFileWriterDevice writer("benchmark-output.pcap");
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
				return;
			}

			// Rewind the file if it reached the end
			state.PauseTiming();
			reader.close();
			reader.open();
			state.ResumeTiming();
			continue;
		}

		// Parse packet
		pcpp::Packet parsedPacket(&rawPacket);

		// Use parsedPacket to prevent compiler optimizations
		assert(parsedPacket.getFirstLayer());

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

		pcpp::Packet packet;

		// Generate random MAC addresses
		pcpp::MacAddress srcMac(randNum, randNum, randNum, randNum, randNum, randNum);
		pcpp::MacAddress dstMac(randNum, randNum, randNum, randNum, randNum, randNum);
		packet.addLayer(new pcpp::EthLayer(srcMac, dstMac), true);

		// Randomly choose between IPv4 and IPv6
		if (randNum % 2)
		{
			packet.addLayer(new pcpp::IPv4Layer(randNum, randNum), true);
		}
		else
		{
			std::array<uint8_t, 16> srcIP = { randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum,
				                              randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum };
			std::array<uint8_t, 16> dstIP = { randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum,
				                              randNum, randNum, randNum, randNum, randNum, randNum, randNum, randNum };

			packet.addLayer(new pcpp::IPv6Layer(srcIP, dstIP), true);
		}

		// Randomly choose between TCP and UDP
		if (randNum % 2)
		{
			packet.addLayer(new pcpp::TcpLayer(randNum % 65536, randNum % 65536), true);
		}
		else
		{
			packet.addLayer(new pcpp::UdpLayer(randNum % 65536, randNum % 65536), true);
		}

		// Calculate all fields to update the packet
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
	}

	if (pcapFileName.empty())
	{
		std::cerr << "Please provide a pcap file name using --pcap-file" << std::endl;
		return 1;
	}

	benchmark::AddCustomContext("PcapPlusPlus version", pcpp::getPcapPlusPlusVersionFull());
	benchmark::AddCustomContext("Build info", pcpp::getBuildDateTime());
	benchmark::AddCustomContext("Git info", pcpp::getGitInfo());
	benchmark::AddCustomContext("Pcap file", pcapFileName);

	// Run the benchmarks
	benchmark::RunSpecifiedBenchmarks();

	return 0;
}
