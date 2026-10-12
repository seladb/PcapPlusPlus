/**
 * PcapSerializer application
 * ==========================
 * This application parses packets using Packet++ and serializes them into a structured, machine-readable format
 * (JSON, YAML or XML) using the serializers available in Common++. Packets can be read from a capture file
 * (pcap, pcapng, snoop) or captured from a live network interface.
 * The result is written to stdout (by default) or to a file (if specified). It can also serialize only the first X
 * packets, or only packets matching a BPF filter.
 *
 * For more details about modes of operation and parameters run PcapSerializer -h
 */

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>
#include <Packet.h>
#include <PacketUtils.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <PcapPlusPlusVersion.h>
#include <RawPacket.h>
#include <Serializers.h>
#include <SystemUtils.h>
#include <getopt.h>

// clang-format off
static struct option PcapSerializerOptions[] = {
	{ "input-file",      required_argument, nullptr, 'f' },
	{ "interface",       required_argument, nullptr, 'i' },
	{ "format",          required_argument, nullptr, 'F' },
	{ "output-file",     required_argument, nullptr, 'o' },
	{ "packet-count",    required_argument, nullptr, 'c' },
	{ "filter",          required_argument, nullptr, 'e' },
	{ "list-interfaces", no_argument,       nullptr, 'l' },
	{ "help",            no_argument,       nullptr, 'h' },
	{ "version",         no_argument,       nullptr, 'v' },
	{ nullptr,           0,                 nullptr, 0   }
};
// clang-format on

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get()
	          << " (-f input_file | -i interface) [-hvl] [-F format] [-o output_file] [-c packet_count] [-e bpf_filter]"
	          << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -f input_file  : Read packets from a capture file (pcap, pcapng or snoop)" << std::endl
	          << "    -i interface   : Capture packets from a live interface. Can be an interface name (e.g eth0) or an"
	          << std::endl
	          << "                     interface IPv4 address. Capturing stops on ctrl-c or after packet_count packets"
	          << std::endl
	          << "    -F format      : Output format: 'json', 'yaml' or 'xml' (default: json)" << std::endl
	          << "    -o output_file : Write the serialized output to a file (default output is stdout)" << std::endl
	          << "    -c packet_count: Serialize only the first packet_count packets" << std::endl
	          << "    -e bpf_filter  : Apply a BPF filter, meaning only filtered packets will be serialized"
	          << std::endl
	          << "    -l             : Print the list of interfaces and exit" << std::endl
	          << "    -v             : Display the current version and exit" << std::endl
	          << "    -h             : Display this help message and exit" << std::endl
	          << std::endl;
}

/**
 * Print application version
 */
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Built from: " << pcpp::getGitInfo() << std::endl;
	exit(0);
}

/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const auto& liveDevices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << std::endl << "Network interfaces:" << std::endl;
	for (const auto& device : liveDevices)
	{
		std::cout << "    -> Name: '" << device->getName() << "'   IP address: " << device->getIPv4Address().toString()
		          << std::endl;
	}
	exit(0);
}

/**
 * Create the serializer matching the requested output format, or return nullptr if the format is unknown
 */
std::unique_ptr<pcpp::ISerializer> createSerializer(std::string format, std::ostream& out)
{
	std::transform(format.begin(), format.end(), format.begin(),
	               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

	if (format == "json")
	{
		return std::unique_ptr<pcpp::ISerializer>(new pcpp::JsonSerializer(out));
	}

	if (format == "yaml" || format == "yml")
	{
		return std::unique_ptr<pcpp::ISerializer>(new pcpp::YamlSerializer(out));
	}

	if (format == "xml")
	{
		return std::unique_ptr<pcpp::ISerializer>(new pcpp::XmlSerializer(out));
	}

	return nullptr;
}

/**
 * Serialize packets read from a capture file. Returns the number of serialized packets
 */
int serializeFromFile(const std::string& fileName, const std::string& filter, int packetCount,
                      pcpp::ISerializer& serializer)
{
	// open a pcap/pcapng/snoop file for reading
	auto reader = pcpp::IFileReaderDevice::tryCreateReader(fileName);
	if (reader == nullptr || !reader->open())
	{
		EXIT_WITH_ERROR("Error opening input file '" << fileName << "'");
	}

	// set a filter if provided
	if (!filter.empty() && !reader->setFilter(filter))
	{
		EXIT_WITH_ERROR("Couldn't set filter '" << filter << "'");
	}

	// read and serialize the packets. A max packet count of 0 means serializing all packets in the file
	auto maxPackets = static_cast<size_t>(packetCount > 0 ? packetCount : 0);
	auto serializedPacketCount = pcpp::serializePackets(*reader, serializer, maxPackets);

	reader->close();

	return static_cast<int>(serializedPacketCount);
}

/**
 * The data shared between the main thread and the capture thread in live traffic mode
 */
struct LiveCaptureData
{
	pcpp::PacketSerializer* packetSerializer;
	int maxPacketCount;
	std::atomic<int> packetCount{ 0 };
	std::atomic<bool> shouldStop{ false };
};

/**
 * The callback invoked on the capture thread for every captured packet
 */
void onPacketArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice*, void* cookie)
{
	auto* data = static_cast<LiveCaptureData*>(cookie);

	// packets may still arrive between reaching the requested count and the main thread stopping the capture
	if (data->shouldStop)
	{
		return;
	}

	pcpp::Packet parsedPacket(rawPacket);
	data->packetSerializer->addPacket(parsedPacket);

	if (++data->packetCount == data->maxPacketCount)
	{
		data->shouldStop = true;
	}
}

/**
 * The callback to be called when application is terminated by ctrl-c
 */
void onApplicationInterrupted(void* cookie)
{
	auto* data = static_cast<LiveCaptureData*>(cookie);
	data->shouldStop = true;
}

/**
 * Serialize packets captured from a live interface. Returns the number of serialized packets
 */
int serializeFromLiveTraffic(const std::string& interfaceNameOrIP, const std::string& filter, int packetCount,
                             pcpp::ISerializer& serializer)
{
	auto* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceNameOrIP);
	if (dev == nullptr)
	{
		EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");
	}

	if (!dev->open())
	{
		EXIT_WITH_ERROR("Couldn't open interface '" << dev->getName() << "'");
	}

	if (!filter.empty() && !dev->setFilter(filter))
	{
		EXIT_WITH_ERROR("Couldn't set filter '" << filter << "'");
	}

	LiveCaptureData data;
	data.maxPacketCount = packetCount;

	{
		// the packets array is opened here and closed when packetSerializer goes out of scope, which happens only
		// after the capture thread is stopped, so it's safe to write to it from the capture callback
		pcpp::PacketSerializer packetSerializer(serializer);
		data.packetSerializer = &packetSerializer;

		pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &data);

		if (!dev->startCapture(onPacketArrives, &data))
		{
			EXIT_WITH_ERROR("Couldn't start capturing on interface '" << dev->getName() << "'");
		}

		while (!data.shouldStop)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

		dev->stopCapture();
	}

	dev->close();

	return data.packetCount;
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string inputFileName;
	std::string interfaceNameOrIP;
	std::string outputFileName;
	std::string format = "json";
	std::string filter;
	int packetCount = -1;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "f:i:F:o:c:e:lhv", PcapSerializerOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'f':
			inputFileName = optarg;
			break;
		case 'i':
			interfaceNameOrIP = optarg;
			break;
		case 'F':
			format = optarg;
			break;
		case 'o':
			outputFileName = optarg;
			break;
		case 'c':
			packetCount = atoi(optarg);
			break;
		case 'e':
			filter = optarg;
			break;
		case 'l':
			listInterfaces();
			break;
		case 'h':
			printUsage();
			exit(0);
		case 'v':
			printAppVersion();
			break;
		default:
			printUsage();
			exit(1);
		}
	}

	if (inputFileName.empty() && interfaceNameOrIP.empty())
	{
		EXIT_WITH_ERROR("Neither input file nor interface were provided");
	}

	if (!inputFileName.empty() && !interfaceNameOrIP.empty())
	{
		EXIT_WITH_ERROR("Please provide either an input file or an interface, not both");
	}

	if (packetCount == 0 || packetCount < -1)
	{
		EXIT_WITH_ERROR("Packet count must be a positive number");
	}

	// write to output file if provided, otherwise output to stdout
	std::ofstream outputFile;
	auto* out = &std::cout;
	if (!outputFileName.empty())
	{
		outputFile.open(outputFileName);
		if (!outputFile.is_open())
		{
			EXIT_WITH_ERROR("Couldn't open output file '" << outputFileName << "'");
		}
		out = &outputFile;
	}

	auto serializer = createSerializer(format, *out);
	if (serializer == nullptr)
	{
		EXIT_WITH_ERROR("Unknown output format '" << format << "'");
	}

	int serializedPacketCount = 0;
	if (!inputFileName.empty())
	{
		serializedPacketCount = serializeFromFile(inputFileName, filter, packetCount, *serializer);
	}
	else
	{
		serializedPacketCount = serializeFromLiveTraffic(interfaceNameOrIP, filter, packetCount, *serializer);
	}

	(*out) << std::endl;

	// when the serialized output goes to stdout, print the summary to stderr so it doesn't corrupt the output
	auto& summaryOut = outputFileName.empty() ? std::cerr : std::cout;
	summaryOut << "Finished. Serialized " << serializedPacketCount << " packets" << std::endl;

	return 0;
}
