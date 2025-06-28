/**
 * TLS Fingerprinting application
 * ==============================
 *
 * This application demonstrates how to extract and use TLS fingerprinting data using PcapPlusPlus.
 * Please read the README.md file for more information.
 *
 * You can also run `TLSFingerprinting -h` for modes of operation and parameters.
 */

#include <unordered_map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include "SystemUtils.h"
#include "TablePrinter.h"
#include "IPLayer.h"
#include "TcpLayer.h"
#include "SSLLayer.h"
#include "SSLHandshake.h"
#include "Packet.h"
#include "PcapPlusPlusVersion.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include <getopt.h>

static struct option TLSFingerprintingOptions[] = {
	{ "interface",       required_argument, nullptr, 'i' },
	{ "input-file",      required_argument, nullptr, 'r' },
	{ "output-file",     required_argument, nullptr, 'o' },
	{ "separator",       required_argument, nullptr, 's' },
	{ "tls-fp-type",     required_argument, nullptr, 't' },
	{ "filter",          required_argument, nullptr, 'f' },
	{ "list-interfaces", no_argument,       nullptr, 'l' },
	{ "version",         no_argument,       nullptr, 'v' },
	{ "help",            no_argument,       nullptr, 'h' },
	{ nullptr,           0,                 nullptr, 0   }
};

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#define TLS_FP_CH_ONLY "ch"
#define TLS_FP_SH_ONLY "sh"
#define TLS_FP_CH_AND_SH "ch_sh"

bool isNotAlphanumeric(char c)
{
	return std::isalnum(c) == 0;
}

/**
 * An auxiliary method for sorting the TLS fingerprint count map. Used in printCommonTLSFingerprints()
 */
bool stringCountComparer(const std::pair<std::string, uint64_t>& first, const std::pair<std::string, uint64_t>& second)
{
	if (first.second == second.second)
	{
		return first.first > second.first;
	}
	return first.second > second.second;
}

/**
 * Print application usage
 */
void printUsage()
{
	std::cout
	    << std::endl
	    << "Usage:" << std::endl
	    << "------" << std::endl
	    << pcpp::AppName::get()
	    << " [-hvlcms] [-r input_file] [-i interface] [-o output_file_name] [-s separator] [-t tls_fp_type] [-f "
	       "bpf_filter]"
	    << std::endl
	    << std::endl
	    << "Options:" << std::endl
	    << std::endl
	    << "    -r input_file       : Input pcap/pcapng file to analyze. Required argument for reading from file"
	    << std::endl
	    << "    -i interface        : Use the specified interface. Can be interface name (e.g eth0) or IP address."
	    << std::endl
	    << "                          Required argument for capturing from live interface" << std::endl
	    << "    -o output_file_name : Output file name. This is a csv file (where 'tab' is the default separator)"
	    << std::endl
	    << "                          which contains information about all of the TLS fingerprints found in the"
	    << std::endl
	    << "                          capture file or live interface. It includes the TLS fingerprint itself"
	    << std::endl
	    << "                          (raw string and MD5), IP addresses, TCP ports and SSL message type (ClientHello"
	    << std::endl
	    << "                          or ServerHello). If this argument is not specified the output file name is the"
	    << std::endl
	    << "                          name of capture file or the live interface and it is written to the current"
	    << std::endl
	    << "                          directory ('.')" << std::endl
	    << "    -s separator        : The separator to use in the csv output file. Valid values are a single character"
	    << std::endl
	    << "                          which is not alphanumeric and not one of the following: '.', ',', ':', '-'."
	    << std::endl
	    << "                          If this argument is not specified the default separator is 'tab' ('\\t')"
	    << std::endl
	    << "    -t tls_fp_type      : Specify whether to calculate TLS fingerprints for ClientHello packets only "
	       "('ch'),"
	    << std::endl
	    << "                          ServerHello packets only ('sh') or both ('ch_sh'). The only valid values are"
	    << std::endl
	    << "                          'ch', 'sh', 'ch_sh'. If this argument is not specified the default value is"
	    << std::endl
	    << "                          ClientHello ('ch')" << std::endl
	    << "    -f bpf_filter       : Apply a BPF filter to the capture file or live interface, meaning TLS fingerprint"
	    << std::endl
	    << "                          will only be generated for the filtered packets" << std::endl
	    << "    -l                  : Print the list of interfaces and exit" << std::endl
	    << "    -v                  : Display the current version and exit" << std::endl
	    << "    -h                  : Display this help message and exit" << std::endl
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
	const std::vector<pcpp::PcapLiveDevice*>& devList =
	    pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << std::endl << "Network interfaces:" << std::endl;
	for (const auto& dev : devList)
	{
		std::cout << "    -> Name: '" << dev->getName() << "'   IP address: " << dev->getIPv4Address().toString()
		          << std::endl;
	}
	exit(0);
}

/**
 * The callback to be called when application is terminated by ctrl-c
 */
static void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}

/**
 * Return a packet source and dest IP addresses
 */
std::pair<pcpp::IPAddress, pcpp::IPAddress> getIPs(const pcpp::Packet& packet)
{
	pcpp::IPAddress srcIP, dstIP;
	if (packet.isPacketOfType(pcpp::IP))
	{
		const pcpp::IPLayer* ipLayer = packet.getLayerOfType<pcpp::IPLayer>();
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	}
	return std::pair<pcpp::IPAddress, pcpp::IPAddress>(srcIP, dstIP);
}

/**
 * Return a packet source and dest TCP ports
 */
std::pair<uint16_t, uint16_t> getTcpPorts(const pcpp::Packet& packet)
{
	uint16_t srcPort = 0, dstPort = 0;
	if (packet.isPacketOfType(pcpp::TCP))
	{
		pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		srcPort = tcpLayer->getSrcPort();
		dstPort = tcpLayer->getDstPort();
	}

	return std::pair<uint16_t, uint16_t>(srcPort, dstPort);
}

/**
 * Write data about a single ClientHello/ServerHello packet to the output file.
 * This method takes the parsed packets and the TLS fingerprint as inputs, extracts the rest of the data such as IP
 * addresses and TCP ports, and writes a single row to the output file
 */
void writeToOutputFile(std::ofstream* outputFile, const pcpp::Packet& parsedPacket, const std::string& tlsFPString,
                       const std::string& tlsFP_MD5, const std::string& tlsFPType, const std::string& separator)
{
	std::pair<pcpp::IPAddress, pcpp::IPAddress> ipSrcDest = getIPs(parsedPacket);
	std::pair<uint16_t, uint16_t> tcpPorts = getTcpPorts(parsedPacket);

	*outputFile << tlsFP_MD5 << separator << tlsFPString << separator << tlsFPType << separator
	            << ipSrcDest.first.toString() << separator << tcpPorts.first << separator << ipSrcDest.second.toString()
	            << separator << tcpPorts.second << std::endl;
}

/**
 * Write the column headers to the output file
 */
void writeHeaderToOutputFile(std::ofstream& outputFile, const std::string& separator)
{
	outputFile << "TLS Fingerprint (MD5)" << separator << "TLS Fingerprint" << separator << "TLS Fingerprint type"
	           << separator << "IP Source" << separator << "TCP Source Port" << separator << "IP Dest" << separator
	           << "TCP Dest Port" << std::endl;
}

struct TLSFingerprintingStats
{
	TLSFingerprintingStats() : numOfPacketsTotal(0), numOfCHPackets(0), numOfSHPackets(0)
	{}
	uint64_t numOfPacketsTotal;
	uint64_t numOfCHPackets;
	uint64_t numOfSHPackets;
	std::unordered_map<std::string, uint64_t> chFingerprints;
	std::unordered_map<std::string, uint64_t> shFingerprints;
};

struct HandlePacketData
{
	bool chFP;
	bool shFP;
	std::ofstream* outputFile;
	std::string separator;
	TLSFingerprintingStats* stats;
};

/**
 * Print cipher-suite map in a table sorted by number of occurrences (most common cipher-suite will be first)
 */
void printCommonTLSFingerprints(const std::unordered_map<std::string, uint64_t>& tlsFingerprintMap, int printCountItems)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back("TLS Fingerprint");
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(32);
	columnsWidths.push_back(7);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the TLS fingerprint map so the most popular will be first
	// since it's not possible to sort a std::unordered_map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int>> map2vec(tlsFingerprintMap.begin(), tlsFingerprintMap.end());
	std::sort(map2vec.begin(), map2vec.end(), &stringCountComparer);

	// go over all items (fingerprints + count) in the sorted vector and print them
	for (auto iter = map2vec.begin(); iter != map2vec.end(); ++iter)
	{
		if (iter - map2vec.begin() >= printCountItems)
			break;

		std::stringstream values;
		values << iter->first << "|" << iter->second;
		printer.printRow(values.str(), '|');
	}
}

/**
 * Print TLS fingerprinting stats
 */
void printStats(const TLSFingerprintingStats& stats, bool chFP, bool shFP)
{
	std::stringstream stream;
	stream << std::endl;
	stream << "Summary:" << std::endl;
	stream << "========" << std::endl;
	stream << "Total packets read:                   " << stats.numOfPacketsTotal << std::endl;
	if (chFP)
	{
		stream << "TLS ClientHello packets:              " << stats.numOfCHPackets << std::endl;
		stream << "Unique ClientHello TLS fingerprints:  " << stats.chFingerprints.size() << std::endl;
	}
	if (shFP)
	{
		stream << "TLS ServerHello packets:              " << stats.numOfSHPackets << std::endl;
		stream << "Unique ServerHello TLS fingerprints:  " << stats.shFingerprints.size() << std::endl;
	}

	std::cout << stream.str() << std::endl;

	// write a table of the 10 most common TLS fingerprints

	// if user requested to extract ClientHello TLS fingerprints and there is data to show
	if (chFP && stats.chFingerprints.size() > 0)
	{
		if (stats.chFingerprints.size() > 10)
			std::cout << "Top 10 ";
		std::cout << "ClientHello TLS fingerprints:" << std::endl;

		// write no more than 10 most common TLS fingerprints
		printCommonTLSFingerprints(stats.chFingerprints, 10);
		std::cout << std::endl;
	}

	// if user requested to extract ServerHello TLS fingerprints and there is data to show
	if (shFP && stats.shFingerprints.size() > 0)
	{
		if (stats.shFingerprints.size() > 10)
			std::cout << "Top 10 ";
		std::cout << "ServerHello TLS fingerprints:" << std::endl;

		// write no more than 10 most common TLS fingerprints
		printCommonTLSFingerprints(stats.shFingerprints, 10);
		std::cout << std::endl;
	}
}

/**
 * Handle an intercepted packet: identify if it's a ClientHello or ServerHello packets, extract the TLS fingerprint and
 * write it to the output file
 */
void handlePacket(pcpp::RawPacket* rawPacket, const HandlePacketData* data)
{
	pcpp::Packet parsedPacket(rawPacket);
	data->stats->numOfPacketsTotal++;
	if (parsedPacket.isPacketOfType(pcpp::SSL))
	{
		// extract the SSL/TLS handhsake layer
		pcpp::SSLHandshakeLayer* sslHandshakeLayer = parsedPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
		if (sslHandshakeLayer != nullptr)
		{
			// if user requested to extract ClientHello TLS fingerprint
			if (data->chFP)
			{
				// check if the SSL/TLS handhsake layer contains a ClientHello message
				pcpp::SSLClientHelloMessage* clientHelloMessage =
				    sslHandshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
				if (clientHelloMessage != nullptr)
				{
					data->stats->numOfCHPackets++;

					// extract the TLS fingerprint
					pcpp::SSLClientHelloMessage::ClientHelloTLSFingerprint tlsFingerprint =
					    clientHelloMessage->generateTLSFingerprint();
					std::pair<std::string, std::string> tlsFingerprintStringAndMD5 = tlsFingerprint.toStringAndMD5();
					data->stats->chFingerprints[tlsFingerprintStringAndMD5.second]++;
					// write data to output file
					writeToOutputFile(data->outputFile, parsedPacket, tlsFingerprintStringAndMD5.first,
					                  tlsFingerprintStringAndMD5.second, "ClientHello", data->separator);
					return;
				}
			}
			// if user requested to extract ServerHello TLS fingerprint
			if (data->shFP)
			{
				// check if the SSL/TLS handhsake layer contains a ServerHello message
				pcpp::SSLServerHelloMessage* servertHelloMessage =
				    sslHandshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();
				if (servertHelloMessage != nullptr)
				{
					data->stats->numOfSHPackets++;

					// extract the TLS fingerprint
					pcpp::SSLServerHelloMessage::ServerHelloTLSFingerprint tlsFingerprint =
					    servertHelloMessage->generateTLSFingerprint();
					std::pair<std::string, std::string> tlsFingerprintStringAndMD5 = tlsFingerprint.toStringAndMD5();
					data->stats->shFingerprints[tlsFingerprintStringAndMD5.second]++;
					// write data to output file
					writeToOutputFile(data->outputFile, parsedPacket, tlsFingerprintStringAndMD5.first,
					                  tlsFingerprintStringAndMD5.second, "ServerHello", data->separator);
				}
			}
		}
	}
}

/**
 * Extract TLS fingerprints from a pcap/pcapng file
 */
void doTlsFingerprintingOnPcapFile(const std::string& inputPcapFileName, std::string& outputFileName,
                                   const std::string& separator, bool chFP, bool shFP, const std::string& bpfFilter)
{
	// open input file (pcap or pcapng file)
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(inputPcapFileName.c_str());

	// try to open the file device
	if (!reader->open())
		EXIT_WITH_ERROR("Cannot open pcap/pcapng file");

	// set output file name to input file name if not provided by the user
	if (outputFileName.empty())
	{
		size_t fileNameOffset = inputPcapFileName.find_last_of("\\/") + 1;
		size_t extensionOffset = inputPcapFileName.find_last_of(".");
		std::string fileNameWithoutExtension =
		    inputPcapFileName.substr(fileNameOffset, extensionOffset - fileNameOffset);
		outputFileName = fileNameWithoutExtension + ".txt";
	}

	// open output file
	std::ofstream outputFile(outputFileName.c_str());
	if (!outputFile)
	{
		EXIT_WITH_ERROR("Cannot open output file '" << outputFileName << "'");
	}

	// write the column headers to the output file
	writeHeaderToOutputFile(outputFile, separator);

	// set BPF filter if provided by the user
	if (!bpfFilter.empty())
	{
		if (!reader->setFilter(bpfFilter))
			EXIT_WITH_ERROR("Error in setting BPF filter to the pcap file");
	}

	std::cout << "Start reading '" << inputPcapFileName << "'..." << std::endl;

	TLSFingerprintingStats stats;
	HandlePacketData data;
	data.chFP = chFP;
	data.shFP = shFP;
	data.outputFile = &outputFile;
	data.separator = separator;
	data.stats = &stats;

	pcpp::RawPacket rawPacket;

	// iterate over all packets in the file
	while (reader->getNextPacket(rawPacket))
	{
		handlePacket(&rawPacket, &data);
	}

	// close the reader and free its memory
	reader->close();
	delete reader;

	printStats(stats, chFP, shFP);

	std::cout << "Output file was written to: '" << outputFileName << "'" << std::endl;
}

/**
 * packet capture callback - called whenever a packet arrives on the live interface (in live device capturing mode)
 */
static void onPacketArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie)
{
	HandlePacketData* data = static_cast<HandlePacketData*>(cookie);
	handlePacket(rawPacket, data);
}

/**
 * Extract TLS fingerprints from a live interface
 */
void doTlsFingerprintingOnLiveTraffic(const std::string& interfaceNameOrIP, std::string& outputFileName,
                                      const std::string& separator, bool chFP, bool shFP, const std::string& bpfFilter)
{
	// extract pcap live device by interface name or IP address
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceNameOrIP);
	if (dev == nullptr)
		EXIT_WITH_ERROR("Couldn't find interface by given IP address or name");

	if (!dev->open())
		EXIT_WITH_ERROR("Couldn't open interface");

	// set output file name to interface name if not provided by the user
	if (outputFileName.empty())
	{
		// take the device name and remove all chars which are not alphanumeric
		outputFileName = std::string(dev->getName());
		outputFileName.erase(remove_if(outputFileName.begin(), outputFileName.end(), isNotAlphanumeric),
		                     outputFileName.end());

		outputFileName += ".txt";
	}

	// open output file
	std::ofstream outputFile(outputFileName.c_str());
	if (!outputFile)
	{
		EXIT_WITH_ERROR("Cannot open output file '" << outputFileName << "'");
	}

	// write the column headers to the output file
	writeHeaderToOutputFile(outputFile, separator);

	// set BPF filter if provided by the user
	if (!bpfFilter.empty())
	{
		if (!dev->setFilter(bpfFilter))
			EXIT_WITH_ERROR("Error in setting BPF filter to interface");
	}

	std::cout << "Start capturing packets from '" << interfaceNameOrIP << "'..." << std::endl;

	TLSFingerprintingStats stats;
	HandlePacketData data;
	data.chFP = chFP;
	data.shFP = shFP;
	data.outputFile = &outputFile;
	data.separator = separator;
	data.stats = &stats;

	// start capturing packets. Each packet arrived will be handled by the onPacketArrives method
	dev->startCapture(onPacketArrives, &data);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	// run in an endless loop until the user press ctrl+c
	while (!shouldStop)
		std::this_thread::sleep_for(std::chrono::seconds(1));

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	printStats(stats, chFP, shFP);

	std::cout << "Output file was written to: '" << outputFileName << "'" << std::endl;
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string interfaceNameOrIP;
	std::string inputPcapFileName;
	std::string outputFileName;
	std::string bpfFilter;
	std::string separator = "\t";
	std::string tlsFingerprintType = TLS_FP_CH_ONLY;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "i:r:o:t:f:s:vhl", TLSFingerprintingOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'i':
			interfaceNameOrIP = optarg;
			break;
		case 'r':
			inputPcapFileName = optarg;
			break;
		case 'o':
			outputFileName = optarg;
			break;
		case 'f':
			bpfFilter = optarg;
			break;
		case 's':
			separator = optarg;
			break;
		case 't':
			tlsFingerprintType = optarg;
			break;
		case 'h':
			printUsage();
			exit(0);
		case 'v':
			printAppVersion();
			break;
		case 'l':
			listInterfaces();
			break;
		default:
			printUsage();
			exit(-1);
		}
	}

	// if no interface or input pcap file provided or both are provided - exit with error
	if (inputPcapFileName.empty() == interfaceNameOrIP.empty())
	{
		EXIT_WITH_ERROR("Please provide an interface or an input pcap file");
	}

	// if the user chosen a separator which is not the default, check if this separator is allowed. Allowed separators
	// are a single character which is not alphanumeric and not one of the following: '.', ',', ':', '-'
	static const std::string disallowedSeparatorsArr[] = { ".", ",", ":", "-" };
	std::vector<std::string> disallowedSeparatorsVec(disallowedSeparatorsArr,
	                                                 disallowedSeparatorsArr + sizeof(disallowedSeparatorsArr) /
	                                                                               sizeof(disallowedSeparatorsArr[0]));
	if (separator.empty() || separator.size() > 1 || std::isalnum(separator[0]) ||
	    std::find(disallowedSeparatorsVec.begin(), disallowedSeparatorsVec.end(), separator) !=
	        disallowedSeparatorsVec.end())
	{
		EXIT_WITH_ERROR(
		    "Allowed separators are single characters which are not alphanumeric and not ',', '.', ':', '-'");
	}

	// validate TLS fingerprint type the user has requested
	if (tlsFingerprintType != TLS_FP_CH_ONLY && tlsFingerprintType != TLS_FP_SH_ONLY &&
	    tlsFingerprintType != TLS_FP_CH_AND_SH)
	{
		EXIT_WITH_ERROR("Possible options for TLS fingerprint types are 'ch' (Client Hello), 'sh' (Server Hello) or "
		                "'ch_sh' (Client Hello & Server Hello)\n");
	}

	bool chFP = true, shFP = true;
	if (tlsFingerprintType == TLS_FP_CH_ONLY)
	{
		shFP = false;
	}
	else if (tlsFingerprintType == TLS_FP_SH_ONLY)
	{
		chFP = false;
	}

	if (!inputPcapFileName.empty())
	{
		doTlsFingerprintingOnPcapFile(inputPcapFileName, outputFileName, separator, chFP, shFP, bpfFilter);
	}
	else
	{
		doTlsFingerprintingOnLiveTraffic(interfaceNameOrIP, outputFileName, separator, chFP, shFP, bpfFilter);
	}
}
