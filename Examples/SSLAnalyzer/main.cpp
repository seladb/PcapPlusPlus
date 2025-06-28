/**
 * SSLAnalyzer application
 * ========================
 * This application analyzes SSL/TLS traffic and presents detailed and diverse information about it. It can operate in
 * live traffic mode where this information is collected on live packets or in file mode where packets are being read
 * from a pcap/pcapng file. The information collected by this application includes:
 * - general data: number of packets, packet rate, amount of traffic, bandwidth
 * - flow data: number of flow, flow rate, average packets per flow, average data per flow
 * - SSL/TLS data: number of client-hello and server-hello messages, number of flows ended with successful handshake,
 *   number of flows ended with SSL alert
 * - hostname map (which hostnames were used and how much. Taken from the server-name-indication extension in the
 *   client-hello message)
 * - cipher-suite map (which cipher-suites were used and how much)
 * - SSL/TLS versions map (which SSL/TLS versions were used and how much)
 * - SSL/TLS ports map (which SSL/TLS TCP ports were used and how much)
 *
 * For more details about modes of operation and parameters run SSLAnalyzer -h
 */

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <memory>
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "SSLStatsCollector.h"
#include "TablePrinter.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#define PRINT_STAT_LINE(description, counter, measurement)                                                             \
	std::cout << std::left << std::setw(46) << (std::string(description) + ":") << std::right << std::setw(15)         \
	          << std::fixed << std::showpoint << std::setprecision(3) << counter << " [" << measurement << "]"         \
	          << std::endl;

#define DEFAULT_CALC_RATES_PERIOD_SEC 2

// clang-format off
static struct option SSLAnalyzerOptions[] = {
	{ "interface",           required_argument, nullptr, 'i' },
	{ "input-file",          required_argument, nullptr, 'f' },
	{ "output-file",         required_argument, nullptr, 'o' },
	{ "rate-calc-period",    required_argument, nullptr, 'r' },
	{ "disable-rates-print", no_argument,       nullptr, 'd' },
	{ "list-interfaces",     no_argument,       nullptr, 'l' },
	{ "help",                no_argument,       nullptr, 'h' },
	{ "version",             no_argument,       nullptr, 'v' },
	{ nullptr,               0,                 nullptr, 0   }
};
// clang-format on

struct SSLPacketArrivedData
{
	SSLStatsCollector* statsCollector;
	pcpp::PcapFileWriterDevice* pcapWriter;
};

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage: PCAP file mode:" << std::endl
	          << "----------------------" << std::endl
	          << pcpp::AppName::get() << " [-hv] -f input_file" << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -f           : The input pcap/pcapng file to analyze. Required argument for this mode"
	          << std::endl
	          << "    -v           : Displays the current version and exists" << std::endl
	          << "    -h           : Displays this help message and exits" << std::endl
	          << std::endl
	          << "Usage: Live traffic mode:" << std::endl
	          << "-------------------------" << std::endl
	          << pcpp::AppName::get() << " [-hvld] [-o output_file] [-r calc_period] -i interface" << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 "
	             "address"
	          << std::endl
	          << "    -o output_file : Save all captured SSL packets to a pcap file. Notice this may cause performance "
	             "degradation"
	          << std::endl
	          << "    -r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds"
	          << std::endl
	          << "    -d             : Disable periodic rates calculation" << std::endl
	          << "    -v             : Displays the current version and exists" << std::endl
	          << "    -h             : Displays this help message and exits" << std::endl
	          << "    -l             : Print the list of interfaces and exists" << std::endl
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

void printStatsHeadline(const std::string& description)
{
	std::string underline;
	for (size_t i = 0; i < description.length(); i++)
	{
		underline += "-";
	}

	std::cout << std::endl << description << std::endl << underline << std::endl << std::endl;
}

/**
 * packet capture callback - called whenever a packet arrives
 */
void sslPacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	pcpp::Packet parsedPacket(packet);

	SSLPacketArrivedData* data = static_cast<SSLPacketArrivedData*>(cookie);

	// give the packet to the collector
	data->statsCollector->collectStats(&parsedPacket);

	// if needed - write the packet to the output pcap file
	if (data->pcapWriter != nullptr)
	{
		data->pcapWriter->writePacket(*packet);
	}
}

/**
 * An auxiliary method for sorting the string count map. Used in printServerNames() and in printCipherSuites()
 */
bool stringCountComparer(const std::pair<std::string, int>& first, const std::pair<std::string, int>& second)
{
	if (first.second == second.second)
	{
		return first.first > second.first;
	}
	return first.second > second.second;
}

/**
 * An auxiliary method for sorting the uint16_t count map. Used in printPorts()
 */
bool uint16CountComparer(std::pair<uint16_t, int> first, std::pair<uint16_t, int> second)
{
	if (first.second == second.second)
	{
		return first.first > second.first;
	}
	return first.second > second.second;
}

/**
 * Print the server-name count map to a table sorted by popularity (most popular names will be first)
 */
void printServerNames(ClientHelloStats& clientHelloStatsCollector)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back("Hostname");
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(40);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the server-name count map so the most popular names will be first
	// since it's not possible to sort a std::unordered_map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int>> map2vec(clientHelloStatsCollector.serverNameCount.begin(),
	                                                 clientHelloStatsCollector.serverNameCount.end());
	std::sort(map2vec.begin(), map2vec.end(), &stringCountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for (const auto& iter : map2vec)
	{
		std::stringstream values;
		values << iter.first << "|" << iter.second;
		printer.printRow(values.str(), '|');
	}
}

/**
 * Print SSL record version map
 */
void printVersions(std::unordered_map<uint16_t, int>& versionMap, const std::string& headline)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back(headline);
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(28);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the version map so the most popular version will be first
	// since it's not possible to sort a std::unordered_map you must copy it to a std::vector and sort it then
	std::vector<std::pair<uint16_t, int>> map2vec(versionMap.begin(), versionMap.end());
	std::sort(map2vec.begin(), map2vec.end(), &uint16CountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for (const auto& iter : map2vec)
	{
		std::stringstream values;
		values << pcpp::SSLVersion(iter.first).toString() << "|" << iter.second;
		printer.printRow(values.str(), '|');
	}
}

/**
 * Print used cipher-suite map to a table sorted by popularity (most popular cipher-suite will be first)
 */
void printCipherSuites(ServerHelloStats& serverHelloStats)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back("Cipher-suite");
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(50);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the cipher-suite count map so the most popular names will be first
	// since it's not possible to sort a std::unordered_map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int>> map2vec(serverHelloStats.cipherSuiteCount.begin(),
	                                                 serverHelloStats.cipherSuiteCount.end());
	std::sort(map2vec.begin(), map2vec.end(), &stringCountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for (const auto& iter : map2vec)
	{
		std::stringstream values;
		values << iter.first << "|" << iter.second;
		printer.printRow(values.str(), '|');
	}
}

void printPorts(SSLGeneralStats& stats)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back("SSL/TLS ports");
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(13);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the port count map so the most popular names will be first
	// since it's not possible to sort a std::unordered_map you must copy it to a std::vector and sort it then
	std::vector<std::pair<uint16_t, int>> map2vec(stats.sslPortCount.begin(), stats.sslPortCount.end());
	std::sort(map2vec.begin(), map2vec.end(), &uint16CountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for (const auto& iter : map2vec)
	{
		std::stringstream values;
		values << iter.first << "|" << iter.second;
		printer.printRow(values.str(), '|');
	}
}

/**
 * Print a summary of all statistics collected by the SSLStatsCollector. Should be called when traffic capture was
 * finished
 */
void printStatsSummary(SSLStatsCollector& collector)
{
	printStatsHeadline("General stats");
	PRINT_STAT_LINE("Sample time", collector.getGeneralStats().sampleTime, "Seconds");
	PRINT_STAT_LINE("Number of SSL packets", collector.getGeneralStats().numOfSSLPackets, "Packets");
	PRINT_STAT_LINE("Rate of SSL packets", collector.getGeneralStats().sslPacketRate.totalRate, "Packets/sec");
	PRINT_STAT_LINE("Number of SSL flows", collector.getGeneralStats().numOfSSLFlows, "Flows");
	PRINT_STAT_LINE("Rate of SSL flows", collector.getGeneralStats().sslFlowRate.totalRate, "Flows/sec");
	PRINT_STAT_LINE("Total SSL data", collector.getGeneralStats().amountOfSSLTraffic, "Bytes");
	PRINT_STAT_LINE("Rate of SSL data", collector.getGeneralStats().sslTrafficRate.totalRate, "Bytes/sec");
	PRINT_STAT_LINE("Average packets per flow", collector.getGeneralStats().averageNumOfPacketsPerFlow, "Packets");
	PRINT_STAT_LINE("Average data per flow", collector.getGeneralStats().averageAmountOfDataPerFlow, "Bytes");
	PRINT_STAT_LINE("Client-hello message", collector.getClientHelloStats().numOfMessages, "Messages");
	PRINT_STAT_LINE("Server-hello message", collector.getServerHelloStats().numOfMessages, "Messages");
	PRINT_STAT_LINE("Number of SSL flows with successful handshake",
	                collector.getGeneralStats().numOfHandshakeCompleteFlows, "Flows");
	PRINT_STAT_LINE("Number of SSL flows ended with alert", collector.getGeneralStats().numOfFlowsWithAlerts, "Flows");

	printStatsHeadline("SSL/TLS ports count");
	printPorts(collector.getGeneralStats());

	printStatsHeadline("SSL/TLS versions count");
	printVersions(collector.getGeneralStats().sslVersionCount, std::string("SSL/TLS version"));

	printStatsHeadline("Cipher-suite count");
	printCipherSuites(collector.getServerHelloStats());

	printStatsHeadline("Server-name count");
	printServerNames(collector.getClientHelloStats());
}

/**
 * Print the current rates. Should be called periodically during traffic capture
 */
void printCurrentRates(SSLStatsCollector& collector)
{
	printStatsHeadline("Current SSL rates");
	PRINT_STAT_LINE("Rate of SSL packets", collector.getGeneralStats().sslPacketRate.currentRate, "Packets/sec");
	PRINT_STAT_LINE("Rate of SSL flows", collector.getGeneralStats().sslFlowRate.currentRate, "Flows/sec");
	PRINT_STAT_LINE("Rate of SSL data", collector.getGeneralStats().sslTrafficRate.currentRate, "Bytes/sec");
	PRINT_STAT_LINE("Rate of SSL requests", collector.getClientHelloStats().messageRate.currentRate, "Requests/sec");
	PRINT_STAT_LINE("Rate of SSL responses", collector.getServerHelloStats().messageRate.currentRate, "Responses/sec");
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = static_cast<bool*>(cookie);
	*shouldStop = true;
}

/**
 * activate SSL/TLS analysis from pcap file
 */
void analyzeSSLFromPcapFile(const std::string& pcapFileName)
{
	// open input file (pcap or pcapng file)
	std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(pcapFileName));

	if (!reader->open())
		EXIT_WITH_ERROR("Could not open input pcap file");

	// read the input file packet by packet and give it to the SSLStatsCollector for collecting stats
	SSLStatsCollector collector;
	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		pcpp::Packet parsedPacket(&rawPacket);
		collector.collectStats(&parsedPacket);
	}

	// print stats summary
	std::cout << std::endl << std::endl << "STATS SUMMARY" << std::endl << "=============" << std::endl;
	printStatsSummary(collector);

	// close input file
	reader->close();
}

/**
 * activate SSL analysis from live traffic
 */
void analyzeSSLFromLiveTraffic(pcpp::PcapLiveDevice* dev, bool printRatesPeriodically, int printRatePeriod,
                               const std::string& savePacketsToFileName)
{
	// open the device
	if (!dev->open())
		EXIT_WITH_ERROR("Could not open the device");

	// set SSL/TLS ports filter on the live device to capture only SSL/TLS packets
	std::vector<pcpp::GeneralFilter*> portFilterVec;

	// Detect all ports considered as SSL/TLS traffic and add them to the filter.
	// The check is made for well known ports because currently SSLLayer does not support customizing of ports
	// considered as SSL/TLS.
	for (uint16_t port = 0; port < 1024; ++port)
		if (pcpp::SSLLayer::isSSLPort(port))
			portFilterVec.push_back(new pcpp::PortFilter(port, pcpp::SRC_OR_DST));

	// make an OR filter out of all port filters
	pcpp::OrFilter orFilter(portFilterVec);

	// set the filter for the device
	if (!dev->setFilter(orFilter))
	{
		std::string filterAsString;
		orFilter.parseToString(filterAsString);
		EXIT_WITH_ERROR("Couldn't set the filter '" << filterAsString << "' for the device");
	}

	// if needed to save the captured packets to file - open a writer device
	std::unique_ptr<pcpp::PcapFileWriterDevice> pcapWriter;
	if (savePacketsToFileName != "")
	{
		pcapWriter.reset(new pcpp::PcapFileWriterDevice(savePacketsToFileName));
		if (!pcapWriter->open())
		{
			EXIT_WITH_ERROR("Could not open pcap file for writing");
		}
	}

	// start capturing packets and collecting stats
	SSLPacketArrivedData data;
	SSLStatsCollector collector;
	data.statsCollector = &collector;
	data.pcapWriter = pcapWriter.get();
	dev->startCapture(sslPacketArrive, &data);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while (!shouldStop)
	{
		std::this_thread::sleep_for(std::chrono::seconds(printRatePeriod));

		// calculate rates
		if (printRatesPeriodically)
		{
			collector.calcRates();
			printCurrentRates(collector);
		}
	}

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	// calculate final rates
	collector.calcRates();

	// print stats summary
	std::cout << std::endl << std::endl << "STATS SUMMARY" << std::endl << "=============" << std::endl;
	printStatsSummary(collector);

	// close and free the writer device
	if (pcapWriter != nullptr)
	{
		pcapWriter->close();
	}
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
	bool printRatesPeriodically = true;
	int printRatePeriod = DEFAULT_CALC_RATES_PERIOD_SEC;
	std::string savePacketsToFileName = "";

	std::string readPacketsFromPcapFileName = "";

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "i:f:o:r:hvld", SSLAnalyzerOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'i':
			interfaceNameOrIP = optarg;
			break;
		case 'f':
			readPacketsFromPcapFileName = optarg;
			break;
		case 'o':
			savePacketsToFileName = optarg;
			break;
		case 'r':
			printRatePeriod = atoi(optarg);
			break;
		case 'd':
			printRatesPeriodically = false;
			break;
		case 'v':
			printAppVersion();
			break;
		case 'h':
			printUsage();
			exit(0);
			break;
		case 'l':
			listInterfaces();
			break;
		default:
			printUsage();
			exit(-1);
		}
	}

	// if no interface nor input pcap file were provided - exit with error
	if (readPacketsFromPcapFileName == "" && interfaceNameOrIP == "")
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// analyze in pcap file mode
	if (readPacketsFromPcapFileName != "")
	{
		analyzeSSLFromPcapFile(readPacketsFromPcapFileName);
	}
	else  // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceNameOrIP);
		if (dev == nullptr)
			EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");

		// start capturing and analyzing traffic
		analyzeSSLFromLiveTraffic(dev, printRatesPeriodically, printRatePeriod, savePacketsToFileName);
	}
}
