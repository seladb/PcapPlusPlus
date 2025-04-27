/**
 * HttpAnalyzer application
 * ========================
 * This application analyzes HTTP traffic and presents detailed and diverse information about it. It can operate in live
 * traffic mode where this information is collected on live packets or in file mode where packets are being read from a
 * pcap/pcapng file. The information collected by this application includes:
 * - general data: number of packets, packet rate, amount of traffic, bandwidth
 * - flow data: number of flow, flow rate, average packets per flow, average data per flow
 * - HTTP data: number and rate of HTTP requests, number and rate of HTTP responses, transaction count and rate,
 *      average transactions per flow, HTTP header size (total and average), HTTP body size, number of HTTP pipelining
 * flows
 * - hostname map
 * - HTTP method map
 * - HTTP status code map
 * - content-type map
 *
 * For more details about modes of operation and parameters run HttpAnalyzer -h
 */

#include <memory>
#include <iomanip>
#include <algorithm>
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "HttpStatsCollector.h"
#include "TablePrinter.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>
#include <iostream>
#include <sstream>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#define PRINT_STAT_LINE(description, counter, measurement)                                                             \
	std::cout << std::left << std::setw(40) << (std::string(description) + ":") << std::right << std::setw(15)         \
	          << std::fixed << std::showpoint << std::setprecision(3) << counter << " [" << measurement << "]"         \
	          << std::endl;

#define DEFAULT_CALC_RATES_PERIOD_SEC 2

// clang-format off
static struct option HttpAnalyzerOptions[] = {
	{ "interface",           required_argument, nullptr, 'i' },
	{ "dst-port",            required_argument, nullptr, 'p' },
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

struct HttpPacketArrivedData
{
	HttpStatsCollector* statsCollector;
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
	          << pcpp::AppName::get() << " [-vh] -f input_file" << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -f             : The input pcap/pcapng file to analyze. Required argument for this mode"
	          << std::endl
	          << "    -v             : Displays the current version and exists" << std::endl
	          << "    -h             : Displays this help message and exits" << std::endl
	          << std::endl
	          << "Usage: Live traffic mode:" << std::endl
	          << "-------------------------" << std::endl
	          << pcpp::AppName::get() << " [-hvld] [-o output_file] [-r calc_period] [-p dst_port] -i interface"
	          << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 "
	             "address"
	          << std::endl
	          << "    -p dst_port    : Use the specified port (optional parameter, the default is 80)" << std::endl
	          << "    -o output_file : Save all captured HTTP packets to a pcap file. Notice this may cause "
	             "performance degradation"
	          << std::endl
	          << "    -r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds"
	          << std::endl
	          << "    -d             : Disable periodic rates calculation" << std::endl
	          << "    -h             : Displays this help message and exits" << std::endl
	          << "    -v             : Displays the current version and exists" << std::endl
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
	const std::vector<pcpp::PcapLiveDevice*>& liveDevices =
	    pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << std::endl << "Network interfaces:" << std::endl;
	for (const auto& device : liveDevices)
	{
		std::cout << "    -> Name: '" << device->getName() << "'   IP address: " << device->getIPv4Address().toString()
		          << std::endl;
	}
	exit(0);
}

void printStatsHeadline(const std::string& description)
{
	std::cout << std::endl
	          << description << std::endl
	          << std::string(description.length(), '-') << std::endl
	          << std::endl;
}

/**
 * packet capture callback - called whenever a packet arrives
 */
void httpPacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	pcpp::Packet parsedPacket(packet);

	HttpPacketArrivedData* data = static_cast<HttpPacketArrivedData*>(cookie);

	// give the packet to the collector
	data->statsCollector->collectStats(&parsedPacket);

	// if needed - write the packet to the output pcap file
	if (data->pcapWriter != nullptr)
	{
		data->pcapWriter->writePacket(*packet);
	}
}

/**
 * Print the method count table
 */
void printMethods(const HttpRequestStats& reqStatscollector)
{
	// create the table
	std::vector<std::string> columnNames = { "Method", "Count" };
	std::vector<int> columnsWidths = { 9, 5 };
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// Copy elements to a vector
	std::vector<std::pair<pcpp::HttpRequestLayer::HttpMethod, int>> map2vec(reqStatscollector.methodCount.begin(),
	                                                                        reqStatscollector.methodCount.end());
	std::sort(
	    map2vec.begin(), map2vec.end(),
	    [](const std::pair<pcpp::HttpRequestLayer::HttpMethod, int>& left,
	       const std::pair<pcpp::HttpRequestLayer::HttpMethod, int>& right) { return left.second > right.second; });

	// go over the method count table, print each method and the aggregated figure
	for (auto iter : map2vec)
	{
		std::stringstream values;

		switch (iter.first)
		{
		case pcpp::HttpRequestLayer::HttpGET:
			values << "GET"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpGET);
			break;
		case pcpp::HttpRequestLayer::HttpPOST:
			values << "POST"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpPOST);
			break;
		case pcpp::HttpRequestLayer::HttpCONNECT:
			values << "CONNECT"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpCONNECT);
			break;
		case pcpp::HttpRequestLayer::HttpDELETE:
			values << "DELETE"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpDELETE);
			break;
		case pcpp::HttpRequestLayer::HttpHEAD:
			values << "HEAD"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpHEAD);
			break;
		case pcpp::HttpRequestLayer::HttpOPTIONS:
			values << "OPTIONS"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpOPTIONS);
			break;
		case pcpp::HttpRequestLayer::HttpPATCH:
			values << "PATCH"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpPATCH);
			break;
		case pcpp::HttpRequestLayer::HttpPUT:
			values << "PUT"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpPUT);
			break;
		case pcpp::HttpRequestLayer::HttpTRACE:
			values << "TRACE"
			       << "|" << reqStatscollector.methodCount.at(pcpp::HttpRequestLayer::HttpTRACE);
			break;
		default:
			break;
		}

		if (iter.first != pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown)
		{
			printer.printRow(values.str(), '|');
		}
	}
}

/**
 * An auxiliary method for sorting the hostname count map. Used only in printHostnames()
 */
bool hostnameComparer(const std::pair<std::string, int>& leftHost, const std::pair<std::string, int>& rightHost)
{
	return leftHost.second > rightHost.second ||
	       (leftHost.second == rightHost.second && leftHost.first > rightHost.first);
}

/**
 * Print the hostname count map to a table sorted by popularity (most popular hostnames will be first)
 */
void printHostnames(HttpRequestStats& reqStatscollector)
{
	// create the table
	std::vector<std::string> columnNames = { "Hostname", "Count" };
	std::vector<int> columnsWidths = { 40, 5 };

	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the hostname count map so the most popular hostnames will be first
	// since it's not possible to sort a std::unordered_map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int>> map2vec(reqStatscollector.hostnameCount.begin(),
	                                                 reqStatscollector.hostnameCount.end());
	std::sort(map2vec.begin(), map2vec.end(), &hostnameComparer);

	// go over all items (hostname + count) in the sorted vector and print them
	for (const auto& hostname : map2vec)
	{
		std::stringstream values;
		values << hostname.first << "|" << hostname.second;
		printer.printRow(values.str(), '|');
	}
}

/**
 * Print the status code count table
 */
void printStatusCodes(const HttpResponseStats& resStatscollector)
{
	// create the table
	std::vector<std::string> columnNames = { "Status Code", "Count" };
	std::vector<int> columnsWidths = { 28, 5 };
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// prints the status codes in lexical order
	std::vector<std::pair<std::string, int>> map2vec(resStatscollector.statusCodeCount.begin(),
	                                                 resStatscollector.statusCodeCount.end());
	std::sort(map2vec.begin(), map2vec.end(),
	          [](const std::pair<std::string, int>& left, const std::pair<std::string, int>& right) {
		          return left.first < right.first;
	          });
	for (const auto& statusCodeStat : map2vec)
	{
		std::stringstream values;
		values << statusCodeStat.first << "|" << statusCodeStat.second;
		printer.printRow(values.str(), '|');
	}
}

/**
 * Print the content-type count table
 */
void printContentTypes(const HttpResponseStats& resStatscollector)
{
	// create the table
	std::vector<std::string> columnNames = { "Content-type", "Count" };
	std::vector<int> columnsWidths = { 30, 5 };
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// prints the content-types in lexical order
	std::vector<std::pair<std::string, int>> map2vec(resStatscollector.contentTypeCount.begin(),
	                                                 resStatscollector.contentTypeCount.end());
	std::sort(map2vec.begin(), map2vec.end(),
	          [](const std::pair<std::string, int>& left, const std::pair<std::string, int>& right) {
		          return left.first < right.first;
	          });
	for (const auto& contentTypeStat : map2vec)
	{
		std::stringstream values;
		values << contentTypeStat.first << "|" << contentTypeStat.second;
		printer.printRow(values.str(), '|');
	}
}

/**
 * Print a summary of all statistics collected by the HttpStatsCollector. Should be called when traffic capture was
 * finished
 */
void printStatsSummary(HttpStatsCollector& collector)
{
	printStatsHeadline("General stats");
	PRINT_STAT_LINE("Sample time", collector.getGeneralStats().sampleTime, "Seconds");
	PRINT_STAT_LINE("Number of HTTP packets", collector.getGeneralStats().numOfHttpPackets, "Packets");
	PRINT_STAT_LINE("Rate of HTTP packets", collector.getGeneralStats().httpPacketRate.totalRate, "Packets/sec");
	PRINT_STAT_LINE("Number of HTTP flows", collector.getGeneralStats().numOfHttpFlows, "Flows");
	PRINT_STAT_LINE("Rate of HTTP flows", collector.getGeneralStats().httpFlowRate.totalRate, "Flows/sec");
	PRINT_STAT_LINE("Number of HTTP pipelining flows", collector.getGeneralStats().numOfHttpPipeliningFlows, "Flows");
	PRINT_STAT_LINE("Number of HTTP transactions", collector.getGeneralStats().numOfHttpTransactions, "Transactions");
	PRINT_STAT_LINE("Rate of HTTP transactions", collector.getGeneralStats().httpTransactionsRate.totalRate,
	                "Transactions/sec");
	PRINT_STAT_LINE("Total HTTP data", collector.getGeneralStats().amountOfHttpTraffic, "Bytes");
	PRINT_STAT_LINE("Rate of HTTP data", collector.getGeneralStats().httpTrafficRate.totalRate, "Bytes/sec");
	PRINT_STAT_LINE("Average packets per flow", collector.getGeneralStats().averageNumOfPacketsPerFlow, "Packets");
	PRINT_STAT_LINE("Average transactions per flow", collector.getGeneralStats().averageNumOfHttpTransactionsPerFlow,
	                "Transactions");
	PRINT_STAT_LINE("Average data per flow", collector.getGeneralStats().averageAmountOfDataPerFlow, "Bytes");

	printStatsHeadline("HTTP request stats");
	PRINT_STAT_LINE("Number of HTTP requests", collector.getRequestStats().numOfMessages, "Requests");
	PRINT_STAT_LINE("Rate of HTTP requests", collector.getRequestStats().messageRate.totalRate, "Requests/sec");
	PRINT_STAT_LINE("Total data in headers", collector.getRequestStats().totalMessageHeaderSize, "Bytes");
	PRINT_STAT_LINE("Average header size", collector.getRequestStats().averageMessageHeaderSize, "Bytes");

	printStatsHeadline("HTTP response stats");
	PRINT_STAT_LINE("Number of HTTP responses", collector.getResponseStats().numOfMessages, "Responses");
	PRINT_STAT_LINE("Rate of HTTP responses", collector.getResponseStats().messageRate.totalRate, "Responses/sec");
	PRINT_STAT_LINE("Total data in headers", collector.getResponseStats().totalMessageHeaderSize, "Bytes");
	PRINT_STAT_LINE("Average header size", collector.getResponseStats().averageMessageHeaderSize, "Bytes");
	PRINT_STAT_LINE("Num of responses with content-length", collector.getResponseStats().numOfMessagesWithContentLength,
	                "Responses");
	PRINT_STAT_LINE("Total body size (may be compressed)", collector.getResponseStats().totalContentLengthSize,
	                "Bytes");
	PRINT_STAT_LINE("Average body size", collector.getResponseStats().averageContentLengthSize, "Bytes");

	printStatsHeadline("HTTP request methods");
	printMethods(collector.getRequestStats());

	printStatsHeadline("Hostnames count");
	printHostnames(collector.getRequestStats());

	printStatsHeadline("Status code count");
	printStatusCodes(collector.getResponseStats());

	printStatsHeadline("Content-type count");
	printContentTypes(collector.getResponseStats());
}

/**
 * Print the current rates. Should be called periodically during traffic capture
 */
void printCurrentRates(HttpStatsCollector& collector)
{
	printStatsHeadline("Current HTTP rates");
	PRINT_STAT_LINE("Rate of HTTP packets", collector.getGeneralStats().httpPacketRate.currentRate, "Packets/sec");
	PRINT_STAT_LINE("Rate of HTTP flows", collector.getGeneralStats().httpFlowRate.currentRate, "Flows/sec");
	PRINT_STAT_LINE("Rate of HTTP transactions", collector.getGeneralStats().httpTransactionsRate.currentRate,
	                "Transactions/sec");
	PRINT_STAT_LINE("Rate of HTTP data", collector.getGeneralStats().httpTrafficRate.currentRate, "Bytes/sec");
	PRINT_STAT_LINE("Rate of HTTP requests", collector.getRequestStats().messageRate.currentRate, "Requests/sec");
	PRINT_STAT_LINE("Rate of HTTP responses", collector.getResponseStats().messageRate.currentRate, "Responses/sec");
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
 * activate HTTP analysis from pcap file
 */
void analyzeHttpFromPcapFile(const std::string& pcapFileName, uint16_t dstPort)
{
	// open input file (pcap or pcapng file)
	std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(pcapFileName));

	if (!reader->open())
		EXIT_WITH_ERROR("Could not open input pcap file");

	// set a port  filter on the reader device to process only HTTP packets
	pcpp::PortFilter httpPortFilter(dstPort, pcpp::SRC_OR_DST);
	if (!reader->setFilter(httpPortFilter))
		EXIT_WITH_ERROR("Could not set up filter on file");

	// read the input file packet by packet and give it to the HttpStatsCollector for collecting stats
	HttpStatsCollector collector(dstPort);
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
 * activate HTTP analysis from live traffic
 */
void analyzeHttpFromLiveTraffic(pcpp::PcapLiveDevice* dev, bool printRatesPeriodically, int printRatePeriod,
                                const std::string& savePacketsToFileName, uint16_t dstPort)
{
	// open the device
	if (!dev->open())
		EXIT_WITH_ERROR("Could not open the device");

	pcpp::PortFilter httpPortFilter(dstPort, pcpp::SRC_OR_DST);
	if (!dev->setFilter(httpPortFilter))
		EXIT_WITH_ERROR("Could not set up filter on device");

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
	HttpPacketArrivedData data;
	HttpStatsCollector collector(dstPort);
	data.statsCollector = &collector;
	data.pcapWriter = pcapWriter.get();
	dev->startCapture(httpPacketArrive, &data);

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
	std::string port = "80";
	bool printRatesPeriodically = true;
	int printRatePeriod = DEFAULT_CALC_RATES_PERIOD_SEC;
	std::string savePacketsToFileName = "";

	std::string readPacketsFromPcapFileName = "";

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "i:p:f:o:r:hvld", HttpAnalyzerOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'i':
			interfaceNameOrIP = optarg;
			break;
		case 'p':
			port = optarg;
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

	// if no interface nor input pcap file were provided - exit with error
	if (readPacketsFromPcapFileName == "" && interfaceNameOrIP == "")
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// get the port
	int nPort = atoi(port.c_str());
	if (nPort <= 0 || nPort > 65535)
		EXIT_WITH_ERROR("Please input a number between 0 to 65535");

	// analyze in pcap file mode
	if (readPacketsFromPcapFileName != "")
	{
		analyzeHttpFromPcapFile(readPacketsFromPcapFileName, nPort);
	}
	else  // analyze in live traffic mode
	{
		pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceNameOrIP);
		if (dev == nullptr)
			EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");

		// start capturing and analyzing traffic
		analyzeHttpFromLiveTraffic(dev, printRatesPeriodically, printRatePeriod, savePacketsToFileName, nPort);
	}
}
