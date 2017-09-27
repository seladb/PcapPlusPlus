/**
 * HttpAnalyzer application
 * ========================
 * This application analyzes HTTP traffic and presents detailed and diverse information about it. It can operate in live traffic
 * mode where this information is collected on live packets or in file mode where packets are being read from a pcap/pcapng file. The
 * information collected by this application includes:
 * - general data: number of packets, packet rate, amount of traffic, bandwidth
 * - flow data: number of flow, flow rate, average packets per flow, average data per flow
 * - HTTP data: number and rate of HTTP requests, number and rate of HTTP responses, transaction count and rate,
 *      average transactions per flow, HTTP header size (total and average), HTTP body size, number of HTTP pipelining flows
 * - hostname map
 * - HTTP method map
 * - HTTP status code map
 * - content-type map
 *
 * For more details about modes of operation and parameters run HttpAnalyzer -h
 */

#include <stdlib.h>
#include <string.h>
#include <algorithm>
#if !defined(WIN32) && !defined(WINx64) //for using ntohl, ntohs, etc.
#include <in.h>
#endif
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "HttpStatsCollector.h"
#include "TablePrinter.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#define PRINT_STAT_LINE(description, counter, measurement, type) \
		printf("%-40s %14" type " [%s]\n", description ":", counter,  measurement)

#define PRINT_STAT_LINE_INT(description, counter, measurement) \
		PRINT_STAT_LINE(description, counter, measurement, "d")

#define PRINT_STAT_LINE_DOUBLE(description, counter, measurement) \
		PRINT_STAT_LINE(description, counter, measurement, ".3f")

#define PRINT_STAT_HEADLINE(description) \
		printf("\n" description "\n--------------------\n\n")


#define DEFAULT_CALC_RATES_PERIOD_SEC 2

using namespace pcpp;

static struct option HttpAnalyzerOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"input-file",  required_argument, 0, 'f'},
	{"output-file", required_argument, 0, 'o'},
	{"rate-calc-period", required_argument, 0, 'r'},
	{"disable-rates-print", no_argument, 0, 'd'},
	{"list-interfaces", no_argument, 0, 'l'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};



struct HttpPacketArrivedData
{
	HttpStatsCollector* statsCollector;
	PcapFileWriterDevice* pcapWriter;
};


/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage: PCAP file mode:\n"
			"----------------------\n"
			"%s [-vh] -f input_file\n"
			"\nOptions:\n\n"
			"    -f           : The input pcap/pcapng file to analyze. Required argument for this mode\n"
			"    -v             : Displays the current version and exists\n"
			"    -h           : Displays this help message and exits\n\n"
			"Usage: Live traffic mode:\n"
			"-------------------------\n"
			"%s [-hvld] [-o output_file] [-r calc_period] -i interface\n"
			"\nOptions:\n\n"
			"    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
			"    -o output_file : Save all captured HTTP packets to a pcap file. Notice this may cause performance degradation\n"
			"    -r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds\n"
			"    -d             : Disable periodic rates calculation\n"
			"    -h             : Displays this help message and exits\n"
			"    -v             : Displays the current version and exists\n"
			"    -l             : Print the list of interfaces and exists\n", AppName::get().c_str(), AppName::get().c_str());
	exit(0);
}


/**
 * Print application version
 */
void printAppVersion()
{
	printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Built from: %s\n", getGitInfo().c_str());
	exit(0);
}


/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const std::vector<PcapLiveDevice*>& devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	printf("\nNetwork interfaces:\n");
	for (std::vector<PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
	}
	exit(0);
}


/**
 * packet capture callback - called whenever a packet arrives
 */
void httpPacketArrive(RawPacket* packet, PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	Packet parsedPacket(packet);

	HttpPacketArrivedData* data  = (HttpPacketArrivedData*)cookie;

	// give the packet to the collector
	data->statsCollector->collectStats(&parsedPacket);

	// if needed - write the packet to the output pcap file
	if (data->pcapWriter != NULL)
	{
		data->pcapWriter->writePacket(*packet);
	}
}

/**
 * Print the method count table
 */
void printMethods(HttpRequestStats& reqStatscollector)
{
	// create the table
	TablePrinter<std::string, int> printer("Method", 9, "Count", 5);

	// go over the method count table and print each method and count
	for(std::map<HttpRequestLayer::HttpMethod, int>::iterator iter = reqStatscollector.methodCount.begin();
			iter != reqStatscollector.methodCount.end();
			iter++)
	{
		switch (iter->first)
		{
		case HttpRequestLayer::HttpGET:
			printer.printRow("GET", reqStatscollector.methodCount[HttpRequestLayer::HttpGET]);
			break;
		case HttpRequestLayer::HttpPOST:
			printer.printRow("POST", reqStatscollector.methodCount[HttpRequestLayer::HttpPOST]);
			break;
		case HttpRequestLayer::HttpCONNECT:
			printer.printRow("CONNECT", reqStatscollector.methodCount[HttpRequestLayer::HttpCONNECT]);
			break;
		case HttpRequestLayer::HttpDELETE:
			printer.printRow("DELETE", reqStatscollector.methodCount[HttpRequestLayer::HttpDELETE]);
			break;
		case HttpRequestLayer::HttpHEAD:
			printer.printRow("HEAD", reqStatscollector.methodCount[HttpRequestLayer::HttpHEAD]);
			break;
		case HttpRequestLayer::HttpOPTIONS:
			printer.printRow("OPTIONS", reqStatscollector.methodCount[HttpRequestLayer::HttpOPTIONS]);
			break;
		case HttpRequestLayer::HttpPATCH:
			printer.printRow("PATCH", reqStatscollector.methodCount[HttpRequestLayer::HttpPATCH]);
			break;
		case HttpRequestLayer::HttpPUT:
			printer.printRow("PUT", reqStatscollector.methodCount[HttpRequestLayer::HttpPUT]);
			break;
		case HttpRequestLayer::HttpTRACE:
			printer.printRow("TRACE", reqStatscollector.methodCount[HttpRequestLayer::HttpTRACE]);
			break;
		default:
			break;
		}

	}

	printer.closeTable();
}


/**
 * An auxiliary method for sorting the hostname count map. Used only in printHostnames()
 */
bool hostnameComparer(std::pair<std::string, int> first, std::pair<std::string, int> second)
{
	return first.second > second.second;
}

/**
 * Print the hostname count map to a table sorted by popularity (most popular hostnames will be first)
 */
void printHostnames(HttpRequestStats& reqStatscollector)
{
	// create the table
	TablePrinter<std::string, int> printer("Hostname", 40, "Count", 5);

	// sort the hostname count map so the most popular hostnames will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int> > map2vec(reqStatscollector.hostnameCount.begin(), reqStatscollector.hostnameCount.end());
	std::sort(map2vec.begin(),map2vec.end(), &hostnameComparer);

	// go over all items (hostname + count) in the sorted vector and print them
	for(std::vector<std::pair<std::string, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		printer.printRow(iter->first, iter->second);
	}

	printer.closeTable();
}


/**
 * Print the status code count table
 */
void printStatusCodes(HttpResponseStats& resStatscollector)
{
	// create the table
	TablePrinter<std::string, int> printer("Status Code", 28, "Count", 5);

	// go over the status code map and print each item
	for(std::map<std::string, int>::iterator iter = resStatscollector.statusCodeCount.begin();
			iter != resStatscollector.statusCodeCount.end();
			iter++)
	{
		printer.printRow(iter->first, iter->second);
	}

	printer.closeTable();
}


/**
 * Print the content-type count table
 */
void printContentTypes(HttpResponseStats& resStatscollector)
{
	// create the table
	TablePrinter<std::string, int> printer("Content-type", 30, "Count", 5);

	// go over the status code map and print each item
	for(std::map<std::string, int>::iterator iter = resStatscollector.contentTypeCount.begin();
			iter != resStatscollector.contentTypeCount.end();
			iter++)
	{
		printer.printRow(iter->first, iter->second);
	}

	printer.closeTable();
}


/**
 * Print a summary of all statistics collected by the HttpStatsCollector. Should be called when traffic capture was finished
 */
void printStatsSummary(HttpStatsCollector& collector)
{
	PRINT_STAT_HEADLINE("General stats");
	PRINT_STAT_LINE_DOUBLE("Sample time", collector.getGeneralStats().sampleTime, "Seconds");
	PRINT_STAT_LINE_INT("Number of HTTP packets", collector.getGeneralStats().numOfHttpPackets, "Packets");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP packets", collector.getGeneralStats().httpPacketRate.totalRate, "Packets/sec");
	PRINT_STAT_LINE_INT("Number of HTTP flows", collector.getGeneralStats().numOfHttpFlows, "Flows");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP flows", collector.getGeneralStats().httpFlowRate.totalRate, "Flows/sec");
	PRINT_STAT_LINE_INT("Number of HTTP pipelining flows", collector.getGeneralStats().numOfHttpPipeliningFlows, "Flows");
	PRINT_STAT_LINE_INT("Number of HTTP transactions", collector.getGeneralStats().numOfHttpTransactions, "Transactions");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP transactions", collector.getGeneralStats().httpTransactionsRate.totalRate, "Transactions/sec");
	PRINT_STAT_LINE_INT("Total HTTP data", collector.getGeneralStats().amountOfHttpTraffic, "Bytes");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP data", collector.getGeneralStats().httpTrafficRate.totalRate, "Bytes/sec");
	PRINT_STAT_LINE_DOUBLE("Average packets per flow", collector.getGeneralStats().averageNumOfPacketsPerFlow, "Packets");
	PRINT_STAT_LINE_DOUBLE("Average transactions per flow", collector.getGeneralStats().averageNumOfHttpTransactionsPerFlow, "Transactions");
	PRINT_STAT_LINE_DOUBLE("Average data per flow", collector.getGeneralStats().averageAmountOfDataPerFlow, "Bytes");

	PRINT_STAT_HEADLINE("HTTP request stats");
	PRINT_STAT_LINE_INT("Number of HTTP requests", collector.getRequestStats().numOfMessages, "Requests");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP requests", collector.getRequestStats().messageRate.totalRate, "Requests/sec");
	PRINT_STAT_LINE_INT("Total data in headers", collector.getRequestStats().totalMessageHeaderSize, "Bytes");
	PRINT_STAT_LINE_DOUBLE("Average header size", collector.getRequestStats().averageMessageHeaderSize, "Bytes");

	PRINT_STAT_HEADLINE("HTTP response stats");
	PRINT_STAT_LINE_INT("Number of HTTP responses", collector.getResponseStats().numOfMessages, "Responses");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP responses", collector.getResponseStats().messageRate.totalRate, "Responses/sec");
	PRINT_STAT_LINE_INT("Total data in headers", collector.getResponseStats().totalMessageHeaderSize, "Bytes");
	PRINT_STAT_LINE_DOUBLE("Average header size", collector.getResponseStats().averageMessageHeaderSize, "Bytes");
	PRINT_STAT_LINE_INT("Num of responses with content-length", collector.getResponseStats().numOfMessagesWithContentLength, "Responses");
	PRINT_STAT_LINE_INT("Total body size (may be compressed)", collector.getResponseStats().totalConentLengthSize, "Bytes");
	PRINT_STAT_LINE_DOUBLE("Average body size", collector.getResponseStats().averageContentLengthSize, "Bytes");

	PRINT_STAT_HEADLINE("HTTP request methods");
	printMethods(collector.getRequestStats());

	PRINT_STAT_HEADLINE("Hostnames count");
	printHostnames(collector.getRequestStats());

	PRINT_STAT_HEADLINE("Status code count");
	printStatusCodes(collector.getResponseStats());

	PRINT_STAT_HEADLINE("Content-type count");
	printContentTypes(collector.getResponseStats());
}


/**
 * Print the current rates. Should be called periodically during traffic capture
 */
void printCurrentRates(HttpStatsCollector& collector)
{
	PRINT_STAT_HEADLINE("Current HTTP rates");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP packets", collector.getGeneralStats().httpPacketRate.currentRate, "Packets/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP flows", collector.getGeneralStats().httpFlowRate.currentRate, "Flows/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP transactions", collector.getGeneralStats().httpTransactionsRate.currentRate, "Transactions/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP data", collector.getGeneralStats().httpTrafficRate.currentRate, "Bytes/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP requests", collector.getRequestStats().messageRate.currentRate, "Requests/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of HTTP responses", collector.getResponseStats().messageRate.currentRate, "Responses/sec");
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


/**
 * activate HTTP analysis from pcap file
 */
void analyzeHttpFromPcapFile(std::string pcapFileName)
{
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(pcapFileName.c_str());

	if (!reader->open())
		EXIT_WITH_ERROR("Could not open input pcap file");

	// set a port 80 filter on the reader device to process only HTTP packets
	PortFilter httpPortFilter(80, SRC_OR_DST);
	reader->setFilter(httpPortFilter);

	// read the input file packet by packet and give it to the HttpStatsCollector for collecting stats
	HttpStatsCollector collector;
	RawPacket rawPacket;
	while(reader->getNextPacket(rawPacket))
	{
		Packet parsedPacket(&rawPacket);
		collector.collectStats(&parsedPacket);
	}

	// print stats summary
	printf("\n\n");
	printf("STATS SUMMARY\n");
	printf("=============\n");
	printStatsSummary(collector);

	// close input file
	reader->close();

	// free reader memory
	delete reader;
}


/**
 * activate HTTP analysis from live traffic
 */
void analyzeHttpFromLiveTraffic(PcapLiveDevice* dev, bool printRatesPeriodicaly, int printRatePeriod, std::string savePacketsToFileName)
{
	// open the device
	if (!dev->open())
		EXIT_WITH_ERROR("Could not open the device");

	// set a port 80 filter on the live device to capture only HTTP packets
	PortFilter httpPortFilter(80, SRC_OR_DST);
	dev->setFilter(httpPortFilter);

	// if needed to save the captured packets to file - open a writer device
	PcapFileWriterDevice* pcapWriter = NULL;
	if (savePacketsToFileName != "")
	{
		pcapWriter = new PcapFileWriterDevice(savePacketsToFileName.c_str());
		if (!pcapWriter->open())
		{
			EXIT_WITH_ERROR("Could not open pcap file for writing");
		}
	}

	// start capturing packets and collecting stats
	HttpPacketArrivedData data;
	HttpStatsCollector collector;
	data.statsCollector = &collector;
	data.pcapWriter = pcapWriter;
	dev->startCapture(httpPacketArrive, &data);


	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while(!shouldStop)
	{
		PCAP_SLEEP(printRatePeriod);

		// calculate rates
		if (printRatesPeriodicaly)
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
	printf("\n\nSTATS SUMMARY\n");
	printf("=============\n");
	printStatsSummary(collector);

	// close and free the writer device
	if (pcapWriter != NULL)
	{
		pcapWriter->close();
		delete pcapWriter;
	}
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
	bool printRatesPeriodicaly = true;
	int printRatePeriod = DEFAULT_CALC_RATES_PERIOD_SEC;
	std::string savePacketsToFileName = "";

	std::string readPacketsFromPcapFileName = "";


	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:f:o:r:hvld", HttpAnalyzerOptions, &optionIndex)) != -1)
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
				printRatesPeriodicaly = false;
				break;
			case 'h':
				printUsage();
				break;
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

	// analyze in pcap file mode
	if (readPacketsFromPcapFileName != "")
	{
		analyzeHttpFromPcapFile(readPacketsFromPcapFileName);
	}
	else // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		PcapLiveDevice* dev = NULL;
		IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided IP");
		}
		else
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided name");
		}

		// start capturing and analyzing traffic
		analyzeHttpFromLiveTraffic(dev, printRatesPeriodicaly, printRatePeriod, savePacketsToFileName);
	}
}
