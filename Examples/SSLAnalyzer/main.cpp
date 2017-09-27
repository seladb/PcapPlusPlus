/**
 * SSLAnalyzer application
 * ========================
 * This application analyzes SSL/TLS traffic and presents detailed and diverse information about it. It can operate in live traffic
 * mode where this information is collected on live packets or in file mode where packets are being read from a pcap/pcapng file. The
 * information collected by this application includes:
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

#include <stdlib.h>
#include <string.h>
#include <algorithm>
#if !defined(WIN32) && !defined(WINx64) //for using ntohl, ntohs, etc.
#include <in.h>
#endif
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "SSLStatsCollector.h"
#include "TablePrinter.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>

using namespace pcpp;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#define PRINT_STAT_LINE(description, counter, measurement, type) \
		printf("%-46s %14" type " [%s]\n", description ":", counter,  measurement)

#define PRINT_STAT_LINE_INT(description, counter, measurement) \
		PRINT_STAT_LINE(description, counter, measurement, "d")

#define PRINT_STAT_LINE_DOUBLE(description, counter, measurement) \
		PRINT_STAT_LINE(description, counter, measurement, ".3f")

#define PRINT_STAT_HEADLINE(description) \
		printf("\n" description "\n--------------------\n\n")


#define DEFAULT_CALC_RATES_PERIOD_SEC 2

static struct option SSLAnalyzerOptions[] =
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



struct SSLPacketArrivedData
{
	SSLStatsCollector* statsCollector;
	PcapFileWriterDevice* pcapWriter;
};


/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage: PCAP file mode:\n"
			"----------------------\n"
			"%s [-hv] -f input_file\n"
			"\nOptions:\n\n"
			"    -f           : The input pcap/pcapng file to analyze. Required argument for this mode\n"
			"    -v           : Displays the current version and exists\n"
			"    -h           : Displays this help message and exits\n\n"
			"Usage: Live traffic mode:\n"
			"-------------------------\n"
			"%s [-hvld] [-o output_file] [-r calc_period] -i interface\n"
			"\nOptions:\n\n"
			"    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
			"    -o output_file : Save all captured SSL packets to a pcap file. Notice this may cause performance degradation\n"
			"    -r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds\n"
			"    -d             : Disable periodic rates calculation\n"
			"    -v             : Displays the current version and exists\n"
			"    -h             : Displays this help message and exits\n"
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
void sslPacketArrive(RawPacket* packet, PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	Packet parsedPacket(packet);

	SSLPacketArrivedData* data  = (SSLPacketArrivedData*)cookie;

	// give the packet to the collector
	data->statsCollector->collectStats(&parsedPacket);

	// if needed - write the packet to the output pcap file
	if (data->pcapWriter != NULL)
	{
		data->pcapWriter->writePacket(*packet);
	}
}


/**
 * An auxiliary method for sorting the string count map. Used in printServerNames() and in printCipherSuites()
 */
bool stringCountComparer(std::pair<std::string, int> first, std::pair<std::string, int> second)
{
	return first.second > second.second;
}


/**
 * An auxiliary method for sorting the uint16_t count map. Used in printPorts()
 */
bool uint16CountComparer(std::pair<uint16_t, int> first, std::pair<uint16_t, int> second)
{
	return first.second > second.second;
}


/**
 * Print the server-name count map to a table sorted by popularity (most popular names will be first)
 */
void printServerNames(ClientHelloStats& clientHelloStatsCollector)
{
	// create the table
	TablePrinter<std::string, int> printer("Hostname", 40, "Count", 5);

	// sort the server-name count map so the most popular names will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int> > map2vec(clientHelloStatsCollector.serverNameCount.begin(), clientHelloStatsCollector.serverNameCount.end());
	std::sort(map2vec.begin(),map2vec.end(), &stringCountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for(std::vector<std::pair<std::string, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		printer.printRow(iter->first, iter->second);
	}

	printer.closeTable();
}


/**
 * Print SSL record version map
 */
void printVersions(std::map<SSLVersion, int>& versionMap, std::string headline)
{
	// create the table
	TablePrinter<std::string, int> printer(headline, 28, "Count", 5);

	// go over the status code map and print each item
	for(std::map<SSLVersion, int>::iterator iter = versionMap.begin();
			iter != versionMap.end();
			iter++)
	{
		printer.printRow(SSLLayer::sslVersionToString(iter->first), iter->second);
	}

	printer.closeTable();
}


/**
 * Print used cipher-suite map to a table sorted by popularity (most popular cipher-suite will be first)
 */
void printCipherSuites(ServerHelloStats& serverHelloStats)
{
	// create the table
	TablePrinter<std::string, int> printer("Cipher-suite", 50, "Count", 5);

	// sort the cipher-suite count map so the most popular names will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int> > map2vec(serverHelloStats.cipherSuiteCount.begin(), serverHelloStats.cipherSuiteCount.end());
	std::sort(map2vec.begin(),map2vec.end(), &stringCountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for(std::vector<std::pair<std::string, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		printer.printRow(iter->first, iter->second);
	}

	printer.closeTable();
}


void printPorts(SSLGeneralStats& stats)
{
	// create the table
	TablePrinter<std::string, int> printer("SSL/TLS ports", 13, "Count", 5);

	// sort the port count map so the most popular names will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<uint16_t, int> > map2vec(stats.sslPortCount.begin(), stats.sslPortCount.end());
	std::sort(map2vec.begin(),map2vec.end(), &uint16CountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for(std::vector<std::pair<uint16_t, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		std::ostringstream portStream;
		portStream << (int)iter->first;
		printer.printRow(portStream.str(), iter->second);
	}

	printer.closeTable();
}


/**
 * Print a summary of all statistics collected by the SSLStatsCollector. Should be called when traffic capture was finished
 */
void printStatsSummary(SSLStatsCollector& collector)
{
	PRINT_STAT_HEADLINE("General stats");
	PRINT_STAT_LINE_DOUBLE("Sample time", collector.getGeneralStats().sampleTime, "Seconds");
	PRINT_STAT_LINE_INT("Number of SSL packets", collector.getGeneralStats().numOfSSLPackets, "Packets");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL packets", collector.getGeneralStats().sslPacketRate.totalRate, "Packets/sec");
	PRINT_STAT_LINE_INT("Number of SSL flows", collector.getGeneralStats().numOfSSLFlows, "Flows");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL flows", collector.getGeneralStats().sslFlowRate.totalRate, "Flows/sec");
	PRINT_STAT_LINE_INT("Total SSL data", collector.getGeneralStats().amountOfSSLTraffic, "Bytes");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL data", collector.getGeneralStats().sslTrafficRate.totalRate, "Bytes/sec");
	PRINT_STAT_LINE_DOUBLE("Average packets per flow", collector.getGeneralStats().averageNumOfPacketsPerFlow, "Packets");
	PRINT_STAT_LINE_DOUBLE("Average data per flow", collector.getGeneralStats().averageAmountOfDataPerFlow, "Bytes");
	PRINT_STAT_LINE_INT("Client-hello message", collector.getClientHelloStats().numOfMessages, "Messages");
	PRINT_STAT_LINE_INT("Server-hello message", collector.getServerHelloStats().numOfMessages, "Messages");
	PRINT_STAT_LINE_INT("Number of SSL flows with successful handshake", collector.getGeneralStats().numOfHandshakeCompleteFlows, "Flows");
	PRINT_STAT_LINE_INT("Number of SSL flows ended with alert", collector.getGeneralStats().numOfFlowsWithAlerts, "Flows");

	PRINT_STAT_HEADLINE("SSL/TLS ports count");
	printPorts(collector.getGeneralStats());

	PRINT_STAT_HEADLINE("SSL versions count");
	printVersions(collector.getGeneralStats().sslRecordVersionCount, std::string("SSL record version"));

	PRINT_STAT_HEADLINE("Client-hello versions count");
	printVersions(collector.getClientHelloStats().sslClientHelloVersionCount, std::string("Client-hello version"));

	PRINT_STAT_HEADLINE("Cipher-suite count");
	printCipherSuites(collector.getServerHelloStats());

	PRINT_STAT_HEADLINE("Server-name count");
	printServerNames(collector.getClientHelloStats());

}


/**
 * Print the current rates. Should be called periodically during traffic capture
 */
void printCurrentRates(SSLStatsCollector& collector)
{
	PRINT_STAT_HEADLINE("Current SSL rates");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL packets", collector.getGeneralStats().sslPacketRate.currentRate, "Packets/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL flows", collector.getGeneralStats().sslFlowRate.currentRate, "Flows/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL data", collector.getGeneralStats().sslTrafficRate.currentRate, "Bytes/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL requests", collector.getClientHelloStats().messageRate.currentRate, "Requests/sec");
	PRINT_STAT_LINE_DOUBLE("Rate of SSL responses", collector.getServerHelloStats().messageRate.currentRate, "Responses/sec");
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
 * activate SSL/TLS analysis from pcap file
 */
void analyzeSSLFromPcapFile(std::string pcapFileName)
{
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(pcapFileName.c_str());

	if (!reader->open())
		EXIT_WITH_ERROR("Could not open input pcap file");

	// read the input file packet by packet and give it to the SSLStatsCollector for collecting stats
	SSLStatsCollector collector;
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
 * activate SSL analysis from live traffic
 */
void analyzeSSLFromLiveTraffic(PcapLiveDevice* dev, bool printRatesPeriodicaly, int printRatePeriod, std::string savePacketsToFileName)
{
	// open the device
	if (!dev->open())
		EXIT_WITH_ERROR("Could not open the device");

	// set SSL/TLS ports filter on the live device to capture only SSL/TLS packets
	std::vector<GeneralFilter*> portFilterVec;

	// get all ports considered as SSL/TLS traffic and add them to the filter
	for (std::map<uint16_t, bool>::const_iterator it = SSLLayer::getSSLPortMap()->begin(); it != SSLLayer::getSSLPortMap()->end(); ++it)
	{
		portFilterVec.push_back(new PortFilter(it->first, pcpp::SRC_OR_DST));
	}

	// make an OR filter out of all port filters
	OrFilter orFilter(portFilterVec);

	// set the filter for the device
	if (!dev->setFilter(orFilter))
	{
		std::string filterAsString;
		orFilter.parseToString(filterAsString);
		EXIT_WITH_ERROR("Couldn't set the filter '%s' for the device", filterAsString.c_str());
	}


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
	SSLPacketArrivedData data;
	SSLStatsCollector collector;
	data.statsCollector = &collector;
	data.pcapWriter = pcapWriter;
	dev->startCapture(sslPacketArrive, &data);


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

	while((opt = getopt_long (argc, argv, "i:f:o:r:hvld", SSLAnalyzerOptions, &optionIndex)) != -1)
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
			case 'v':
				printAppVersion();
				break;
			case 'h':
				printUsage();
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
		analyzeSSLFromLiveTraffic(dev, printRatesPeriodicaly, printRatePeriod, savePacketsToFileName);
	}
}
