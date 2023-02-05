/**
 * Filter Traffic DPDK example application
 * =======================================
 * An application that listens to one or more DPDK ports (a.k.a DPDK devices), captures all traffic
 * and matches packets by user-defined matching criteria. Matching criteria is given on startup and can contain one or more of the following:
 * source IP, destination IP, source TCP/UDP port, destination TCP/UDP port and TCP or UDP protocol. Matching is done per flow, meaning the first packet
 * received on a flow is matched against the matching criteria and if it's matched then all packets of the same flow will be matched too.
 * Packets that are matched can be send to a DPDK port and/or be save to a pcap file.
 * In addition the application collect statistics on received and matched packets: number of packets per protocol, number of matched flows and number
 * of matched packets.
 *
 * The application uses the concept of worker threads. Number of cores can be set by the user or set to default (default is all machine cores minus one
 * management core). Each core is assigned with one worker thread. The application divides the DPDK ports and RX queues equally between worker threads.
 * For example: if there are 2 DPDK ports to listen to, each one with 6 RX queues and there are 3 worker threads, then worker #1 will get RX queues
 * 1-4 of port 1, worker #2 will get RX queues 5-6 of port 1 and RX queues 1-2 of port 2, and worker #3 will get RX queues 3-6 of port 2.
 * Each worker thread does exactly the same work: receiving packets, collecting packet statistics, matching flows and sending/saving matched packets
 *
 * __Important__: this application (like all applications using DPDK) should be run as 'sudo'
 */

#include "Common.h"
#include "PacketMatchingEngine.h"
#include "AppWorkerThread.h"

#include "DpdkDeviceList.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "TablePrinter.h"

#include <vector>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <unistd.h>


#define DEFAULT_MBUF_POOL_SIZE 4095
#define MAX_QUEUES 64


static struct option FilterTrafficOptions[] =
{
	{"dpdk-ports",  required_argument, 0, 'd'},
	{"send-matched-packets", optional_argument, 0, 's'},
	{"save-matched-packets", optional_argument, 0, 'f'},
	{"match-source-ip", optional_argument, 0, 'i'},
	{"match-dest-ip", optional_argument, 0, 'I'},
	{"match-source-port", optional_argument, 0, 'p'},
	{"match-dest-port", optional_argument, 0, 'P'},
	{"match-protocol", optional_argument, 0, 'o'},
	{"core-mask",  optional_argument, 0, 'c'},
	{"mbuf-pool-size",  optional_argument, 0, 'm'},
	{"rx-queues",  optional_argument, 0, 'r'},
	{"tx-queues",  optional_argument, 0, 't'},
	{"help", optional_argument, 0, 'h'},
	{"version", optional_argument, 0, 'v'},
	{"list", optional_argument, 0, 'l'},
	{0, 0, 0, 0}
};


/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
		<< "Usage:" << std::endl
		<< "------" << std::endl
		<< pcpp::AppName::get() << " [-hvl] [-s PORT] [-f FILENAME] [-i IPV4_ADDR] [-I IPV4_ADDR] [-p PORT] [-P PORT] [-r PROTOCOL]" << std::endl
		<< "                  [-c CORE_MASK] [-m POOL_SIZE] [-r NUM_QUEUES] [-t NUM_QUEUES] -d PORT_1,PORT_3,...,PORT_N" << std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -h|--help                                  : Displays this help message and exits" << std::endl
		<< "    -v|--version                               : Displays the current version and exits" << std::endl
		<< "    -l|--list                                  : Print the list of DPDK ports and exists" << std::endl
		<< "    -d|--dpdk-ports PORT_1,PORT_3,...,PORT_N   : A comma-separated list of DPDK port numbers to receive" << std::endl
		<< "                                                 packets from. To see all available DPDK ports use the -l switch" << std::endl
		<< "    -s|--send-matched-packets PORT             : DPDK port to send matched packets to" << std::endl
		<< "    -f|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH. Packets" << std::endl
		<< "                                                 matched by core X will be saved under 'FILEPATH/CoreX.pcap'" << std::endl
		<< "    -i|--match-source-ip      IPV4_ADDR        : Match source IPv4 address" << std::endl
		<< "    -I|--match-dest-ip        IPV4_ADDR        : Match destination IPv4 address" << std::endl
		<< "    -p|--match-source-port    PORT             : Match source TCP/UDP port" << std::endl
		<< "    -P|--match-dest-port      PORT             : Match destination TCP/UDP port" << std::endl
		<< "    -o|--match-protocol       PROTOCOL         : Match protocol. Valid values are 'TCP' or 'UDP'" << std::endl
		<< "    -c|--core-mask            CORE_MASK        : Core mask of cores to use." << std::endl
		<< "                                                 For example: use 7 (binary 0111) to use cores 0,1,2." << std::endl
		<< "                                                 Default is using all cores except management core" << std::endl
		<< "    -m|--mbuf-pool-size       POOL_SIZE        : DPDK mBuf pool size to initialize DPDK with." << std::endl
		<< "                                                 Default value is 4095" << std::endl
		<< "    -r|--rx-queues            NUM_QUEUES       : Number of RX queues to open. Cannot exceed the max allowed by the NIC or " << MAX_QUEUES << std::endl
		<< "                                                 The default is 1" << std::endl
		<< "    -t|--tx-queues            NUM_QUEUES       : Number of TX queues to open. Cannot exceed the max allowed by the NIC or " << MAX_QUEUES << std::endl
		<< "                                                 The default is 1" << std::endl
		<< std::endl;
}


/**
 * Print application version
 */
void printAppVersion()
{
	std::cout
		<< pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
		<< "Built: " << pcpp::getBuildDateTime() << std::endl
		<< "Built from: " << pcpp::getGitInfo() << std::endl;
	exit(0);
}


/**
 * Print to console all available DPDK ports. Used by the -l switch
 */
void listDpdkPorts()
{
	pcpp::CoreMask coreMaskToUse = pcpp::getCoreMaskForAllMachineCores();

	// initialize DPDK
	if (!pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, DEFAULT_MBUF_POOL_SIZE))
	{
		EXIT_WITH_ERROR("couldn't initialize DPDK");
	}

	std::cout << "DPDK port list:" << std::endl;

	// go over all available DPDK devices and print info for each one
	std::vector<pcpp::DpdkDevice*> deviceList = pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList();
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
	{
		pcpp::DpdkDevice* dev = *iter;
		std::cout << "   "
			<< " Port #" << dev->getDeviceId() << ":"
			<< " MAC address='" << dev->getMacAddress() << "';"
			<< " PCI address='" << dev->getPciAddress() << "';"
			<< " PMD='" << dev->getPMDName() << "'"
			<< std::endl;
	}
}


/**
 * Prepare the configuration for each core. Configuration includes: which DpdkDevices and which RX queues to receive packets from, where to send the matched
 * packets, etc.
 */
void prepareCoreConfiguration(std::vector<pcpp::DpdkDevice*>& dpdkDevicesToUse, std::vector<pcpp::SystemCore>& coresToUse,
		bool writePacketsToDisk, const std::string &packetFilePath, pcpp::DpdkDevice* sendPacketsTo,
		AppWorkerConfig workerConfigArr[], int workerConfigArrLen, uint16_t rxQueues)
{
	// create a list of pairs of DpdkDevice and RX queues for all RX queues in all requested devices
	int totalNumOfRxQueues = 0;
	std::vector<std::pair<pcpp::DpdkDevice*, int> > deviceAndRxQVec;
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
	{
		for (int rxQueueIndex = 0; rxQueueIndex < rxQueues; rxQueueIndex++)
		{
			std::pair<pcpp::DpdkDevice*, int> curPair(*iter, rxQueueIndex);
			deviceAndRxQVec.push_back(curPair);
		}
		totalNumOfRxQueues += rxQueues;
	}

	// calculate how many RX queues each core will read packets from. We divide the total number of RX queues with total number of core
	int numOfRxQueuesPerCore = totalNumOfRxQueues / coresToUse.size();
	int rxQueuesRemainder = totalNumOfRxQueues % coresToUse.size();

	// prepare the configuration for every core: divide the devices and RX queue for each device with the various cores
	int i = 0;
	std::vector<std::pair<pcpp::DpdkDevice*, int> >::iterator pairVecIter = deviceAndRxQVec.begin();
	for (std::vector<pcpp::SystemCore>::iterator iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
	{
		std::cout << "Using core " << (int)iter->Id << std::endl;
		workerConfigArr[i].CoreId = iter->Id;
		workerConfigArr[i].WriteMatchedPacketsToFile = writePacketsToDisk;

		std::stringstream packetFileName;
		packetFileName << packetFilePath << "Core" << workerConfigArr[i].CoreId << ".pcap";
		workerConfigArr[i].PathToWritePackets = packetFileName.str();

		workerConfigArr[i].SendPacketsTo = sendPacketsTo;
		for (int rxQIndex = 0; rxQIndex < numOfRxQueuesPerCore; rxQIndex++)
		{
			if (pairVecIter == deviceAndRxQVec.end())
				break;
			workerConfigArr[i].InDataCfg[pairVecIter->first].push_back(pairVecIter->second);
			pairVecIter++;
		}
		if (rxQueuesRemainder > 0 && (pairVecIter != deviceAndRxQVec.end()))
		{
			workerConfigArr[i].InDataCfg[pairVecIter->first].push_back(pairVecIter->second);
			pairVecIter++;
			rxQueuesRemainder--;
		}

		// print configuration for core
		std::cout << "   Core configuration:" << std::endl;
		for (InputDataConfig::iterator iter2 = workerConfigArr[i].InDataCfg.begin(); iter2 != workerConfigArr[i].InDataCfg.end(); iter2++)
		{
			std::cout << "      DPDK device#" << iter2->first->getDeviceId() << ": ";
			for (std::vector<int>::iterator iter3 = iter2->second.begin(); iter3 != iter2->second.end(); iter3++)
			{
				std::cout << "RX-Queue#" << *iter3 << ";  ";
			}
			std::cout << std::endl;
		}
		if (workerConfigArr[i].InDataCfg.size() == 0)
		{
			std::cout << "      None" << std::endl;
		}
		i++;
	}
}


struct FilterTrafficArgs
{
	bool shouldStop;
	std::vector<pcpp::DpdkWorkerThread*>* workerThreadsVector;

	FilterTrafficArgs() : shouldStop(false), workerThreadsVector(NULL) {}
};

/**
 * The callback to be called when application is terminated by ctrl-c. Do cleanup and print summary stats
 */
void onApplicationInterrupted(void* cookie)
{
	FilterTrafficArgs* args = (FilterTrafficArgs*)cookie;

	std::cout << std::endl << std::endl << "Application stopped" << std::endl;

	// stop worker threads
	pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

	// create table printer
	std::vector<std::string> columnNames;
	std::vector<int> columnWidths;
	PacketStats::getStatsColumns(columnNames, columnWidths);
	pcpp::TablePrinter printer(columnNames, columnWidths);

	// print final stats for every worker thread plus sum of all threads and free worker threads memory
	PacketStats aggregatedStats;
	for (std::vector<pcpp::DpdkWorkerThread*>::iterator iter = args->workerThreadsVector->begin(); iter != args->workerThreadsVector->end(); iter++)
	{
		AppWorkerThread* thread = (AppWorkerThread*)(*iter);
		PacketStats threadStats = thread->getStats();
		aggregatedStats.collectStats(threadStats);
		printer.printRow(threadStats.getStatValuesAsString("|"), '|');
		delete thread;
	}

	printer.printSeparator();
	printer.printRow(aggregatedStats.getStatValuesAsString("|"), '|');

	args->shouldStop = true;
}


/**
 * main method of the application. Responsible for parsing user args, preparing worker thread configuration, creating the worker threads and activate them.
 * At program termination worker threads are stopped, statistics are collected from them and printed to console
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::vector<int> dpdkPortVec;

	bool writePacketsToDisk = false;

	std::string packetFilePath = "";

	pcpp::CoreMask coreMaskToUse = pcpp::getCoreMaskForAllMachineCores();

	int sendPacketsToPort = -1;

	int optionIndex = 0;
	int opt = 0;

	uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;

	pcpp::IPv4Address 	srcIPToMatch = pcpp::IPv4Address::Zero;
	pcpp::IPv4Address 	dstIPToMatch = pcpp::IPv4Address::Zero;
	uint16_t 			srcPortToMatch = 0;
	uint16_t 			dstPortToMatch = 0;
	pcpp::ProtocolType	protocolToMatch = pcpp::UnknownProtocol;

	uint16_t rxQueues = 1;
	uint16_t txQueues = 1;

	while((opt = getopt_long(argc, argv, "d:c:s:f:m:i:I:p:P:o:r:t:hvl", FilterTrafficOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
			{
				break;
			}
			case 'd':
			{
				std::string portListAsString = std::string(optarg);
				std::stringstream stream(portListAsString);
				std::string portAsString;
				int port;
				// break comma-separated string into string list
				while(getline(stream, portAsString, ','))
				{
					char c;
					std::stringstream stream2(portAsString);
					stream2 >> port;
					if (stream2.fail() || stream2.get(c))
					{
						// not an integer
						EXIT_WITH_ERROR_AND_PRINT_USAGE("DPDK ports list is invalid");
					}
					dpdkPortVec.push_back(port);
				}

				// verify list is not empty
				if (dpdkPortVec.empty())
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("DPDK ports list is empty");
				}
				break;
			}
			case 's':
			{
				sendPacketsToPort = atoi(optarg);
				break;
			}
			case 'c':
			{
				coreMaskToUse = atoi(optarg);
				break;
			}
			case 'f':
			{
				packetFilePath = std::string(optarg);
				writePacketsToDisk = true;
				if (packetFilePath.empty())
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Filename to write packets is empty");
				}
				break;
			}
			case 'm':
			{
				mBufPoolSize = atoi(optarg);
				break;
			}
			case 'i':
			{
				srcIPToMatch = pcpp::IPv4Address(optarg);
				if (!srcIPToMatch.isValid())
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Source IP to match isn't a valid IP address");
				}
				break;
			}
			case 'I':
			{
				dstIPToMatch = pcpp::IPv4Address(optarg);
				if (!dstIPToMatch.isValid())
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Destination IP to match isn't a valid IP address");
				}
				break;
			}
			case 'p':
			{
				int ret = atoi(optarg);
				if (ret <= 0 || ret > 65535)
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Source port to match isn't a valid TCP/UDP port");
				}
				srcPortToMatch = ret;
				break;
			}
			case 'P':
			{
				int ret = atoi(optarg);
				if (ret <= 0 || ret > 65535)
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Destination port to match isn't a valid TCP/UDP port");
				}
				dstPortToMatch = ret;
				break;
			}
			case 'o':
			{
				std::string protocol = std::string(optarg);
				if (protocol == "TCP")
					protocolToMatch = pcpp::TCP;
				else if (protocol == "UDP")
					protocolToMatch = pcpp::UDP;
				else
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Protocol to match isn't TCP or UDP");
				}
				break;
			}
			case 'r':
			{
				rxQueues = atoi(optarg);
				if (rxQueues == 0)
				{
					EXIT_WITH_ERROR("Cannot open the device with 0 RX queues");
				}
				if (rxQueues > MAX_QUEUES)
				{
					EXIT_WITH_ERROR("The number of RX queues cannot exceed " << MAX_QUEUES);
				}
				break;
			}
			case 't':
			{
				txQueues = atoi(optarg);
				if (txQueues == 0)
				{
					EXIT_WITH_ERROR("Cannot open the device with 0 TX queues");
				}
				if (txQueues > MAX_QUEUES)
				{
					EXIT_WITH_ERROR("The number of TX queues cannot exceed " << MAX_QUEUES);
				}
				break;
			}
			case 'h':
			{
				printUsage();
				exit(0);
			}
			case 'v':
			{
				printAppVersion();
				break;
			}
			case 'l':
			{
				listDpdkPorts();
				exit(0);
			}
			default:
			{
				printUsage();
				exit(0);
			}
		}
	}

	// verify list is not empty
	if (dpdkPortVec.empty())
	{
		EXIT_WITH_ERROR_AND_PRINT_USAGE("DPDK ports list is empty. Please use the -d switch");
	}

	// extract core vector from core mask
	std::vector<pcpp::SystemCore> coresToUse;
	pcpp::createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

	// need minimum of 2 cores to start - 1 management core + 1 (or more) worker thread(s)
	if (coresToUse.size() < 2)
	{
		EXIT_WITH_ERROR("Needed minimum of 2 cores to start the application");
	}

	// initialize DPDK
	if (!pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, mBufPoolSize))
	{
		EXIT_WITH_ERROR("Couldn't initialize DPDK");
	}

	// removing DPDK master core from core mask because DPDK worker threads cannot run on master core
	coreMaskToUse = coreMaskToUse & ~(pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);

	// re-calculate cores to use after removing master core
	coresToUse.clear();
	createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

	// collect the list of DPDK devices
	std::vector<pcpp::DpdkDevice*> dpdkDevicesToUse;
	for (std::vector<int>::iterator iter = dpdkPortVec.begin(); iter != dpdkPortVec.end(); iter++)
	{
		pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(*iter);
		if (dev == NULL)
		{
			EXIT_WITH_ERROR("DPDK device for port " << *iter << " doesn't exist");
		}
		dpdkDevicesToUse.push_back(dev);
	}

	// go over all devices and open them
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
	{
		if (rxQueues > (*iter)->getTotalNumOfRxQueues())
		{
			EXIT_WITH_ERROR("Number of RX errors cannot exceed the max allowed by the device which is " << (*iter)->getTotalNumOfRxQueues());
		}
		if (txQueues > (*iter)->getTotalNumOfTxQueues())
		{
			EXIT_WITH_ERROR("Number of TX errors cannot exceed the max allowed by the device which is " << (*iter)->getTotalNumOfTxQueues());
		}
		if (!(*iter)->openMultiQueues(rxQueues, txQueues))
		{
			EXIT_WITH_ERROR("Couldn't open DPDK device #" << (*iter)->getDeviceId() << ", PMD '" << (*iter)->getPMDName() << "'");
		}
		std::cout
			<< "Opened device #" << (*iter)->getDeviceId()
			<< " with " << rxQueues << " RX queues and " << txQueues << " TX queues."
			<< " RSS hash functions:" << std::endl;
		std::vector<std::string> rssHashFunctions = (*iter)->rssHashFunctionMaskToString((*iter)->getConfiguredRssHashFunction());
		for(std::vector<std::string>::iterator it = rssHashFunctions.begin(); it != rssHashFunctions.end(); ++it)
		{
			std::cout << "   " << (*it) << std::endl;
		}
	}

	// get DPDK device to send packets to (or NULL if doesn't exist)
	pcpp::DpdkDevice* sendPacketsTo = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
	if (sendPacketsTo != NULL && !sendPacketsTo->isOpened() &&  !sendPacketsTo->open())
	{
		EXIT_WITH_ERROR("Could not open port#" << sendPacketsToPort << " for sending matched packets");
	}

	// prepare configuration for every core
	AppWorkerConfig workerConfigArr[coresToUse.size()];
	prepareCoreConfiguration(dpdkDevicesToUse, coresToUse, writePacketsToDisk, packetFilePath, sendPacketsTo, workerConfigArr, coresToUse.size(), rxQueues);

	PacketMatchingEngine matchingEngine(srcIPToMatch, dstIPToMatch, srcPortToMatch, dstPortToMatch, protocolToMatch);

	// create worker thread for every core
	std::vector<pcpp::DpdkWorkerThread*> workerThreadVec;
	int i = 0;
	for (std::vector<pcpp::SystemCore>::iterator iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
	{
		AppWorkerThread* newWorker = new AppWorkerThread(workerConfigArr[i], matchingEngine);
		workerThreadVec.push_back(newWorker);
		i++;
	}

	// start all worker threads
	if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
	{
		EXIT_WITH_ERROR("Couldn't start worker threads");
	}

	// register the on app close event to print summary stats on app termination
	FilterTrafficArgs args;
	args.workerThreadsVector = &workerThreadVec;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	// infinite loop (until program is terminated)
	while (!args.shouldStop)
	{
		sleep(5);
	}
}
