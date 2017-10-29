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

#include <vector>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <string>
#include <sstream>
#include <unistd.h>

using namespace pcpp;

#define DEFAULT_MBUF_POOL_SIZE 4095


static struct option FilterTrafficOptions[] =
{
	{"dpdk-ports",  required_argument, 0, 'd'},
	{"send-matched-packets", optional_argument, 0, 's'},
	{"save-matched-packets", optional_argument, 0, 'f'},
	{"match-source-ip", optional_argument, 0, 'i'},
	{"match-dest-ip", optional_argument, 0, 'I'},
	{"match-source-port", optional_argument, 0, 'p'},
	{"match-dest-port", optional_argument, 0, 'P'},
	{"match-protocol", optional_argument, 0, 'r'},
	{"core-mask",  optional_argument, 0, 'c'},
	{"mbuf-pool-size",  optional_argument, 0, 'm'},
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
	printf("\nUsage:\n"
                 "------\n"
                        "%s [-hvl] [-s PORT] [-f FILENAME] [-i IPV4_ADDR] [-I IPV4_ADDR] [-p PORT] [-P PORT] [-r PROTOCOL]\n"
			"                     [-c CORE_MASK] [-m POOL_SIZE] -d PORT_1,PORT_3,...,PORT_N\n"
			"\nOptions:\n\n"
			"    -h|--help                                  : Displays this help message and exits\n"
                        "    -v|--version                               : Displays the current version and exits\n"
			"    -l|--list                                  : Print the list of DPDK ports and exists\n"
			"    -d|--dpdk-ports PORT_1,PORT_3,...,PORT_N   : A comma-separated list of DPDK port numbers to receive packets from.\n"
			"                                                 To see all available DPDK ports use the -l switch\n"
			"    -s|--send-matched-packets PORT             : DPDK port to send matched packets to\n"
			"    -f|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH. Packets matched by core X will be saved under 'FILEPATH/CoreX.pcap'\n"
			"    -i|--match-source-ip      IPV4_ADDR        : Match source IPv4 address\n"
			"    -I|--match-dest-ip        IPV4_ADDR        : Match destination IPv4 address\n"
			"    -p|--match-source-port    PORT             : Match source TCP/UDP port\n"
			"    -P|--match-dest-port      PORT             : Match destination TCP/UDP port\n"
			"    -r|--match-protocol       PROTOCOL         : Match protocol. Valid values are 'TCP' or 'UDP'\n"
			"    -c|--core-mask            CORE_MASK        : Core mask of cores to use. For example: use 7 (binary 0111) to use cores 0,1,2.\n"
			"                                                 Default is using all cores except management core\n"
			"    -m|--mbuf-pool-size       POOL_SIZE        : DPDK mBuf pool size to initialize DPDK with. Default value is 4095\n\n", AppName::get().c_str());
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
 * Print to console all available DPDK ports. Used by the -l switch
 */
void listDpdkPorts()
{
	CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

	// initialize DPDK
	if (!DpdkDeviceList::initDpdk(coreMaskToUse, DEFAULT_MBUF_POOL_SIZE))
	{
		EXIT_WITH_ERROR("couldn't initialize DPDK");
	}

	printf("DPDK port list:\n");

	// go over all available DPDK devices and print info for each one
	vector<DpdkDevice*> deviceList = DpdkDeviceList::getInstance().getDpdkDeviceList();
	for (vector<DpdkDevice*>::iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
	{
		DpdkDevice* dev = *iter;
		printf("    Port #%d: MAC address='%s'; PCI address='%s'; PMD='%s'\n",
				dev->getDeviceId(),
				dev->getMacAddress().toString().c_str(),
				dev->getPciAddress().toString().c_str(),
				dev->getPMDName().c_str());
	}
}


/**
 * Prepare the configuration for each core. Configuration includes: which DpdkDevices and which RX queues to receive packets from, where to send the matched
 * packets, etc.
 */
void prepareCoreConfiguration(vector<DpdkDevice*>& dpdkDevicesToUse, vector<SystemCore>& coresToUse,
		bool writePacketsToDisk, string packetFilePath, DpdkDevice* sendPacketsTo,
		AppWorkerConfig workerConfigArr[], int workerConfigArrLen)
{
	// create a list of pairs of DpdkDevice and RX queues for all RX queues in all requested devices
	int totalNumOfRxQueues = 0;
	vector<pair<DpdkDevice*, int> > deviceAndRxQVec;
	for (vector<DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
	{
		for (int rxQueueIndex = 0; rxQueueIndex < (*iter)->getTotalNumOfRxQueues(); rxQueueIndex++)
		{
			pair<DpdkDevice*, int> curPair(*iter, rxQueueIndex);
			deviceAndRxQVec.push_back(curPair);
		}
		totalNumOfRxQueues += (*iter)->getTotalNumOfRxQueues();
	}

	// calculate how many RX queues each core will read packets from. We divide the total number of RX queues with total number of core
	int numOfRxQueuesPerCore = totalNumOfRxQueues / coresToUse.size();
	int rxQueuesRemainder = totalNumOfRxQueues % coresToUse.size();

	// prepare the configuration for every core: divide the devices and RX queue for each device with the various cores
	int i = 0;
	vector<pair<DpdkDevice*, int> >::iterator pairVecIter = deviceAndRxQVec.begin();
	for (vector<SystemCore>::iterator iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
	{
		printf("Using core %d\n", iter->Id);
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
		printf("   Core configuration:\n");
		for (InputDataConfig::iterator iter = workerConfigArr[i].InDataCfg.begin(); iter != workerConfigArr[i].InDataCfg.end(); iter++)
		{
			printf("      DPDK device#%d: ", iter->first->getDeviceId());
			for (vector<int>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++)
			{
				printf("RX-Queue#%d;  ", *iter2);

			}
			printf("\n");
		}
		if (workerConfigArr[i].InDataCfg.size() == 0)
		{
			printf("      None\n");
		}
		i++;
	}
}


struct FiltetTrafficArgs
{
	bool shouldStop;
	std::vector<DpdkWorkerThread*>* workerThreadsVector;

	FiltetTrafficArgs() : shouldStop(false), workerThreadsVector(NULL) {}
};

/**
 * The callback to be called when application is terminated by ctrl-c. Do cleanup and print summary stats
 */
void onApplicationInterrupted(void* cookie)
{
	FiltetTrafficArgs* args = (FiltetTrafficArgs*)cookie;

	printf("\n\nApplication stopped\n");

	// stop worker threads
	DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

	// print final stats for every worker thread plus sum of all threads and free worker threads memory
	PacketStats aggregatedStats;
	for (std::vector<DpdkWorkerThread*>::iterator iter = args->workerThreadsVector->begin(); iter != args->workerThreadsVector->end(); iter++)
	{
		AppWorkerThread* thread = (AppWorkerThread*)(*iter);
		PacketStats threadStats = thread->getStats();
		aggregatedStats.collectStats(threadStats);
		if (iter == args->workerThreadsVector->begin())
			threadStats.printStatsHeadline();
		threadStats.printStats();
		delete thread;
	}
	aggregatedStats.printStats();

	args->shouldStop = true;
}


/**
 * main method of the application. Responsible for parsing user args, preparing worker thread configuration, creating the worker threads and activate them.
 * At program termination worker threads are stopped, statistics are collected from them and printed to console
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::vector<int> dpdkPortVec;

	bool writePacketsToDisk = false;

	string packetFilePath = "";

	CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

	int sendPacketsToPort = -1;

	int optionIndex = 0;
	char opt = 0;

	uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;

	IPv4Address 	srcIPToMatch = IPv4Address::Zero;
	IPv4Address 	dstIPToMatch = IPv4Address::Zero;
	uint16_t 		srcPortToMatch = 0;
	uint16_t 		dstPortToMatch = 0;
	ProtocolType	protocolToMatch = UnknownProtocol;

	while((opt = getopt_long (argc, argv, "d:c:s:f:m:i:I:p:P:r:hvl", FilterTrafficOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
			{
				break;
			}
			case 'd':
			{
				string portListAsString = string(optarg);
				stringstream stream(portListAsString);
				string portAsString;
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
				packetFilePath = string(optarg);
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
				srcIPToMatch = IPv4Address(optarg);
				if (!srcIPToMatch.isValid())
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Source IP to match isn't a valid IP address");
				}
				break;
			}
			case 'I':
			{
				dstIPToMatch = IPv4Address(optarg);
				if (!dstIPToMatch.isValid())
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Destination IP to match isn't a valid IP address");
				}
				break;
			}
			case 'p':
			{
				srcPortToMatch = atoi(optarg);
				if (srcPortToMatch <= 0)
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Source port to match isn't a valid TCP/UDP port");
				}
				break;
			}
			case 'P':
			{
				dstPortToMatch = atoi(optarg);
				if (dstPortToMatch <= 0)
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Destination port to match isn't a valid TCP/UDP port");
				}
				break;
			}
			case 'r':
			{
				string protocol = string(optarg);
				if (protocol == "TCP")
					protocolToMatch = TCP;
				else if (protocol == "UDP")
					protocolToMatch = UDP;
				else
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("Protocol to match isn't TCP or UDP");
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
	vector<SystemCore> coresToUse;
	createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

	// need minimum of 2 cores to start - 1 management core + 1 (or more) worker thread(s)
	if (coresToUse.size() < 2)
	{
		EXIT_WITH_ERROR("Needed minimum of 2 cores to start the application");
	}

	// initialize DPDK
	if (!DpdkDeviceList::initDpdk(coreMaskToUse, mBufPoolSize))
	{
		EXIT_WITH_ERROR("Couldn't initialize DPDK");
	}

	// removing DPDK master core from core mask because DPDK worker threads cannot run on master core
	coreMaskToUse = coreMaskToUse & ~(DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);

	// re-calculate cores to use after removing master core
	coresToUse.clear();
	createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

	// collect the list of DPDK devices
	vector<DpdkDevice*> dpdkDevicesToUse;
	for (vector<int>::iterator iter = dpdkPortVec.begin(); iter != dpdkPortVec.end(); iter++)
	{
		DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(*iter);
		if (dev == NULL)
		{
			EXIT_WITH_ERROR("DPDK device for port %d doesn't exist", *iter);
		}
		dpdkDevicesToUse.push_back(dev);
	}

	// get DPDK device to send packets to (or NULL if doesn't exist)
	DpdkDevice* sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
	if (sendPacketsTo != NULL && !sendPacketsTo->open())
	{
		EXIT_WITH_ERROR("Could not open port#%d for sending matched packets", sendPacketsToPort);
	}

	// go over all devices and open them
	for (vector<DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
	{
		if (!(*iter)->openMultiQueues((*iter)->getTotalNumOfRxQueues(), (*iter)->getTotalNumOfTxQueues()))
		{
			EXIT_WITH_ERROR("Couldn't open DPDK device #%d, PMD '%s'", (*iter)->getDeviceId(), (*iter)->getPMDName().c_str());
		}
	}

	// prepare configuration for every core
	AppWorkerConfig workerConfigArr[coresToUse.size()];
	prepareCoreConfiguration(dpdkDevicesToUse, coresToUse, writePacketsToDisk, packetFilePath, sendPacketsTo, workerConfigArr, coresToUse.size());

	PacketMatchingEngine matchingEngine(srcIPToMatch, dstIPToMatch, srcPortToMatch, dstPortToMatch, protocolToMatch);

	// create worker thread for every core
	vector<DpdkWorkerThread*> workerThreadVec;
	int i = 0;
	for (vector<SystemCore>::iterator iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
	{
		AppWorkerThread* newWorker = new AppWorkerThread(workerConfigArr[i], matchingEngine);
		workerThreadVec.push_back(newWorker);
		i++;
	}

	// start all worker threads
	if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
	{
		EXIT_WITH_ERROR("Couldn't start worker threads");
	}

	// register the on app close event to print summary stats on app termination
	FiltetTrafficArgs args;
	args.workerThreadsVector = &workerThreadVec;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	// infinite loop (until program is terminated)
	while (!args.shouldStop)
	{
		sleep(5);
	}
}
