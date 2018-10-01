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
#include <unistd.h>

using namespace pcpp;

#define DEFAULT_MBUF_POOL_SIZE 4095


static struct option FilterTrafficOptions[] =
{
	{"dpdk-ports",  required_argument, 0, 'd'},
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
                        "%s [-hvl] [-c CORE_MASK] [-m POOL_SIZE] -d PORT_1,PORT_2\n"
			"\nOptions:\n\n"
			"    -h|--help                                  : Displays this help message and exits\n"
                        "    -v|--version                               : Displays the current version and exits\n"
			"    -l|--list                                  : Print the list of DPDK ports and exists\n"
			"    -d|--dpdk-ports PORT_1,PORT_2              : A comma-separated list of two DPDK port numbers to be bridged.\n"
			"                                                 To see all available DPDK ports use the -l switch\n"
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

struct DpdkBridgeArgs
{
	bool shouldStop;
	std::vector<DpdkWorkerThread*>* workerThreadsVector;

	DpdkBridgeArgs() : shouldStop(false), workerThreadsVector(NULL) {}
};

/**
 * The callback to be called when application is terminated by ctrl-c. Do cleanup and print summary stats
 */
void onApplicationInterrupted(void* cookie)
{
	DpdkBridgeArgs* args = (DpdkBridgeArgs*)cookie;

	printf("\n\nApplication stopped\n");

	// stop worker threads
	DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

	// create table printer
	std::vector<std::string> columnNames;
	std::vector<int> columnWidths;
	PacketStats::getStatsColumns(columnNames, columnWidths);
	TablePrinter printer(columnNames, columnWidths);

	// print final stats for every worker thread plus sum of all threads and free worker threads memory
	PacketStats aggregatedStats;
	for (std::vector<DpdkWorkerThread*>::iterator iter = args->workerThreadsVector->begin(); iter != args->workerThreadsVector->end(); iter++)
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
	AppName::init(argc, argv);

	std::vector<int> dpdkPortVec;

	CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

	int sendPacketsToPort = -1;

	int optionIndex = 0;
	char opt = 0;

	uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;

	while((opt = getopt_long (argc, argv, "d:c:m:hvl", FilterTrafficOptions, &optionIndex)) != -1)
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
				// verify list contains two ports
				if(dpdkPortVec.size()!=2)
				{
					EXIT_WITH_ERROR_AND_PRINT_USAGE("DPDK list must contain two values");
				}
				break;
			}
			case 'c':
			{
				coreMaskToUse = atoi(optarg);
				break;
			}
			case 'm':
			{
				mBufPoolSize = atoi(optarg);
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

	// go over all devices and open them
	for (vector<DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
	{
		if (!(*iter)->openMultiQueues(1,1))
		{
			EXIT_WITH_ERROR("Couldn't open DPDK device #%d, PMD '%s'", (*iter)->getDeviceId(), (*iter)->getPMDName().c_str());
		}
	}

	// get DPDK device to send packets to (or NULL if doesn't exist)
	DpdkDevice* sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
	if (sendPacketsTo != NULL && !sendPacketsTo->isOpened() &&  !sendPacketsTo->open())
	{
		EXIT_WITH_ERROR("Could not open port#%d for sending matched packets", sendPacketsToPort);
	}

	// prepare configuration for every core
	AppWorkerConfig workerConfigArr[2];
	workerConfigArr[0].CoreId = coresToUse.at(0).Id;
	workerConfigArr[0].RxDevice = dpdkDevicesToUse.at(0);
	workerConfigArr[0].TxDevice = dpdkDevicesToUse.at(1);
	workerConfigArr[1].CoreId = coresToUse.at(1).Id;
	workerConfigArr[1].RxDevice = dpdkDevicesToUse.at(1);
	workerConfigArr[1].TxDevice = dpdkDevicesToUse.at(0);

	// create worker thread for every core
	vector<DpdkWorkerThread*> workerThreadVec;
	workerThreadVec.push_back(new AppWorkerThread(workerConfigArr[0]));
	workerThreadVec.push_back(new AppWorkerThread(workerConfigArr[1]));

	// start all worker threads
	if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
	{
		EXIT_WITH_ERROR("Couldn't start worker threads");
	}

	// register the on app close event to print summary stats on app termination
	DpdkBridgeArgs args;
	args.workerThreadsVector = &workerThreadVec;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	// infinite loop (until program is terminated)
	while (!args.shouldStop)
	{
		sleep(5);
	}
}
