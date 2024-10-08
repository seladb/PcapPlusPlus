/**
 * DPDK bridge example application
 * =======================================
 * This application demonstrates how to create a bridge between two network devices using PcapPlusPlus DPDK APIs.
 * It listens to two DPDK ports (a.k.a DPDK devices), and forwards all the traffic received on one port to the other,
 * acting like a L2 bridge.
 *
 * The application is very similar to [DPDK's L2 forwarding
 * example](https://doc.dpdk.org/guides/sample_app_ug/l2_forward_real_virtual.html) and demonstrates how to achieve the
 * same functionality with PcapPlusPlus using less and easier to understand C++ code.
 *
 * The application uses the concept of worker threads. It creates 2 worker threads running in an endless loop (as long
 * as the app is running): one for receiving packets on NIC#1 and sending them to NIC#2, and another for receiving
 * packets on NIC#2 and sending them to NIC#1.
 *
 * __Important__:
 * - This application runs only on Linux (DPDK is not supported on Windows and Mac OS X)
 * - This application (like all applications using DPDK) should be run as 'sudo'
 * - In order to test this application you need an envorinment where the bridge is connected directly (back-to-back) to
 * the two machines the bridge wants to connect
 */

#include "Common.h"
#include "AppWorkerThread.h"

#include "DpdkDeviceList.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "TablePrinter.h"

#include <vector>
#include <iostream>
#include <getopt.h>
#include <string>
#include <sstream>
#include <unistd.h>

#define COLLECT_STATS_EVERY_SEC 1
#define DEFAULT_MBUF_POOL_SIZE 4095
#define DEFAULT_QUEUE_QUANTITY 1

// clang-format off
static struct option DpdkBridgeOptions[] = {
	{ "dpdk-ports",     required_argument, nullptr, 'd' },
	{ "core-mask",      optional_argument, nullptr, 'c' },
	{ "mbuf-pool-size", optional_argument, nullptr, 'm' },
	{ "queue-quantity", optional_argument, nullptr, 'q' },
	{ "help",           optional_argument, nullptr, 'h' },
	{ "list",           optional_argument, nullptr, 'l' },
	{ "version",        optional_argument, nullptr, 'v' },
	{ nullptr,          0,                 nullptr,  0  }
};
// clang-format on

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get() << " [-hlv] [-c CORE_MASK] [-m POOL_SIZE] [-q QUEUE_QTY] -d PORT_1,PORT_2"
	          << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -h|--help                                  : Displays this help message and exits" << std::endl
	          << "    -l|--list                                  : Print the list of DPDK ports and exits" << std::endl
	          << "    -v|--version                               : Displays the current version and exits" << std::endl
	          << "    -c|--core-mask CORE_MASK                   : Core mask of cores to use. For example: use 7 "
	             "(binary 0111) to use cores 0,1,2."
	          << std::endl
	          << "                                                 Default is using all cores except management core"
	          << std::endl
	          << "    -m|--mbuf-pool-size POOL_SIZE              : DPDK mBuf pool size to initialize DPDK with. "
	             "Default value is 4095\n"
	          << std::endl
	          << "    -d|--dpdk-ports PORT_1,PORT_2              : A comma-separated list of two DPDK port numbers to "
	             "be bridged."
	          << std::endl
	          << "                                                 To see all available DPDK ports use the -l switch"
	          << std::endl
	          << "    -q|--queue-quantity QUEUE_QTY              : Quantity of RX queues to be opened for each DPDK "
	             "device. Default value is 1"
	          << std::endl
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
	for (const auto& iter : deviceList)
	{
		pcpp::DpdkDevice* dev = iter;
		std::cout << "   "
		          << " Port #" << dev->getDeviceId() << ":"
		          << " MAC address='" << dev->getMacAddress() << "';"
		          << " PCI address='" << dev->getPciAddress() << "';"
		          << " PMD='" << dev->getPMDName() << "'" << std::endl;
	}
}

struct DpdkBridgeArgs
{
	bool shouldStop;
	std::vector<pcpp::DpdkWorkerThread*>* workerThreadsVector;

	DpdkBridgeArgs() : shouldStop(false), workerThreadsVector(nullptr)
	{}
};

/**
 * The callback to be called when application is terminated by ctrl-c. Do cleanup and print summary stats
 */
void onApplicationInterrupted(void* cookie)
{
	DpdkBridgeArgs* args = (DpdkBridgeArgs*)cookie;

	std::cout << std::endl << std::endl << "Application stopped" << std::endl;

	// stop worker threads
	pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

	args->shouldStop = true;
}

/**
 * Extract and print traffic stats from a device
 */
void printStats(pcpp::DpdkDevice* device)
{
	pcpp::DpdkDevice::DpdkDeviceStats stats;
	device->getStatistics(stats);

	std::cout << std::endl << "Statistics for port " << device->getDeviceId() << ":" << std::endl;

	std::vector<std::string> columnNames;
	columnNames.push_back(" ");
	columnNames.push_back("Total Packets");
	columnNames.push_back("Packets/sec");
	columnNames.push_back("Total Bytes");
	columnNames.push_back("Bytes/sec");

	std::vector<int> columnLengths;
	columnLengths.push_back(10);
	columnLengths.push_back(15);
	columnLengths.push_back(15);
	columnLengths.push_back(15);
	columnLengths.push_back(15);

	pcpp::TablePrinter printer(columnNames, columnLengths);

	std::stringstream totalRx;
	totalRx << "rx"
	        << "|" << stats.aggregatedRxStats.packets << "|" << stats.aggregatedRxStats.packetsPerSec << "|"
	        << stats.aggregatedRxStats.bytes << "|" << stats.aggregatedRxStats.bytesPerSec;
	printer.printRow(totalRx.str(), '|');

	std::stringstream totalTx;
	totalTx << "tx"
	        << "|" << stats.aggregatedTxStats.packets << "|" << stats.aggregatedTxStats.packetsPerSec << "|"
	        << stats.aggregatedTxStats.bytes << "|" << stats.aggregatedTxStats.bytesPerSec;
	printer.printRow(totalTx.str(), '|');
}

/**
 * main method of the application. Responsible for parsing user args, preparing worker thread configuration, creating
 * the worker threads and activate them. At program termination worker threads are stopped, statistics are collected
 * from them and printed to console
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::vector<int> dpdkPortVec;

	// if core mask is not provided, use the 3 first cores
	pcpp::CoreMask coreMaskToUse = (pcpp::getCoreMaskForAllMachineCores() & 7);

	int optionIndex = 0;
	int opt = 0;

	uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;
	uint16_t queueQuantity = DEFAULT_QUEUE_QUANTITY;

	while ((opt = getopt_long(argc, argv, "d:c:m:q:hvl", DpdkBridgeOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
		{
			break;
		}
		case 'c':
		{
			coreMaskToUse = atoi(optarg);
			break;
		}
		case 'd':
		{
			std::string portListAsString = std::string(optarg);
			std::stringstream stream(portListAsString);
			std::string portAsString;
			int port;
			// break comma-separated string into string list
			while (getline(stream, portAsString, ','))
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
			if (dpdkPortVec.size() != 2)
			{
				EXIT_WITH_ERROR_AND_PRINT_USAGE("DPDK list must contain two values");
			}
			break;
		}
		case 'm':
		{
			mBufPoolSize = atoi(optarg);
			break;
		}
		case 'q':
		{
			queueQuantity = atoi(optarg);
			break;
		}
		case 'h':
		{
			printUsage();
			exit(0);
		}
		case 'l':
		{
			listDpdkPorts();
			exit(0);
		}
		case 'v':
		{
			printAppVersion();
			break;
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
	createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

	// need minimum of 3 cores to start - 1 management core + 1 (or more) worker thread(s)
	if (coresToUse.size() < 3)
	{
		EXIT_WITH_ERROR("Needed minimum of 3 cores to start the application");
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
	for (const auto& port : dpdkPortVec)
	{
		pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(port);
		if (dev == nullptr)
		{
			EXIT_WITH_ERROR("DPDK device for port " << port << " doesn't exist");
		}
		dpdkDevicesToUse.push_back(dev);
	}

	// go over all devices and open them
	for (const auto& dev : dpdkDevicesToUse)
	{
		if (!dev->openMultiQueues(queueQuantity, 1))
		{
			EXIT_WITH_ERROR("Couldn't open DPDK device #" << dev->getDeviceId() << ", PMD '" << dev->getPMDName()
			                                              << "'");
		}
	}

	// prepare configuration for every core
	AppWorkerConfig workerConfigArr[2];
	workerConfigArr[0].CoreId = coresToUse.at(0).Id;
	workerConfigArr[0].RxDevice = dpdkDevicesToUse.at(0);
	workerConfigArr[0].RxQueues = queueQuantity;
	workerConfigArr[0].TxDevice = dpdkDevicesToUse.at(1);
	workerConfigArr[1].CoreId = coresToUse.at(1).Id;
	workerConfigArr[1].RxDevice = dpdkDevicesToUse.at(1);
	workerConfigArr[1].RxQueues = queueQuantity;
	workerConfigArr[1].TxDevice = dpdkDevicesToUse.at(0);

	// create worker thread for every core
	std::vector<pcpp::DpdkWorkerThread*> workerThreadVec;
	workerThreadVec.push_back(new AppWorkerThread(workerConfigArr[0]));
	workerThreadVec.push_back(new AppWorkerThread(workerConfigArr[1]));

	// start all worker threads
	if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
	{
		EXIT_WITH_ERROR("Couldn't start worker threads");
	}

	// register the on app close event to print summary stats on app termination
	DpdkBridgeArgs args;
	args.workerThreadsVector = &workerThreadVec;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	// infinite loop (until program is terminated)
	uint64_t counter = 0;
	int statsCounter = 1;

	// Keep running while flag is on
	while (!args.shouldStop)
	{
		// Sleep for 1 second
		sleep(1);

		// Print stats every COLLECT_STATS_EVERY_SEC seconds
		// cppcheck-suppress moduloofone
		if (counter % COLLECT_STATS_EVERY_SEC == 0)
		{
			// Clear screen and move to top left
			std::cout << "\033[2J\033[1;1H";

			// Print devices traffic stats
			std::cout << "Stats #" << statsCounter++ << std::endl << "==========" << std::endl;
			printStats(dpdkDevicesToUse.at(0));
			printStats(dpdkDevicesToUse.at(1));
		}
		counter++;
	}
}
