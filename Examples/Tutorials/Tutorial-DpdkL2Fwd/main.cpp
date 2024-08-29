#include <vector>
#include <unistd.h>
#include <sstream>
#include "SystemUtils.h"
#include "DpdkDeviceList.h"
#include "TablePrinter.h"
#include "WorkerThread.h"

#define MBUF_POOL_SIZE 16 * 1024 - 1
#define DEVICE_ID_1 0
#define DEVICE_ID_2 1
#define COLLECT_STATS_EVERY_SEC 2

// Keep running flag
bool keepRunning = true;

void onApplicationInterrupted(void* cookie)
{
	keepRunning = false;
	std::cout << std::endl << "Shutting down..." << std::endl;
}

void printStats(pcpp::DpdkDevice* rxDevice, pcpp::DpdkDevice* txDevice)
{
	pcpp::DpdkDevice::DpdkDeviceStats rxStats;
	pcpp::DpdkDevice::DpdkDeviceStats txStats;
	rxDevice->getStatistics(rxStats);
	txDevice->getStatistics(txStats);

	std::vector<std::string> columnNames = { " ", "Total Packets", "Packets/sec", "Bytes", "Bits/sec" };
	std::vector<int> columnLengths = { 10, 15, 15, 15, 15 };

	pcpp::TablePrinter printer(columnNames, columnLengths);

	std::stringstream totalRx;
	totalRx << "rx"
	        << "|" << rxStats.aggregatedRxStats.packets << "|" << rxStats.aggregatedRxStats.packetsPerSec << "|"
	        << rxStats.aggregatedRxStats.bytes << "|" << rxStats.aggregatedRxStats.bytesPerSec * 8;
	printer.printRow(totalRx.str(), '|');

	std::stringstream totalTx;
	totalTx << "tx"
	        << "|" << txStats.aggregatedTxStats.packets << "|" << txStats.aggregatedTxStats.packetsPerSec << "|"
	        << txStats.aggregatedTxStats.bytes << "|" << txStats.aggregatedTxStats.bytesPerSec * 8;
	printer.printRow(totalTx.str(), '|');
}

int main(int argc, char* argv[])
{
	// Register the on app close event handler
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, nullptr);

	// Initialize DPDK
	pcpp::CoreMask coreMaskToUse = pcpp::getCoreMaskForAllMachineCores();
	pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, MBUF_POOL_SIZE);

	// Find DPDK devices
	pcpp::DpdkDevice* device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DEVICE_ID_1);
	if (device1 == nullptr)
	{
		std::cerr << "Cannot find device1 with port '" << DEVICE_ID_1 << "'" << std::endl;
		return 1;
	}

	pcpp::DpdkDevice* device2 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DEVICE_ID_2);
	if (device2 == nullptr)
	{
		std::cerr << "Cannot find device2 with port '" << DEVICE_ID_2 << "'" << std::endl;
		return 1;
	}

	// Open DPDK devices
	if (!device1->openMultiQueues(1, 1))
	{
		std::cerr << "Couldn't open device1 #" << device1->getDeviceId() << ", PMD '" << device1->getPMDName() << "'"
		          << std::endl;
		return 1;
	}

	if (!device2->openMultiQueues(1, 1))
	{
		std::cerr << "Couldn't open device2 #" << device2->getDeviceId() << ", PMD '" << device2->getPMDName() << "'"
		          << std::endl;
		return 1;
	}

	// Create worker threads
	std::vector<pcpp::DpdkWorkerThread*> workers;
	// Constructs a DpdkWorkerThread* directly within the vector's storage
	workers.emplace_back(new L2FwdWorkerThread(device1, device2));
	workers.emplace_back(new L2FwdWorkerThread(device2, device1));

	// Create core mask - use core 1 and 2 for the two threads
	int workersCoreMask = 0;
	for (int i = 1; i <= 2; i++)
	{
		workersCoreMask = workersCoreMask | (1 << i);
	}

	// Start capture in async mode
	if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(workersCoreMask, workers))
	{
		std::cerr << "Couldn't start worker threads" << std::endl;
		return 1;
	}

	uint64_t counter = 0;
	int statsCounter = 1;

	// Keep running while flag is on
	while (keepRunning)
	{
		// Sleep for 1 second
		sleep(1);

		// Print stats every COLLECT_STATS_EVERY_SEC seconds
		if (counter % COLLECT_STATS_EVERY_SEC == 0)
		{
			// Clear screen and move to top left
			std::cout << "\033[2J\033[1;1H";

			std::cout << "Stats #" << statsCounter++ << std::endl << "==========" << std::endl << std::endl;

			// Print stats of traffic going from Device1 to Device2
			std::cout << std::endl << "Device1->Device2 stats:" << std::endl << std::endl;
			printStats(device1, device2);

			// Print stats of traffic going from Device2 to Device1
			std::cout << std::endl << "Device2->Device1 stats:" << std::endl << std::endl;
			printStats(device2, device1);
		}
		counter++;
	}

	// Stop worker threads
	pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

	// Exit app with normal exit code
	return 0;
}
