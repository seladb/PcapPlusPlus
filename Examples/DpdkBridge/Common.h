#pragma once

#include "Packet.h"
#include "DpdkDevice.h"

#include <SystemUtils.h>

#include <string>
#include <map>
#include <vector>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdlib.h>

using namespace std;

/**
 * Macros for exiting the application with error
 */

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("Application terminated in error: " reason "\n", ## __VA_ARGS__); \
	exit(1); \
	} while(0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while (0)


/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK ports to receive packets from
 * - Which DPDK ports to send packets to
 */
struct AppWorkerConfig
{
	uint32_t CoreId;
	pcpp::DpdkDevice* RxDevice;
	uint16_t RxQueues;
	pcpp::DpdkDevice* TxDevice;

	AppWorkerConfig() : CoreId(MAX_NUM_OF_CORES+1), RxDevice(NULL), RxQueues(1), TxDevice(NULL)
	{
	}
};
