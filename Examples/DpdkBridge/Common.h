#pragma once

#include "DpdkDevice.h"
#include "Packet.h"

#include <SystemUtils.h>

#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <vector>

/**
 * Macros for exiting the application with error
 */

#define EXIT_WITH_ERROR(reason)                       \
    do {                                              \
        std::cout << std::endl                        \
                  << "ERROR: " << reason << std::endl \
                  << std::endl;                       \
        exit(1);                                      \
    } while (0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason)       \
    do {                                              \
        printUsage();                                 \
        std::cout << std::endl                        \
                  << "ERROR: " << reason << std::endl \
                  << std::endl;                       \
        exit(1);                                      \
    } while (0)

/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK port to receive packets from
 * - Which DPDK port to send packets to
 */
struct AppWorkerConfig {
    uint32_t CoreId;
    pcpp::DpdkDevice* RxDevice;
    uint16_t RxQueues;
    pcpp::DpdkDevice* TxDevice;

    AppWorkerConfig()
        : CoreId(MAX_NUM_OF_CORES + 1), RxDevice(NULL), RxQueues(1),
          TxDevice(NULL) {}
};
