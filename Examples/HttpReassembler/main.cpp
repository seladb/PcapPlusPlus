/**
 * HttpReassembler application
 * ========================
 * This application reassembles HTTP payloads from captured packets as a text file.
 */

#include <iostream>
#include <getopt.h>
#include "PcapPlusPlusVersion.h"
#include "SystemUtils.h"

#define EXIT_WITH_ERROR(reason) do { \
	printUsage(); \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)

static struct option HttpReassemblerOptions[] =
{
	{"help", no_argument, nullptr, 'h'},
	{"version", no_argument, nullptr, 'v'}
};

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
		<< "Usage:" << std::endl
		<< "----------------------" << std::endl
		<< pcpp::AppName::get() << " [-vh]" << std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -v             : Displays the current version and exists" << std::endl
		<< "    -h             : Displays this help message and exits" << std::endl
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
 * Utility's main method
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	if (argc == 1) {
		printUsage();
		exit(0);
	}

	while((opt = getopt_long(argc, argv, "hv", HttpReassemblerOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'h':
				printUsage();
				exit(0);
				break;
			case 'v':
				printAppVersion();
				break;
			default:
				printUsage();
				exit(-1);
		}
	}
}
