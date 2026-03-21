#include "PcapPlusPlusVersion.h"
#include "Logger.h"
#include "PcppTestFrameworkRun.h"
#include "TestDefinition.h"
#include <getopt.h>

// clang-format off
static struct option PcapTestOptions[] = {
	{ "verbose",             no_argument,       nullptr, 'v' },
	{ "mem-verbose",         no_argument,       nullptr, 'm' },
	{ "skip-mem-leak-check", no_argument,       nullptr, 's' },
	{ "include-tags",        required_argument, nullptr, 't' },
	{ "exclude-tags",        required_argument, nullptr, 'x' },
	{ "show-skipped-tests",  no_argument,       nullptr, 'w' },
	{ "help",                no_argument,       nullptr, 'h' },
	{ nullptr,               0,                 nullptr,  0   },
};
// clang-format on

void printUsage()
{
	std::cout << "Usage: Logger++Test [-s] [-m] [-t tags] [-w] [-h]\n\n"
	          << "Flags:\n"
	          << "-v --verbose             Run in verbose mode (emits more output in several tests)\n"
	          << "-m --mem-verbose         Output information about each memory allocation and deallocation\n"
	          << "-s --skip-mem-leak-check Skip memory leak check\n"
	          << "-t --include-tags        A list of semicolon separated tags for tests to run\n"
	          << "-x --exclude-tags        A list of semicolon separated tags for tests to exclude\n"
	          << "-w --show-skipped-tests  Show tests that are skipped. Default is to hide them in tests results\n"
	          << "-h --help                Display this help message and exit\n";
}

int main(int argc, char* argv[])
{
	std::string userTagsInclude = "", userTagsExclude = "", configTags = "";
	bool memVerbose = false;
	bool skipMemLeakCheck = false;

	int optionIndex = 0;
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "k:i:br:p:d:nvt:x:smw", PcapTestOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'v':
			PTF_SET_VERBOSE_MODE(true);
			break;
		case 't':
			userTagsInclude = optarg;
			break;
		case 'x':
			userTagsExclude = optarg;
			break;
		case 's':
			skipMemLeakCheck = true;
			break;
		case 'm':
			memVerbose = true;
			break;
		case 'w':
			PTF_SHOW_SKIPPED_TESTS(true);
			break;
		case 'h':
			printUsage();
			exit(0);
		default:
			printUsage();
			exit(-1);
		}
	}

#ifdef NDEBUG
	skipMemLeakCheck = true;
	std::cout << "Disabling memory leak check in MSVC Release builds due to caching logic in stream objects that looks "
	             "like a memory leak:"
	          << std::endl
	          << "     https://github.com/cpputest/cpputest/issues/786#issuecomment-148921958" << std::endl;
#endif

	auto& logger = pcpp::Logger::getInstance();
	// The logger singleton looks like a memory leak. Invoke it before starting the memory check.
	// Disables context pooling to avoid false positives in the memory leak check, as the contexts persist in the pool.
	logger.useContextPooling(false);

	logger.suppressLogs();
	logger.emit(pcpp::LogSource(pcpp::LogModule::UndefinedLogModule, "main.cpp", "main", __LINE__),
	            pcpp::LogLevel::Error, "Needed log to initialize lastError string before memory snapshot.");
	logger.enableLogs();

	// cppcheck-suppress knownConditionTrueFalse
	if (skipMemLeakCheck)
	{
		if (configTags != "")
			configTags += ";";

		configTags += "skip_mem_leak_check";
		std::cout << "Skipping memory leak check for all test cases" << std::endl;
	}

	if (memVerbose)
	{
		if (configTags != "")
			configTags += ";";

		configTags += "mem_leak_check_verbose";
		std::cout << "Turning on verbose information on memory allocations" << std::endl;
	}

	std::cout << "PcapPlusPlus version: " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Git info: " << pcpp::getGitInfo() << std::endl;

	PTF_START_RUNNING_TESTS(userTagsInclude, userTagsExclude, configTags);

	PTF_RUN_TEST(TestLogger, "no_network;logger");
	PTF_RUN_TEST(TestLoggerMultiThread, "no_network;logger;skip_mem_leak_check");

	PTF_END_RUNNING_TESTS;
}

#ifdef _MSC_VER
#	pragma warning(pop)
#endif
