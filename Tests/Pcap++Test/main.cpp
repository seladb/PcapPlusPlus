#include "PcapPlusPlusVersion.h"
#include "Logger.h"
#include "PcppTestFrameworkRun.h"
#include "TestDefinition.h"
#include "Common/GlobalTestArgs.h"
#include "Common/TestUtils.h"
#include <getopt.h>

// clang-format off
static struct option PcapTestOptions[] = {
	{ "debug-mode",          no_argument,       nullptr, 'b' },
	{ "use-ip",              required_argument, nullptr, 'i' },
	{ "remote-ip",           required_argument, nullptr, 'r' },
	{ "remote-port",         required_argument, nullptr, 'p' },
	{ "dpdk-port",           required_argument, nullptr, 'd' },
	{ "no-networking",       no_argument,       nullptr, 'n' },
	{ "verbose",             no_argument,       nullptr, 'v' },
	{ "mem-verbose",         no_argument,       nullptr, 'm' },
	{ "kni-ip",              no_argument,       nullptr, 'k' },
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
	std::cout << "Usage: Pcap++Test -i ip_to_use | [-n] [-b] [-s] [-m] [-r remote_ip_addr] [-p remote_port] [-d "
	             "dpdk_port] [-k ip_addr] [-t tags] [-w] [-h]\n\n"
	          << "Flags:\n"
	          << "-i --use-ip              IP to use for sending and receiving packets\n"
	          << "-b --debug-mode          Set log level to DEBUG\n"
	          << "-r --remote-ip	          IP of remote machine running rpcapd to test remote capture\n"
	          << "-p --remote-port         Port of remote machine running rpcapd to test remote capture\n"
	          << "-d --dpdk-port           The DPDK NIC port to test. Required if compiling with DPDK\n"
	          << "-n --no-networking       Do not run tests that requires networking\n"
	          << "-v --verbose             Run in verbose mode (emits more output in several tests)\n"
	          << "-m --mem-verbose         Output information about each memory allocation and deallocation\n"
	          << "-s --skip-mem-leak-check Skip memory leak check\n"
	          << "-k --kni-ip              IP address for KNI device tests to use must not be the same\n"
	          << "                         as any of existing network interfaces in your system.\n"
	          << "                         If this parameter is omitted KNI tests will be skipped. Must be an IPv4.\n"
	          << "                         For Linux systems only\n"
	          << "-t --include-tags        A list of semicolon separated tags for tests to run\n"
	          << "-x --exclude-tags        A list of semicolon separated tags for tests to exclude\n"
	          << "-w --show-skipped-tests  Show tests that are skipped. Default is to hide them in tests results\n"
	          << "-h --help                Display this help message and exit\n";
}

PcapTestArgs PcapTestGlobalArgs;

int main(int argc, char* argv[])
{
	PcapTestGlobalArgs.ipToSendReceivePackets = "";
	PcapTestGlobalArgs.debugMode = false;
	PcapTestGlobalArgs.dpdkPort = -1;
	PcapTestGlobalArgs.kniIp = "";

	std::string userTagsInclude = "", userTagsExclude = "", configTags = "";
	bool runWithNetworking = true;
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
		case 'k':
			PcapTestGlobalArgs.kniIp = optarg;
			break;
		case 'i':
			PcapTestGlobalArgs.ipToSendReceivePackets = optarg;
			break;
		case 'b':
			PcapTestGlobalArgs.debugMode = true;
			break;
		case 'r':
			PcapTestGlobalArgs.remoteIp = optarg;
			break;
		case 'p':
			PcapTestGlobalArgs.remotePort = (uint16_t)atoi(optarg);
			break;
		case 'd':
			PcapTestGlobalArgs.dpdkPort = (int)atoi(optarg);
			break;
		case 'n':
			runWithNetworking = false;
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

	if (!runWithNetworking)
	{
		if (userTagsInclude != "")
			userTagsInclude += ";";

		userTagsInclude += "no_network";
		std::cout << "Running only tests that don't require network connection" << std::endl;
	}
	else if (PcapTestGlobalArgs.ipToSendReceivePackets == "")
	{
		std::cerr << "Please provide an IP address to send and receive packets (-i argument)\n\n";
		printUsage();
		exit(-1);
	}

#ifdef NDEBUG
	skipMemLeakCheck = true;
	std::cout << "Disabling memory leak check in MSVC Release builds due to caching logic in stream objects that looks "
	             "like a memory leak:"
	          << std::endl
	          << "     https://github.com/cpputest/cpputest/issues/786#issuecomment-148921958" << std::endl;
#endif

	// The logger singleton looks like a memory leak. Invoke it before starting the memory check.
	// Disables context pooling to avoid false positives in the memory leak check, as the contexts persist in the pool.
	pcpp::Logger::getInstance().useContextPooling(false);

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

#ifdef USE_DPDK
	if (PcapTestGlobalArgs.dpdkPort == -1 && runWithNetworking)
	{
		std::cerr << "When testing with DPDK you must provide the DPDK NIC port to test\n\n";
		printUsage();
		exit(-1);
	}
#endif  // USE_DPDK

	if (PcapTestGlobalArgs.debugMode)
	{
		pcpp::Logger::getInstance().setAllModulesToLogLevel(pcpp::Logger::Debug);
	}

	std::cout << "PcapPlusPlus version: " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Git info: " << pcpp::getGitInfo() << std::endl
	          << "Using ip: " << PcapTestGlobalArgs.ipToSendReceivePackets << std::endl
	          << "Debug mode: " << (PcapTestGlobalArgs.debugMode ? "on" : "off") << std::endl;

#ifdef USE_DPDK
	if (runWithNetworking)
	{
		std::cout << "Using DPDK port: " << PcapTestGlobalArgs.dpdkPort << std::endl;
		if (PcapTestGlobalArgs.kniIp == "")
			std::cout << "DPDK KNI tests: skipped" << std::endl;
		else
			std::cout << "Using IP address for KNI: " << PcapTestGlobalArgs.kniIp << std::endl;
	}
#endif

	PTF_START_RUNNING_TESTS(userTagsInclude, userTagsExclude, configTags);

	testSetUp();

	PTF_RUN_TEST(TestIPAddress, "no_network;ip");
	PTF_RUN_TEST(TestMacAddress, "no_network;mac");
	PTF_RUN_TEST(TestLRUList, "no_network");
	PTF_RUN_TEST(TestGeneralUtils, "no_network");
	PTF_RUN_TEST(TestGetMacAddress, "mac");
	PTF_RUN_TEST(TestIPv4Network, "no_network;ip");
	PTF_RUN_TEST(TestIPv6Network, "no_network;ip");
	PTF_RUN_TEST(TestIPNetwork, "no_network;ip");

	PTF_RUN_TEST(TestObjectPool, "no_network");

	PTF_RUN_TEST(TestLogger, "no_network;logger");
	PTF_RUN_TEST(TestLoggerMultiThread, "no_network;logger;skip_mem_leak_check");

	PTF_RUN_TEST(TestPcapFileReadWrite, "no_network;pcap");
	PTF_RUN_TEST(TestPcapFilePrecision, "no_network;pcap");
	PTF_RUN_TEST(TestPcapSllFileReadWrite, "no_network;pcap");
	PTF_RUN_TEST(TestPcapSll2FileReadWrite, "no_network;pcap");
	PTF_RUN_TEST(TestPcapRawIPFileReadWrite, "no_network;pcap");
	PTF_RUN_TEST(TestPcapFileAppend, "no_network;pcap");
	PTF_RUN_TEST(TestPcapNgFileReadWrite, "no_network;pcap;pcapng");
	PTF_RUN_TEST(TestPcapNgFileReadWriteAdv, "no_network;pcap;pcapng");
	PTF_RUN_TEST(TestPcapNgFileTooManyInterfaces, "no_network;pcap;pcapng");
	PTF_RUN_TEST(TestPcapNgFilePrecision, "no_network;pcapng");
	PTF_RUN_TEST(TestPcapFileReadLinkTypeIPv6, "no_network;pcap");
	PTF_RUN_TEST(TestPcapFileReadLinkTypeIPv4, "no_network;pcap");
	PTF_RUN_TEST(TestSolarisSnoopFileRead, "no_network;pcap;snoop");
	PTF_RUN_TEST(TestPcapFileWriterDeviceDestructor, "no_network;pcap");

	PTF_RUN_TEST(TestPcapLiveDeviceList, "no_network;live_device;skip_mem_leak_check");
	PTF_RUN_TEST(TestPcapLiveDeviceListSearch, "live_device");
	PTF_RUN_TEST(TestPcapLiveDevice, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceClone, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceNoNetworking, "no_network;live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceStatsMode, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceBlockingMode, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceWithLambda, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceBlockingModeWithLambda, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceSpecialCfg, "live_device");
	PTF_RUN_TEST(TestWinPcapLiveDevice, "live_device;winpcap");
	PTF_RUN_TEST(TestSendPacket, "live_device;send");
	PTF_RUN_TEST(TestSendPackets, "live_device;send");
	PTF_RUN_TEST(TestMtuSize, "live_device;mtu");
	PTF_RUN_TEST(TestRemoteCapture, "live_device;remote_capture;winpcap");

	PTF_RUN_TEST(TestPcapFilters_MatchStatic, "no_network;filters;skip_mem_leak_check");
	PTF_RUN_TEST(TestPcapFiltersLive, "filters");
	PTF_RUN_TEST(TestPcapFilters_General_BPFStr, "no_network;filters;skip_mem_leak_check");
	PTF_RUN_TEST(TestPcapFiltersOffline, "no_network;filters");
	PTF_RUN_TEST(TestPcapFilters_LinkLayer, "no_network;filters;skip_mem_leak_check");

	PTF_RUN_TEST(TestHttpRequestParsing, "no_network;http");
	PTF_RUN_TEST(TestHttpResponseParsing, "no_network;http");
	PTF_RUN_TEST(TestPrintPacketAndLayers, "no_network;print");
	PTF_RUN_TEST(TestDnsParsing, "no_network;dns");

	PTF_RUN_TEST(TestPfRingDevice, "pf_ring");
	PTF_RUN_TEST(TestPfRingDeviceSingleChannel, "pf_ring");
	PTF_RUN_TEST(TestPfRingMultiThreadAllCores, "pf_ring");
	PTF_RUN_TEST(TestPfRingMultiThreadSomeCores, "pf_ring");
	PTF_RUN_TEST(TestPfRingSendPacket, "pf_ring");
	PTF_RUN_TEST(TestPfRingSendPackets, "pf_ring");
	PTF_RUN_TEST(TestPfRingFilters, "pf_ring");

	PTF_RUN_TEST(TestDpdkInitDevice, "dpdk;dpdk-init;skip_mem_leak_check");
	PTF_RUN_TEST(TestDpdkDevice, "dpdk");
	PTF_RUN_TEST(TestDpdkMultiThread, "dpdk");
	PTF_RUN_TEST(TestDpdkDeviceSendPackets, "dpdk");
	PTF_RUN_TEST(TestDpdkDeviceWorkerThreads, "dpdk");
	PTF_RUN_TEST(TestDpdkMbufRawPacket, "dpdk");

	PTF_RUN_TEST(TestKniDevice, "dpdk;kni;skip_mem_leak_check");
	PTF_RUN_TEST(TestKniDeviceSendReceive, "dpdk;kni;skip_mem_leak_check");

	PTF_RUN_TEST(TestTcpReassemblySanity, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyRetran, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMissingData, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyOutOfOrder, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyOOOWithManualClose, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyWithFIN_RST, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMalformedPkts, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMultipleConns, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyIPv6, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyIPv6MultConns, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyIPv6_OOO, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyCleanup, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMaxOOOFrags, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMaxSeq, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyDisableOOOCleanup, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyTimeStamps, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyFinReset, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyHighPrecision, "no_network;tcp_reassembly");

	PTF_RUN_TEST(TestIPFragmentationSanity, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragOutOfOrder, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragPartialData, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragMultipleFrags, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragMapOverflow, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragRemove, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragWithPadding, "no_network;ip_frag");

	PTF_RUN_TEST(TestRawSockets, "raw_sockets");

	PTF_RUN_TEST(TestSystemCoreUtils, "no_network;system_utils");

	PTF_RUN_TEST(TestXdpDeviceReceivePackets, "xdp");
	PTF_RUN_TEST(TestXdpDeviceSendPackets, "xdp");
	PTF_RUN_TEST(TestXdpDeviceNonDefaultConfig, "xdp");
	PTF_RUN_TEST(TestXdpDeviceInvalidConfig, "xdp");

	PTF_END_RUNNING_TESTS;
}

#ifdef _MSC_VER
#	pragma warning(pop)
#endif
