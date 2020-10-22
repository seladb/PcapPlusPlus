
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <string>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>
#include <getopt.h>

#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>

#include <Packet.h>
#include <EthLayer.h>
#include <ArpLayer.h>
#include <IPv4Layer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>

#include <DpdkDeviceList.h>
#include <KniDevice.h>
#include <KniDeviceList.h>

#define EXIT_WITH_ERROR(reasonFmt, ...) \
	do { \
		std::fprintf(stderr, "ERROR: " reasonFmt "\n", ## __VA_ARGS__ ); \
		std::exit(-1); \
	} while (false)

#define IO_BUFF_SIZE (1 << 14)
#define WANT_POLLIN (-2)
#define WANT_POLLOUT (-3)
#define DEFAULT_KNI_NAME "pcppkni0"
#define DEFAULT_PORT 62604

namespace
{
struct KniPongArgs
{
	std::string kniIp;
	std::string outIp;
	std::string kniName;
	uint16_t kniPort;
};

typedef int linuxFd;

struct LinuxSocket
{
	inline operator int() const { return m_Socket; }
	linuxFd m_Socket;
};

struct PacketStats
{
	unsigned long totalPackets;
	unsigned long udpPacketsIn;
	unsigned long udpPacketsOutFail;
	unsigned long arpPacketsIn;
	unsigned long arpPacketsOutFail;
};

static bool doContinue = true;

inline void printVersion()
{
	std::printf(
		"%s %s\n"
		"Built: %s\n"
		"Built from: %s\n",
		pcpp::AppName::get().c_str(), pcpp::getPcapPlusPlusVersionFull().c_str(),
		pcpp::getBuildDateTime().c_str(),
		pcpp::getGitInfo().c_str()
	);
}

inline void printUsage()
{
	std::printf(
		"\nUsage:\n\n"
		"    %s -s <src_ipv4> -d <dst_ipv4> [-n <kni_device_name>] [-p <port>] [-v] [-h]\n\n"
		"Options:\n"
		"    -s --src <src_ipv4>           : IP to assign to created KNI device\n"
		"    -d --dst <dst_ipv4>           : Virtual IP to communicate with. Must be in /24 subnet with <src_ipv4>\n"
		"    -n --name <kni_device_name>   : Name for KNI device. Default: \"" DEFAULT_KNI_NAME "\"\n"
		"    -p --port <port>              : Port for communication. Default: %d\n"
		"    -v --version                  : Displays the current version and exits\n"
		"    -h --help                     : Displays this help message and exits\n\n",
		pcpp::AppName::get().c_str(),
		DEFAULT_PORT
	);
}

inline void parseArgs(int argc, char* argv[], KniPongArgs& args)
{
	struct option KniPongOptions[] =
	{
		{"src", required_argument, NULL, 's'},
		{"dst", required_argument, NULL, 'd'},
		{"name", optional_argument, NULL, 'n'},
		{"port", optional_argument, NULL, 'p'},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{NULL, 0, NULL, 0}
	};
	// Default port:
	args.kniPort = DEFAULT_PORT;
	int optionIndex = 0;
	char opt = 0;
	while ((opt = getopt_long(argc, argv, "s:d:n:p:hv", KniPongOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 's':
				args.kniIp = optarg;
				break;
			case 'd':
				args.outIp = optarg;
				break;
			case 'n':
				args.kniName = optarg;
				break;
			case 'p':
				args.kniPort = std::strtoul(optarg, NULL, 10) & 0xFFFF;
				break;
			case 'v':
				printVersion();
				/* fall-through */
			case 'h':
			{
				printUsage();
				std::exit(1);
			} break;
			default:
			{
				printUsage();
				EXIT_WITH_ERROR("Unknown option flag <%#0x>", opt);
			} break;
		}
	}
	// Default name for KNI device:
	if (args.kniName.empty())
		args.kniName = DEFAULT_KNI_NAME;
	if (args.kniIp.empty())
	{
		printUsage();
		EXIT_WITH_ERROR("IP for KNI device not provided");
	}
	if (args.outIp.empty())
	{
		printUsage();
		EXIT_WITH_ERROR("Virtual IP for communication not provided");
	}
	pcpp::IPv4Address kniIp = args.kniIp;
	pcpp::IPv4Address outIp = args.outIp;
	if (!(kniIp.isValid() && outIp.isValid()))
	{
		EXIT_WITH_ERROR("One of provided IPs is not valid");
	}
	if (!outIp.matchSubnet(kniIp, pcpp::IPv4Address("255.255.255.0")))
	{
		EXIT_WITH_ERROR(
			"Provided Virtual IP <%s> is not in same required subnet <255.255.255.0> as KNI IP <%s>",
			outIp.toString().c_str(),
			kniIp.toString().c_str()
		);
	}
}

// Simple dummy callbacks that always yields success for Linux Kernel
struct KniDummyCallbacks
{
	static int changeMtuNew(uint16_t, unsigned int) { return 0; }
	static int changeMtuOld(uint8_t, unsigned int) { return 0; }
	static int configNetworkIfNew(uint16_t, uint8_t) { return 0; }
	static int configNetworkIfOld(uint8_t, uint8_t) { return 0; }
	static int configMacAddress(uint16_t, uint8_t[]) { return 0; }
	static int configPromiscusity(uint16_t, uint8_t) { return 0; }

	static pcpp::KniDevice::KniIoctlCallbacks cbNew;
	static pcpp::KniDevice::KniOldIoctlCallbacks cbOld;

	static void setCallbacks()
	{
		cbNew.change_mtu = changeMtuNew;
		cbNew.config_network_if = configNetworkIfNew;
		cbNew.config_mac_address = configMacAddress;
		cbNew.config_promiscusity = configPromiscusity;
		cbOld.change_mtu = changeMtuOld;
		cbOld.config_network_if = configNetworkIfOld;
	}
};
pcpp::KniDevice::KniIoctlCallbacks KniDummyCallbacks::cbNew;
pcpp::KniDevice::KniOldIoctlCallbacks KniDummyCallbacks::cbOld;

// Setup IP of net device by calling the ip unix utility
inline bool setKniIp(const pcpp::IPv4Address& ip, const std::string& kniName)
{
	char buff[256];
	snprintf(buff, sizeof(buff), "ip a add %s/24 dev %s", ip.toString().c_str(), kniName.c_str());
	(void)pcpp::executeShellCommand(buff);
	snprintf(buff, sizeof(buff), "ip a | grep %s", ip.toString().c_str());
	std::string result = pcpp::executeShellCommand(buff);
	return result != "" && result != "ERROR";
}

// KNI device setup routine
inline pcpp::KniDevice* setupKniDevice(const KniPongArgs& args)
{
	{	// Setup DPDK
		pcpp::CoreMask cm = 0x3;
		bool dpdkInitSuccess = pcpp::DpdkDeviceList::initDpdk(cm, 1023);
		if (!dpdkInitSuccess)
			EXIT_WITH_ERROR("Failed to init DPDK");
	}
	pcpp::IPv4Address kniIp = args.kniIp;
	// Setup device config
	pcpp::KniDevice* device = NULL;
	pcpp::KniDevice::KniDeviceConfiguration devConfig;
	devConfig.name = args.kniName;
	KniDummyCallbacks::setCallbacks();
	if (pcpp::KniDeviceList::callbackVersion() == pcpp::KniDeviceList::CALLBACKS_NEW)
	{
		devConfig.callbacks = &KniDummyCallbacks::cbNew;
	}
	else
	{
		devConfig.oldCallbacks = &KniDummyCallbacks::cbOld;
	}
	devConfig.bindKthread = false;
	pcpp::KniDeviceList& kniDeviceList = pcpp::KniDeviceList::getInstance();
	if (!kniDeviceList.isInitialized())
		EXIT_WITH_ERROR("Can't initialize KNI device list");
	device = kniDeviceList.createDevice(devConfig, 1024);
	if (device == NULL)
		EXIT_WITH_ERROR("Can't create KNI device");
	// Check KNI device and start request thread
	if (!device->isInitialized())
		EXIT_WITH_ERROR("KNI device was not initialized correctly");
	if (!device->open())
		EXIT_WITH_ERROR("Could not open KNI device");
	if (!device->startRequestHandlerThread(0, 500000000))
		EXIT_WITH_ERROR("Could not start KNI device request handler thread");
	// Assign IP
	if (!setKniIp(kniIp, args.kniName))
		EXIT_WITH_ERROR("Can't set KNI device IP");
	// Turn device on for Linux Kernel
	if (!device->setLinkState(pcpp::KniDevice::LINK_UP))
		EXIT_WITH_ERROR("Can't set KNI device link state to UP");
	return device;
}

// Open UDP socket for communication with KNI device
inline LinuxSocket setupLinuxSocket(const KniPongArgs& args)
{	// Open socket
	enum { INVALID_FD = -1 };
	LinuxSocket sock;
	sock.m_Socket = INVALID_FD;
	if ((sock.m_Socket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_FD)
	{
		int old_errno = errno;
		EXIT_WITH_ERROR("Could not open socket\nErrno: %s", std::strerror(old_errno));
	}
	// Bind socket to KNI device IP
	struct sockaddr_in egress;
	std::memset(&egress, 0, sizeof(egress));
	egress.sin_family = AF_INET;
	egress.sin_addr.s_addr = inet_addr(args.kniIp.c_str());
	egress.sin_port = pcpp::hostToNet16(args.kniPort);
	if (bind(sock, (struct sockaddr*)&egress, sizeof(egress)) == -1)
	{
		int old_errno = errno;
		close(sock);
		EXIT_WITH_ERROR("Could not bind socket\nErrno: %s", std::strerror(old_errno));
	}

	return sock;
}

// Handle all ARP requests on KNI interface: map all IPs to same MAC
inline void processArp(pcpp::Packet& packet, pcpp::ArpLayer* arpLayer)
{
	pcpp::MacAddress rndMac("00:42:43:74:11:54");
	pcpp::EthLayer* ethernetLayer = NULL;
	pcpp::arphdr arpHdr;
	pcpp::arphdr* origArpHdr = arpLayer->getArpHeader();
	// Copy ARP request
	std::memcpy(&arpHdr, origArpHdr, sizeof(arpHdr));
	// Fill fields
	arpHdr.hardwareType = pcpp::hostToNet16(0x0001); // ETHERNET
	arpHdr.hardwareSize = sizeof(((pcpp::arphdr*)0)->senderMacAddr); // sizeof(MAC)
	arpHdr.protocolSize = sizeof(((pcpp::arphdr*)0)->senderIpAddr);  // sizeof(IPv4)
	arpHdr.opcode = pcpp::hostToNet16(pcpp::ARP_REPLY);
	std::memcpy(arpHdr.targetMacAddr, origArpHdr->senderMacAddr, sizeof(((pcpp::arphdr*)0)->senderMacAddr));
	std::memcpy(&arpHdr.targetIpAddr, &origArpHdr->senderIpAddr, sizeof(((pcpp::arphdr*)0)->senderIpAddr));
	std::memcpy(&arpHdr.senderIpAddr, &origArpHdr->targetIpAddr, sizeof(((pcpp::arphdr*)0)->senderIpAddr));
	// Set rnd MAC in response
	rndMac.copyTo(arpHdr.senderMacAddr);
	// Copy ready ARP response to packet
	std::memcpy(origArpHdr, &arpHdr, sizeof(arpHdr));

	// Setup Ethernet addresses in Ethernet layer
	ethernetLayer = packet.getLayerOfType<pcpp::EthLayer>();
	pcpp::ether_header ethHdr;
	pcpp::ether_header* origEthHdr = ethernetLayer->getEthHeader();
	std::memcpy(&ethHdr, origEthHdr, sizeof(ethHdr));
	std::memcpy(ethHdr.dstMac, origEthHdr->srcMac, sizeof(ethHdr.dstMac));
	rndMac.copyTo(ethHdr.srcMac);
	// Copy ready Ethernet layer to packet
	std::memcpy(origEthHdr, &ethHdr, sizeof(ethHdr));
}

// Handle all UDP packets as a packet carying a "ping" string to "pong" to with same string
// Handle only packets that are of type: Eth / Ip / Udp / Payload
inline bool processUdp(pcpp::Packet& packet, pcpp::UdpLayer* udpLayer)
{
	pcpp::EthLayer* ethernetLayer = NULL;
	pcpp::IPv4Layer* ipLayer = NULL;

	ethernetLayer = packet.getLayerOfType<pcpp::EthLayer>();
	pcpp::ether_header ethHdr;
	pcpp::ether_header* origEthHdr = ethernetLayer->getEthHeader();
	std::memcpy(&ethHdr, origEthHdr, sizeof(ethHdr));
	// Swap MACs for Ethernet layer
	std::memcpy(ethHdr.dstMac, origEthHdr->srcMac, sizeof(ethHdr.dstMac));
	std::memcpy(ethHdr.srcMac, origEthHdr->dstMac, sizeof(ethHdr.srcMac));
	std::memcpy(origEthHdr, &ethHdr, sizeof(ethHdr));

	ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == NULL) // Some invalid packet
		return false;
	pcpp::iphdr ipHdr;
	pcpp::iphdr* origIpHdr = ipLayer->getIPv4Header();
	std::memcpy(&ipHdr, origIpHdr, sizeof(ipHdr));
	if (pcpp::netToHost16(ipHdr.fragmentOffset) & 0x1FFF) // Fragmanted packet
		return false;
	// Swap src and dst IPs
	std::memcpy(&ipHdr.ipSrc, &origIpHdr->ipDst, sizeof(ipHdr.ipSrc));
	std::memcpy(&ipHdr.ipDst, &origIpHdr->ipSrc, sizeof(ipHdr.ipDst));
	// Randomize IP id
	ipHdr.ipId = std::rand() & 0xFFFF;
	// Set by RFC791
	ipHdr.timeToLive = 64;
	std::memcpy(origIpHdr, &ipHdr, sizeof(ipHdr));

	pcpp::udphdr udpHdr;
	pcpp::udphdr* origUdpHdr = udpLayer->getUdpHeader();
	std::memcpy(&udpHdr, origUdpHdr, sizeof(udpHdr));
	// Swap src and dst ports
	std::memcpy(&udpHdr.portSrc, &origUdpHdr->portDst, sizeof(udpHdr.portSrc));
	std::memcpy(&udpHdr.portDst, &origUdpHdr->portSrc, sizeof(udpHdr.portDst));
	std::memcpy(origUdpHdr, &udpHdr, sizeof(udpHdr));

	// Calculate checksums of IP and UDP layers
	packet.computeCalculateFields();
	// Packet is ready to be sent
	return true;
}

// Process burst of packets
bool processBurst(pcpp::MBufRawPacket packets[], uint32_t numOfPackets, pcpp::KniDevice* kni, void* cookie)
{
	PacketStats* packetStats = (PacketStats*)cookie;
	pcpp::Packet packet;
	pcpp::ArpLayer* arpLayer = NULL;
	pcpp::UdpLayer* udpLayer = NULL;

	packetStats->totalPackets += numOfPackets;
	for (uint32_t i = 0; i < numOfPackets; ++i)
	{
		packet.setRawPacket(packets + i, false);
		if ((arpLayer = packet.getLayerOfType<pcpp::ArpLayer>()) != NULL)
		{
			++packetStats->arpPacketsIn;
			processArp(packet, arpLayer);
			// Packet is ready to be sent -> have no fields to recalculate
			if (!kni->sendPacket(packet))
				++packetStats->arpPacketsOutFail;
			arpLayer = NULL;
			continue;
		}

		if ((udpLayer = packet.getLayerOfType<pcpp::UdpLayer>()) != NULL)
		{	
			++packetStats->udpPacketsIn;
			//! Warning (echo-Mike): DO NOT normalize next logic statement it relays on short circuiting
			if (!processUdp(packet, udpLayer) || !kni->sendPacket(packet))
				++packetStats->udpPacketsOutFail;
			udpLayer = NULL;
			continue;
		}

		// Other packets are just ignored
	}

	return true;
}

// Connect UDP socket to other IP:port pair derived from our
void connectUDPSocket(const LinuxSocket& sock, const KniPongArgs& args)
{
	struct sockaddr_in ingress;
	std::memset(&ingress, 0, sizeof(ingress));
	ingress.sin_family = AF_INET;
	ingress.sin_addr.s_addr = inet_addr(args.outIp.c_str());
	ingress.sin_port = pcpp::hostToNet16(args.kniPort);
	if (connect(sock, (struct sockaddr*)&ingress, sizeof(ingress)) == -1)
	{
		int old_errno = errno;
		close(sock);
		EXIT_WITH_ERROR("Could not connect socket\nErrno: %s", std::strerror(old_errno));
	}
}

// Reworked fillbuf from netcat. See description in pingPongProcess
ssize_t fillbuf(linuxFd fd, unsigned char buff[], size_t& buffPos)
{
	size_t num = IO_BUFF_SIZE - buffPos;
	ssize_t n;

	n = read(fd, buff + buffPos, num);
	if (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = WANT_POLLIN;
	if (n <= 0)
		return n;
	buffPos += n;
	return n;
}

// Reworked drainbuf from netcat. See description in pingPongProcess
ssize_t drainbuf(linuxFd fd, unsigned char buff[], size_t& buffPos)
{
	ssize_t n;
	ssize_t adjust;

	n = write(fd, buff, buffPos);
	if (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = WANT_POLLOUT;
	if (n <= 0)
		return n;
	/* adjust buffer */
	adjust = buffPos - n;
	if (adjust > 0)
		std::memmove(buff, buff + n, adjust);
	buffPos -= n;
	return n;
}

// Reworked readwrite from netcat. See description in pingPongProcess
void pingPongProcess(const LinuxSocket& sock)
{	//? Note (echo-Mike): This function and fillbuf/drainbuf
	//? are analogous to code of NETCAT utility (OpenBSD version)
	// Authors of original codebase:
	//  - Eric Jackson <ericj@monkey.org>
	//  - Bob Beck
	//  - *Hobbit* <hobbit@avian.org>
	//? See: http://man7.org/linux/man-pages/man1/ncat.1.html
	struct pollfd pfd[4];
	const int POLL_STDIN = 0, POLL_NETOUT = 1, POLL_NETIN = 2, POLL_STDOUT = 3;
	const int DEFAULT_POLL_TIMEOUT = 3000;//milisec
	unsigned char netbuff[IO_BUFF_SIZE];
	size_t netbuffPos = 0;
	unsigned char ttybuff[IO_BUFF_SIZE];
	size_t ttybuffPos = 0;
	int n, num_fds;
	ssize_t ret;

	/* stdin */
	pfd[POLL_STDIN].fd = STDIN_FILENO;
	pfd[POLL_STDIN].events = POLLIN;
	/* network out */
	pfd[POLL_NETOUT].fd = sock;
	pfd[POLL_NETOUT].events = 0;
	/* network in */
	pfd[POLL_NETIN].fd = sock;
	pfd[POLL_NETIN].events = POLLIN;
	/* stdout */
	pfd[POLL_STDOUT].fd = STDOUT_FILENO;
	pfd[POLL_STDOUT].events = 0;

	while (doContinue)
	{
		/* both inputs are gone, buffers are empty, we are done */
		if (pfd[POLL_STDIN].fd == -1 &&
			pfd[POLL_NETIN].fd == -1 &&
			ttybuffPos == 0 &&
			netbuffPos == 0
		)
		{
			return;
		}
		/* both outputs are gone, we can't continue */
		if (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1)
			return;

		/* poll */
		num_fds = poll(pfd, 4, DEFAULT_POLL_TIMEOUT);

		/* treat poll errors */
		if (num_fds == -1)
		{
			int old_errno = errno;
			if (old_errno != EINTR)
			{
				close(sock);
				EXIT_WITH_ERROR("poll returned an error\nErrno: %s", std::strerror(old_errno));
			}
			continue;
		}

		if (num_fds == 0)
		{	// Note (echo-Mike): uncomment if debug needed
			// std::printf("poll: timeout\n");
			continue;
		}

		/* treat socket error conditions */
		for (n = 0; n < 4; ++n)
		{
			if (pfd[n].revents & (POLLERR|POLLNVAL))
			{
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		if (pfd[POLL_STDIN].events & POLLIN &&
			pfd[POLL_STDIN].revents & POLLHUP &&
			!(pfd[POLL_STDIN].revents & POLLIN)
		)
		{
			pfd[POLL_STDIN].fd = -1;
		}

		if (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    !(pfd[POLL_NETIN].revents & POLLIN)
		)
		{
			pfd[POLL_NETIN].fd = -1;
		}

		if (pfd[POLL_NETOUT].revents & POLLHUP)
		{
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		if (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		if (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		if (pfd[POLL_STDOUT].fd == -1)
		{
			if (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		if (pfd[POLL_STDIN].revents & POLLIN && ttybuffPos < IO_BUFF_SIZE)
		{
			ret = fillbuf(pfd[POLL_STDIN].fd, ttybuff, ttybuffPos);
			if (ret == WANT_POLLIN)
				pfd[POLL_STDIN].events = POLLIN;
			else if (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			if (ttybuffPos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			if (ttybuffPos == IO_BUFF_SIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		if (pfd[POLL_NETOUT].revents & POLLOUT && ttybuffPos > 0)
		{
			ret = drainbuf(pfd[POLL_NETOUT].fd, ttybuff, ttybuffPos);
			if (ret == WANT_POLLOUT)
				pfd[POLL_NETOUT].events = POLLOUT;
			else if (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			if (ttybuffPos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			if (ttybuffPos < IO_BUFF_SIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		if (pfd[POLL_NETIN].revents & POLLIN && netbuffPos < IO_BUFF_SIZE)
		{
			ret = fillbuf(pfd[POLL_NETIN].fd, netbuff, netbuffPos);
			if (ret == WANT_POLLIN)
				pfd[POLL_NETIN].events = POLLIN;
			else if (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			if (ret == 0)
			{
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			if (netbuffPos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			if (netbuffPos == IO_BUFF_SIZE)
				pfd[POLL_NETIN].events = 0;
		}
		/* try to write to stdout */
		if (pfd[POLL_STDOUT].revents & POLLOUT && netbuffPos > 0)
		{
			ret = drainbuf(pfd[POLL_STDOUT].fd, netbuff, netbuffPos);
			if (ret == WANT_POLLOUT)
				pfd[POLL_STDOUT].events = POLLOUT;
			else if (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			if (netbuffPos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			if (netbuffPos < IO_BUFF_SIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		if (pfd[POLL_STDIN].fd == -1 && ttybuffPos == 0)
		{
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		if (pfd[POLL_NETIN].fd == -1 && netbuffPos == 0)
		{
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

} // namespace

extern "C" void signal_handler(int)
{
	doContinue = false;
}

int main(int argc, char* argv[])
{
	PacketStats packetStats;
	std::memset(&packetStats, 0, sizeof(packetStats));
	KniPongArgs args;
	std::srand(std::time(NULL));
	pcpp::AppName::init(argc, argv);
	parseArgs(argc, argv, args);
	pcpp::KniDevice* device = setupKniDevice(args);
	LinuxSocket sock = setupLinuxSocket(args);
	if (!device->startCapture(processBurst, &packetStats))
	{
		close(sock);
		EXIT_WITH_ERROR("Could not start capture thread on KNI device");
	}
	connectUDPSocket(sock, args);
	std::signal(SIGINT, signal_handler);
	std::printf("Ready for input:\n");
	pingPongProcess(sock);
	//! Close socket before device
	close(sock);
	device->stopCapture();
	device->close();
	device->stopRequestHandlerThread();
	std::printf(
		"\nPacket statistics from KNI thread:\n"
		"    Total packets met: %lu\n"
		"    UDP packets met: %lu\n"
		"    Failed PONG packets: %lu\n"
		"    ARP packets met: %lu\n"
		"    Failed ARP replay packets: %lu\n",
		packetStats.totalPackets,
		packetStats.udpPacketsIn,
		packetStats.udpPacketsOutFail,
		packetStats.arpPacketsIn,
		packetStats.arpPacketsOutFail
	);
	return 0;
}