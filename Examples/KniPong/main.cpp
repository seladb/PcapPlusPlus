
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <string>
#include <iostream>

#include <unistd.h>
#include <cerrno>
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

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		std::cout << '\n' << "ERROR: " << reason << '\n' << '\n';                                                      \
		exit(1);                                                                                                       \
	} while (0)

#define DEFAULT_KNI_NAME "pcppkni0"

constexpr auto IO_BUFF_SIZE = (1 << 14);
constexpr auto WANT_POLLIN = (-2);
constexpr auto WANT_POLLOUT = (-3);
constexpr auto DEFAULT_PORT = 62604;

namespace
{

	struct KniPongArgs
	{
		std::string kniIp;
		std::string outIp;
		std::string kniName;
		uint16_t kniPort{};
	};

	using linuxFd = int;

	struct LinuxSocket
	{
		operator int() const
		{
			return m_Socket;
		}
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

	bool doContinue = true;

	/**
	 * Print application version
	 */
	void printAppVersion()
	{
		std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << '\n'
		          << "Built: " << pcpp::getBuildDateTime() << '\n'
		          << "Built from: " << pcpp::getGitInfo() << '\n';
		exit(0);
	}

	/**
	 * Print application usage
	 */
	inline void printUsage()
	{
		std::cout << '\n'
		          << "Usage:" << '\n'
		          << "------" << '\n'
		          << pcpp::AppName::get() << " [-hv] [-n KNI_DEVICE_NAME] [-p PORT] -s SRC_IPV4 -d DST_IPV4" << '\n'
		          << '\n'
		          << "Options:" << '\n'
		          << "    -s --src SRC_IPV4           : IPv4 address to assign to the created KNI device" << '\n'
		          << "    -d --dst DST_IPV4           : Virtual IPv4 address to communicate with. Must be in /24 "
		             "subnet with SRC_IPV4"
		          << '\n'
		          << "    -n --name KNI_DEVICE_NAME   : Name for KNI device. Default: \"" << DEFAULT_KNI_NAME << "\""
		          << '\n'
		          << "    -p --port PORT              : Port for communication. Default: " << DEFAULT_PORT << '\n'
		          << "    -v --version                : Displays the current version and exits" << '\n'
		          << "    -h --help                   : Displays this help message and exits" << '\n'
		          << '\n';
	}

	inline void parseArgs(int argc, char* argv[], KniPongArgs& args)
	{
		struct option KniPongOptions[] = {
			{ "src",     required_argument, nullptr, 's' },
			{ "dst",     required_argument, nullptr, 'd' },
			{ "name",    optional_argument, nullptr, 'n' },
			{ "port",    optional_argument, nullptr, 'p' },
			{ "help",    no_argument,       nullptr, 'h' },
			{ "version", no_argument,       nullptr, 'v' },
			{ nullptr,   0,                 nullptr, 0   }
		};
		// Default port:
		args.kniPort = DEFAULT_PORT;
		int optionIndex = 0;
		int opt = 0;
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
				args.kniPort = std::strtoul(optarg, nullptr, 10) & 0xFFFF;
				break;
			case 'v':
				printAppVersion();
				break;
			case 'h':
			{
				printUsage();
				std::exit(0);
			}
			break;
			default:
			{
				printUsage();
				exit(1);
			}
			break;
			}
		}
		// Default name for KNI device:
		if (args.kniName.empty())
		{
			args.kniName = DEFAULT_KNI_NAME;
		}
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

		pcpp::IPv4Address kniIp;
		pcpp::IPv4Address outIp;
		try
		{
			kniIp = pcpp::IPv4Address(args.kniIp);
		}
		catch (const std::exception&)
		{
			EXIT_WITH_ERROR("Cannot assign an invalid IPv4 address to the KNI device");
		}
		try
		{
			outIp = pcpp::IPv4Address(args.outIp);
		}
		catch (const std::exception&)
		{
			EXIT_WITH_ERROR("Cannot assign an invalid IPv4 address as the virtual address");
		}

		if (!outIp.matchNetwork(pcpp::IPv4Network(kniIp, "255.255.255.0")))
		{
			EXIT_WITH_ERROR("Provided Virtual IP '"
			                << outIp << "' is not in same required subnet '255.255.255.0' as KNI IP '" << kniIp << "'");
		}
	}

	/**
	 * Simple dummy callbacks that always yields success for Linux Kernel
	 */
	struct KniDummyCallbacks
	{
		static int changeMtuNew(uint16_t /*unused*/, unsigned int /*unused*/)
		{
			return 0;
		}
		static int changeMtuOld(uint8_t /*unused*/, unsigned int /*unused*/)
		{
			return 0;
		}
		static int configNetworkIfNew(uint16_t /*unused*/, uint8_t /*unused*/)
		{
			return 0;
		}
		static int configNetworkIfOld(uint8_t /*unused*/, uint8_t /*unused*/)
		{
			return 0;
		}
		static int configMacAddress(uint16_t /*unused*/, uint8_t /*unused*/[])
		{
			return 0;
		}
		static int configPromiscusity(uint16_t /*unused*/, uint8_t /*unused*/)
		{
			return 0;
		}

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

	/**
	 * Setup IP of net device by calling the ip unix utility
	 */
	inline bool setKniIp(const pcpp::IPv4Address& ipAddr, const std::string& kniName)
	{
		std::ostringstream command;
		command << "ip a add " << ipAddr << "/24 dev " << kniName;
		pcpp::executeShellCommand(command.str());
		command.str("");
		command << "ip a | grep " << ipAddr;
		try
		{
			const std::string result = pcpp::executeShellCommand(command.str());
			return !result.empty();
		}
		catch (const std::runtime_error&)
		{
			return false;
		}
	}

	/**
	 * KNI device setup routine
	 */
	inline pcpp::KniDevice* setupKniDevice(const KniPongArgs& args)
	{
		{
			// Setup DPDK
			const pcpp::CoreMask cMask = 0x3;
			const bool dpdkInitSuccess = pcpp::DpdkDeviceList::initDpdk(cMask, 1023);
			if (!dpdkInitSuccess)
			{
				EXIT_WITH_ERROR("Failed to init DPDK");
			}
		}
		const pcpp::IPv4Address kniIp = args.kniIp;
		// Setup device config
		pcpp::KniDevice* device = nullptr;
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
		{
			EXIT_WITH_ERROR("Can't initialize KNI device list");
		}
		device = kniDeviceList.createDevice(devConfig, 1024);
		if (device == nullptr)
		{
			EXIT_WITH_ERROR("Can't create KNI device");
		}
		// Check KNI device and start request thread
		if (!device->isInitialized())
		{
			EXIT_WITH_ERROR("KNI device was not initialized correctly");
		}
		if (!device->open())
		{
			EXIT_WITH_ERROR("Could not open KNI device");
		}
		if (!device->startRequestHandlerThread(0, 500000000))
		{
			EXIT_WITH_ERROR("Could not start KNI device request handler thread");
		}
		// Assign IP
		if (!setKniIp(kniIp, args.kniName))
		{
			EXIT_WITH_ERROR("Can't set KNI device IP");
		}
		// Turn device on for Linux Kernel
		if (!device->setLinkState(pcpp::KniDevice::LINK_UP))
		{
			EXIT_WITH_ERROR("Can't set KNI device link state to UP");
		}
		return device;
	}

	/**
	 * Open UDP socket for communication with KNI device
	 */
	inline LinuxSocket setupLinuxSocket(const KniPongArgs& args)
	{  // Open socket
		constexpr auto INVALID_FD = -1;
		LinuxSocket sock{};
		if ((sock.m_Socket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_FD)
		{
			const int old_errno = errno;
			EXIT_WITH_ERROR("Could not open socket" << '\n' << "Errno: " << std::strerror(old_errno));
		}
		// Bind socket to KNI device IP
		struct sockaddr_in egress{};
		std::memset(&egress, 0, sizeof(egress));
		egress.sin_family = AF_INET;
		egress.sin_addr.s_addr = inet_addr(args.kniIp.c_str());
		egress.sin_port = pcpp::hostToNet16(args.kniPort);
		if (bind(sock, reinterpret_cast<struct sockaddr*>(&egress), sizeof(egress)) == -1)
		{
			const int old_errno = errno;
			close(sock);
			EXIT_WITH_ERROR("Could not bind socket" << '\n' << "Errno: " << std::strerror(old_errno));
		}

		return sock;
	}

	/**
	 * Handle all ARP requests on KNI interface: map all IPs to same MAC
	 */
	inline void processArp(pcpp::Packet& packet, pcpp::ArpLayer* arpLayer)
	{
		const pcpp::MacAddress rndMac("00:42:43:74:11:54");
		pcpp::EthLayer* ethernetLayer = nullptr;
		pcpp::arphdr arpHdr{};
		pcpp::arphdr* origArpHdr = arpLayer->getArpHeader();
		// Copy ARP request
		std::memcpy(&arpHdr, origArpHdr, sizeof(arpHdr));
		// Fill fields
		arpHdr.hardwareType = pcpp::hostToNet16(0x0001);                        // ETHERNET
		arpHdr.hardwareSize = sizeof(((pcpp::arphdr*)nullptr)->senderMacAddr);  // sizeof(MAC)
		arpHdr.protocolSize = sizeof(((pcpp::arphdr*)nullptr)->senderIpAddr);   // sizeof(IPv4)
		arpHdr.opcode = pcpp::hostToNet16(pcpp::ARP_REPLY);
		std::memcpy(arpHdr.targetMacAddr, origArpHdr->senderMacAddr, sizeof(((pcpp::arphdr*)nullptr)->senderMacAddr));
		std::memcpy(&arpHdr.targetIpAddr, &origArpHdr->senderIpAddr, sizeof(((pcpp::arphdr*)nullptr)->senderIpAddr));
		std::memcpy(&arpHdr.senderIpAddr, &origArpHdr->targetIpAddr, sizeof(((pcpp::arphdr*)nullptr)->senderIpAddr));
		// Set rnd MAC in response
		rndMac.copyTo(arpHdr.senderMacAddr);
		// Copy ready ARP response to packet
		std::memcpy(origArpHdr, &arpHdr, sizeof(arpHdr));

		// Setup Ethernet addresses in Ethernet layer
		ethernetLayer = packet.getLayerOfType<pcpp::EthLayer>();
		pcpp::ether_header ethHdr{};
		pcpp::ether_header* origEthHdr = ethernetLayer->getEthHeader();
		std::memcpy(&ethHdr, origEthHdr, sizeof(ethHdr));
		std::memcpy(ethHdr.dstMac, origEthHdr->srcMac, sizeof(ethHdr.dstMac));
		rndMac.copyTo(ethHdr.srcMac);
		// Copy ready Ethernet layer to packet
		std::memcpy(origEthHdr, &ethHdr, sizeof(ethHdr));
	}

	/**
	 * Handle all UDP packets as a packet carrying a "ping" string to "pong" to with same string.
	 * Handle only packets that are of type: Eth / Ip / Udp / Payload.
	 */
	inline bool processUdp(pcpp::Packet& packet, pcpp::UdpLayer* udpLayer)
	{
		pcpp::EthLayer* ethernetLayer = nullptr;
		pcpp::IPv4Layer* ipLayer = nullptr;

		ethernetLayer = packet.getLayerOfType<pcpp::EthLayer>();
		pcpp::ether_header ethHdr{};
		pcpp::ether_header* origEthHdr = ethernetLayer->getEthHeader();
		std::memcpy(&ethHdr, origEthHdr, sizeof(ethHdr));
		// Swap MACs for Ethernet layer
		std::memcpy(ethHdr.dstMac, origEthHdr->srcMac, sizeof(ethHdr.dstMac));
		std::memcpy(ethHdr.srcMac, origEthHdr->dstMac, sizeof(ethHdr.srcMac));
		std::memcpy(origEthHdr, &ethHdr, sizeof(ethHdr));

		ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
		if (ipLayer == nullptr)
		{  // Some invalid packet
			return false;
		}
		pcpp::iphdr ipHdr{};
		pcpp::iphdr* origIpHdr = ipLayer->getIPv4Header();
		std::memcpy(&ipHdr, origIpHdr, sizeof(ipHdr));
		if ((pcpp::netToHost16(ipHdr.fragmentOffset) & 0x1FFF) != 0)
		{  // Fragmented packet
			return false;
		}
		// Swap src and dst IPs
		std::memcpy(&ipHdr.ipSrc, &origIpHdr->ipDst, sizeof(ipHdr.ipSrc));
		std::memcpy(&ipHdr.ipDst, &origIpHdr->ipSrc, sizeof(ipHdr.ipDst));
		// Randomize IP id
		ipHdr.ipId = std::rand() & 0xFFFF;  // NOLINT(cert-msc30-c,cert-msc50-cpp)
		// Set by RFC791
		ipHdr.timeToLive = 64;
		std::memcpy(origIpHdr, &ipHdr, sizeof(ipHdr));

		pcpp::udphdr udpHdr{};
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

	/**
	 * Process burst of packets
	 */
	bool processBurst(pcpp::MBufRawPacket packets[], uint32_t numOfPackets, pcpp::KniDevice* kni, void* cookie)
	{
		auto* packetStats = reinterpret_cast<PacketStats*>(cookie);
		pcpp::Packet packet;
		pcpp::ArpLayer* arpLayer = nullptr;
		pcpp::UdpLayer* udpLayer = nullptr;

		packetStats->totalPackets += numOfPackets;
		for (uint32_t i = 0; i < numOfPackets; ++i)
		{
			packet.setRawPacket(packets + i, false);
			if ((arpLayer = packet.getLayerOfType<pcpp::ArpLayer>()) != nullptr)
			{
				++packetStats->arpPacketsIn;
				processArp(packet, arpLayer);
				// Packet is ready to be sent -> have no fields to recalculate
				if (!kni->sendPacket(packet))
				{
					++packetStats->arpPacketsOutFail;
				}
				arpLayer = nullptr;
				continue;
			}

			if ((udpLayer = packet.getLayerOfType<pcpp::UdpLayer>()) != nullptr)
			{
				++packetStats->udpPacketsIn;
				//! Warning (echo-Mike): DO NOT normalize next logic statement it relays on short circuiting
				if (!processUdp(packet, udpLayer) || !kni->sendPacket(packet))
				{
					++packetStats->udpPacketsOutFail;
				}
				udpLayer = nullptr;
				continue;
			}

			// Other packets are just ignored
		}

		return true;
	}

	/**
	 * Connect UDP socket to other IP:port pair derived from our args
	 */
	void connectUDPSocket(const LinuxSocket& sock, const KniPongArgs& args)
	{
		struct sockaddr_in ingress{};
		std::memset(&ingress, 0, sizeof(ingress));
		ingress.sin_family = AF_INET;
		ingress.sin_addr.s_addr = inet_addr(args.outIp.c_str());
		ingress.sin_port = pcpp::hostToNet16(args.kniPort);
		if (connect(sock, reinterpret_cast<struct sockaddr*>(&ingress), sizeof(ingress)) == -1)
		{
			const int old_errno = errno;
			close(sock);
			EXIT_WITH_ERROR("Could not connect socket" << '\n' << "Errno: " << std::strerror(old_errno));
		}
	}

	/**
	 * Reworked fillbuf from netcat. See description in pingPongProcess
	 */
	ssize_t fillbuf(linuxFd fDesc, unsigned char buff[], size_t& buffPos)
	{
		const size_t num = IO_BUFF_SIZE - buffPos;
		ssize_t nSize = 0;

		nSize = read(fDesc, buff + buffPos, num);
		if (nSize == -1 && (errno == EAGAIN || errno == EINTR))
		{
			nSize = WANT_POLLIN;
		}
		if (nSize <= 0)
		{
			return nSize;
		}
		buffPos += nSize;
		return nSize;
	}

	/**
	 * Reworked drainbuf from netcat. See description in pingPongProcess
	 */
	ssize_t drainbuf(linuxFd fDesc, unsigned char buff[], size_t& buffPos)
	{
		ssize_t nSize = 0;
		ssize_t adjust = 0;

		nSize = write(fDesc, buff, buffPos);
		if (nSize == -1 && (errno == EAGAIN || errno == EINTR))
		{
			nSize = WANT_POLLOUT;
		}
		if (nSize <= 0)
		{
			return nSize;
		}
		/* adjust buffer */
		adjust = static_cast<ssize_t>(buffPos) - nSize;
		if (adjust > 0)
		{
			std::memmove(buff, buff + nSize, adjust);
		}
		buffPos -= nSize;
		return nSize;
	}

	/**
	 * Reworked readwrite from netcat.
	 *
	 * Note (echo-Mike): This function and fillbuf/drainbuf
	 * are analogous to code of NETCAT utility (OpenBSD version)
	 * Authors of original codebase:
	 *  - Eric Jackson <ericj@monkey.org>
	 *  - Bob Beck
	 *  - *Hobbit* <hobbit@avian.org>
	 *  See: http://man7.org/linux/man-pages/man1/ncat.1.html
	 */
	void pingPongProcess(const LinuxSocket& sock)
	{

		struct pollfd pfd[4];
		const int POLL_STDIN = 0;
		const int POLL_NETOUT = 1;
		const int POLL_NETIN = 2;
		const int POLL_STDOUT = 3;
		const int DEFAULT_POLL_TIMEOUT = 3000;  // milisec
		unsigned char netbuff[IO_BUFF_SIZE];
		size_t netbuffPos = 0;
		unsigned char ttybuff[IO_BUFF_SIZE];
		size_t ttybuffPos = 0;
		ssize_t ret = 0;

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
			if (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1 && ttybuffPos == 0 && netbuffPos == 0)
			{
				return;
			}
			/* both outputs are gone, we can't continue */
			if (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1)
			{
				return;
			}

			/* poll */
			const int num_fds = poll(pfd, 4, DEFAULT_POLL_TIMEOUT);

			/* treat poll errors */
			if (num_fds == -1)
			{
				const int old_errno = errno;
				if (old_errno != EINTR)
				{
					close(sock);
					EXIT_WITH_ERROR("poll returned an error" << '\n' << "Errno: " << std::strerror(old_errno));
				}
				continue;
			}

			if (num_fds == 0)
			{
				continue;
			}

			/* treat socket error conditions */
			for (int idx = 0; idx < 4; ++idx)
			{
				if ((pfd[idx].revents & (POLLERR | POLLNVAL)) != 0)
				{
					pfd[idx].fd = -1;
				}
			}
			/* reading is possible after HUP */
			if (((pfd[POLL_STDIN].events & POLLIN) != 0) && ((pfd[POLL_STDIN].revents & POLLHUP) != 0) &&
			    ((pfd[POLL_STDIN].revents & POLLIN) == 0))
			{
				pfd[POLL_STDIN].fd = -1;
			}

			if (((pfd[POLL_NETIN].events & POLLIN) != 0) && ((pfd[POLL_NETIN].revents & POLLHUP) != 0) &&
			    ((pfd[POLL_NETIN].revents & POLLIN) == 0))
			{
				pfd[POLL_NETIN].fd = -1;
			}

			if ((pfd[POLL_NETOUT].revents & POLLHUP) != 0)
			{
				pfd[POLL_NETOUT].fd = -1;
			}
			/* if HUP, stop watching stdout */
			if ((pfd[POLL_STDOUT].revents & POLLHUP) != 0)
			{
				pfd[POLL_STDOUT].fd = -1;
			}
			/* if no net out, stop watching stdin */
			if (pfd[POLL_NETOUT].fd == -1)
			{
				pfd[POLL_STDIN].fd = -1;
			}
			/* if no stdout, stop watching net in */
			if (pfd[POLL_STDOUT].fd == -1)
			{
				if (pfd[POLL_NETIN].fd != -1)
				{
					shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				}
				pfd[POLL_NETIN].fd = -1;
			}

			/* try to read from stdin */
			if (((pfd[POLL_STDIN].revents & POLLIN) != 0) && ttybuffPos < IO_BUFF_SIZE)
			{
				ret = fillbuf(pfd[POLL_STDIN].fd, ttybuff, ttybuffPos);
				if (ret == WANT_POLLIN)
				{
					pfd[POLL_STDIN].events = POLLIN;
				}
				else if (ret == 0 || ret == -1)
				{
					pfd[POLL_STDIN].fd = -1;
				}
				/* read something - poll net out */
				if (ttybuffPos > 0)
				{
					pfd[POLL_NETOUT].events = POLLOUT;
				}
				/* filled buffer - remove self from polling */
				if (ttybuffPos == IO_BUFF_SIZE)
				{
					pfd[POLL_STDIN].events = 0;
				}
			}
			/* try to write to network */
			if (((pfd[POLL_NETOUT].revents & POLLOUT) != 0) && ttybuffPos > 0)
			{
				ret = drainbuf(pfd[POLL_NETOUT].fd, ttybuff, ttybuffPos);
				if (ret == WANT_POLLOUT)
				{
					pfd[POLL_NETOUT].events = POLLOUT;
				}
				else if (ret == -1)
				{
					pfd[POLL_NETOUT].fd = -1;
				}
				/* buffer empty - remove self from polling */
				if (ttybuffPos == 0)
				{
					pfd[POLL_NETOUT].events = 0;
				}
				/* buffer no longer full - poll stdin again */
				if (ttybuffPos < IO_BUFF_SIZE)
				{
					pfd[POLL_STDIN].events = POLLIN;
				}
			}
			/* try to read from network */
			if (((pfd[POLL_NETIN].revents & POLLIN) != 0) && netbuffPos < IO_BUFF_SIZE)
			{
				ret = fillbuf(pfd[POLL_NETIN].fd, netbuff, netbuffPos);
				if (ret == WANT_POLLIN)
				{
					pfd[POLL_NETIN].events = POLLIN;
				}
				else if (ret == -1)
				{
					pfd[POLL_NETIN].fd = -1;
				}
				/* eof on net in - remove from pfd */
				if (ret == 0)
				{
					shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
					pfd[POLL_NETIN].fd = -1;
				}
				/* read something - poll stdout */
				if (netbuffPos > 0)
				{
					pfd[POLL_STDOUT].events = POLLOUT;
				}
				/* filled buffer - remove self from polling */
				if (netbuffPos == IO_BUFF_SIZE)
				{
					pfd[POLL_NETIN].events = 0;
				}
			}
			/* try to write to stdout */
			if (((pfd[POLL_STDOUT].revents & POLLOUT) != 0) && netbuffPos > 0)
			{
				ret = drainbuf(pfd[POLL_STDOUT].fd, netbuff, netbuffPos);
				if (ret == WANT_POLLOUT)
				{
					pfd[POLL_STDOUT].events = POLLOUT;
				}
				else if (ret == -1)
				{
					pfd[POLL_STDOUT].fd = -1;
				}
				/* buffer empty - remove self from polling */
				if (netbuffPos == 0)
				{
					pfd[POLL_STDOUT].events = 0;
				}
				/* buffer no longer full - poll net in again */
				if (netbuffPos < IO_BUFF_SIZE)
				{
					pfd[POLL_NETIN].events = POLLIN;
				}
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

}  // namespace

extern "C" void signal_handler(int /*unused*/)
{
	doContinue = false;
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	PacketStats packetStats{};
	std::memset(&packetStats, 0, sizeof(packetStats));
	KniPongArgs args;
	std::srand(std::time(nullptr));  // NOLINT(cert-msc32-c,cert-msc51-cpp)
	pcpp::AppName::init(argc, argv);
	parseArgs(argc, argv, args);
	pcpp::KniDevice* device = setupKniDevice(args);
	const LinuxSocket sock = setupLinuxSocket(args);
	if (!device->startCapture(processBurst, &packetStats))
	{
		close(sock);
		EXIT_WITH_ERROR("Could not start capture thread on KNI device");
	}
	connectUDPSocket(sock, args);
	std::signal(SIGINT, signal_handler);
	std::cout << "Ready for input:" << '\n';
	pingPongProcess(sock);
	//! Close socket before device
	close(sock);
	device->stopCapture();
	device->close();
	device->stopRequestHandlerThread();
	std::cout << '\n'
	          << '\n'
	          << "Packet statistics from KNI thread:" << '\n'
	          << "  Total packets met:         " << packetStats.totalPackets << '\n'
	          << "  UDP packets met:           " << packetStats.udpPacketsIn << '\n'
	          << "  Failed PONG packets:       " << packetStats.udpPacketsOutFail << '\n'
	          << "  ARP packets met:           " << packetStats.arpPacketsIn << '\n'
	          << "  Failed ARP replay packets: " << packetStats.arpPacketsOutFail << '\n'
	          << '\n';
	return 0;
}
