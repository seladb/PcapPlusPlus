#include <SSLHandshake.h>
#include <SSLLayer.h>
#include <TcpReassembly.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <X509Decoder.h>
#include <GeneralUtils.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason)                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#if defined(_WIN32)
#	define DIR_SEPARATOR '\\'
#else
#	define DIR_SEPARATOR '/'
#endif

const std::string GREEN_COLOR = "\033[32m";
const std::string RED_COLOR = "\033[31m";
const std::string RESET_COLOR = "\033[0m";

static struct option X509ToolkitOptions[] = {
	{ "input",      required_argument, nullptr, 'i' },
    { "output",     required_argument, nullptr, 'o' },
	{ "format",     required_argument, nullptr, 'f' },
	{ "stats",      no_argument,       nullptr, 's' },
    { "help",       no_argument,       nullptr, 'h' },
	{ "version",    no_argument,       nullptr, 'v' },
};

/// Print application usage
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get() << " <command> [options]" << std::endl
	          << std::endl
	          << "Commands:" << std::endl
	          << "  convert      -i <input> -f <PEM|DER> [-o <output>]        Convert certificate format" << std::endl
	          << "  info         -i <input>                                   Show certificate info" << std::endl
	          << "  json         -i <input> [-o <output>]                     Parse certificate as JSON" << std::endl
	          << "  expire       -i <input>                                   Show expiration info" << std::endl
	          << "  pcap-extract -i <pcap> -f <PEM|DER> [-o <directory>] [-s] Extract X509 certificates from pcap file" << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << "  -v, --version          Display version information and exit" << std::endl
	          << "  -h, --help             Display this help message and exit" << std::endl
	          << std::endl
	          << "Examples:" << std::endl
	          << "  " << pcpp::AppName::get() << " convert -i cert.der -o cert.pem -c PEM" << std::endl
	          << "  " << pcpp::AppName::get() << " info -i cert.pem" << std::endl
	          << "  " << pcpp::AppName::get() << " json -i cert.pem -o cert.json" << std::endl
	          << "  " << pcpp::AppName::get() << " expire -i cert.pem" << std::endl
	          << std::endl;
}

/// Print application version
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Built from: " << pcpp::getGitInfo() << std::endl;
}

/// Open input file and return X509Certificate object
std::unique_ptr<pcpp::X509Certificate> openCertFile(const std::string& certFileName)
{
	std::ifstream certFile(certFileName, std::ios::in | std::ios::binary);
	if (!certFile.good())
	{
		EXIT_WITH_ERROR("Input file doesn't exist or cannot be opened");
	}

	try
	{
		return pcpp::X509Certificate::fromDERFile(certFileName);
	}
	catch (...)
	{
		try
		{
			return pcpp::X509Certificate::fromPEMFile(certFileName);
		}
		catch (...)
		{
			EXIT_WITH_ERROR("Failed to open input file");
		}
	}
}

/// Show certificate info
void showCertInfo(const std::string& inputFileName)
{
	if (inputFileName.empty())
	{
		EXIT_WITH_ERROR("Input file name is not specified");
	}

	auto cert = openCertFile(inputFileName);

	std::cout << "Subject:        " << cert->getSubject().toString() << std::endl
	          << "Issuer:         " << cert->getIssuer().toString() << std::endl
	          << "Serial Number:  " << cert->getSerialNumber().toString() << std::endl
	          << std::endl
	          << "Valid From:     " << cert->getNotBefore().toString() << " UTC" << std::endl
	          << "Valid To:       " << cert->getNotAfter().toString() << " UTC" << std::endl
	          << std::endl
	          << "Signature Algo: " << cert->getSignatureAlgorithm().toString() << std::endl
	          << "Public Key:     " << cert->getPublicKeyAlgorithm().toString() << std::endl
	          << std::endl
	          << "Certificate Version: " << static_cast<int>(cert->getVersion()) + 1 << std::endl;
}

/// Convert certificate to PEM or DER
void convertCertFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& format)
{
	if (inputFileName.empty())
	{
		EXIT_WITH_ERROR("Input file name is not specified");
	}

	if (format.empty())
	{
		EXIT_WITH_ERROR("Output format is not specified");
	}

	if (format != "PEM" && format != "DER")
	{
		EXIT_WITH_ERROR("Unsupported format: " + format);
	}

	auto cert = openCertFile(inputFileName);

	if (format == "PEM")
	{
		auto pem = cert->toPEM();
		if (outputFileName.empty())
		{
			std::cout << pem << std::endl;
			return;
		}
		std::ofstream pemFile(outputFileName);
		if (!pemFile.is_open())
		{
			EXIT_WITH_ERROR("Failed to open output file");
		}
		pemFile << pem;
		pemFile.close();

		std::cout << GREEN_COLOR << "[V] Converted successfully to: " << outputFileName << RESET_COLOR << std::endl;
	}
	else
	{
		auto der = cert->toDER();
		if (outputFileName.empty())
		{
			std::cout << pcpp::Base64::encode(der) << std::endl;
			return;
		}
		std::ofstream derFile(outputFileName);
		if (!derFile.is_open())
		{
			EXIT_WITH_ERROR("Failed to open output file");
		}
		derFile.write(reinterpret_cast<const char*>(der.data()), der.size());
		derFile.close();

		std::cout << GREEN_COLOR << "Converted successfully to: " << outputFileName << RESET_COLOR << std::endl;
	}
}

/// Convert certificate to JSON format
void parseCertAsJson(const std::string& inputFileName, const std::string& outputFileName)
{
	if (inputFileName.empty())
	{
		EXIT_WITH_ERROR("Input file name is not specified");
	}

	auto cert = openCertFile(inputFileName);

	auto json = cert->toJson(4);
	if (outputFileName.empty())
	{
		std::cout << json << std::endl;
		return;
	}
	std::ofstream jsonFile(outputFileName);
	jsonFile << json;
	jsonFile.close();
}

/// Check and print certificate expiration info
void checkCertExpiration(const std::string& inputFileName)
{
	if (inputFileName.empty())
	{
		EXIT_WITH_ERROR("Input file name is not specified");
	}

	auto cert = openCertFile(inputFileName);

	auto validityInfo = "Valid from:     " + cert->getNotBefore().toString() +
	                    " UTC\nValid until:    " + cert->getNotAfter().toString() + " UTC";

	using days = std::chrono::duration<int, std::ratio<86400>>;

	auto now = std::chrono::system_clock::now();
	if (now > cert->getNotAfter().getTimestamp())
	{
		std::cout << RED_COLOR << "[X] Certificate has expired." << RESET_COLOR << std::endl;
		std::cout << validityInfo << std::endl;
		auto expiredDays = std::chrono::duration_cast<days>(now - cert->getNotAfter().getTimestamp()).count();
		std::cout << "Expired " << expiredDays << " days ago." << std::endl;
		exit(2);
	}

	if (now < cert->getNotBefore().getTimestamp())
	{
		std::cout << RED_COLOR << "[X] Certificate is not yet valid." << RESET_COLOR << std::endl;
		std::cout << validityInfo << std::endl;
		auto daysRemaining = std::chrono::duration_cast<days>(cert->getNotBefore().getTimestamp() - now).count();
		std::cout << "Starts in " << daysRemaining << " days." << std::endl;
		exit(2);
	}

	std::cout << GREEN_COLOR << "[V] Certificate is valid." << RESET_COLOR << std::endl;
	std::cout << validityInfo << std::endl;
	auto daysRemaining = std::chrono::duration_cast<days>(cert->getNotAfter().getTimestamp() - now).count();
	std::cout << daysRemaining << " days remaining." << std::endl;
}

struct SSLConnectionData
{
	int8_t curSide = -1;
	std::vector<uint8_t> data;
	bool canIgnoreFlow = false;

	explicit SSLConnectionData(int8_t side) : curSide(side) {}
};

using SSLConnectionManager = std::unordered_map<uint32_t, SSLConnectionData>;

struct SSLPcapStats
{
	uint64_t packets = 0;
	uint64_t sslPackets = 0;
	uint64_t sslHandshakeMessages = 0;
	uint64_t sslFlows = 0;
	uint64_t parsedCertificates = 0;
	uint64_t failedIncompleteCertificates = 0;
	uint64_t failedParsingCertificates = 0;
};

using SSLData = std::tuple<SSLConnectionManager*, SSLPcapStats*, std::string, std::string>;

void extractFromPcapFile(const std::string& pcapFileName, const std::string& outputDirectory, const std::string& format, bool showStats)
{
	std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(pcapFileName));

	if (!reader->open())
	{
		EXIT_WITH_ERROR("Error opening pcap file");
	}

	if (format != "PEM" && format != "DER")
	{
		EXIT_WITH_ERROR("Unsupported format: " + format);
	}

	if (!outputDirectory.empty() && !pcpp::directoryExists(outputDirectory))
	{
		EXIT_WITH_ERROR("Output directory '" + outputDirectory + "' does not exist");
	}

	auto onMessageReady = [](int8_t side, const pcpp::TcpStreamData& tcpData, void* userCookie)
	{
		auto* sslData = static_cast<SSLData*>(userCookie);
		auto* connMgr = std::get<0>(*sslData);
		auto* stats = std::get<1>(*sslData);
		stats->packets++;

		if (!(pcpp::SSLLayer::isSSLPort(tcpData.getConnectionData().srcPort) || pcpp::SSLLayer::isSSLPort(tcpData.getConnectionData().dstPort)))
		{
			return;
		}

		stats->sslPackets++;
		auto flow = connMgr->find(tcpData.getConnectionData().flowKey);
		if (flow == connMgr->end())
		{
			stats->sslFlows++;
			connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, SSLConnectionData(side)));
			flow = connMgr->find(tcpData.getConnectionData().flowKey);
		}

		if (flow->second.canIgnoreFlow)
		{
			return;
		}

		if (flow->second.curSide == side)
		{
			flow->second.data.insert(flow->second.data.end(), tcpData.getData(), tcpData.getData() + tcpData.getDataLength());
			return;
		}

		if (flow->second.data.empty())
		{
			return;
		}

		size_t dataSize = flow->second.data.size();
		uint8_t* data = new uint8_t[dataSize];
		std::memcpy(data, flow->second.data.data(), dataSize);

		flow->second.curSide = side;
		flow->second.data.clear();
		flow->second.data.insert(flow->second.data.end(), tcpData.getData(), tcpData.getData() + tcpData.getDataLength());

		auto sslMessageUniquePtr = std::unique_ptr<pcpp::SSLLayer>(pcpp::SSLLayer::createSSLMessage(data, dataSize, nullptr, nullptr));
		auto sslMessage = sslMessageUniquePtr.get();
		while (sslMessage != nullptr)
		{
			auto* applicationDataLayer = dynamic_cast<pcpp::SSLApplicationDataLayer*>(sslMessage);
			if (applicationDataLayer != nullptr)
			{
				flow->second.data.clear();
				flow->second.canIgnoreFlow = true;
				return;
			}

			auto* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(sslMessage);
			if (handshakeLayer == nullptr)
			{
				sslMessage->parseNextLayer();
				sslMessage = dynamic_cast<pcpp::SSLLayer*>(sslMessage->getNextLayer());
				continue;
			}

			stats->sslHandshakeMessages++;

			auto* certMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLCertificateMessage>();
			while (certMessage != nullptr)
			{
				for (int i = 0; i < certMessage->getNumOfCertificates(); i++)
				{
					try
					{
						auto x509Cert = certMessage->getCertificate(i)->getX509Certificate();
						if (x509Cert != nullptr)
						{
							auto format = std::get<2>(*sslData);
							auto outputDirectory = std::get<3>(*sslData);
							if (format == "PEM")
							{
								auto pem = x509Cert->toPEM();
								if (outputDirectory.empty())
								{
									std::cout << pem << std::endl;
								}
								else
								{
									std::string outputFileName = outputDirectory + DIR_SEPARATOR + std::to_string(stats->parsedCertificates + 1) + ".pem";
									std::ofstream pemFile(outputFileName);
									if (!pemFile.is_open())
									{
										stats->failedParsingCertificates++;
									}
									pemFile << pem;
									pemFile.close();
								}
							}
							else
							{
								auto der = x509Cert->toDER();
								if (outputDirectory.empty())
								{
									std::cout << pcpp::Base64::encode(der) << std::endl;
								}
								else
								{
									std::string outputFileName = outputDirectory + DIR_SEPARATOR + std::to_string(stats->parsedCertificates + 1) + ".der";
									std::ofstream derFile(outputFileName);
									if (!derFile.is_open())
									{
										stats->failedParsingCertificates++;
									}
									derFile.write(reinterpret_cast<const char*>(der.data()), der.size());
									derFile.close();
								}
							}
							stats->parsedCertificates++;
						}
						else
						{
							stats->failedIncompleteCertificates++;
						}
					}
					catch (...)
					{
						stats->failedParsingCertificates++;
					}
				}
				certMessage = handshakeLayer->getNextHandshakeMessageOfType<pcpp::SSLCertificateMessage>(certMessage);
			}

			sslMessage->parseNextLayer();
			sslMessage = dynamic_cast<pcpp::SSLLayer*>(sslMessage->getNextLayer());
		}
	};

	auto onConnectionEnd = [](const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
	{
		auto* sslData = static_cast<SSLData*>(userCookie);
		auto* connMgr = std::get<0>(*sslData);
		auto flow = connMgr->find(connectionData.flowKey);
		if (flow != connMgr->end())
		{
			connMgr->erase(flow);
		}
	};

	SSLConnectionManager connectionManager;
	SSLPcapStats stats;
	SSLData sslData(&connectionManager, &stats, format, outputDirectory);

	pcpp::TcpReassembly tcpReassembly(onMessageReady, &sslData, nullptr, onConnectionEnd);

	pcpp::RawPacketVector rawPackets;
	while (reader->getNextPackets(rawPackets, 20) > 0)
	{
		for (auto& rawPacket : rawPackets)
		{
			tcpReassembly.reassemblePacket(rawPacket);
		}
		rawPackets.clear();
	}

	if (showStats)
	{
		std::cout << "Packet count: " << stats.packets << std::endl
					<< "TLS packets: " << stats.sslPackets << std::endl
					<< "TLS Flows: " << stats.sslFlows << std::endl
					<< "TLS handshake messages: " << stats.sslHandshakeMessages << std::endl
					<< "Certificates parsed: " << stats.parsedCertificates << std::endl
					<< "Certificates failed parsing: " << stats.failedParsingCertificates << std::endl
					<< "Incomplete Certificates: " << stats.failedIncompleteCertificates << std::endl;

	}

	std::cout << "DONE!" << std::endl;
}

/// main method of this utility
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	std::string operation;
	std::string inputFileName;
	std::string outputFileNameOrDirectory;
	std::string format;
	std::string extractField;
	bool showStats = false;

	while ((opt = getopt_long(argc, argv, "i:o:f:svh", X509ToolkitOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'i':
			inputFileName = optarg;
			break;
		case 'o':
			outputFileNameOrDirectory = optarg;
			break;
		case 'f':
			format = optarg;
			break;
		case 's':
			showStats = true;
			break;
		case 'h':
			printUsage();
			exit(0);
		case 'v':
			printAppVersion();
			exit(0);
		default:
			printUsage();
			exit(-1);
		}
	}

	if (optind < argc)
	{
		operation = argv[optind];
	}

	if (operation == "")
	{
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Operation was not specified");
	}

	if (operation == "info")
	{
		showCertInfo(inputFileName);
	}
	else if (operation == "convert")
	{
		convertCertFile(inputFileName, outputFileNameOrDirectory, format);
	}
	else if (operation == "json")
	{
		parseCertAsJson(inputFileName, outputFileNameOrDirectory);
	}
	else if (operation == "expire")
	{
		checkCertExpiration(inputFileName);
	}
	else if (operation == "pcap-extract")
	{
		extractFromPcapFile(inputFileName, outputFileNameOrDirectory, format, showStats);
	}
	else
	{
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Unsupported operation: " + operation);
	}
}
