#include "PcapExtract.h"
#include "X509Decoder.h"
#include "GeneralUtils.h"
#include "PcapPlusPlusVersion.h"
#include "SystemUtils.h"
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

const std::string GREEN_COLOR = "\033[32m";
const std::string RED_COLOR = "\033[31m";
const std::string RESET_COLOR = "\033[0m";

static struct option X509ToolkitOptions[] = {
	{ "input",   required_argument, nullptr, 'i' },
    { "output",  required_argument, nullptr, 'o' },
	{ "format",  required_argument, nullptr, 'f' },
    { "stats",   no_argument,       nullptr, 's' },
	{ "help",    no_argument,       nullptr, 'h' },
    { "version", no_argument,       nullptr, 'v' },
};

/// Print application usage
static void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "  " << pcpp::AppName::get() << " <command> [options]" << std::endl
	          << std::endl
	          << "Commands:" << std::endl
	          << "  convert      -i <input> -f <PEM|DER> [-o <output>]" << std::endl
	          << "               Convert an X.509 certificate between PEM and DER formats." << std::endl
	          << "               If -o is not specified, the result is written to stdout." << std::endl
	          << std::endl
	          << "  info         -i <input>" << std::endl
	          << "               Display detailed information about the certificate, including subject," << std::endl
	          << "               issuer, serial number, validity period, and more." << std::endl
	          << std::endl
	          << "  json         -i <input> [-o <output>]" << std::endl
	          << "               Parse the certificate and output its structure as a formatted JSON object."
	          << std::endl
	          << "               If -o is not specified, the result is written to stdout." << std::endl
	          << std::endl
	          << "  expire       -i <input>" << std::endl
	          << "               Show the certificate's expiration date and the number of days until it expires."
	          << std::endl
	          << std::endl
	          << "  pcap-extract -i <pcap> -f <PEM|DER> [-o <directory>] [-s]" << std::endl
	          << "               Extract X.509 certificates from a packet capture (pcap/pcapng) file." << std::endl
	          << "               Certificates are written to the output directory or to stdout in the specified format."
	          << std::endl
	          << "               Use -s to display extraction statistics after processing." << std::endl
	          << "               If -o is not specified, the certificates are written to stdout." << std::endl
	          << std::endl
	          << "Examples:" << std::endl
	          << "  " << pcpp::AppName::get() << " convert -i cert.der -o cert.pem -f PEM" << std::endl
	          << "  " << pcpp::AppName::get() << " info -i cert.pem" << std::endl
	          << "  " << pcpp::AppName::get() << " json -i cert.pem -o cert.json" << std::endl
	          << "  " << pcpp::AppName::get() << " expire -i cert.pem" << std::endl
	          << "  " << pcpp::AppName::get() << " pcap-extract -i tls.pcap -o MyCertDir -f PEM -s" << std::endl
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
	if (certFileName.empty())
	{
		EXIT_WITH_ERROR("Input file name is not specified");
	}

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
static void showCertInfo(const std::string& inputFileName)
{
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
static void convertCertFile(const std::string& inputFileName, const std::string& outputFileName,
                            const std::string& format)
{
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
		std::ofstream derFile(outputFileName, std::ios::binary);
		if (!derFile.is_open())
		{
			EXIT_WITH_ERROR("Failed to open output file");
		}
		derFile.write(reinterpret_cast<const char*>(der.data()), der.size());
		derFile.close();

		std::cout << GREEN_COLOR << "[V] Converted successfully to: " << outputFileName << RESET_COLOR << std::endl;
	}
}

/// Convert certificate to JSON format
static void parseCertAsJson(const std::string& inputFileName, const std::string& outputFileName)
{
	auto cert = openCertFile(inputFileName);

	auto json = cert->toJson(4);
	if (outputFileName.empty())
	{
		std::cout << json << std::endl;
		return;
	}
	std::ofstream jsonFile(outputFileName);
	if (!jsonFile.is_open())
	{
		EXIT_WITH_ERROR("Failed to open output file");
	}
	jsonFile << json;
	jsonFile.close();
}

/// Check and print certificate expiration info
static void checkCertExpiration(const std::string& inputFileName)
{
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

/// Extract certificates from a pcap/pcapng file
static void extractFromPcapFile(const std::string& pcapFileName, const std::string& outputDirectory,
                                const std::string& format, bool showStats)
{
	try
	{
		PcapExtract pcapExtract(pcapFileName, outputDirectory, format, showStats);
		pcapExtract.run();
	}
	catch (const std::exception& ex)
	{
		EXIT_WITH_ERROR(ex.what());
	}
}

/// main method of this utility
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	std::string command;
	std::string inputFileName;
	std::string outputFileNameOrDirectory;
	std::string format;
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
		command = argv[optind];
	}

	if (command.empty())
	{
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Command was not specified");
	}

	if (command == "info")
	{
		showCertInfo(inputFileName);
	}
	else if (command == "convert")
	{
		convertCertFile(inputFileName, outputFileNameOrDirectory, format);
	}
	else if (command == "json")
	{
		parseCertAsJson(inputFileName, outputFileNameOrDirectory);
	}
	else if (command == "expire")
	{
		checkCertExpiration(inputFileName);
	}
	else if (command == "pcap-extract")
	{
		extractFromPcapFile(inputFileName, outputFileNameOrDirectory, format, showStats);
	}
	else
	{
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Unsupported command: " + command);
	}
}
