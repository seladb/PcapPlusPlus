#include <X509Decoder.h>
#include <GeneralUtils.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <chrono>

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

static struct option X509ToolkitOptions[] = {
	{ "input",      required_argument, nullptr, 'i' },
    { "output",     required_argument, nullptr, 'o' },
	{ "convert-to", required_argument, nullptr, 'c' },
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
	          << "  convert -i <input> [-o <output>] -c <PEM|DER>  Convert certificate format" << std::endl
	          << "  info    -i <input>                             Show certificate info" << std::endl
	          << "  json    -i <input> [-o <output>]               Parse certificate as JSON" << std::endl
	          << "  expire  -i <input>                             Show expiration info" << std::endl
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
void convertCertFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& convertTo)
{
	if (inputFileName.empty())
	{
		EXIT_WITH_ERROR("Input file name is not specified");
	}

	if (convertTo.empty())
	{
		EXIT_WITH_ERROR("Output format is not specified");
	}

	if (convertTo != "PEM" && convertTo != "DER")
	{
		EXIT_WITH_ERROR("Unsupported format: " + convertTo);
	}

	auto cert = openCertFile(inputFileName);

	if (convertTo == "PEM")
	{
		auto pem = cert->toPEM();
		if (outputFileName.empty())
		{
			std::cout << pem << std::endl;
			return;
		}
		std::ofstream pemFile(outputFileName);
		pemFile << pem;
		pemFile.close();
	}
	else
	{
		auto der = cert->toDER();
		if (outputFileName.empty())
		{
			std::cout << pcpp::byteArrayToHexString(der.data(), der.size()) << std::endl;
			return;
		}
		std::ofstream derFile(outputFileName);
		derFile.write(reinterpret_cast<const char*>(der.data()), der.size());
		derFile.close();
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
		std::cout << "\u274c Certificate has expired." << std::endl;
		std::cout << validityInfo << std::endl;
		auto expiredDays = std::chrono::duration_cast<days>(now - cert->getNotAfter().getTimestamp()).count();
		std::cout << "Expired " << expiredDays << " days ago." << std::endl;
		exit(2);
	}

	if (now < cert->getNotBefore().getTimestamp())
	{
		std::cout << "\u274c Certificate is not yet valid." << std::endl;
		std::cout << validityInfo << std::endl;
		auto daysRemaining = std::chrono::duration_cast<days>(cert->getNotBefore().getTimestamp() - now).count();
		std::cout << "Starts in " << daysRemaining << " days." << std::endl;
		exit(2);
	}

	std::cout << "\u2705 Certificate is valid." << std::endl;
	std::cout << validityInfo << std::endl;
	auto daysRemaining = std::chrono::duration_cast<days>(cert->getNotAfter().getTimestamp() - now).count();
	std::cout << daysRemaining << " days remaining." << std::endl;
}

/// main method of this utility
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	std::string operation = "";
	std::string inputFileName = "";
	std::string outputFileName = "";
	std::string convertTo = "";
	std::string extractField = "";

	while ((opt = getopt_long(argc, argv, "i:o:c:lvh", X509ToolkitOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'i':
			inputFileName = optarg;
			break;
		case 'o':
			outputFileName = optarg;
			break;
		case 'c':
			convertTo = optarg;
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
		convertCertFile(inputFileName, outputFileName, convertTo);
	}
	else if (operation == "json")
	{
		parseCertAsJson(inputFileName, outputFileName);
	}
	else if (operation == "expire")
	{
		checkCertExpiration(inputFileName);
	}
	else
	{
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Unsupported operation: " + operation);
	}
}
