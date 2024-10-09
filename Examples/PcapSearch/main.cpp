/**
 * PcapSearch application
 * ======================
 * This application searches all pcap and pcapng files in a given directory and all its sub-directories (unless stated
 * otherwise) and outputs how many and which packets in those files match a certain pattern given by the user. The
 * pattern is given in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html). For example: if running
 * the application with the following parameters:
 *
 * `PcapSearch.exe -d C:\ -s "ip net 1.1.1.1" -r C:\report.txt`
 *
 * The application will search all '.pcap' files in all directories under C drive and try to match packets that matches
 * IP 1.1.1.1. The result will be printed to stdout and a more detailed report will be printed to c:\report.txt
 *
 * Output example:
 *
 * ```
 *     1 packets found in 'C:\\path\example\Dns.pcap'
 *     5 packets found in 'C:\\path\example\bla1\my_pcap2.pcap'
 *     7299 packets found in 'C:\\path2\example\example2\big_pcap.pcap'
 *     7435 packets found in 'C:\\path3\dir1\dir2\dir3\dir4\another.pcap'
 *     435 packets found in 'C:\\path3\dirx\diry\dirz\ok.pcap'
 *     4662 packets found in 'C:\\path4\gotit.pcap' 7299 packets found in 'C:\\enough.pcap'
 * ```
 *
 * There are switches that allows the user to search only in the provided folder (without sub-directories), search
 * user-defined file extensions (sometimes pcap files have an extension which is not '.pcap'), and output or not output
 * the detailed report
 *
 * For more details about modes of operation and parameters please run PcapSearch -h
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <dirent.h>
#include <utility>
#include <vector>
#include <unordered_map>
#include <Logger.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <RawPacket.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <getopt.h>

// clang-format off
static struct option PcapSearchOptions[] = {
	{ "input-dir",           required_argument, nullptr, 'd' },
	{ "not-include-sub-dir", no_argument,       nullptr, 'n' },
	{ "search",              required_argument, nullptr, 's' },
	{ "detailed-report",     required_argument, nullptr, 'r' },
	{ "set-extensions",      required_argument, nullptr, 'e' },
	{ "version",             no_argument,       nullptr, 'v' },
	{ "help",                no_argument,       nullptr, 'h' },
	{ nullptr,               0,                 nullptr, 0   }
};
// clang-format on

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#if defined(_WIN32)
#	define DIR_SEPARATOR "\\"
#else
#	define DIR_SEPARATOR "/"
#endif

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get()
	          << " [-h] [-v] [-n] [-r file_name] [-e extension_list] -d directory -s search_criteria" << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -d directory        : Input directory" << std::endl
	          << "    -n                  : Don't include sub-directories (default is include them)" << std::endl
	          << "    -s search_criteria  : Criteria to search in Berkeley Packet Filter (BPF) syntax "
	             "(http://biot.com/capstats/bpf.html)"
	          << std::endl
	          << "                          i.e: 'ip net 1.1.1.1'" << std::endl
	          << "    -r file_name        : Write a detailed search report to a file" << std::endl
	          << "    -e extension_list   : Set file extensions to search. The default is searching '.pcap' and "
	             "'.pcapng' files."
	          << std::endl
	          << "                          extension_list should be a comma-separated list of extensions, for "
	             "example: pcap,net,dmp"
	          << std::endl
	          << "    -v                  : Displays the current version and exists" << std::endl
	          << "    -h                  : Displays this help message and exits" << std::endl
	          << std::endl;
}

/**
 * Print application version
 */
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Built from: " << pcpp::getGitInfo() << std::endl;
	exit(0);
}

/*
 * Returns the extension of a given file name
 */
std::string getExtension(const std::string& fileName)
{
	return fileName.substr(fileName.find_last_of(".") + 1);
}

/**
 * Searches all packet in a given pcap file for a certain search criteria. Returns how many packets matched the search
 * criteria
 */
int searchPcap(const std::string& pcapFilePath, std::string searchCriteria, std::ofstream* detailedReportFile)
{
	// create the pcap/pcap-ng reader
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFilePath);

	// if the reader fails to open
	if (!reader->open())
	{
		if (detailedReportFile != nullptr)
		{
			// PcapPlusPlus logger saves the last internal error. Write this error to the report file
			(*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
			(*detailedReportFile) << "    ";
			(*detailedReportFile) << pcpp::Logger::getInstance().getLastError() << std::endl;
		}

		// free the reader memory and return
		delete reader;
		return 0;
	}

	// set the filter for the file so only packets that match the search criteria will be read
	if (!reader->setFilter(std::move(searchCriteria)))
	{
		// free the reader memory and return
		delete reader;
		return 0;
	}

	if (detailedReportFile != nullptr)
	{
		(*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
	}

	int packetCount = 0;
	pcpp::RawPacket rawPacket;

	// read packets from the file. Since we already set the filter, only packets that matches the filter will be read
	while (reader->getNextPacket(rawPacket))
	{
		// if a detailed report is required, parse the packet and print it to the report file
		if (detailedReportFile != nullptr)
		{
			// parse the packet
			pcpp::Packet parsedPacket(&rawPacket);

			// print layer by layer by layer as we want to add a few spaces before each layer
			std::vector<std::string> packetLayers;
			parsedPacket.toStringList(packetLayers);
			for (const auto& layer : packetLayers)
				(*detailedReportFile) << "\n    " << layer;
			(*detailedReportFile) << std::endl;
		}

		// count the packet read
		packetCount++;
	}

	// close the reader file
	reader->close();

	// finalize the report
	if (detailedReportFile != nullptr)
	{
		if (packetCount > 0)
			(*detailedReportFile) << "\n";

		(*detailedReportFile) << "    ----> Found " << packetCount << " packets" << std::endl << std::endl;
	}

	// free the reader memory
	delete reader;

	// return how many packets matched the search criteria
	return packetCount;
}

/**
 * Searches all pcap files in given directory (and sub-directories if directed by the user) and output how many packets
 * in each file matches a given search criteria. This method outputs how many directories were searched, how many files
 * were searched and how many packets were matched
 */
void searchDirectories(const std::string& directory, bool includeSubDirectories, const std::string& searchCriteria,
                       std::ofstream* detailedReportFile, std::unordered_map<std::string, bool> extensionsToSearch,
                       int& totalDirSearched, int& totalFilesSearched, int& totalPacketsFound)
{
	// open the directory
	DIR* dir = opendir(directory.c_str());

	// dir is null usually when user has no access permissions
	if (dir == nullptr)
		return;

	struct dirent* entry = readdir(dir);

	std::vector<std::string> pcapList;

	// go over all files in this directory
	while (entry != nullptr)
	{
		std::string name(entry->d_name);

		// construct directory full path
		std::string dirPath = directory;
		std::string dirSep = DIR_SEPARATOR;
		if (0 != directory.compare(directory.length() - dirSep.length(), dirSep.length(),
		                           dirSep))  // directory doesn't contain separator in the end
			dirPath += DIR_SEPARATOR;
		dirPath += name;

		struct stat info;

		// get file attributes
		if (stat(dirPath.c_str(), &info) != 0)
		{
			entry = readdir(dir);
			continue;
		}

		// if the file is not a directory
		if (!(info.st_mode & S_IFDIR))
		{
			// check if the file extension matches the requested extensions to search. If it does, put the file name in
			// a list of files that should be searched (don't do the search just yet)
			if (extensionsToSearch.find(getExtension(name)) != extensionsToSearch.end())
				pcapList.push_back(dirPath);
			entry = readdir(dir);
			continue;
		}

		// if the file is a '.' or '..' skip it
		if (name == "." || name == "..")
		{
			entry = readdir(dir);
			continue;
		}

		// if we got to here it means the file is actually a directory. If required to search sub-directories, call this
		// method recursively to search inside this sub-directory
		if (includeSubDirectories)
			searchDirectories(dirPath, true, searchCriteria, detailedReportFile, extensionsToSearch, totalDirSearched,
			                  totalFilesSearched, totalPacketsFound);

		// move to the next file
		entry = readdir(dir);
	}

	// close dir
	closedir(dir);

	totalDirSearched++;

	// when we get to here we already covered all sub-directories and collected all the files in this directory that are
	// required for search go over each such file and search its packets to find the search criteria
	for (const auto& iter : pcapList)
	{
		// do the actual search
		int packetsFound = searchPcap(iter, searchCriteria, detailedReportFile);

		// add to total matched packets
		totalFilesSearched++;
		if (packetsFound > 0)
		{
			std::cout << packetsFound << " packets found in '" << iter << "'" << std::endl;
			totalPacketsFound += packetsFound;
		}
	}
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string inputDirectory = "";

	std::string searchCriteria = "";

	bool includeSubDirectories = true;

	std::string detailedReportFileName = "";

	std::unordered_map<std::string, bool> extensionsToSearch;

	// the default (unless set otherwise) is to search in '.pcap' and '.pcapng' extensions
	extensionsToSearch["pcap"] = true;
	extensionsToSearch["pcapng"] = true;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "d:s:r:e:hvn", PcapSearchOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'd':
			inputDirectory = optarg;
			break;
		case 'n':
			includeSubDirectories = false;
			break;
		case 's':
			searchCriteria = optarg;
			break;
		case 'r':
			detailedReportFileName = optarg;
			break;
		case 'e':
		{
			// read the extension list into the map
			extensionsToSearch.clear();
			std::string extensionsListAsString = std::string(optarg);
			std::stringstream stream(extensionsListAsString);
			std::string extension;
			// break comma-separated string into string list
			while (std::getline(stream, extension, ','))
			{
				// add the extension into the map if it doesn't already exist
				if (extensionsToSearch.find(extension) == extensionsToSearch.end())
					extensionsToSearch[extension] = true;
			}

			// verify list is not empty
			if (extensionsToSearch.empty())
			{
				EXIT_WITH_ERROR("Couldn't parse extensions list");
			}
			break;
		}
		case 'h':
			printUsage();
			exit(0);
		case 'v':
			printAppVersion();
			break;
		default:
			printUsage();
			exit(-1);
		}
	}

	if (inputDirectory == "")
	{
		EXIT_WITH_ERROR("Input directory was not given");
	}

	if (searchCriteria == "")
	{
		EXIT_WITH_ERROR("Search criteria was not given");
	}

	DIR* dir = opendir(inputDirectory.c_str());
	if (dir == nullptr)
	{
		EXIT_WITH_ERROR("Cannot find or open input directory");
	}
	closedir(dir);

	// verify the search criteria is a valid BPF filter
	pcpp::BPFStringFilter filter(searchCriteria);
	if (!filter.verifyFilter())
	{
		EXIT_WITH_ERROR("Search criteria isn't valid");
	}

	// open the detailed report file if requested by the user
	std::ofstream* detailedReportFile = nullptr;
	if (detailedReportFileName != "")
	{
		detailedReportFile = new std::ofstream();
		detailedReportFile->open(detailedReportFileName.c_str());
		if (detailedReportFile->fail())
		{
			EXIT_WITH_ERROR("Couldn't open detailed report file '" << detailedReportFileName << "' for writing");
		}
	}

	std::cout << "Searching..." << std::endl;
	int totalDirSearched = 0;
	int totalFilesSearched = 0;
	int totalPacketsFound = 0;

	// the main call - start searching!
	searchDirectories(inputDirectory, includeSubDirectories, searchCriteria, detailedReportFile, extensionsToSearch,
	                  totalDirSearched, totalFilesSearched, totalPacketsFound);

	// after search is done, close the report file and delete its instance
	std::cout << std::endl
	          << std::endl
	          << "Done! Searched " << totalFilesSearched << " files in " << totalDirSearched << " directories, "
	          << totalPacketsFound << " packets were matched to search criteria" << std::endl;

	if (detailedReportFile != nullptr)
	{
		if (detailedReportFile->is_open())
			detailedReportFile->close();

		delete detailedReportFile;
		std::cout << "Detailed report written to '" << detailedReportFileName << "'" << std::endl;
	}

	return 0;
}
