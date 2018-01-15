/**
 * PcapSearch application
 * ======================
 * This application searches all pcap and pcapng files in a given directory and all its sub-directories (unless stated otherwise) and outputs how many and which
 * packets in those files match a certain pattern given by the user. The pattern is given in Berkeley Packet Filter (BPF) syntax
 * (http://biot.com/capstats/bpf.html). For example: if running the application with the following parameters:
 * PcapSearch.exe -d C:\ -s "ip net 1.1.1.1" -r C:\report.txt
 * The application will search all '.pcap' files in all directories under C drive and try to match packets that matches IP 1.1.1.1. The result will be
 * printed to stdout and a more detailed report will be printed to c:\report.txt
 * Output example:
 *    1 packets found in 'C:\\path\example\Dns.pcap'
 *    5 packets found in 'C:\\path\example\bla1\my_pcap2.pcap'
 *    7299 packets found in 'C:\\path2\example\example2\big_pcap.pcap'
 *    7435 packets found in 'C:\\path3\dir1\dir2\dir3\dir4\another.pcap'
 *    435 packets found in 'C:\\path3\dirx\diry\dirz\ok.pcap'
 *    4662 packets found in 'C:\\path4\gotit.pcap'
 *    7299 packets found in 'C:\\enough.pcap'
 *
 * There are switches that allows the user to search only in the provided folder (without sub-directories), search user-defined file extensions (sometimes
 * pcap files have an extension which is not '.pcap'), and output or not output the detailed report
 *
 * For more details about modes of operation and parameters please run PcapSearch -h
 */

#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <dirent.h>
#include <vector>
#include <map>
#include <Logger.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <RawPacket.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <getopt.h>


using namespace pcpp;

static struct option PcapSearchOptions[] =
{
	{"input-dir",  required_argument, 0, 'd'},
	{"not-include-sub-dir", no_argument, 0, 'n'},
	{"search", required_argument, 0, 's'},
	{"detailed-report", required_argument, 0, 'r'},
	{"set-extensions", required_argument, 0, 'e'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};


#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#if defined(WIN32) || defined(WINx64)
#define DIR_SEPARATOR "\\"
#else
#define DIR_SEPARATOR "/"
#endif


#define ERROR_STRING_LEN 500

char errorString[ERROR_STRING_LEN];

/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"-------\n"
			"%s [-h] [-v] [-n] [-r file_name] [-e extension_list] -d directory -s search_criteria\n"
			"\nOptions:\n\n"
			"    -d directory        : Input directory\n"
			"    -n                  : Don't include sub-directories (default is include them)\n"
			"    -s search_criteria  : Criteria to search in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'\n"
			"    -r file_name        : Write a detailed search report to a file\n"
			"    -e extension_list   : Set file extensions to search. The default is searching '.pcap' and '.pcapng' files.\n"
			"                          extnesions_list should be a comma-separated list of extensions, for example: pcap,net,dmp\n"
			"    -v                  : Displays the current version and exists\n"
			"    -h                  : Displays this help message and exits\n", AppName::get().c_str());
	exit(0);
}


/**
 * Print application version
 */
void printAppVersion()
{
	printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Built from: %s\n", getGitInfo().c_str());
	exit(0);
}


/*
 * Returns the extension of a given file name
 */
std::string getExtension(std::string fileName)
{
	return fileName.substr(fileName.find_last_of(".") + 1);
}


/**
 * Searches all packet in a given pcap file for a certain search criteria. Returns how many packets matched the seatch criteria
 */
int searchPcap(std::string pcapFilePath, std::string searchCriteria, std::ofstream* detailedReportFile)
{
	// create the pcap/pcap-ng reader
	IFileReaderDevice* reader = IFileReaderDevice::getReader(pcapFilePath.c_str());

	// if the reader fails to open
	if (!reader->open())
	{
		if (detailedReportFile != NULL)
		{
			// PcapPlusPlus writes the error to the error string variable we set it to write to
			// write this error to the report file
			(*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
			(*detailedReportFile) << "    ";
			std::string errorStr = errorString;
			(*detailedReportFile) << errorStr << std::endl;
		}

		// free the reader memory and return
		delete reader;
		return 0;
	}

	// set the filter for the file so only packets that match the search criteria will be read
	if (!reader->setFilter(searchCriteria))
	{
		// free the reader memory and return
		delete reader;
		return 0;
	}

	if (detailedReportFile != NULL)
	{
		(*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
	}

	int packetCount = 0;
	RawPacket rawPacket;

	// read packets from the file. Since we already set the filter, only packets that matches the filter will be read
	while (reader->getNextPacket(rawPacket))
	{
		// if a detailed report is required, parse the packet and print it to the report file
		if (detailedReportFile != NULL)
		{
			// parse the packet
			Packet parsedPacket(&rawPacket);

			// print layer by layer by layer as we want to add a few spaces before each layer
			std::vector<std::string> packetLayers;
			parsedPacket.toStringList(packetLayers);
			for (std::vector<std::string>::iterator iter = packetLayers.begin(); iter != packetLayers.end(); iter++)
				(*detailedReportFile) << "\n    " << (*iter);
			(*detailedReportFile) << std::endl;
		}

		// count the packet read
		packetCount++;
	}

	// close the reader file
	reader->close();

	// finalize the report
	if (detailedReportFile != NULL)
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
 * Searches all pcap files in given directory (and sub-directories if directed by the user) and output how many packets in each file matches a given
 * search criteria. This method outputs how many directories were searched, how many files were searched and how many packets were matched
 */
void searchtDirectories(std::string directory, bool includeSubDirectories, std::string searchCriteria, std::ofstream* detailedReportFile,
		std::map<std::string, bool> extensionsToSearch,
		int& totalDirSearched, int& totalFilesSearched, int& totalPacketsFound)
{
    // open the directory
    DIR *dir = opendir(directory.c_str());

    // dir is null usually when user has no access permissions 
    if (dir == NULL)
        return;

    struct dirent *entry = readdir(dir);

    std::vector<std::string> pcapList;

    // go over all files in this directory
    while (entry != NULL)
    {
    	std::string name(entry->d_name);

    	// construct directory full path
    	std::string dirPath = directory;
    	std::string dirSep = DIR_SEPARATOR;
    	if (0 != directory.compare(directory.length() - dirSep.length(), dirSep.length(), dirSep)) // directory doesn't contain separator in the end
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
    		// check if the file extension matches the requested extensions to search. If it does, put the file name in a list of files
    		// that should be searched (don't do the search just yet)
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

    	// if we got to here it means the file is actually a directory. If required to search sub-directories, call this method recursively to search
    	// inside this sub-directory
        if (includeSubDirectories)
        	searchtDirectories(dirPath, true, searchCriteria, detailedReportFile, extensionsToSearch, totalDirSearched, totalFilesSearched, totalPacketsFound);

        // move to the next file
        entry = readdir(dir);
    }

    // close dir
    closedir(dir);

    totalDirSearched++;

    // when we get to here we already covered all sub-directories and collected all the files in this directory that are required for search
    // go over each such file and search its packets to find the search criteria
    for (std::vector<std::string>::iterator iter = pcapList.begin(); iter != pcapList.end(); iter++)
    {
    	// do the actual search
    	int packetsFound = searchPcap(*iter, searchCriteria, detailedReportFile);

    	// add to total matched packets
    	totalFilesSearched++;
    	if (packetsFound > 0)
    	{
    		printf("%d packets found in '%s'\n", packetsFound, iter->c_str());
    		totalPacketsFound += packetsFound;
    	}
    }

}



/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string inputDirectory = "";

	std::string searchCriteria = "";

	bool includeSubDirectories = true;

	std::string detailedReportFileName = "";

	std::map<std::string, bool> extensionsToSearch;

	// the default (unless set otherwise) is to search in '.pcap' and '.pcapng' extensions
	extensionsToSearch["pcap"] = true;
	extensionsToSearch["pcapng"] = true;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "d:s:r:e:hvn", PcapSearchOptions, &optionIndex)) != -1)
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
				while(std::getline(stream, extension, ','))
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
				break;
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

	DIR *dir = opendir(inputDirectory.c_str());
	if (dir == NULL)
	{
		EXIT_WITH_ERROR("Cannot find or open input directory");
	}

	// verify the search criteria is a valid BPF filter
	if (!pcpp::IPcapDevice::verifyFilter(searchCriteria))
	{
		EXIT_WITH_ERROR("Search criteria isn't valid");
	}

	// open the detailed report file if requested by the user
	std::ofstream* detailedReportFile = NULL;
	if (detailedReportFileName != "")
	{
		detailedReportFile = new std::ofstream();
		detailedReportFile->open(detailedReportFileName.c_str());
		if (detailedReportFile->fail())
		{
			EXIT_WITH_ERROR("Couldn't open detailed report file '%s' for writing", detailedReportFileName.c_str());
		}

		// in cases where the user requests a detailed report, all errors will be written to the report also. That's why we need to save the error messages
		// to a variable and write them to the report file later
		pcpp::LoggerPP::getInstance().setErrorString(errorString, ERROR_STRING_LEN);
	}


	printf("Searching...\n");
	int totalDirSearched = 0;
	int totalFilesSearched = 0;
	int totalPacketsFound = 0;

	// the main call - start searching!
	searchtDirectories(inputDirectory, includeSubDirectories, searchCriteria, detailedReportFile, extensionsToSearch, totalDirSearched, totalFilesSearched, totalPacketsFound);

	// after search is done, close the report file and delete its instance
	printf("\n\nDone! Searched %d files in %d directories, %d packets were matched to search criteria\n", totalFilesSearched, totalDirSearched, totalPacketsFound);
	if (detailedReportFile != NULL)
	{
		if (detailedReportFile->is_open())
			detailedReportFile->close();

		delete detailedReportFile;
		printf("Detailed report written to '%s'\n", detailedReportFileName.c_str());
	}

	return 0;
}
