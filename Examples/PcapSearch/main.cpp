/**
 * PcapSearch application
 * ======================
 * This application takes a pcap file, parses its packets using Packet++ and output each layer in each packet
 * as a readable string (quite similar to the way Wireshark shows packets).
 * The result is printed to stdout (by default) or to a file (if specified). It can also print only the
 * first X packets of a file
 *
 * For more details about modes of operation and parameters run PcapPrinter -h
 */

#include <stdlib.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <dirent.h>
#include <vector>
#include <map>
#include <Logger.h>
#include <RawPacket.h>
#include <Packet.h>
#include <PcapFileDevice.h>



using namespace pcpp;

static struct option PcapSearchOptions[] =
{
	{"input-dir",  required_argument, 0, 'd'},
	{"not-include-sub-dir", no_argument, 0, 'n'},
	{"search", required_argument, 0, 's'},
	{"detailed-report", required_argument, 0, 'r'},
	{"set-extensions", required_argument, 0, 'e'},
	{"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};


#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#ifdef WIN32
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
			"PcapPrinter [-h] [-n] [-r file_name] [-e extension_list] -d directory -s search_criteria\n"
			"\nOptions:\n\n"
			"    -d directory        : Input directory\n"
			"    -n                  : Don't include sub-directories (default is include them)\n"
			"    -s search_criteria  : Criteria to search in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'\n"
			"    -r file_name        : Write a detailed search report to a file\n"
			"    -e extension_list   : Set file extensions to search. The default is searching '.pcap' files only.\n"
			"                          extnesions_list should be a comma-separated list of extensions, for example: pcap,net,dmp\n"
			"    -h                  : Displays this help message and exits\n");
	exit(0);
}


bool hasEnding(std::string const &fullString, std::string const &ending)
{
    if (fullString.length() >= ending.length())
    {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    }
    else
    {
        return false;
    }
}

std::string getExtension(std::string fileName)
{
	return fileName.substr(fileName.find_last_of(".") + 1);
}


int searchPcap(std::string pcapFilePath, std::string searchCriteria, std::ofstream* detailedReportFile)
{
	PcapFileReaderDevice reader(pcapFilePath.c_str());
	if (!reader.open())
	{
		if (detailedReportFile != NULL)
		{
			(*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
			(*detailedReportFile) << "    ";
			std::string errorStr = errorString;
			(*detailedReportFile) << errorStr << std::endl;
		}

		return 0;
	}

	if (!reader.setFilter(searchCriteria))
	{
		return 0;
	}

	if (detailedReportFile != NULL)
	{
		(*detailedReportFile) << "File '" << pcapFilePath << "':" << std::endl;
	}

	int packetCount = 0;
	RawPacket rawPacket;
	while (reader.getNextPacket(rawPacket))
	{
		if (detailedReportFile != NULL)
		{
			Packet parsedPacket(&rawPacket);
			std::vector<std::string> packetLayers;
			parsedPacket.printToStringList(packetLayers);
			for (std::vector<std::string>::iterator iter = packetLayers.begin(); iter != packetLayers.end(); iter++)
				(*detailedReportFile) << "\n    " << (*iter);
			(*detailedReportFile) << std::endl;
		}

		packetCount++;
	}

	reader.close();

	if (detailedReportFile != NULL)
	{
		if (packetCount > 0)
			(*detailedReportFile) << "\n";

		(*detailedReportFile) << "    ----> Found " << packetCount << " packets" << std::endl << std::endl;

	}

	return packetCount;
}

void searchtDirectories(std::string directory, bool includeSubDirectories, std::string searchCriteria, std::ofstream* detailedReportFile,
		std::map<std::string, bool> extensionsToSearch,
		int& totalDirSearched, int& totalFilesSearched, int& totalPacketsFound)
{
    DIR *dir = opendir(directory.c_str());

    struct dirent *entry = readdir(dir);

    std::vector<std::string> pcapList;

    while (entry != NULL)
    {
    	std::string name(entry->d_name);
    	std::string dirPath = directory + DIR_SEPARATOR + name;
    	struct stat info;
    	if (stat(dirPath.c_str(), &info) != 0)
    	{
    		entry = readdir(dir);
    		continue;
    	}

    	if (!(info.st_mode & S_IFDIR))
    	{
    		if (extensionsToSearch.find(getExtension(name)) != extensionsToSearch.end())
    			pcapList.push_back(dirPath);
//    		if (hasEnding(name, ".pcap"))
//    			pcapList.push_back(dirPath);
    		entry = readdir(dir);
    		continue;
    	}

    	if (name == "." || name == "..")
    	{
    		entry = readdir(dir);
    		continue;
    	}

        if (includeSubDirectories)
        	searchtDirectories(dirPath, true, searchCriteria, detailedReportFile, extensionsToSearch, totalDirSearched, totalFilesSearched, totalPacketsFound);

        entry = readdir(dir);
    }

    closedir(dir);

    totalDirSearched++;

    for (std::vector<std::string>::iterator iter = pcapList.begin(); iter != pcapList.end(); iter++)
    {
    	int packetsFound = searchPcap(*iter, searchCriteria, detailedReportFile);
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
	std::string inputDirectory = "";

	std::string searchCriteria = "";

	bool includeSubDirectories = true;

	std::string detailedReportFileName = "";

	std::map<std::string, bool> extensionsToSearch;
	extensionsToSearch["pcap"] = true;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "d:s:r:e:hn", PcapSearchOptions, &optionIndex)) != -1)
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
				extensionsToSearch.clear();
				std::string extensionsListAsString = std::string(optarg);
				std::stringstream stream(extensionsListAsString);
				std::string extension;
				// break comma-separated string into string list
				while(std::getline(stream, extension, ','))
				{
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

	if (!pcpp::IPcapDevice::verifyFilter(searchCriteria))
	{
		EXIT_WITH_ERROR("Search criteria isn't valid");
	}

	std::ofstream* detailedReportFile = NULL;
	if (detailedReportFileName != "")
	{
		detailedReportFile = new std::ofstream();
		detailedReportFile->open(detailedReportFileName.c_str());
		if (detailedReportFile->fail())
		{
			EXIT_WITH_ERROR("Couldn't open detailed report file '%s' for writing", detailedReportFileName.c_str());
		}
		pcpp::LoggerPP::getInstance().setErrorString(errorString, ERROR_STRING_LEN);
	}


	printf("Searching...\n");
	int totalDirSearched = 0;
	int totalFilesSearched = 0;
	int totalPacketsFound = 0;
	searchtDirectories(inputDirectory, includeSubDirectories, searchCriteria, detailedReportFile, extensionsToSearch, totalDirSearched, totalFilesSearched, totalPacketsFound);

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
