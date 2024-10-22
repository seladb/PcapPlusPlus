#ifndef PCAPPP_VERSION_H
#define PCAPPP_VERSION_H

#include <string>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	#define PCAPPLUSPLUS_VERSION "21.11"
	#define PCAPPLUSPLUS_VERSION_OFFICIAL "official release"

	#define PCAPPLUSPLUS_VERSION_FULL "v" PCAPPLUSPLUS_VERSION " (" PCAPPLUSPLUS_VERSION_OFFICIAL ")"

	/**
	 * @return PcapPlusPlus current version, e.g: 21.11. Notice that for non-official releases (which were pulled from GitHub) the version will end with a '+'.
	 * For example: '21.11+' means non-official release but '21.11' means official release
	 */
	inline std::string getPcapPlusPlusVersion() { return PCAPPLUSPLUS_VERSION; }

	/**
	 * @return PcapPlusPlus long version string which includes the version and info whether it's an official or non-official release. For example: "v21.11+ (non-official release)"
	 * or "v21.11 (official release)"
	 */
	inline std::string getPcapPlusPlusVersionFull() { return PCAPPLUSPLUS_VERSION_FULL; }

	/**
	 * @return The build date and time in a format of "Mmm dd yyyy hh:mm:ss"
	 */
	inline std::string getBuildDateTime() { return std::string(__DATE__) + " " + std::string(__TIME__); }
	
	/**
	 * @return The Git commit (revision) the binaries are built from
	 */
	std::string getGitCommit();

	/**
	 * @return The Git branch the binaries are built from
	 */
	std::string getGitBranch();

	/**
	 * @return Git branch and commit the binaries are built from.
	 * Aggregates data from getGitCommit() and getGitBranch()
	 */
	std::string getGitInfo();

}

#endif /* PCAPPP_VERSION_H */
