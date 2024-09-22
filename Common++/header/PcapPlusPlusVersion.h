#pragma once

#include <string>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
#define PCAPPLUSPLUS_VERSION "24.09+"
#define PCAPPLUSPLUS_VERSION_OFFICIAL "non-official release"

#define PCAPPLUSPLUS_VERSION_FULL "v" PCAPPLUSPLUS_VERSION " (" PCAPPLUSPLUS_VERSION_OFFICIAL ")"

	/**
	 * @return PcapPlusPlus current version, e.g: 23.09. Notice that for non-official releases (which were pulled from
	 * GitHub) the version will end with a '+'. For example: '23.09+' means non-official release but '23.09' means
	 * official release
	 */
	inline std::string getPcapPlusPlusVersion()
	{
		return PCAPPLUSPLUS_VERSION;
	}

	/**
	 * @return PcapPlusPlus long version string which includes the version and info whether it's an official or
	 * non-official release. For example: "v23.09+ (non-official release)" or "v23.09 (official release)"
	 */
	inline std::string getPcapPlusPlusVersionFull()
	{
		return PCAPPLUSPLUS_VERSION_FULL;
	}

	/**
	 * @return The build date and time in a format of "Mmm dd yyyy hh:mm:ss"
	 */
#ifdef PCAPPP_BUILD_REPRODUCIBLE
	inline std::string getBuildDateTime()
	{
		return " ";
	}
#else
	inline std::string getBuildDateTime()
	{
		return std::string(__DATE__) + " " + std::string(__TIME__);
	}
#endif

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

}  // namespace pcpp
