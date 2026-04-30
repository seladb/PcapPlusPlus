#pragma once

#include <string>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
/// @def PCAPPLUSPLUS_VERSION_YEAR
/// @brief The year component of the PcapPlusPlus version (e.g., 25 for 2025)
#define PCAPPLUSPLUS_VERSION_YEAR 25

/// @def PCAPPLUSPLUS_VERSION_MONTH
/// @brief The month component of the PcapPlusPlus version (e.g., 5 for May)
#define PCAPPLUSPLUS_VERSION_MONTH 5

/// @def PCAPPLUSPLUS_VERSION_PATCH
/// @brief The patch number component of the PcapPlusPlus version
#define PCAPPLUSPLUS_VERSION_PATCH 0

/// @def PCAPPLUSPLUS_VERSION_DEV
/// @brief Development flag: non-zero for development/nightly builds, zero for official releases
#define PCAPPLUSPLUS_VERSION_DEV 1

/// @def PCAPPLUSPLUS_VERSION
/// @brief Short version string (e.g., "25.05" for official release or "25.05+" for development)
#define PCAPPLUSPLUS_VERSION "25.05+"

/// @def PCAPPLUSPLUS_VERSION_OFFICIAL
/// @brief String indicating whether this is an official or non-official release
#if PCAPPLUSPLUS_VERSION_DEV
#	define PCAPPLUSPLUS_VERSION_OFFICIAL "non-official release"
#else
#	define PCAPPLUSPLUS_VERSION_OFFICIAL "official release"
#endif

/// @def PCAPPLUSPLUS_MAKE_VERSION_FULL(year, month, patch, dev)
/// @brief Create a comparable numeric version from year, month, patch, and dev components
/// @param year The year component (e.g., 25 for 2025)
/// @param month The month component (1-12)
/// @param patch The patch number
/// @param dev The development flag (0 for official, 1 for dev)
#define PCAPPLUSPLUS_MAKE_VERSION_FULL(year, month, patch, dev) ((year) * 100000 + (month) * 1000 + (patch) * 10 + dev)

/// @def PCAPPLUSPLUS_MAKE_VERSION(year, month, patch)
/// @brief Create a comparable numeric version for official releases (dev=0)
/// @param year The year component
/// @param month The month component
/// @param patch The patch number
#define PCAPPLUSPLUS_MAKE_VERSION(year, month, patch) PCAPPLUSPLUS_MAKE_VERSION_FULL(year, month, patch, 0)

/// @def PCAPPLUSPLUS_VERSION_NUM
/// @brief The current PcapPlusPlus version as a comparable numeric value
#define PCAPPLUSPLUS_VERSION_NUM                                                                                       \
	PCAPPLUSPLUS_MAKE_VERSION_FULL(PCAPPLUSPLUS_VERSION_YEAR, PCAPPLUSPLUS_VERSION_MONTH, PCAPPLUSPLUS_VERSION_PATCH,  \
	                               PCAPPLUSPLUS_VERSION_DEV)

/// @def PCAPPLUSPLUS_VERSION_EQUALS(major, minor, patch)
/// @brief Check if the current version equals the specified version
/// @param major The major (year) component to compare
/// @param minor The minor (month) component to compare
/// @param patch The patch number to compare
#define PCAPPLUSPLUS_VERSION_EQUALS(major, minor, patch)                                                               \
	PCAPPLUSPLUS_VERSION_NUM == PCAPPLUSPLUS_MAKE_VERSION(major, minor, patch)

/// @def PCAPPLUSPLUS_VERSION_LOWER_THAN(year, month, patch)
/// @brief Check if the current version is lower than the specified version
/// @param year The year component to compare
/// @param month The month component to compare
/// @param patch The patch number to compare
#define PCAPPLUSPLUS_VERSION_LOWER_THAN(year, month, patch)                                                            \
	PCAPPLUSPLUS_VERSION_NUM < PCAPPLUSPLUS_MAKE_VERSION(year, month, patch)

/// @def PCAPPLUSPLUS_VERSION_LOWER_OR_EQUAL_THAN(year, month, patch)
/// @brief Check if the current version is lower than or equal to the specified version
/// @param year The year component to compare
/// @param month The month component to compare
/// @param patch The patch number to compare
#define PCAPPLUSPLUS_VERSION_LOWER_OR_EQUAL_THAN(year, month, patch)                                                   \
	PCAPPLUSPLUS_VERSION_NUM <= PCAPPLUSPLUS_MAKE_VERSION(year, month, patch)

/// @def PCAPPLUSPLUS_VERSION_HIGHER_THAN(year, month, patch)
/// @brief Check if the current version is higher than the specified version
/// @param year The year component to compare
/// @param month The month component to compare
/// @param patch The patch number to compare
#define PCAPPLUSPLUS_VERSION_HIGHER_THAN(year, month, patch)                                                           \
	PCAPPLUSPLUS_VERSION_NUM > PCAPPLUSPLUS_MAKE_VERSION(year, month, patch)

/// @def PCAPPLUSPLUS_VERSION_HIGHER_OR_EQUAL_THAN(year, month, patch)
/// @brief Check if the current version is higher than or equal to the specified version
/// @param year The year component to compare
/// @param month The month component to compare
/// @param patch The patch number to compare
#define PCAPPLUSPLUS_VERSION_HIGHER_OR_EQUAL_THAN(year, month, patch)                                                  \
	PCAPPLUSPLUS_VERSION_NUM >= PCAPPLUSPLUS_MAKE_VERSION(year, month, patch)

/// @def PCAPPLUSPLUS_VERSION_FULL
/// @brief Full version string including version and release type (e.g., "v25.05+ (non-official release)")
#define PCAPPLUSPLUS_VERSION_FULL "v" PCAPPLUSPLUS_VERSION " (" PCAPPLUSPLUS_VERSION_OFFICIAL ")"

	/// @return PcapPlusPlus current version, e.g: 23.09. Notice that for non-official releases (which were pulled from
	/// GitHub) the version will end with a '+'. For example: '23.09+' means non-official release but '23.09' means
	/// official release
	inline std::string getPcapPlusPlusVersion()
	{
		return PCAPPLUSPLUS_VERSION;
	}

	/// @return PcapPlusPlus long version string which includes the version and info whether it's an official or
	/// non-official release. For example: "v23.09+ (non-official release)" or "v23.09 (official release)"
	inline std::string getPcapPlusPlusVersionFull()
	{
		return PCAPPLUSPLUS_VERSION_FULL;
	}

	/// @return The build date and time in a format of "Mmm dd yyyy hh:mm:ss"
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

	/// @return The Git commit (revision) the binaries are built from
	std::string getGitCommit();

	/// @return The Git branch the binaries are built from
	std::string getGitBranch();

	/// @return Git branch and commit the binaries are built from.
	/// Aggregates data from getGitCommit() and getGitBranch()
	std::string getGitInfo();

}  // namespace pcpp
