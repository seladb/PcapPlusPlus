#include "PcapPlusPlusVersion.h"

namespace pcpp
{
	
std::string getGitCommit()
{
	#ifdef GIT_COMMIT
	return GIT_COMMIT;
	#endif
	return "unavailable";
}

std::string getGitBranch()
{
	#ifdef GIT_BRANCH
	return GIT_BRANCH;
	#endif
	return "unavailable";	
}

std::string getGitInfo()
{
	return "Git branch '" + getGitBranch() + "', commit '" + getGitCommit() + "'";
}

}
