#include "PcapPlusPlusVersion.h"

namespace pcpp
{

	std::string getGitCommit()
	{
#ifdef GIT_COMMIT
		return GIT_COMMIT;
#else
		return "unavailable";
#endif
	}

	std::string getGitBranch()
	{
#ifdef GIT_BRANCH
		return GIT_BRANCH;
#else
		return "unavailable";
#endif
	}

	std::string getGitInfo()
	{
		return "Git branch '" + getGitBranch() + "', commit '" + getGitCommit() + "'";
	}

}  // namespace pcpp
