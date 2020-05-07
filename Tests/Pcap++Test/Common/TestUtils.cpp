#include "TestUtils.h"
#include <stdlib.h>

bool sendURLRequest(std::string url)
{
#ifdef WIN32
	std::string cmd = "cUrl\\curl_win32.exe -s -o cUrl\\curl_output.txt";
#elif LINUX
	std::string cmd = "cUrl/curl.linux32 -s -o cUrl/curl_output.txt";
#elif MAC_OS_X || FREEBSD
	std::string cmd = "curl -s -o cUrl/curl_output.txt";
#endif

	cmd += " " + url;
	if (system(cmd.c_str()) == -1)
		return false;
	return true;
}