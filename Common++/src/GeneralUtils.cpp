#define LOG_MODULE CommonLogModuleGenericUtils

#include "GeneralUtils.h"
#include "Logger.h"
#include <sstream>
#include <iomanip>
#include <string.h>
#include <stdlib.h>

namespace pcpp
{

std::string byteArrayToHexString(const uint8_t* byteArr, size_t byteArrSize, int stringSizeLimit)
{
	if (stringSizeLimit <= 0)
		stringSizeLimit = byteArrSize;

	std::stringstream dataStream;
	dataStream << std::hex;
	for (size_t i = 0; i < byteArrSize; ++i)
	{
		if (i >= (size_t)stringSizeLimit)
			break;

		dataStream << std::setw(2) << std::setfill('0') << (int)byteArr[i];
	}

	return dataStream.str();
}

static int char2int(char input)
{
	if(input >= '0' && input <= '9')
		return input - '0';
	if(input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if(input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return -1;
}

size_t hexStringToByteArray(const std::string& hexString, uint8_t* resultByteArr, size_t resultByteArrSize)
{
	if (hexString.size() % 2 != 0)
	{
		LOG_ERROR("Input string is in odd size");
		return 0;
	}

	memset(resultByteArr, 0, resultByteArrSize);
	for (size_t i = 0; i < hexString.length(); i += 2)
	{
		if (i >= resultByteArrSize * 2)
			return resultByteArrSize;

		int firstChar = char2int(hexString[i]);
		int secondChar = char2int(hexString[i + 1]);
		if (firstChar < 0 || secondChar < 0)
		{
			LOG_ERROR("Input string has an illegal character");
			resultByteArr[0] = '\0';
			return 0;
		}

		resultByteArr[i / 2] = (firstChar << 4) | secondChar;
	}

	return hexString.length() / 2;
}


char* cross_platform_memmem(const char* haystack, size_t haystackLen, const char* needle, size_t needleLen)
{
	char* ptr = (char*)haystack;
	while (needleLen <= (haystackLen - (ptr - haystack)))
	{
		if (NULL != (ptr = (char*)memchr(ptr, (int)(*needle), haystackLen - (ptr - haystack))))
		{
			// check if there is room to do a memcmp 
			if(needleLen > (haystackLen - (ptr - haystack)))
			{
				return NULL;
			}

			if (0 == memcmp(ptr, needle, needleLen))
				return ptr;
			else
				++ptr;
		}
		else
			break;
	}

	return NULL;
}

}
