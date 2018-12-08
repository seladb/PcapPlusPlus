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
		if (i >= resultByteArrSize*2)
			return resultByteArrSize;

		std::string byteString = hexString.substr(i, 2);
		int firstChar = char2int(byteString[0]);
		int secondChar = char2int(byteString[1]);
		if (firstChar < 0 || secondChar < 0)
		{
			LOG_ERROR("Input string has an illegal character");
			memset(resultByteArr, 0, resultByteArrSize);
			return 0;
		}

		uint8_t byte = (uint8_t)(firstChar*16 + secondChar);
		resultByteArr[i/2] = byte;
	}

	return (size_t)(hexString.length() / 2);
}

}
