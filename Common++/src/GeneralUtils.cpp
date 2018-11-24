#include "GeneralUtils.h"
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

size_t hexStringToByteArray(const std::string& hexString, uint8_t* resultByteArr, size_t resultByteArrSize)
{
	memset(resultByteArr, 0, resultByteArrSize);
	for (size_t i = 0; i < hexString.length(); i += 2)
	{
		if (i >= resultByteArrSize*2)
			return resultByteArrSize;

		std::string byteString = hexString.substr(i, 2);
		uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
		resultByteArr[i/2] = byte;
	}

	return (size_t)(hexString.length() / 2);
}

}
