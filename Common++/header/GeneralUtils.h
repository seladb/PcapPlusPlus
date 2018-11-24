#ifndef PCAPPP_GENERAL_UTILS
#define PCAPPP_GENERAL_UTILS

#include <string>
#include <stdint.h>

namespace pcpp
{
	std::string byteArrayToHexString(const uint8_t* byteArr, size_t byteArrSize, int stringSizeLimit = -1);

	size_t hexStringToByteArray(const std::string& hexString, uint8_t* resultByteArr, size_t resultByteArrSize);
}

#endif // PCAPPP_GENERAL_UTILS
