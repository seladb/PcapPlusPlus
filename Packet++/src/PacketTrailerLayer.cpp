#include "PacketTrailerLayer.h"
#include <string.h>
#include <sstream>
#include <iomanip>

namespace pcpp
{

std::string PacketTrailerLayer::dataAsString(size_t sizeLimitation)
{
	  std::stringstream trailerStream;
	  trailerStream << std::hex;
	  for (size_t i = 0; i < m_DataLen; ++i)
	  {
		  if (i >= sizeLimitation)
			  break;

		  trailerStream << std::setw(2) << std::setfill('0') << (int)m_Data[i];
	  }

	  return trailerStream.str();
}

std::string PacketTrailerLayer::getTrailerDataAsHexString()
{
	return dataAsString(m_DataLen + 4);
}

std::string PacketTrailerLayer::toString()
{
	std::ostringstream dataLenStream;
	dataLenStream << m_DataLen;

	std::string trailerStr = dataAsString(15);

	if (m_DataLen > 15)
		trailerStr += "...";

	return "Packet Trailer, Data: " + trailerStr + ", Length: " + dataLenStream.str() + " [Bytes]";
}

}

