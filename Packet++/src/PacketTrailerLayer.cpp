#include "PacketTrailerLayer.h"
#include "GeneralUtils.h"
#include <sstream>

namespace pcpp
{

	std::string PacketTrailerLayer::getTrailerDataAsHexString() const
	{
		return byteArrayToHexString(m_Data, m_DataLen, m_DataLen + 4);
	}

	std::string PacketTrailerLayer::toString() const
	{
		std::ostringstream dataLenStream;
		dataLenStream << m_DataLen;

		std::string trailerStr = byteArrayToHexString(m_Data, m_DataLen, 15);

		if (m_DataLen > 15)
			trailerStr += "...";

		return "Packet Trailer, Data: " + trailerStr + ", Length: " + dataLenStream.str() + " [Bytes]";
	}

}  // namespace pcpp
