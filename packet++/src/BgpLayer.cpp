#define LOG_MODULE PacketLogModuleBgpLayer

#include "BgpLayer.h"
#include <sstream>

namespace pcpp
{

BgpLayer::BgpLayer(uint8_t messageType)
{
	m_DataLen = sizeof(bgp_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0xff, BGP_MARKER_SIZE_BYTES);

	m_Protocol = BGP;

	bgp_header* bgpHeader = getBgpHeader();
	bgpHeader->messageLength = m_DataLen;
	bgpHeader->messageType = messageType;
}

BgpMessageType BgpLayer::getMessageType()
{
	uint8_t type = getBgpHeader()->messageType;
	return (type > BGP_UNKNOWN && type < BGP_NUM_MESSAGE_TYPES) ? (BgpMessageType) type : BGP_UNKNOWN;
}

/**
 * @param[in] type Type to check
 * @return True if the layer if of the given type, false otherwise
 */
bool BgpLayer::isMessageOfType(BgpMessageType type)
{
	return getMessageType() == type;
}

void BgpLayer::parseNextLayer()
{

}

std::string BgpLayer::toString()
{
	std::ostringstream stream;
	stream << "BGP Layer, Type: " << getMessageType();

	return stream.str();
}

} // namespace pcpp
