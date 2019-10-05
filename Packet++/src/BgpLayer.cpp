#define LOG_MODULE PacketLogModuleBgpLayer

#include "BgpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
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
	size_t headerLen = getHeaderLen();
	if (headerLen < sizeof(bgp_header))
	{
		// do nothing
		return;
	}

	if (m_DataLen <= headerLen)
	{
		// no data beyond headerLen, nothing to parse further
		return;
	}

	uint8_t subProto = *(uint8_t*)(m_Data + headerLen);
	if (subProto >= 0x45 && subProto <= 0x4e)
	{
		m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	}
	else if ((subProto & 0xf0) == 0x60)
	{
		m_NextLayer = new IPv6Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	}
	else
	{
		m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	}
}

std::string BgpLayer::toString()
{
	std::ostringstream stream;
	stream << "BGP Layer, Type: " << getMessageType();

	return stream.str();
}

} // namespace pcpp
