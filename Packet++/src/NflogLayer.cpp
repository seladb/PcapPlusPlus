#define LOG_MODULE PacketLogModuleNflogLayer

#include "NflogLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "NullLoopbackLayer.h"

#include <string.h>


namespace pcpp
{

uint8_t NflogLayer::getFamily()
{
	return getNflogHeader()->address_family;
}

std::pair<uint8_t*, int> NflogLayer::getTlvByType(uint32_t type) const
{
	NflogTlv tlv = m_TlvReader.getTLVRecord(
		type,
		getTlvsBasePtr(),
		m_DataLen - sizeof(nflog_header));

	std::pair<uint8_t*, int> out = std::make_pair(tlv.getValue(), tlv.getTotalSize());
	return out;
}

nflog_packet_header* NflogLayer::getPacketHeader()
{
	// NFULA_PACKET_HDR is the first tlv
	uint8_t* data = m_Data + sizeof(nflog_header) + sizeof(nflog_tlv);
	return (nflog_packet_header*)data;
}

void NflogLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(nflog_header))
		return;
	auto payloadInfo = getTlvByType(NflogTlvType::NFULA_PAYLOAD);
	uint8_t* payload = payloadInfo.first;
	size_t payloadLen = payloadInfo.second + sizeof(nflog_tlv);

	uint8_t family = getFamily();

	switch (family)
	{
	case PCPP_BSD_AF_INET:
		m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_BSD_AF_INET6_BSD:
	case PCPP_BSD_AF_INET6_FREEBSD:
	case PCPP_BSD_AF_INET6_DARWIN:
		m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	default:
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

}

std::string NflogLayer::toString() const
{
	return "Linux Netfilter NFLOG";
}

} // namespace pcpp
