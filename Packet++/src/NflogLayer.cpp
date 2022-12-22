#define LOG_MODULE PacketLogModuleNflogLayer

#include "NflogLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include <string.h>
#include "NullLoopbackLayer.h"

namespace pcpp
{

uint8_t NflogLayer::getFamily()
{
	return getNflogHeader()->address_family;
}

std::pair<uint8_t*, int> NflogLayer::getPayload()
{
	uint8_t* data = m_Data + sizeof(nflog_header);
	nflog_tlv* current_tlv = (nflog_tlv*)data;

	uint16_t offset = sizeof(nflog_header);

	while (current_tlv->tlv_type != NFULA_PAYLOAD) {
		uint16_t len = current_tlv->tlv_length;
		data = data + len;
		offset += len;
		while (*data == 0) {
			data += 1;
			offset += 1;
		}
		current_tlv = (nflog_tlv*)data;
	}
	return std::make_pair(data + sizeof(nflog_tlv), offset);
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

	auto payloadInfo = getPayload();
	uint8_t* payload = payloadInfo.first;
	size_t payloadLen = m_DataLen - payloadInfo.second + 1;

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
