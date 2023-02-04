#define LOG_MODULE PacketLogModuleNflogLayer

#include "NflogLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"

#include <string.h>


namespace pcpp
{

uint8_t NflogLayer::getFamily()
{
	return getNflogHeader()->addressFamily;
}

uint8_t NflogLayer::getVersion()
{
	return getNflogHeader()->version;
}

uint16_t NflogLayer::getResourceId()
{
	return be16toh(getNflogHeader()->resourceId);
}

NflogTLV NflogLayer::getTlvByType(NflogTlvType type) const
{
	NflogTLV tlv = m_TlvReader.getTLVRecord(
		static_cast<uint32_t> (type),
		getTlvsBasePtr(),
		m_DataLen - sizeof(nflog_header));

	return tlv;
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
	if (payloadInfo.isNull())
	{
		return;
	}

	uint8_t* payload = payloadInfo.getValue();
	size_t payloadLen = payloadInfo.getTotalSize() - sizeof(nflog_tlv);

	uint8_t family = getFamily();

	switch (family)
	{
	case PCPP_WS_NFPROTO_IPV4:
		m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_WS_NFPROTO_IPV6:
		m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	default:
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

}

size_t NflogLayer::getHeaderLen() const
{
	size_t headerLen = 0;
	NflogTLV currentTLV =  m_TlvReader.getFirstTLVRecord(
		getTlvsBasePtr(),
		m_DataLen - sizeof(nflog_header));

	while (currentTLV.getType() != static_cast<uint16_t> (NflogTlvType::NFULA_PAYLOAD))
	{
		headerLen += currentTLV.getTotalSize();
		currentTLV = m_TlvReader.getNextTLVRecord(currentTLV, getTlvsBasePtr(), m_DataLen - sizeof(nflog_header));
	}
	if (currentTLV.getType() == static_cast<uint16_t> (NflogTlvType::NFULA_PAYLOAD))
	{
		// for the length and type of the payload TLV
		headerLen += 2 * sizeof (uint16_t);
	}
	// nflog_header has not a form of TLV and contains 3 fields (family, resource_id, version)
	return headerLen + sizeof(nflog_header);
}

std::string NflogLayer::toString() const
{
	return "Linux Netfilter NFLOG";
}

} // namespace pcpp
