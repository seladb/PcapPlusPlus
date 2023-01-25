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

void NflogLayer::initLayer()
{
	m_Packet = NULL;
	const size_t headerLen = sizeof(nflog_header);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	m_Protocol = NFLOG;
	memset(m_Data, 0, headerLen);
	nflog_header* nflogHeader = getNflogHeader();
	nflogHeader->addressFamily = pcpp::IPv4;
	nflogHeader->resourceId = 0;
	nflogHeader->version = 0;
}

NflogLayer::NflogLayer()
{
	initLayer();
}

void NflogLayer::setFamily(uint8_t family)
{
	getNflogHeader()->addressFamily = family;
}

uint8_t NflogLayer::getFamily()
{
	return getNflogHeader()->addressFamily;
}

void NflogLayer::setVersion(uint8_t version)
{
	getNflogHeader()->version = version;
}

uint8_t NflogLayer::getVersion()
{
	return getNflogHeader()->version;
}

void NflogLayer::setResourceId(uint16_t resourceId)
{
	getNflogHeader()->resourceId = resourceId;
}

uint16_t NflogLayer::getResourceId()
{
	return getNflogHeader()->resourceId;
}

NflogTlv NflogLayer::getTlvByType(NflogTlvType type) const
{
	NflogTlv tlv = m_TlvReader.getTLVRecord(
		static_cast<uint32_t> (type),
		getTlvsBasePtr(),
		m_DataLen - sizeof(nflog_header));

	// std::pair<uint8_t*, int> out = std::make_pair(tlv.getValue(), tlv.getTotalSize());
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
	uint8_t* payload = payloadInfo.getValue();
	size_t payloadLen = payloadInfo.getTotalSize() + sizeof(nflog_tlv);

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
