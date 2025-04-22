#define LOG_MODULE PacketLogModuleNflogLayer

#include "NflogLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"

namespace pcpp
{
/// IPv4 protocol
#define PCPP_WS_NFPROTO_IPV4 2
/// IPv6 protocol
#define PCPP_WS_NFPROTO_IPV6 10

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

	NflogTlv NflogLayer::getTlvByType(NflogTlvType type) const
	{
		const auto typeNum = static_cast<uint32_t>(type);
		NflogTlv tlv = m_TlvReader.getTLVRecord(typeNum, getTlvsBasePtr(), m_DataLen - sizeof(nflog_header));

		return tlv;
	}

	void NflogLayer::parseNextLayer()
	{
		if (m_DataLen <= sizeof(nflog_header))
		{
			return;
		}
		auto payloadInfo = getTlvByType(NflogTlvType::NFULA_PAYLOAD);
		if (payloadInfo.isNull())
		{
			return;
		}

		uint8_t* payload = payloadInfo.getValue();
		size_t payloadLen = payloadInfo.getTotalSize() - sizeof(uint16_t) * 2;

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
		size_t headerLen = sizeof(nflog_header);
		NflogTlv currentTLV = m_TlvReader.getFirstTLVRecord(getTlvsBasePtr(), m_DataLen - sizeof(nflog_header));

		while (!currentTLV.isNull() && currentTLV.getType() != static_cast<uint16_t>(NflogTlvType::NFULA_PAYLOAD))
		{
			headerLen += currentTLV.getTotalSize();
			currentTLV = m_TlvReader.getNextTLVRecord(currentTLV, getTlvsBasePtr(), m_DataLen - sizeof(nflog_header));
		}
		if (!currentTLV.isNull() && currentTLV.getType() == static_cast<uint16_t>(NflogTlvType::NFULA_PAYLOAD))
		{
			// for the length and type of the payload TLV
			headerLen += 2 * sizeof(uint16_t);
		}
		// nflog_header has not a form of TLV and contains 3 fields (family, resource_id, version)
		return headerLen;
	}

	std::string NflogLayer::toString() const
	{
		return "Linux Netfilter NFLOG";
	}

	bool NflogLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(nflog_header);
	}

}  // namespace pcpp
