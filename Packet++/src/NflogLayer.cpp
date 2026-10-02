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
	constexpr uint8_t NflogFamilyIpv4 = 2;
	/// IPv6 protocol
	constexpr uint8_t NflogFamilyIpv6 = 10;

	uint8_t NflogLayer::getFamily() const
	{
		return getNflogHeader()->addressFamily;
	}

	uint8_t NflogLayer::getVersion() const
	{
		return getNflogHeader()->version;
	}

	uint16_t NflogLayer::getResourceId() const
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
		case NflogFamilyIpv4:
		{
			tryConstructNextLayerWithFallback<IPv4Layer, PayloadLayer>(payload, payloadLen);
			break;
		}
		case NflogFamilyIpv6:
		{
			tryConstructNextLayerWithFallback<IPv6Layer, PayloadLayer>(payload, payloadLen);
			break;
		}
		default:
		{
			constructNextLayer<PayloadLayer>(payload, payloadLen);
			break;
		}
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

	const FieldDescriptor NflogLayer::SerializedFields::Family{ Layer::SerializedFields::MaxID + 1, "family" };
	const FieldDescriptor NflogLayer::SerializedFields::Version{ Layer::SerializedFields::MaxID + 2, "version" };
	const FieldDescriptor NflogLayer::SerializedFields::ResourceID{ Layer::SerializedFields::MaxID + 3, "resourceID" };
	const FieldDescriptor NflogLayer::SerializedFields::Attributes{ Layer::SerializedFields::MaxID + 4, "attributes" };
	const FieldDescriptor NflogLayer::SerializedFields::Attribute{ 0, "attribute" };

	static constexpr const char* getAttributeTypeAsString(const NflogTlv& attribute)
	{
		switch (attribute.getType())
		{
		case 1:
			return "NFULA_PACKET_HDR";
		case 2:
			return "NFULA_MARK";
		case 3:
			return "NFULA_TIMESTAMP";
		case 4:
			return "NFULA_IFINDEX_INDEV";
		case 5:
			return "NFULA_IFINDEX_OUTDEV";
		case 6:
			return "NFULA_IFINDEX_PHYSINDEV";
		case 7:
			return "NFULA_IFINDEX_PHYSOUTDEV";
		case 8:
			return "NFULA_HWADDR";
		case 9:
			return "NFULA_PAYLOAD";
		case 10:
			return "NFULA_PREFIX";
		case 11:
			return "NFULA_UID";
		case 12:
			return "NFULA_SEQ";
		case 13:
			return "NFULA_SEQ_GLOBAL";
		case 14:
			return "NFULA_GID";
		case 15:
			return "NFULA_HWTYPE";
		case 16:
			return "NFULA_HWHEADER";
		case 17:
			return "NFULA_HWLEN";
		default:
			return "Unknown";
		}
	}

	void NflogLayer::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SerializedFields::Family, getFamily());
		serializer.writeField(SerializedFields::Version, getVersion());
		serializer.writeField(SerializedFields::ResourceID, getResourceId());
		{
			auto attributesArray = serializer.writeArray(SerializedFields::Attributes);
			for (auto currentAttr = m_TlvReader.getFirstTLVRecord(getTlvsBasePtr(), m_DataLen - sizeof(nflog_header));
			     !currentAttr.isNull(); currentAttr = m_TlvReader.getNextTLVRecord(currentAttr, getTlvsBasePtr(),
			                                                                       m_DataLen - sizeof(nflog_header)))
			{
				attributesArray.writeField(SerializedFields::Attribute, getAttributeTypeAsString(currentAttr));
			}
		}
	}
}  // namespace pcpp
