#define LOG_MODULE PacketLogModuleDoipLayer

#include "DoIpLayer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"
#include <algorithm>
#include <sstream>
#include <iostream>

namespace pcpp
{
	DoIpLayer::DoIpLayer(DoIpProtocolVersion version, DoIpPayloadTypes type, const IDoIpMessageData* data)
	{
		initLayer();
		setProtocolVersion(version);
		setInvertProtocolVersion(~(static_cast<uint8_t>(version)));
		buildLayer(type, data);
	}
	DoIpLayer::DoIpLayer()
	{
		VehicleAnnouncementData data;
		initLayer();
		setProtocolVersion(DoIpProtocolVersion::version03Iso2019);
		setInvertProtocolVersion(~(static_cast<uint8_t>(DoIpProtocolVersion::version03Iso2019)));
		buildLayer(DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE, &data);
	}

	DoIpProtocolVersion DoIpLayer::getProtocolVersion() const
	{
		return static_cast<DoIpProtocolVersion>(getDoIpHeader()->protocolVersion);
	}

	std::string DoIpLayer::getProtocolVersionAsStr() const
	{
		auto it = internal::DoIpEnumToStringProtocolVersion.find(getProtocolVersion());
		if (it != internal::DoIpEnumToStringProtocolVersion.end())
		{
			return it->second;
		}
		else
		{
			return "Unknown Protocol Version";
		}
	}

	void DoIpLayer::setProtocolVersion(DoIpProtocolVersion version)
	{
		getDoIpHeader()->protocolVersion = static_cast<uint8_t>(version);
	}

	uint8_t DoIpLayer::getInvertProtocolVersion() const
	{
		return getDoIpHeader()->invertProtocolVersion;
	}

	void DoIpLayer::setInvertProtocolVersion(uint8_t iVersion)
	{
		getDoIpHeader()->invertProtocolVersion = iVersion;
	}

	DoIpPayloadTypes DoIpLayer::getPayloadType() const
	{
		return static_cast<DoIpPayloadTypes>(be16toh(getDoIpHeader()->payloadType));
	}

	void DoIpLayer::setPayloadType(DoIpPayloadTypes type)
	{
		getDoIpHeader()->payloadType = htobe16(static_cast<uint16_t>(type));
	}

	std::string DoIpLayer::getPayloadTypeAsStr() const
	{
		auto it = internal::DoIpEnumToStringPayloadType.find(getPayloadType());
		if (it != internal::DoIpEnumToStringPayloadType.end())
		{
			return it->second;
		}
		else
		{
			return "Unknown Payload type";
		}
	}

	uint32_t DoIpLayer::getPayloadLength() const
	{
		return htobe32(getDoIpHeader()->payloadLength);
	}

	void DoIpLayer::setPayloadLength(uint32_t Payloadength)
	{
		getDoIpHeader()->payloadLength = be32toh(Payloadength);
	}

	bool DoIpLayer::resolveProtocolVersion() const
	{
		DoIpProtocolVersion version = getProtocolVersion();
		uint8_t inVersion = getInvertProtocolVersion();
		DoIpPayloadTypes type = getPayloadType();

		// Idea is token from wireshark
		if (!(version == DoIpProtocolVersion::version01Iso2010 || version == DoIpProtocolVersion::version02Iso2012 ||
		      version == DoIpProtocolVersion::version03Iso2019 ||
		      version == DoIpProtocolVersion::version04Iso2019_AMD1 ||
		      (version == DoIpProtocolVersion::defaultVersion &&
		       (type >= DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST &&
		        type <= DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN))))
		{
			PCPP_LOG_ERROR("Invalid/unsupported DoIP version!");
			return false;
		}
		if ((uint8_t)(version) != (uint8_t)~(inVersion))
		{
			PCPP_LOG_ERROR("Version and invert version are not synchronised !");
			return false;
		}
		return true;
	}

	bool DoIpLayer::resolvePayloadLength() const
	{
		uint32_t length = getPayloadLength();

		if (m_DataLen < sizeof(doiphdr))
		{
			PCPP_LOG_ERROR("Payload length is smaller than the minimum header size");
			return false;
		}

		if (length != (m_DataLen - sizeof(doiphdr)))
		{
			PCPP_LOG_ERROR("Payload length does not match expected size");
			return false;
		}

		return true;
	}
	bool DoIpLayer::resolveLayer() const
	{
		// Validate the protocol version and payload length
		if (!resolveProtocolVersion() || !resolvePayloadLength())
		{
			PCPP_LOG_ERROR("Failed to Parse DoIP layer");
			return false;
		}
		return true;
	}

	std::string DoIpLayer::toString() const
	{
		if (!resolveLayer())
		{
			return "Malformed doip Packet";
		}
		std::stringstream os;
		DoIpProtocolVersion version = getProtocolVersion();
		DoIpPayloadTypes type = getPayloadType();
		uint32_t length = getPayloadLength();

		os << "DOIP Layer:" << "\n";
		os << "Protocol Version: " << getProtocolVersionAsStr() << std::hex << " (0x" << unsigned((uint8_t)version)
		   << ")" << "\n";
		os << "Payload Type: " << getPayloadTypeAsStr() << std::hex << " (0x" << std::setw(4) << std::setfill('0')
		   << (uint16_t)type << ")" << "\n";
		os << std::dec << "Payload Length: " << length << "\n";

		return os.str();
	}

	void DoIpLayer::serializeData(uint8_t* dest, std::vector<uint8_t> data)
	{
		memcpy(dest, data.data(), data.size());
	}

	void DoIpLayer::initLayer()
	{
		m_DataLen = sizeof(doiphdr);
		m_Protocol = DOIP;
		m_Data = new uint8_t[m_DataLen]{};
	}

	void DoIpLayer::buildLayer(DoIpPayloadTypes type, const IDoIpMessageData* data)
	{
		switch (type)
		{
		case DoIpPayloadTypes::ALIVE_CHECK_REQUEST:
		case DoIpPayloadTypes::ENTITY_STATUS_REQUEST:
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST:
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST:
			setPayloadType(type);
			setPayloadLength(0);
			break;
		default:
			// Payload handling for rest of types
			{
				if (data == nullptr)
				{
					PCPP_LOG_ERROR("Cannot build Layer with empty Data");
					break;
				}
				size_t payloadSize = data->getData().size();
				size_t headerLength = sizeof(doiphdr);

				setPayloadType(data->getType());
				setPayloadLength(payloadSize);
				extendLayer(headerLength, payloadSize);
				serializeData(m_Data + headerLength, data->getData());
				break;
			}
		}
	}

	void DoIpLayer::parseNextLayer()
	{
		DiagnosticMessageData diagnosticMessage;
		if (diagnosticMessage.buildFromLayer(*this))
		{
			// handle UDS layer as generic PayloadLayer for now.
			m_NextLayer = new PayloadLayer(diagnosticMessage.diagnosticData.data(),
			                               diagnosticMessage.diagnosticData.size(), this, m_Packet);
		}
	}
}  // namespace pcpp
