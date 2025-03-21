#define LOG_MODULE PacketLogModuleDoIpLayer

#include "DoIpLayer.h"
#include "DoIpLayerData.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"
#include <sstream>
#include <iomanip>
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
		setProtocolVersion(DoIpProtocolVersion::Version02Iso2012);
		setInvertProtocolVersion(~(static_cast<uint8_t>(DoIpProtocolVersion::Version02Iso2012)));
		buildLayer(DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE, &data);
	}

	DoIpProtocolVersion DoIpLayer::getProtocolVersion() const
	{
		uint8_t version = getDoIpHeader()->protocolVersion;

		switch (static_cast<DoIpProtocolVersion>(version))
		{
		case DoIpProtocolVersion::ReservedVersion:
		case DoIpProtocolVersion::Version01Iso2010:
		case DoIpProtocolVersion::Version02Iso2012:
		case DoIpProtocolVersion::Version03Iso2019:
		case DoIpProtocolVersion::Version04Iso2019_AMD1:
		case DoIpProtocolVersion::DefaultVersion:
			return static_cast<DoIpProtocolVersion>(version);

		default:
			return DoIpProtocolVersion::UnknownVersion;
		}
	}

	std::string DoIpLayer::getProtocolVersionAsStr() const
	{
		auto it = DoIpEnumToStringProtocolVersion.find(getProtocolVersion());
		if (it != DoIpEnumToStringProtocolVersion.end())
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
		auto it = DoIpEnumToStringPayloadType.find(getPayloadType());
		if (it != DoIpEnumToStringPayloadType.end())
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

	void DoIpLayer::setPayloadLength(uint32_t payloadLength) const
	{
		getDoIpHeader()->payloadLength = be32toh(payloadLength);
	}

	bool DoIpLayer::isProtocolVersionValid() const
	{
		DoIpProtocolVersion version = getProtocolVersion();
		uint8_t inVersion = getInvertProtocolVersion();
		DoIpPayloadTypes type = getPayloadType();

		if ((version == DoIpProtocolVersion::UnknownVersion) || (version == DoIpProtocolVersion::ReservedVersion) ||
		    (version == DoIpProtocolVersion::DefaultVersion &&
		     (type != DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN &&
		      type != DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID &&
		      type != DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST)))
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

	bool DoIpLayer::isPayloadLengthValid() const
	{
		uint32_t length = getPayloadLength();

		if (length != (m_DataLen - sizeof(doiphdr)))
		{
			PCPP_LOG_ERROR("Payload length does not match expected size");
			return false;
		}

		return true;
	}

	bool DoIpLayer::isLayerDataValid() const
	{
		// Validate the protocol version and payload length
		if (!isProtocolVersionValid() || !isPayloadLengthValid())
		{
			PCPP_LOG_ERROR("Failed to Parse DoIP layer");
			return false;
		}
		return true;
	}

	std::string DoIpLayer::toString() const
	{
		if (!isLayerDataValid())
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
