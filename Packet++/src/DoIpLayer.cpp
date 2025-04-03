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
	/// @brief Mapping of DoIP Protocol Versions to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each version of the
	/// DoIP protocol as defined in ISO 13400. It maps the `DoIpProtocolVersion` enum values
	/// to their corresponding descriptions.
	const std::unordered_map<DoIpProtocolVersion, std::string> DoIpEnumToStringProtocolVersion{
		{ DoIpProtocolVersion::DefaultVersion,        "Default value for vehicle identification request messages" },
		{ DoIpProtocolVersion::Version01Iso2010,      "DoIP ISO/DIS 13400-2:2010"                                 },
		{ DoIpProtocolVersion::Version02Iso2012,      "DoIP ISO 13400-2:2012"                                     },
		{ DoIpProtocolVersion::Version03Iso2019,      "DoIP ISO 13400-2:2019"                                     },
		{ DoIpProtocolVersion::Version04Iso2019_AMD1, "DoIP ISO 13400-2:2012 AMD1"                                },
		{ DoIpProtocolVersion::ReservedVersion,       "Reserved"                                                  },
		{ DoIpProtocolVersion::UnknownVersion,        "Unknown Protocol Version"                                  }
	};

	/// @brief Mapping of DoIP Payload Types to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each payload type
	/// defined in the DoIP protocol as per ISO 13400. It maps the `DoIpPayloadTypes` enum values
	/// to their corresponding descriptions.
	const std::unordered_map<DoIpPayloadTypes, std::string> DoIpEnumToStringPayloadType{
		{ DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK,                  "Generic DOIP header Nack"                   },
		{ DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST,          "Vehicle identification request"             },
		{ DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID, "Vehicle identification request with EID"    },
		{ DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN, "Vehicle identification request with VIN"    },
		{ DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE,
         "Vehicle announcement message / vehicle identification response message"                                 },
		{ DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST,              "Routing activation request"                 },
		{ DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE,             "Routing activation response"                },
		{ DoIpPayloadTypes::ALIVE_CHECK_REQUEST,                     "Alive check request"                        },
		{ DoIpPayloadTypes::ALIVE_CHECK_RESPONSE,                    "Alive check response"                       },
		{ DoIpPayloadTypes::ENTITY_STATUS_REQUEST,                   "DOIP entity status request"                 },
		{ DoIpPayloadTypes::ENTITY_STATUS_RESPONSE,                  "DOIP entity status response"                },
		{ DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST,           "Diagnostic power mode request information"  },
		{ DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE,          "Diagnostic power mode response information" },
		{ DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE,                 "Diagnostic message"                         },
		{ DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK,              "Diagnostic message Ack"                     },
		{ DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK,              "Diagnostic message Nack"                    },
		{ DoIpPayloadTypes::UNKNOWN_PAYLOAD_TYPE,                    "Unknown payload type"                       }
	};

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
		return it->second;
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
		switch (static_cast<DoIpPayloadTypes>(be16toh(getDoIpHeader()->payloadType)))
		{
		case DoIpPayloadTypes::ALIVE_CHECK_REQUEST:
		case DoIpPayloadTypes::ALIVE_CHECK_RESPONSE:
		case DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE:
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK:
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK:
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE:
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST:
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE:
		case DoIpPayloadTypes::ENTITY_STATUS_REQUEST:
		case DoIpPayloadTypes::ENTITY_STATUS_RESPONSE:
		case DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK:
		case DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST:
		case DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE:
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST:
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID:
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN:
			return static_cast<DoIpPayloadTypes>(be16toh(getDoIpHeader()->payloadType));

		default:
			return DoIpPayloadTypes::UNKNOWN_PAYLOAD_TYPE;
		}
	}

	void DoIpLayer::setPayloadType(DoIpPayloadTypes type)
	{
		getDoIpHeader()->payloadType = htobe16(static_cast<uint16_t>(type));
	}

	std::string DoIpLayer::getPayloadTypeAsStr() const
	{
		auto it = DoIpEnumToStringPayloadType.find(getPayloadType());
		return it->second;
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
			return "Malformed DoIP packet";
		}

		std::ostringstream os;
		DoIpPayloadTypes type = getPayloadType();

		os << "DOIP Layer, " << getPayloadTypeAsStr() << " (0x" << std::hex << std::setw(4) << std::setfill('0')
		   << (type == DoIpPayloadTypes::UNKNOWN_PAYLOAD_TYPE
		           ? static_cast<uint16_t>(be16toh(getDoIpHeader()->payloadType))
		           : static_cast<uint16_t>(type))
		   << ")";

		return os.str();
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
				memcpy(m_Data + headerLength, data->getData().data(), payloadSize);
				break;
			}
		}
	}

	void DoIpLayer::parseNextLayer()
	{
		if (getPayloadType() == DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE)
		{
			size_t headerLen = sizeof(doiphdr);

			if (m_DataLen <= headerLen + 2 /*source address size*/ + 2 /*target address size*/)
				return;

			uint8_t* payload = m_Data + (headerLen + 2 + 2);
			size_t payloadLen = m_DataLen - (headerLen + 2 + 2);
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		}
	}
}  // namespace pcpp
