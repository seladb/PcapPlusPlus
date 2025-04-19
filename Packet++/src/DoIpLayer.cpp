#define LOG_MODULE PacketLogModuleDoIpLayer

#include "DoIpLayer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <iostream>
#include "GeneralUtils.h"

namespace pcpp
{

	// This unordered map provides human-readable descriptions for each activation type
	// defined in the DoIP protocol as per ISO 13400. It maps the `DoIpActivationTypes` enum values
	// to their corresponding descriptions.
	static const std::unordered_map<DoIpActivationTypes, std::string> DoIpEnumToStringActivationTypes{
		{ DoIpActivationTypes::Default,          "Default"          },
		{ DoIpActivationTypes::WWH_OBD,          "WWH-OBD"          },
		{ DoIpActivationTypes::CENTRAL_SECURITY, "Central security" },
	};

	// This unordered map provides human-readable descriptions for each Nack code related to
	// the DoIP Generic Header as per ISO 13400. It maps the `DoIpGenericHeaderNackCodes` enum
	// values to their corresponding descriptions.
	static const std::unordered_map<DoIpGenericHeaderNackCodes, std::string> DoIpEnumToStringGenericHeaderNackCodes{
		{ DoIpGenericHeaderNackCodes::INCORRECT_PATTERN,      "Incorrect pattern format" },
		{ DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE,   "Unknown payload type"     },
		{ DoIpGenericHeaderNackCodes::INVALID_PAYLOAD_LENGTH, "Invalid payload length"   },
		{ DoIpGenericHeaderNackCodes::MESSAGE_TOO_LARGE,      "Message too large"        },
		{ DoIpGenericHeaderNackCodes::OUT_OF_MEMORY,          "Out of memory"            },
	};

	// This unordered map provides human-readable descriptions for each action code related to
	// the DoIP announcement message, as per ISO 13400. It maps the `DoIpActionCodes` enum
	// values to their corresponding descriptions.
	static const std::unordered_map<DoIpActionCodes, std::string> DoIpEnumToStringActionCodes{
		{ DoIpActionCodes::NO_FURTHER_ACTION_REQUIRED,  "No further action required"                               },
		{ DoIpActionCodes::RESERVED_ISO_0x01,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x02,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x03,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x04,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x05,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x06,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x07,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x08,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x09,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x0A,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x0B,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x0C,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x0D,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x0E,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::RESERVED_ISO_0x0F,           "Reserved by ISO 13400"                                    },
		{ DoIpActionCodes::ROUTING_ACTIVATION_REQUIRED, "Routing activation required to initiate central security" }
	};

	// This unordered map provides human-readable descriptions for each routing response code
	// related to the DoIP routing activation process, as per ISO 13400. It maps the `DoIpRoutingResponseCodes`
	// enum values to their corresponding descriptions.
	static const std::unordered_map<DoIpRoutingResponseCodes, std::string> DoIpEnumToStringRoutingResponseCodes{
		{ DoIpRoutingResponseCodes::UNKNOWN_SOURCE_ADDRESS,            "Routing activation denied due to unknown source address"                   },
		{ DoIpRoutingResponseCodes::NO_FREE_SOCKET,
         "Routing activation denied because all concurrently supported TCP_DATA sockets are registered and active"                                 },
		{ DoIpRoutingResponseCodes::WRONG_SOURCE_ADDRESS,
         "Routing activation denied because an SA different from the table connection entry was received on the already activated TCP_DATA socket" },
		{ DoIpRoutingResponseCodes::SOURCE_ADDRESS_ALREADY_REGISTERED,
         "Routing activation denied because the SA is already registered and active on a different TCP_DATA socket"                                },
		{ DoIpRoutingResponseCodes::MISSING_AUTHENTICATION,            "Routing activation denied due to missing authentication"                   },
		{ DoIpRoutingResponseCodes::REJECTED_CONFIRMATION,             "Routing activation denied due to rejected confirmation"                    },
		{ DoIpRoutingResponseCodes::UNSUPPORTED_ACTIVATION_TYPE,
         "Routing activation denied due to unsupported routing activation type"                                                                    },
		{ DoIpRoutingResponseCodes::ENCRYPTED_CONNECTION_TLS,
         "Routing activation denied due to request for encrypted connection via TLS"                                                               },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x08,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x09,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x0A,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x0B,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x0C,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x0D,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x0E,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::RESERVED_ISO_0x0F,                 "Reserved by ISO 13400"                                                     },
		{ DoIpRoutingResponseCodes::ROUTING_SUCCESSFULLY_ACTIVATED,    "Routing successfully activated"                                            },
		{ DoIpRoutingResponseCodes::CONFIRMATION_REQUIRED,             "Routing will be activated; confirmation required"                          }
	};

	// This unordered map provides human-readable descriptions for each NACK (negative acknowledgment) code
	// related to DoIP diagnostic messages, as per ISO 13400. It maps the `DoIpDiagnosticMessageNackCodes` enum
	// values to their corresponding descriptions.
	static const std::unordered_map<DoIpDiagnosticMessageNackCodes, std::string> DoIpEnumToStringDiagnosticNackCodes{
		{ DoIpDiagnosticMessageNackCodes::RESERVED_ISO_0x00,        "Reserved by ISO 13400"        },
		{ DoIpDiagnosticMessageNackCodes::RESERVED_ISO_0x01,        "Reserved by ISO 13400"        },
		{ DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS,   "Invalid source address"       },
		{ DoIpDiagnosticMessageNackCodes::INVALID_TARGET_ADDRESS,   "Unknown target address"       },
		{ DoIpDiagnosticMessageNackCodes::MESSAGE_TOO_LARGE,        "Diagnostic message too large" },
		{ DoIpDiagnosticMessageNackCodes::OUT_OF_MEMORY,            "Out of memory"                },
		{ DoIpDiagnosticMessageNackCodes::TARGET_UNREACHABLE,       "Target unreachable"           },
		{ DoIpDiagnosticMessageNackCodes::UNKNOWN_NETWORK,          "Unknown network"              },
		{ DoIpDiagnosticMessageNackCodes::TRANSPORT_PROTOCOL_ERROR, "Transport protocol error"     },
	};

	// This unordered map provides human-readable descriptions for each power mode code
	// related to DoIP diagnostics, as per ISO 13400. It maps the `DoIpDiagnosticPowerMode` enum
	// values to their corresponding descriptions.
	static const std::unordered_map<DoIpDiagnosticPowerModeCodes, std::string> DoIpEnumToStringDiagnosticPowerModeCodes{
		{ DoIpDiagnosticPowerModeCodes::NOT_READY,     "not ready"     },
		{ DoIpDiagnosticPowerModeCodes::READY,         "ready"         },
		{ DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED, "not supported" },
	};

	// This unordered map provides human-readable descriptions for the entity status codes
	// in the context of DoIP (Diagnostic over IP). It maps the `DoIpEntityStatus` enum values
	// to their corresponding descriptions, distinguishing between a "DoIP node" and a "DoIP gateway."
	static const std::unordered_map<DoIpEntityStatus, std::string> DoIpEnumToStringEntityStatusNodeTypes{
		{ DoIpEntityStatus::NODE,    "DoIp node"    },
		{ DoIpEntityStatus::GATEWAY, "DoIP gateway" },
	};

	// This unordered map provides a human-readable description for the DoIP acknowledgement
	// code `ACK`, which is used to confirm the successful reception or processing of a message.
	static const std::unordered_map<DoIpDiagnosticAckCodes, std::string> DoIpEnumToStringAckCode{
		{ DoIpDiagnosticAckCodes::ACK, "ACK" },
	};

	// This unordered map provides a human-readable string for each synchronization status
	// defined in the `DoIpSyncStatus` enumeration. It is used to convert synchronization status
	// values to their respective descriptions for logging or display purposes.
	static const std::unordered_map<DoIpSyncStatus, std::string> DoIpEnumToStringSyncStatus{
		{ DoIpSyncStatus::VIN_AND_OR_GID_ARE_SINCHRONIZED,     "VIN and/or GID are synchronized"     },
		{ DoIpSyncStatus::RESERVED_ISO_0x01,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x02,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x03,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x04,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x05,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x06,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x07,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x08,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x09,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x0A,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x0B,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x0C,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x0D,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x0E,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::RESERVED_ISO_0x0F,                   "Reserved by ISO 13400"               },
		{ DoIpSyncStatus::VIN_AND_OR_GID_ARE_NOT_SINCHRONIZED, "VIN and/or GID are not synchronized" },
		{ DoIpSyncStatus::NON_INITIALIZED,                     "NULL"                                }
	};

	// This unordered map provides human-readable descriptions for each version of the
	// DoIP protocol as defined in ISO 13400. It maps the `DoIpProtocolVersion` enum values
	// to their corresponding descriptions.
	static const std::unordered_map<DoIpProtocolVersion, std::string> DoIpEnumToStringProtocolVersion{
		{ DoIpProtocolVersion::DefaultVersion,        "Default value for vehicle identification request messages" },
		{ DoIpProtocolVersion::Version01Iso2010,      "DoIP ISO/DIS 13400-2:2010"                                 },
		{ DoIpProtocolVersion::Version02Iso2012,      "DoIP ISO 13400-2:2012"                                     },
		{ DoIpProtocolVersion::Version03Iso2019,      "DoIP ISO 13400-2:2019"                                     },
		{ DoIpProtocolVersion::Version04Iso2019_AMD1, "DoIP ISO 13400-2:2012 AMD1"                                },
		{ DoIpProtocolVersion::ReservedVersion,       "Reserved"                                                  },
		{ DoIpProtocolVersion::UnknownVersion,        "Unknown Protocol Version"                                  }
	};

	// This unordered map provides human-readable descriptions for each payload type
	// defined in the DoIP protocol as per ISO 13400. It maps the `DoIpPayloadTypes` enum values
	// to their corresponding descriptions.
	static const std::unordered_map<DoIpPayloadTypes, std::string> DoIpEnumToStringPayloadType{
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

	DoIpLayer::DoIpLayer()
	{
		m_DataLen = sizeof(doiphdr);
		m_Protocol = DOIP;
		m_Data = new uint8_t[m_DataLen]{};
	}

	DoIpLayer::DoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet, DOIP)
	{}

	DoIpLayer* DoIpLayer::parseDoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		doiphdr* doipHeader = reinterpret_cast<doiphdr*>(data);
		uint16_t payloadType = doipHeader->payloadType;
		DoIpPayloadTypes detectedPayloadType = static_cast<DoIpPayloadTypes>(htobe16(payloadType));

		switch (detectedPayloadType)
		{
		case DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST:
			return new RoutingActivationRequest(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE:
			return new RoutingActivationResponse(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK:
			return new GenericHeaderNack(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID:
			return new VehicleIdentificationRequestEID(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN:
			return new VehicleIdentificationRequestVIN(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE:
			return new VehicleAnnouncement(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::ALIVE_CHECK_RESPONSE:
			return new AliveCheckResponse(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE:
			return new DiagnosticPowerModeResponse(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::ENTITY_STATUS_RESPONSE:
			return new EntityStatusResponse(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE:
			return new DiagnosticMessage(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK:
			return new DiagnosticAckMessage(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK:
			return new DiagnosticNackMessage(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST:
			return new VehicleIdentificationRequest(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::ALIVE_CHECK_REQUEST:
			return new AliveCheckRequest(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST:
			return new DiagnosticPowerModeRequest(data, dataLen, prevLayer, packet);
		case DoIpPayloadTypes::ENTITY_STATUS_REQUEST:
			return new EntityStatusRequest(data, dataLen, prevLayer, packet);
		default:
			return nullptr;
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

	void DoIpLayer::setPayloadType(DoIpPayloadTypes type)
	{
		getDoIpHeader()->payloadType = htobe16(static_cast<uint16_t>(type));
	}

	std::string DoIpLayer::getPayloadTypeAsStr() const
	{
		auto it =
		    DoIpEnumToStringPayloadType.find(static_cast<DoIpPayloadTypes>(be16toh(getDoIpHeader()->payloadType)));
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

	std::string DoIpLayer::toString() const
	{
		std::ostringstream oss;
		DoIpPayloadTypes type = getPayloadType();

		oss << "DoIP Layer, " << getPayloadTypeAsStr() << " (0x" << std::hex << std::setw(4) << std::setfill('0')
		    << (type == DoIpPayloadTypes::UNKNOWN_PAYLOAD_TYPE ? (be16toh(getDoIpHeader()->payloadType))
		                                                       : static_cast<uint16_t>(type))
		    << ")";

		return oss.str();
	}

	void DoIpLayer::setHeaderFields(DoIpProtocolVersion version, DoIpPayloadTypes type, uint32_t length)
	{
		setProtocolVersion(version);
		setInvertProtocolVersion(~(static_cast<uint8_t>(version)));
		setPayloadType(type);
		setPayloadLength(length);
	}

	void DoIpLayer::parseNextLayer()
	{
		if (getPayloadType() == DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE)
		{
			constexpr size_t headerLen = sizeof(doiphdr);

			if (m_DataLen <= headerLen + 2 /*source address size*/ + 2 /*target address size*/)
				return;

			uint8_t* payload = m_Data + (headerLen + 2 + 2);
			size_t payloadLen = m_DataLen - (headerLen + 2 + 2);
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		}
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// RoutingActivationRequest |
	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	RoutingActivationRequest::RoutingActivationRequest(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		constexpr size_t headerLength = sizeof(doiphdr);

		if (dataLen < (headerLength + FIXED_LEN) || dataLen > (headerLength + OPT_LEN))
		{
			throw std::runtime_error("RoutingActivationRequest: Invalid payload length");
		}
		if (dataLen > (headerLength + FIXED_LEN) && dataLen < (headerLength + OPT_LEN))
		{
			throw std::runtime_error("RoutingActivationRequest: Invalid OEM field length");
		}

		uint8_t* dataPtr = getDataPtr(headerLength);

		memcpy(&_sourceAddress, dataPtr, sizeof(_sourceAddress));
		dataPtr += sizeof(_sourceAddress);

		_activationType = static_cast<DoIpActivationTypes>(*dataPtr);
		dataPtr += sizeof(_activationType);

		memcpy(dataPtr, &_reservedIso, DOIP_RESERVED_ISO_LEN);
		dataPtr += DOIP_RESERVED_ISO_LEN;

		if (dataLen - (RESERVED_OEM_OFFSET) == DOIP_RESERVED_OEM_LEN)
		{
			memcpy(dataPtr, &_reservedOem, DOIP_RESERVED_OEM_LEN);
			_hasReservedOem = true;
		}
		else
		{
			PCPP_LOG_DEBUG("Reserved OEM field is empty !");
			_hasReservedOem = false;
		}
	}

	RoutingActivationRequest::RoutingActivationRequest(uint16_t sourrceAddress, DoIpActivationTypes activationType)
	    : _reservedIso{}, _hasReservedOem(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN);
		extendLayer(sizeof(doiphdr), FIXED_LEN);
		setSourceAddress(sourrceAddress);
		setActivationType(activationType);
	}

	DoIpActivationTypes RoutingActivationRequest::getActivationType() const
	{
		return _activationType;
	}

	void RoutingActivationRequest::setActivationType(const DoIpActivationTypes& activationType)
	{
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr) + sizeof(_sourceAddress));
		memcpy(dataPtr, &activationType, sizeof(activationType));
		_activationType = activationType;
	}

	uint16_t RoutingActivationRequest::getSourceAddress() const
	{
		return htobe16(_sourceAddress);
	}

	void RoutingActivationRequest::setSourceAddress(uint16_t sourceAddress)
	{
		_sourceAddress = htobe16(sourceAddress);
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr));
		memcpy(dataPtr, &_sourceAddress, sizeof(_sourceAddress));
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> RoutingActivationRequest::getReservedIso() const
	{
		return _reservedIso;
	}

	void RoutingActivationRequest::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		_reservedIso = reservedIso;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr) + sizeof(_sourceAddress) + sizeof(_activationType));
		memcpy(dataPtr, &_reservedIso, DOIP_RESERVED_ISO_LEN);
	}

	bool RoutingActivationRequest::hasReservedOem() const
	{
		return _hasReservedOem;
	}

	const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>* RoutingActivationRequest::getReservedOem() const
	{
		return _hasReservedOem ? &_reservedOem : nullptr;
	}

	void RoutingActivationRequest::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		_reservedOem = reservedOem;
		if (!_hasReservedOem)
		{
			extendLayer(RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN);
		memcpy(getDataPtr(RESERVED_OEM_OFFSET), &reservedOem, sizeof(_reservedOem));
		_hasReservedOem = true;
	}

	void RoutingActivationRequest::clearReserveOem()
	{
		if (getDataLen() == sizeof(doiphdr) + OPT_LEN)
		{
			shortenLayer(RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
			_hasReservedOem = false;
			PCPP_LOG_INFO("Reserved OEM field has been removed successfully!");
		}
		if (getDataLen() == RESERVED_OEM_OFFSET)
		{
			PCPP_LOG_DEBUG("doip packet has no reserved OEM field!");
		}
	}
	std::string RoutingActivationRequest::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		auto it = DoIpEnumToStringActivationTypes.find(_activationType);
		if (it != DoIpEnumToStringActivationTypes.end())
		{
			oss << "Activation type: " << it->second << std::hex << " (0x" << unsigned(_activationType) << ")\n";
		}
		else
		{
			oss << "Activation type: Unknown" << std::hex << " (0x" << unsigned(_activationType) << ")\n";
		}
		oss << "Reserved by ISO: " << pcpp::byteArrayToHexString(_reservedIso.data(), DOIP_RESERVED_ISO_LEN) << "\n";
		if (_hasReservedOem)
		{
			oss << "Reserved by OEM: " << pcpp::byteArrayToHexString(_reservedOem.data(), DOIP_RESERVED_OEM_LEN)
			    << '\n';
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// RoutingActivationResponse |
	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	RoutingActivationResponse::RoutingActivationResponse(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                     Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		constexpr size_t headerLength = sizeof(doiphdr);
		if (dataLen < headerLength + FIXED_LEN || dataLen > headerLength + OPT_LEN)
		{
			throw std::runtime_error("RoutingActivationResponse: Invalid payload length!");
		}

		if (dataLen > (headerLength + FIXED_LEN) && dataLen < (headerLength + OPT_LEN))
		{
			throw std::runtime_error("RoutingActivationRequest: invalid OEM field length");
		}

		const uint8_t* dataPtr = getDataPtr(sizeof(doiphdr));

		memcpy(&_logicalAddressExternalTester, dataPtr, sizeof(_logicalAddressExternalTester));
		dataPtr += sizeof(_logicalAddressExternalTester);

		memcpy(&_sourceAddress, dataPtr, sizeof(_sourceAddress));
		dataPtr += sizeof(_sourceAddress);

		_responseCode = static_cast<DoIpRoutingResponseCodes>(*dataPtr++);
		memcpy(&_reservedIso, dataPtr, DOIP_RESERVED_ISO_LEN);
		dataPtr += DOIP_RESERVED_ISO_LEN;

		if (dataLen - (RESERVED_OEM_OFFSET) == DOIP_RESERVED_OEM_LEN)
		{
			memcpy(&_reservedOem, dataPtr, DOIP_RESERVED_OEM_LEN);
			_hasReservedOem = true;
		}
		else
		{
			PCPP_LOG_DEBUG("Reserved OEM field is empty !");
			_hasReservedOem = false;
		}
	}
	RoutingActivationResponse::RoutingActivationResponse(uint16_t logicalAddressExternalTester, uint16_t sourceAddress,
	                                                     DoIpRoutingResponseCodes responseCode)
	    : _reservedIso{}, _reservedOem{}, _hasReservedOem(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN);
		extendLayer(sizeof(doiphdr), FIXED_LEN);

		setLogicalAddressExternalTester(logicalAddressExternalTester);
		setSourceAddress(sourceAddress);
		setResponseCode(responseCode);
	}

	uint16_t RoutingActivationResponse::getLogicalAddressExternalTester() const
	{
		return htobe16(_logicalAddressExternalTester);
	}
	void RoutingActivationResponse::setLogicalAddressExternalTester(uint16_t addr)
	{
		_logicalAddressExternalTester = htobe16(addr);
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr));
		memcpy(dataPtr, &_logicalAddressExternalTester, sizeof(_logicalAddressExternalTester));
	}

	uint16_t RoutingActivationResponse::getSourceAddress() const
	{
		return htobe16(_sourceAddress);
	}
	void RoutingActivationResponse::setSourceAddress(uint16_t sourceAddress)
	{
		_sourceAddress = htobe16(sourceAddress);
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr) + sizeof(_logicalAddressExternalTester));
		memcpy(dataPtr, &_sourceAddress, sizeof(_sourceAddress));
	}

	DoIpRoutingResponseCodes RoutingActivationResponse::getResponseCode() const
	{
		return _responseCode;
	}

	void RoutingActivationResponse::setResponseCode(DoIpRoutingResponseCodes code)
	{
		_responseCode = code;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr) + sizeof(_logicalAddressExternalTester) + sizeof(_sourceAddress));
		*dataPtr = static_cast<uint8_t>(code);
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> RoutingActivationResponse::getReservedIso() const
	{
		return _reservedIso;
	}
	void RoutingActivationResponse::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		_reservedIso = reservedIso;
		uint8_t* dataPtr = getDataPtr(RESERVED_OEM_OFFSET - DOIP_RESERVED_ISO_LEN);
		memcpy(dataPtr, &_reservedIso, sizeof(reservedIso));
	}

	bool RoutingActivationResponse::hasReservedOem() const
	{
		return _hasReservedOem;
	}

	const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>* RoutingActivationResponse::getReservedOem() const
	{
		return _hasReservedOem ? &_reservedOem : nullptr;
	}

	void RoutingActivationResponse::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		_reservedOem = reservedOem;
		if (!_hasReservedOem)
		{
			extendLayer(RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN);
		memcpy(getDataPtr(RESERVED_OEM_OFFSET), &_reservedOem, sizeof(_reservedOem));
		_hasReservedOem = true;
	}

	void RoutingActivationResponse::clearReservedOem()
	{
		if (getDataLen() == sizeof(doiphdr) + OPT_LEN)
		{
			shortenLayer(RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
			_hasReservedOem = false;
			PCPP_LOG_INFO("Reserved OEM field has been removed successfully!");
		}
		if (getDataLen() == RESERVED_OEM_OFFSET)
		{
			PCPP_LOG_DEBUG("doip packet has no reserved OEM field!");
		}
	}
	std::string RoutingActivationResponse::getSummary() const
	{
		std::ostringstream ss;
		ss << "Logical Address (Tester): 0x" << std::hex << htobe16(_logicalAddressExternalTester) << "\n";
		ss << "Source Address: 0x" << std::hex << htobe16(_sourceAddress) << "\n";
		auto it = DoIpEnumToStringRoutingResponseCodes.find(_responseCode);
		if (it != DoIpEnumToStringRoutingResponseCodes.end())
			ss << "Routing activation response code: " << it->second << " (0x" << std::hex << unsigned(_responseCode)
			   << ")\n";
		else
			ss << "Response Code: Unknown (0x" << std::hex << unsigned(_responseCode) << ")\n";

		ss << "Reserved by ISO: " << pcpp::byteArrayToHexString(_reservedIso.data(), DOIP_RESERVED_ISO_LEN) << "\n";
		if (_hasReservedOem)
			ss << "Reserved by OEM: " << pcpp::byteArrayToHexString(_reservedOem.data(), DOIP_RESERVED_OEM_LEN) << "\n";

		return ss.str();
	}

	//~~~~~~~~~~~~~~~~~~~|
	// GenericHeaderNack |
	//~~~~~~~~~~~~~~~~~~~|
	GenericHeaderNack::GenericHeaderNack(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen != (sizeof(doiphdr) + sizeof(_nackCode)))
			throw std::runtime_error("GenericHeaderNack: Invalid payload length!");

		_nackCode = static_cast<DoIpGenericHeaderNackCodes>(data[sizeof(doiphdr)]);
	}

	GenericHeaderNack::GenericHeaderNack(DoIpGenericHeaderNackCodes nackCode)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), sizeof(_nackCode));
		extendLayer(sizeof(doiphdr), sizeof(_nackCode));
		setNackCode(nackCode);
	}

	DoIpGenericHeaderNackCodes GenericHeaderNack::getNackCode() const
	{
		return _nackCode;
	}

	void GenericHeaderNack::setNackCode(DoIpGenericHeaderNackCodes nackCode)
	{
		_nackCode = nackCode;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr));
		*dataPtr = static_cast<uint8_t>(nackCode);
	}

	std::string GenericHeaderNack::getSummary() const
	{
		std::ostringstream ss;
		auto it = DoIpEnumToStringGenericHeaderNackCodes.find(_nackCode);
		if (it != DoIpEnumToStringGenericHeaderNackCodes.end())
		{
			ss << "Generic header nack code: " << it->second << " (0x" << std::hex << static_cast<int>(_nackCode)
			   << ")\n";
		}
		else
		{
			ss << "Generic header nack code: Unknown (0x" << std::hex << static_cast<int>(_nackCode) << ")\n";
		}
		return ss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// VehicleIdentificationRequestEID |
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	VehicleIdentificationRequestEID::VehicleIdentificationRequestEID(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                                 Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen != sizeof(doiphdr) + DOIP_EID_LEN)
			throw std::runtime_error("VehicleIdentificationRequestEID: Invalid payload length");

		memcpy(&_eid, data + sizeof(doiphdr), DOIP_EID_LEN);
	}

	VehicleIdentificationRequestEID::VehicleIdentificationRequestEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	    : _eid(eid)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_EID_LEN);
		extendLayer(sizeof(doiphdr), DOIP_EID_LEN);
		setEID(eid);
	}

	std::array<uint8_t, DOIP_EID_LEN> VehicleIdentificationRequestEID::getEID() const
	{
		return _eid;
	}

	void VehicleIdentificationRequestEID::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		_eid = eid;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr));
		memcpy(dataPtr, &_eid, DOIP_EID_LEN);
	}

	std::string VehicleIdentificationRequestEID::getSummary() const
	{
		std::ostringstream oss;
		oss << "EID: " << pcpp::byteArrayToHexString(_eid.data(), DOIP_EID_LEN) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// VehicleIdentificationRequestVIN |
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	VehicleIdentificationRequestVIN::VehicleIdentificationRequestVIN(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                                 Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen != sizeof(doiphdr) + DOIP_VIN_LEN)
			throw std::runtime_error("VehicleIdentificationRequestVIN: Invalid payload length");

		memcpy(&_vin, data + sizeof(doiphdr), DOIP_VIN_LEN);
	}

	VehicleIdentificationRequestVIN::VehicleIdentificationRequestVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_VIN_LEN);
		extendLayer(sizeof(doiphdr), DOIP_VIN_LEN);
		setVIN(vin);
	}

	std::array<uint8_t, DOIP_VIN_LEN> VehicleIdentificationRequestVIN::getVIN() const
	{
		return _vin;
	}

	void VehicleIdentificationRequestVIN::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		_vin = vin;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr));
		memcpy(dataPtr, &_vin, DOIP_VIN_LEN);
	}

	std::string VehicleIdentificationRequestVIN::getSummary() const
	{
		std::ostringstream oss;
		oss << "VIN: " << std::string(reinterpret_cast<const char*>(_vin.data()), _vin.size()) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~|
	// VehicleAnnouncement |
	//~~~~~~~~~~~~~~~~~~~~~|
	VehicleAnnouncement::VehicleAnnouncement(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		uint8_t* dataPtr = data + sizeof(doiphdr);

		if (dataLen < SYNC_STATUS_OFFSET || dataLen > sizeof(doiphdr) + OPT_LEN)
		{
			throw std::runtime_error("VehicleAnnouncement: invalid payload length!");
		}

		memcpy(&_vin, dataPtr, DOIP_VIN_LEN);
		dataPtr += DOIP_VIN_LEN;

		memcpy(&_logicalAddress, dataPtr, sizeof(_logicalAddress));
		dataPtr += sizeof(_logicalAddress);

		memcpy(&_eid, dataPtr, DOIP_EID_LEN);
		dataPtr += DOIP_EID_LEN;

		memcpy(&_gid, dataPtr, DOIP_GID_LEN);
		dataPtr += DOIP_GID_LEN;

		_actionCode = static_cast<DoIpActionCodes>(*(dataPtr++));

		if (dataLen - SYNC_STATUS_OFFSET == sizeof(_syncStatus))
		{
			_syncStatus = static_cast<DoIpSyncStatus>(*(dataPtr));
			_hasSyncStatus = true;
		}
		else
		{
			PCPP_LOG_INFO("Sync status field is empty!");
			_hasSyncStatus = false;
		}
	}

	VehicleAnnouncement::VehicleAnnouncement(const std::array<uint8_t, DOIP_VIN_LEN>& vin, uint16_t logicalAddress,
	                                         const std::array<uint8_t, DOIP_EID_LEN>& eid,
	                                         const std::array<uint8_t, DOIP_GID_LEN>& gid, DoIpActionCodes actionCode)

	    : _vin(vin), _logicalAddress(logicalAddress), _eid(eid), _gid(gid), _actionCode(actionCode),
	      _hasSyncStatus(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN);
		extendLayer(sizeof(doiphdr), FIXED_LEN);

		setVIN(vin);
		setLogicalAddress(logicalAddress);
		setEID(eid);
		setGID(gid);
		setFurtherActionRequired(actionCode);
	}
	std::array<uint8_t, DOIP_VIN_LEN> VehicleAnnouncement::getVIN() const
	{
		return _vin;
	}
	uint16_t VehicleAnnouncement::getLogicalAddress() const
	{
		return htobe16(_logicalAddress);
	}

	std::array<uint8_t, DOIP_EID_LEN> VehicleAnnouncement::getEID() const
	{
		return _eid;
	}
	std::array<uint8_t, DOIP_GID_LEN> VehicleAnnouncement::getGID() const
	{
		return _gid;
	}
	DoIpActionCodes VehicleAnnouncement::getFurtherActionRequired() const
	{
		return _actionCode;
	}
	const DoIpSyncStatus* VehicleAnnouncement::getSyncStatus() const
	{
		return _hasSyncStatus ? &_syncStatus : nullptr;
	}

	void VehicleAnnouncement::clearSyncStatus()
	{
		if (getDataLen() == sizeof(doiphdr) + OPT_LEN)
		{
			shortenLayer(FIXED_LEN, sizeof(_syncStatus));
			_hasSyncStatus = false;
			PCPP_LOG_INFO("Sync status has been removed successfully!");
		}
		if (getDataLen() == SYNC_STATUS_OFFSET)
		{
			PCPP_LOG_DEBUG("doip packet has no syncStatus!");
		}
	}
	void VehicleAnnouncement::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		_vin = vin;
		memcpy(getDataPtr(sizeof(doiphdr)), &_vin, DOIP_VIN_LEN);
	}

	void VehicleAnnouncement::setLogicalAddress(uint16_t logicalAddress)
	{
		_logicalAddress = htobe16(logicalAddress);
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr) + DOIP_VIN_LEN);
		memcpy(dataPtr, &_logicalAddress, sizeof(_logicalAddress));
	}

	void VehicleAnnouncement::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		_eid = eid;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr) + DOIP_VIN_LEN + sizeof(_logicalAddress));
		memcpy(dataPtr, &_eid, DOIP_EID_LEN);
	}

	void VehicleAnnouncement::setGID(const std::array<uint8_t, DOIP_GID_LEN>& gid)
	{
		_gid = gid;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr) + DOIP_VIN_LEN + sizeof(_logicalAddress) + DOIP_EID_LEN);
		memcpy(dataPtr, &_gid, DOIP_GID_LEN);
	}

	void VehicleAnnouncement::setFurtherActionRequired(DoIpActionCodes action)
	{
		_actionCode = action;
		uint8_t* dataPtr =
		    getDataPtr(sizeof(doiphdr) + DOIP_VIN_LEN + sizeof(_logicalAddress) + DOIP_EID_LEN + DOIP_GID_LEN);
		*dataPtr = static_cast<uint8_t>(action);
	}

	void VehicleAnnouncement::setSyncStatus(DoIpSyncStatus sync)
	{
		_syncStatus = sync;
		if (!_hasSyncStatus)
		{
			extendLayer(SYNC_STATUS_OFFSET, sizeof(_syncStatus));
		}
		setPayloadLength(OPT_LEN);
		*getDataPtr(SYNC_STATUS_OFFSET) = static_cast<uint8_t>(_syncStatus);
		_hasSyncStatus = true;
	}

	bool VehicleAnnouncement::hasSyncStatus() const
	{
		return _hasSyncStatus;
	}

	std::string VehicleAnnouncement::getSummary() const
	{
		std::ostringstream oss;

		oss << "VIN: " << std::string(reinterpret_cast<const char*>(_vin.data()), _vin.size()) << "\n";
		oss << "Logical address: " << std::hex << "0x" << htobe16(_logicalAddress) << "\n";
		oss << "EID: " << pcpp::byteArrayToHexString(_eid.data(), DOIP_EID_LEN) << "\n";
		oss << "GID: " << pcpp::byteArrayToHexString(_gid.data(), DOIP_GID_LEN) << "\n";
		auto it = DoIpEnumToStringActionCodes.find(_actionCode);
		if (it != DoIpEnumToStringActionCodes.end())
		{
			oss << "Further action required: " << it->second << std::hex << " (0x" << unsigned(_actionCode) << ")"
			    << "\n";
		}
		else
		{
			oss << "Further action required: Unknown" << std::hex << " (0x" << unsigned(_actionCode) << ")"
			    << "\n";
		}
		if (_hasSyncStatus)
		{
			auto it_ = DoIpEnumToStringSyncStatus.find(_syncStatus);
			if (it_ != DoIpEnumToStringSyncStatus.end())
			{
				oss << "VIN/GID sync status: " << it_->second << "\n";  // Convert enum to byte
			}
			else
			{
				oss << "VIN/GID sync status: Unknown" << std::hex << " (0x" << unsigned(_syncStatus) << ")" << "\n";
			}
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~|
	// AliveCheckResponse |
	//~~~~~~~~~~~~~~~~~~~~|
	AliveCheckResponse::AliveCheckResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen < sizeof(doiphdr) + sizeof(_sourceAddress))
			throw std::runtime_error("AliveCheckResponse: insufficient payload length");

		const uint8_t* dataPtr = data + sizeof(doiphdr);
		memcpy(&_sourceAddress, dataPtr, sizeof(_sourceAddress));
	}

	AliveCheckResponse::AliveCheckResponse(uint16_t sourceAddress)
	{
		const size_t payloadLen = sizeof(_sourceAddress);
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), payloadLen);
		extendLayer(sizeof(doiphdr), payloadLen);
		setSourceAddress(sourceAddress);
	}

	uint16_t AliveCheckResponse::getSourceAddress() const
	{
		return htobe16(_sourceAddress);
	}

	void AliveCheckResponse::setSourceAddress(uint16_t address)
	{
		_sourceAddress = htobe16(address);
		memcpy(getDataPtr(sizeof(doiphdr)), &_sourceAddress, sizeof(_sourceAddress));
	}

	std::string AliveCheckResponse::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DiagnosticPowerModeResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DiagnosticPowerModeResponse::DiagnosticPowerModeResponse(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                         Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		constexpr size_t payloadLen = sizeof(doiphdr) + sizeof(_powerModeCode);
		if (dataLen != payloadLen)
			throw std::runtime_error("DiagnosticPowerModeResponse: invalid payload length!");

		const uint8_t* payloadPtr = data + sizeof(doiphdr);
		_powerModeCode = static_cast<DoIpDiagnosticPowerModeCodes>(*payloadPtr);
	}

	DiagnosticPowerModeResponse::DiagnosticPowerModeResponse(DoIpDiagnosticPowerModeCodes code) : _powerModeCode(code)
	{
		const size_t payloadLen = sizeof(_powerModeCode);
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), payloadLen);
		extendLayer(sizeof(doiphdr), payloadLen);
		setPowerModeCode(code);
	}

	DoIpDiagnosticPowerModeCodes DiagnosticPowerModeResponse::getPowerModeCode() const
	{
		return _powerModeCode;
	}

	void DiagnosticPowerModeResponse::setPowerModeCode(DoIpDiagnosticPowerModeCodes code)
	{
		_powerModeCode = code;
		uint8_t* dataPtr = getDataPtr(sizeof(doiphdr));
		*dataPtr = static_cast<uint8_t>(code);
	}

	std::string DiagnosticPowerModeResponse::getSummary() const
	{
		std::ostringstream oss;
		auto it = DoIpEnumToStringDiagnosticPowerModeCodes.find(_powerModeCode);
		if (it != DoIpEnumToStringDiagnosticPowerModeCodes.end())
		{
			oss << "Diagnostic power mode: " << it->second << std::hex << " (0x" << unsigned(_powerModeCode) << ")\n";
		}
		else
		{
			oss << "Diagnostic power mode: Unknown" << std::hex << " (0x" << unsigned(_powerModeCode) << ")\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~|
	// EntityStatusResponse|
	//~~~~~~~~~~~~~~~~~~~~~|
	EntityStatusResponse::EntityStatusResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		constexpr size_t headerLength = sizeof(doiphdr);
		if (dataLen < headerLength + FIXED_LEN || dataLen > headerLength + OPT_LEN)
		{
			throw std::runtime_error("EntityStatusResponse: Invalid payload length!");
		}

		if (dataLen > (headerLength + FIXED_LEN) && dataLen < (headerLength + OPT_LEN))
		{
			throw std::runtime_error("EntityStatusResponse: Invalid MaxDataSize field length!");
		}

		const uint8_t* dataPtr = data + sizeof(doiphdr);
		_nodeType = static_cast<DoIpEntityStatus>(*dataPtr);
		dataPtr += sizeof(_nodeType);

		_maxConcurrentSockets = (*dataPtr);
		dataPtr += sizeof(_maxConcurrentSockets);

		_currentlyOpenSockets = (*dataPtr);
		dataPtr += sizeof(_currentlyOpenSockets);

		if (dataLen - (MAX_DATA_SIZE_OFFSET) == sizeof(_maxDataSize))
		{
			memcpy(&_maxDataSize, dataPtr, sizeof(_maxDataSize));
			_hasMaxDataSize = true;
		}
		else
		{
			PCPP_LOG_INFO("MaxDataSize field is empty !");
			_hasMaxDataSize = false;
		}
	}

	EntityStatusResponse::EntityStatusResponse(DoIpEntityStatus nodeType, uint8_t maxConcurrentSockets,
	                                           uint8_t currentlyOpenSockets)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN);
		extendLayer(sizeof(doiphdr), FIXED_LEN);

		setNodeType(nodeType);
		setMaxConcurrentSockets(maxConcurrentSockets);
		setCurrentlyOpenSockets(currentlyOpenSockets);
	}
	DoIpEntityStatus EntityStatusResponse::getNodeType() const
	{
		return _nodeType;
	}
	uint8_t EntityStatusResponse::getMaxConcurrentSockets() const
	{
		return _maxConcurrentSockets;
	}
	uint8_t EntityStatusResponse::getCurrentlyOpenSockets() const
	{
		return _currentlyOpenSockets;
	}
	const std::array<uint8_t, 4>* EntityStatusResponse::getMaxDataSize() const
	{
		return _hasMaxDataSize ? &_maxDataSize : nullptr;
	}
	void EntityStatusResponse::setNodeType(DoIpEntityStatus nodeType)
	{
		_nodeType = nodeType;
		getDataPtr(sizeof(doiphdr))[0] = static_cast<uint8_t>(nodeType);
	}
	bool EntityStatusResponse::hasMaxDataSize() const
	{
		return _hasMaxDataSize;
	}
	void EntityStatusResponse::clearMaxDataSize()
	{
		if (getDataLen() == sizeof(doiphdr) + OPT_LEN && _hasMaxDataSize)
		{
			shortenLayer(FIXED_LEN, sizeof(_maxDataSize));
			_hasMaxDataSize = false;
			PCPP_LOG_INFO("MaxDataSize has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no MaxDataSize field!");
		}
	}
	void EntityStatusResponse::setMaxConcurrentSockets(uint8_t sockets)
	{
		_maxConcurrentSockets = sockets;
		getDataPtr(sizeof(doiphdr))[1] = sockets;
	}

	void EntityStatusResponse::setCurrentlyOpenSockets(uint8_t sockets)
	{
		_currentlyOpenSockets = sockets;
		getDataPtr(sizeof(doiphdr))[2] = sockets;
	}

	void EntityStatusResponse::setMaxDataSize(const std::array<uint8_t, 4>& data)
	{
		_maxDataSize = data;
		if (!_hasMaxDataSize)
		{
			extendLayer(MAX_DATA_SIZE_OFFSET, sizeof(_maxDataSize));
		}
		memcpy(getDataPtr(MAX_DATA_SIZE_OFFSET), &_maxDataSize, sizeof(_maxDataSize));
		setPayloadLength(OPT_LEN);
		_hasMaxDataSize = true;
	}

	std::string EntityStatusResponse::getSummary() const
	{
		std::ostringstream oos;
		auto it = DoIpEnumToStringEntityStatusNodeTypes.find(_nodeType);
		if (it != DoIpEnumToStringEntityStatusNodeTypes.end())
		{
			oos << "Entity status: " << it->second << std::hex << " (0x" << unsigned(_nodeType) << ")" << "\n";
		}
		else
		{
			oos << "Node Type: Unknown" << std::hex << " (0x" << unsigned(_nodeType) << ")\n";
		}
		oos << "Max Concurrent Socket: " << unsigned(_maxConcurrentSockets) << "\n";
		oos << "Currently Opened Socket: " << unsigned(_currentlyOpenSockets) << "\n";
		if (_hasMaxDataSize)
		{
			oos << "Max Data Size: "
			    << "0x" << pcpp::byteArrayToHexString(_maxDataSize.data(), 4) << "\n";
		}
		return oos.str();
	}

	//~~~~~~~~~~~~~~~~~~|
	// DiagnosticMessage|
	//~~~~~~~~~~~~~~~~~~|
	DiagnosticMessage::DiagnosticMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen <
		    sizeof(doiphdr) + sizeof(_sourceAddress) + sizeof(_targetAddress) + 1 /*Minimum diag payload len*/)
			throw std::runtime_error("DiagnosticMessage: insufficient payload");

		const uint8_t* dataPtr = data + sizeof(doiphdr);
		memcpy(&_sourceAddress, dataPtr, sizeof(_sourceAddress));
		dataPtr += (sizeof(_sourceAddress));
		memcpy(&_targetAddress, dataPtr, sizeof(_targetAddress));
		dataPtr += (sizeof(_targetAddress));

		_diagnosticData.assign(
		    dataPtr, dataPtr + (dataLen - (sizeof(doiphdr) + sizeof(_sourceAddress) + sizeof(_targetAddress))));
	}

	DiagnosticMessage::DiagnosticMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                     const std::vector<uint8_t>& diagData)
	{
		size_t payloadLen = sizeof(_sourceAddress) + sizeof(_targetAddress) + _diagnosticData.size();
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), payloadLen);
		extendLayer(sizeof(doiphdr), payloadLen);
		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
		setDiagnosticData(diagData);
	}

	uint16_t DiagnosticMessage::getSourceAddress() const
	{
		return htobe16(_sourceAddress);
	}
	uint16_t DiagnosticMessage::getTargetAddress() const
	{
		return htobe16(_targetAddress);
	}
	const std::vector<uint8_t>& DiagnosticMessage::getDiagnosticData() const
	{
		return _diagnosticData;
	}

	void DiagnosticMessage::setSourceAddress(uint16_t address)
	{
		_sourceAddress = htobe16(address);
		memcpy(getDataPtr(sizeof(doiphdr)), &_sourceAddress, sizeof(_sourceAddress));
	}

	void DiagnosticMessage::setTargetAddress(uint16_t targetAddress)
	{
		_targetAddress = htobe16(targetAddress);
		memcpy(getDataPtr(sizeof(doiphdr) + sizeof(_sourceAddress)), &_targetAddress, sizeof(_targetAddress));
	}

	void DiagnosticMessage::setDiagnosticData(const std::vector<uint8_t>& data)
	{
		constexpr size_t fixedLen = sizeof(doiphdr) + sizeof(_sourceAddress) + sizeof(_targetAddress);
		const size_t newPayloadlLength = sizeof(_sourceAddress) + sizeof(_targetAddress) + data.size();
		uint8_t* dataPtr = getDataPtr(fixedLen);
		setPayloadLength(newPayloadlLength);
		// always clear the current diagnostic data and extendLayer with the new provided data
		if (_diagnosticData.size() > 0)
		{
			shortenLayer(fixedLen, _diagnosticData.size());
		}
		extendLayer(fixedLen, data.size());
		memcpy(dataPtr, data.data(), data.size());
		_diagnosticData = data;
	}

	std::string DiagnosticMessage::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		oss << "Target Address: " << std::hex << "0x" << getTargetAddress() << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~|
	// DiagnosticAckMessage|
	//~~~~~~~~~~~~~~~~~~~~~|
	DiagnosticAckMessage::DiagnosticAckMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen < PREVIOUS_MSG_OFFSET)
			throw std::runtime_error("DiagnosticAckMessage: Invalid payload length");

		const uint8_t* ptr = data + sizeof(doiphdr);
		memcpy(&_sourceAddress, ptr, sizeof(_sourceAddress));
		ptr += sizeof(_sourceAddress);

		memcpy(&_targetAddress, ptr, sizeof(_targetAddress));
		ptr += sizeof(_targetAddress);

		_ackCode = static_cast<DoIpDiagnosticAckCodes>(*ptr++);

		const size_t remainingData = dataLen - (PREVIOUS_MSG_OFFSET);
		if (remainingData > 0)
		{
			_previousMessage.assign(ptr, ptr + remainingData);
			_hasPreviousMessage = true;
		}
		else
		{
			PCPP_LOG_INFO("PreviousMessage field is empty!");
			_hasPreviousMessage = false;
		}
	}

	DiagnosticAckMessage::DiagnosticAckMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                           DoIpDiagnosticAckCodes ackCode)
	    : _hasPreviousMessage(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN);
		extendLayer(sizeof(doiphdr), FIXED_LEN);

		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
		setAckCode(ackCode);
	}

	uint16_t DiagnosticAckMessage::getSourceAddress() const
	{
		return htobe16(_sourceAddress);
	}
	uint16_t DiagnosticAckMessage::getTargetAddress() const
	{
		return htobe16(_targetAddress);
	}
	DoIpDiagnosticAckCodes DiagnosticAckMessage::getAckCode() const
	{
		return _ackCode;
	}
	const std::vector<uint8_t>* DiagnosticAckMessage::getPreviousMessage() const
	{
		return _hasPreviousMessage ? &_previousMessage : nullptr;
	}

	// Setter implementations.
	void DiagnosticAckMessage::setSourceAddress(uint16_t address)
	{
		_sourceAddress = htobe16(address);
		// Write sourceAddress into payload at offset 0 (immediately after doiphdr)
		memcpy(getDataPtr(sizeof(doiphdr)), &_sourceAddress, sizeof(_sourceAddress));
	}

	void DiagnosticAckMessage::setTargetAddress(uint16_t address)
	{
		_targetAddress = htobe16(address);
		memcpy(getDataPtr(sizeof(doiphdr) + sizeof(_sourceAddress)), &_targetAddress, sizeof(_targetAddress));
	}

	void DiagnosticAckMessage::setAckCode(DoIpDiagnosticAckCodes code)
	{
		_ackCode = code;
		uint8_t* ptr = getDataPtr(sizeof(doiphdr) + sizeof(_sourceAddress) + sizeof(_targetAddress));
		*ptr = static_cast<uint8_t>(code);
	}

	bool DiagnosticAckMessage::hasPreviousMessage()
	{
		return _hasPreviousMessage;
	}

	void DiagnosticAckMessage::setPreviousMessage(const std::vector<uint8_t>& msg)
	{

		size_t newPayloadLen = FIXED_LEN + msg.size();
		// clear memory for old previous message
		if (_hasPreviousMessage)
		{
			shortenLayer(PREVIOUS_MSG_OFFSET, _previousMessage.size());
		}
		setPayloadLength(newPayloadLen);
		extendLayer(PREVIOUS_MSG_OFFSET, msg.size());
		uint8_t* ptr = getDataPtr(PREVIOUS_MSG_OFFSET);
		memcpy(ptr, msg.data(), msg.size());
		_previousMessage = msg;
		_hasPreviousMessage = true;
	}

	void DiagnosticAckMessage::clearPreviousMessage()
	{
		if (_hasPreviousMessage)
		{
			shortenLayer(FIXED_LEN, sizeof(_previousMessage));
			_hasPreviousMessage = false;
			PCPP_LOG_INFO("PreviousMessage has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no PreviousMessage field!");
		}
	}
	// Summary method.
	std::string DiagnosticAckMessage::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		oss << "Target Address: " << std::hex << "0x" << getTargetAddress() << "\n";
		auto it = DoIpEnumToStringAckCode.find(_ackCode);
		if (it != DoIpEnumToStringAckCode.end())
		{
			oss << "ACK code: " << it->second << " (0x" << unsigned(_ackCode) << ")\n";
		}
		else
		{
			oss << "ACK code: Unknown" << std::hex << " (0x" << unsigned(_ackCode) << ")\n";
		}
		if (_hasPreviousMessage)
		{
			oss << "Previous message: " << pcpp::byteArrayToHexString(_previousMessage.data(), _previousMessage.size())
			    << "\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DiagnosticNackMessage|
	//~~~~~~~~~~~~~~~~~~~~~~|
	DiagnosticNackMessage::DiagnosticNackMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen < PREVIOUS_MSG_OFFSET)
			throw std::runtime_error("DiagnosticNackMessage: Invalid payload length");

		const uint8_t* ptr = data + sizeof(doiphdr);
		memcpy(&_sourceAddress, ptr, sizeof(_sourceAddress));
		ptr += sizeof(_sourceAddress);

		memcpy(&_targetAddress, ptr, sizeof(_targetAddress));
		ptr += sizeof(_targetAddress);

		_nackCode = static_cast<DoIpDiagnosticMessageNackCodes>(*ptr++);

		const size_t remainingData = dataLen - (PREVIOUS_MSG_OFFSET);
		if (remainingData > 0)
		{
			_previousMessage.assign(ptr, ptr + remainingData);
			_hasPreviousMessage = true;
		}
		else
		{
			PCPP_LOG_INFO("PreviousMessage field is empty!");
			_hasPreviousMessage = false;
		}
	}

	DiagnosticNackMessage::DiagnosticNackMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                             DoIpDiagnosticMessageNackCodes nackCode)
	    : _hasPreviousMessage(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN);
		extendLayer(sizeof(doiphdr), FIXED_LEN);

		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
		setNackCode(nackCode);
	}

	uint16_t DiagnosticNackMessage::getSourceAddress() const
	{
		return htobe16(_sourceAddress);
	}
	uint16_t DiagnosticNackMessage::getTargetAddress() const
	{
		return htobe16(_targetAddress);
	}
	DoIpDiagnosticMessageNackCodes DiagnosticNackMessage::getNackCode() const
	{
		return _nackCode;
	}
	const std::vector<uint8_t>* DiagnosticNackMessage::getPreviousMessage() const
	{
		return _hasPreviousMessage ? &_previousMessage : nullptr;
	}
	bool DiagnosticNackMessage::hasPreviousMessage() const
	{
		return _hasPreviousMessage;
	}

	void DiagnosticNackMessage::setSourceAddress(uint16_t address)
	{
		_sourceAddress = htobe16(address);
		memcpy(getDataPtr(sizeof(doiphdr)), &_sourceAddress, sizeof(_sourceAddress));
	}

	void DiagnosticNackMessage::setTargetAddress(uint16_t address)
	{
		_targetAddress = htobe16(address);
		memcpy(getDataPtr(sizeof(doiphdr) + sizeof(_sourceAddress)), &_targetAddress, sizeof(_targetAddress));
	}

	void DiagnosticNackMessage::setNackCode(DoIpDiagnosticMessageNackCodes code)
	{
		_nackCode = code;
		uint8_t* ptr = getDataPtr(sizeof(doiphdr) + sizeof(_sourceAddress) + sizeof(_targetAddress));
		*ptr = static_cast<uint8_t>(code);
	}

	void DiagnosticNackMessage::setPreviousMessage(const std::vector<uint8_t>& msg)
	{
		const size_t newPayloadLen = FIXED_LEN + msg.size();

		if (_hasPreviousMessage)
		{
			shortenLayer(PREVIOUS_MSG_OFFSET, _previousMessage.size());
		}

		setPayloadLength(newPayloadLen);
		extendLayer(PREVIOUS_MSG_OFFSET, msg.size());

		uint8_t* dataPtr = getDataPtr(PREVIOUS_MSG_OFFSET);
		memcpy(dataPtr, msg.data(), msg.size());

		_previousMessage = msg;
		_hasPreviousMessage = true;
	}

	void DiagnosticNackMessage::clearPreviousMessage()
	{
		if (_hasPreviousMessage)
		{
			shortenLayer(PREVIOUS_MSG_OFFSET, _previousMessage.size());
			_hasPreviousMessage = false;
			PCPP_LOG_INFO("PreviousMessage has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no PreviousMessage field!");
		}
	}

	std::string DiagnosticNackMessage::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";
		oss << "Target Address: 0x" << std::hex << getTargetAddress() << "\n";

		auto it = DoIpEnumToStringDiagnosticNackCodes.find(_nackCode);
		if (it != DoIpEnumToStringDiagnosticNackCodes.end())
		{
			oss << "NACK code: " << it->second << " (0x" << unsigned(_nackCode) << ")\n";
		}
		else
		{
			oss << "NACK code: Unknown (0x" << unsigned(_nackCode) << ")\n";
		}

		if (_hasPreviousMessage)
		{
			oss << "Previous message: " << pcpp::byteArrayToHexString(_previousMessage.data(), _previousMessage.size())
			    << "\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~|
	// AliveCheckRequest|
	//~~~~~~~~~~~~~~~~~~|
	AliveCheckRequest::AliveCheckRequest()
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// VehicleIdentificationRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	VehicleIdentificationRequest::VehicleIdentificationRequest()
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DiagnosticPowerModeRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DiagnosticPowerModeRequest::DiagnosticPowerModeRequest()
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~|
	// EntityStatusRequest|
	//~~~~~~~~~~~~~~~~~~~~|
	EntityStatusRequest::EntityStatusRequest()
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}
}  // namespace pcpp
