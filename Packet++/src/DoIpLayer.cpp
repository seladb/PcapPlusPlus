#define LOG_MODULE PacketLogModuleDoIpLayer

#include <unordered_map>
#include <sstream>
#include <iomanip>
#include "DoIpLayer.h"
#include "GeneralUtils.h"
#include "PayloadLayer.h"

namespace pcpp
{

	// This unordered map provides human-readable descriptions for each activation type
	// defined in the DoIP protocol as per ISO 13400. It maps the `DoIpActivationTypes` enum values
	// to their corresponding descriptions.
	static const std::unordered_map<DoIpActivationTypes, std::string> DoIpEnumToStringActivationTypes{
		{ DoIpActivationTypes::DEFAULT,          "Default"          },
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
	static const std::unordered_map<DoIpEntityStatusResponse, std::string> DoIpEnumToStringEntityStatusNodeTypes{
		{ DoIpEntityStatusResponse::NODE,    "DoIp node"    },
		{ DoIpEntityStatusResponse::GATEWAY, "DoIP gateway" },
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
		{ DoIpSyncStatus::VIN_AND_OR_GID_ARE_NOT_SINCHRONIZED, "VIN and/or GID are not synchronized" }
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
		{ DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK,              "Diagnostic message Nack"                    }
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
		m_DataLen = DOIP_HEADER_LEN;
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

	void DoIpLayer::setProtocolVersion(uint8_t version)
	{
		getDoIpHeader()->protocolVersion = version;
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
		auto it = DoIpEnumToStringPayloadType.find(getPayloadType());
		return it->second;
	}

	uint32_t DoIpLayer::getPayloadLength() const
	{
		return htobe32(getDoIpHeader()->payloadLength);
	}

	void DoIpLayer::setPayloadLength(uint32_t payloadLength)
	{
		getDoIpHeader()->payloadLength = be32toh(payloadLength);
	}

	std::string DoIpLayer::toString() const
	{
		std::ostringstream oss;
		DoIpPayloadTypes type = getPayloadType();

		oss << "DoIP Layer, " << getPayloadTypeAsStr() << " (0x" << std::hex << std::setw(4) << std::setfill('0')
		    << static_cast<uint16_t>(type) << ")";

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
			if (m_DataLen <= DOIP_HEADER_LEN + 2 /*source address size*/ + 2 /*target address size*/)
				return;

			uint8_t* payload = m_Data + (DOIP_HEADER_LEN + 2 + 2);
			size_t payloadLen = m_DataLen - (DOIP_HEADER_LEN + 2 + 2);
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		}
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	// RoutingActivationRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	RoutingActivationRequest::RoutingActivationRequest(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen < FIXED_LEN || dataLen > OPT_LEN)
			throw std::runtime_error("RoutingActivationRequest: Invalid payload length!");

		if (dataLen > FIXED_LEN && dataLen < OPT_LEN)
			throw std::runtime_error("RoutingActivationRequest: Invalid OEM field length!");

		if (dataLen == OPT_LEN)
		{
			_hasReservedOem = true;
		}
		else
		{
			_hasReservedOem = false;
			PCPP_LOG_DEBUG("Reserved OEM field is empty!");
		}
	}

	RoutingActivationRequest::RoutingActivationRequest(uint16_t sourceAddress, DoIpActivationTypes activationType)
	    : _hasReservedOem(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);
		extendLayer(DOIP_HEADER_LEN, FIXED_LEN - DOIP_HEADER_LEN);

		auto* payload = getRoutingRequest();
		payload->sourceAddress = htobe16(sourceAddress);
		payload->activationType = activationType;
		// Reserved ISO is always all zeros
		payload->reservedIso.fill(0);
	}

	uint16_t RoutingActivationRequest::getSourceAddress() const
	{
		return be16toh(getRoutingRequest()->sourceAddress);
	}

	void RoutingActivationRequest::setSourceAddress(uint16_t value)
	{
		getRoutingRequest()->sourceAddress = htobe16(value);
	}

	DoIpActivationTypes RoutingActivationRequest::getActivationType() const
	{
		return getRoutingRequest()->activationType;
	}

	void RoutingActivationRequest::setActivationType(DoIpActivationTypes activationType)
	{
		getRoutingRequest()->activationType = activationType;
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> RoutingActivationRequest::getReservedIso() const
	{
		return getRoutingRequest()->reservedIso;
	}

	void RoutingActivationRequest::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		getRoutingRequest()->reservedIso = reservedIso;
	}

	bool RoutingActivationRequest::hasReservedOem() const
	{
		return _hasReservedOem;
	}

	const uint8_t* RoutingActivationRequest::getReservedOem() const
	{
		return _hasReservedOem ? (m_Data + FIXED_LEN) : nullptr;
	}

	void RoutingActivationRequest::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		if (!_hasReservedOem)
		{
			extendLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		memcpy((m_Data + FIXED_LEN), reservedOem.data(), DOIP_RESERVED_OEM_LEN);
		_hasReservedOem = true;
	}

	void RoutingActivationRequest::clearReservedOem()
	{
		if (m_DataLen == OPT_LEN)
		{
			shortenLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
			_hasReservedOem = false;
			PCPP_LOG_INFO("Reserved OEM field has been removed successfully!");
		}
		else if (m_DataLen == FIXED_LEN)
		{
			PCPP_LOG_DEBUG("DoIP packet has no reserved OEM field!");
		}
	}
	std::string RoutingActivationRequest::getSummary() const
	{
		std::ostringstream oss;
		DoIpActivationTypes type = getActivationType();
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		auto it = DoIpEnumToStringActivationTypes.find(type);
		if (it != DoIpEnumToStringActivationTypes.end())
		{
			oss << "Activation type: " << it->second << std::hex << " (0x" << unsigned(type) << ")\n";
		}
		else
		{
			oss << "Activation type: Unknown" << std::hex << " (0x" << unsigned(type) << ")\n";
		}
		oss << "Reserved by ISO: " << pcpp::byteArrayToHexString(getReservedIso().data(), DOIP_RESERVED_ISO_LEN)
		    << "\n";
		if (_hasReservedOem)
		{
			oss << "Reserved by OEM: " << pcpp::byteArrayToHexString(getReservedOem(), DOIP_RESERVED_OEM_LEN) << '\n';
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// RoutingActivationResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	RoutingActivationResponse::RoutingActivationResponse(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                     Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen < FIXED_LEN || dataLen > OPT_LEN)
		{
			throw std::runtime_error("RoutingActivationResponse: Invalid payload length!");
		}

		if (dataLen > FIXED_LEN && dataLen < OPT_LEN)
		{
			throw std::runtime_error("RoutingActivationResponse: invalid OEM field length");
		}

		// Optional OEM part
		if (dataLen == OPT_LEN)
		{
			_hasReservedOem = true;
		}
		else
		{
			_hasReservedOem = false;
			PCPP_LOG_DEBUG("Reserved OEM field is empty!");
		}
	}

	RoutingActivationResponse::RoutingActivationResponse(uint16_t logicalAddressExternalTester, uint16_t sourceAddress,
	                                                     DoIpRoutingResponseCodes responseCode)
	    : _hasReservedOem(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));
		extendLayer(DOIP_HEADER_LEN, (FIXED_LEN - DOIP_HEADER_LEN));

		auto* payload = getRoutingResponse();
		payload->logicalAddressExternalTester = htobe16(logicalAddressExternalTester);
		payload->sourceAddress = htobe16(sourceAddress);
		payload->responseCode = responseCode;
		payload->reservedIso.fill(0);
	}

	uint16_t RoutingActivationResponse::getLogicalAddressExternalTester() const
	{
		return htobe16(getRoutingResponse()->logicalAddressExternalTester);
	}

	void RoutingActivationResponse::setLogicalAddressExternalTester(uint16_t addr)
	{
		getRoutingResponse()->logicalAddressExternalTester = htobe16(addr);
	}

	uint16_t RoutingActivationResponse::getSourceAddress() const
	{
		return htobe16(getRoutingResponse()->sourceAddress);
	}

	void RoutingActivationResponse::setSourceAddress(uint16_t sourceAddress)
	{
		getRoutingResponse()->sourceAddress = htobe16(sourceAddress);
	}

	DoIpRoutingResponseCodes RoutingActivationResponse::getResponseCode() const
	{
		return getRoutingResponse()->responseCode;
	}

	void RoutingActivationResponse::setResponseCode(DoIpRoutingResponseCodes code)
	{
		getRoutingResponse()->responseCode = code;
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> RoutingActivationResponse::getReservedIso() const
	{
		return getRoutingResponse()->reservedIso;
	}

	void RoutingActivationResponse::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		getRoutingResponse()->reservedIso = reservedIso;
	}

	bool RoutingActivationResponse::hasReservedOem() const
	{
		return _hasReservedOem;
	}

	const uint8_t* RoutingActivationResponse::getReservedOem() const
	{
		return _hasReservedOem ? (m_Data + FIXED_LEN) : nullptr;
	}

	void RoutingActivationResponse::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		if (!_hasReservedOem)
		{
			extendLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		memcpy((m_Data + FIXED_LEN), &reservedOem, DOIP_RESERVED_OEM_LEN);
		_hasReservedOem = true;
	}

	void RoutingActivationResponse::clearReservedOem()
	{
		if (m_DataLen == OPT_LEN)
		{
			shortenLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
			_hasReservedOem = false;
			PCPP_LOG_INFO("Reserved OEM field has been removed successfully!");
		}
		if (m_DataLen == FIXED_LEN)
		{
			PCPP_LOG_DEBUG("doip packet has no reserved OEM field!");
		}
	}

	std::string RoutingActivationResponse::getSummary() const
	{
		std::ostringstream ss;
		DoIpRoutingResponseCodes code = getResponseCode();
		ss << "Logical Address (Tester): 0x" << std::hex << getLogicalAddressExternalTester() << "\n";
		ss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";
		auto it = DoIpEnumToStringRoutingResponseCodes.find(code);
		if (it != DoIpEnumToStringRoutingResponseCodes.end())
			ss << "Routing activation response code: " << it->second << " (0x" << std::hex << unsigned(code) << ")\n";
		else
			ss << "Response Code: Unknown (0x" << std::hex << unsigned(code) << ")\n";

		ss << "Reserved by ISO: " << pcpp::byteArrayToHexString(getReservedIso().data(), DOIP_RESERVED_ISO_LEN) << "\n";
		if (_hasReservedOem)
			ss << "Reserved by OEM: " << pcpp::byteArrayToHexString(getReservedOem(), DOIP_RESERVED_OEM_LEN) << "\n";

		return ss.str();
	}

	//~~~~~~~~~~~~~~~~~~~|
	// GenericHeaderNack |
	//~~~~~~~~~~~~~~~~~~~|
	GenericHeaderNack::GenericHeaderNack(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen != FIXED_LEN)
			throw std::runtime_error("GenericHeaderNack: Invalid payload length!");
	}

	GenericHeaderNack::GenericHeaderNack(DoIpGenericHeaderNackCodes nackCode)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), NACK_CODE_LEN);
		extendLayer(NACK_CODE_OFFSET, NACK_CODE_LEN);
		setNackCode(nackCode);
	}

	DoIpGenericHeaderNackCodes GenericHeaderNack::getNackCode() const
	{
		return static_cast<DoIpGenericHeaderNackCodes>(*(m_Data + NACK_CODE_OFFSET));
	}

	void GenericHeaderNack::setNackCode(DoIpGenericHeaderNackCodes nackCode)
	{
		*(m_Data + NACK_CODE_OFFSET) = static_cast<uint8_t>(nackCode);
	}

	void GenericHeaderNack::setNackCode(uint8_t nackCode)
	{
		*(m_Data + NACK_CODE_OFFSET) = nackCode;
	}

	std::string GenericHeaderNack::getSummary() const
	{
		std::ostringstream ss;
		DoIpGenericHeaderNackCodes nackCode = getNackCode();
		auto it = DoIpEnumToStringGenericHeaderNackCodes.find(nackCode);
		if (it != DoIpEnumToStringGenericHeaderNackCodes.end())
		{
			ss << "Generic header nack code: " << it->second << " (0x" << std::hex << static_cast<int>(nackCode)
			   << ")\n";
		}
		else
		{
			ss << "Generic header nack code: Unknown (0x" << std::hex << static_cast<int>(nackCode) << ")\n";
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
		if (dataLen != FIXED_LEN)
			throw std::runtime_error("VehicleIdentificationRequestEID: Invalid payload length");
	}

	VehicleIdentificationRequestEID::VehicleIdentificationRequestEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_EID_LEN);
		extendLayer(EID_OFFSET, DOIP_EID_LEN);
		setEID(eid);
	}

	std::array<uint8_t, DOIP_EID_LEN> VehicleIdentificationRequestEID::getEID() const
	{
		return *reinterpret_cast<const std::array<uint8_t, DOIP_EID_LEN>*>(m_Data + EID_OFFSET);
	}

	void VehicleIdentificationRequestEID::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		memcpy(m_Data + EID_OFFSET, &eid, DOIP_EID_LEN);
	}

	std::string VehicleIdentificationRequestEID::getSummary() const
	{
		std::ostringstream oss;
		oss << "EID: " << pcpp::byteArrayToHexString(getEID().data(), DOIP_EID_LEN) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// VehicleIdentificationRequestVIN |
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	VehicleIdentificationRequestVIN::VehicleIdentificationRequestVIN(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                                 Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen != FIXED_LEN)
			throw std::runtime_error("VehicleIdentificationRequestVIN: Invalid payload length!");
	}

	VehicleIdentificationRequestVIN::VehicleIdentificationRequestVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_VIN_LEN);
		extendLayer(VIN_OFFSET, DOIP_VIN_LEN);
		setVIN(vin);
	}

	std::array<uint8_t, DOIP_VIN_LEN> VehicleIdentificationRequestVIN::getVIN() const
	{
		return *reinterpret_cast<const std::array<uint8_t, DOIP_VIN_LEN>*>(m_Data + VIN_OFFSET);
	}

	void VehicleIdentificationRequestVIN::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		memcpy(m_Data + VIN_OFFSET, &vin, DOIP_VIN_LEN);
	}

	std::string VehicleIdentificationRequestVIN::getSummary() const
	{
		std::ostringstream oss;
		oss << "VIN: " << std::string(reinterpret_cast<const char*>(getVIN().data()), DOIP_VIN_LEN) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~|
	// VehicleAnnouncement |
	//~~~~~~~~~~~~~~~~~~~~~|
	VehicleAnnouncement::VehicleAnnouncement(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen < FIXED_LEN || dataLen > OPT_LEN)
			throw std::runtime_error("VehicleAnnouncement: invalid payload length!");

		if (dataLen == OPT_LEN)
		{
			_hasSyncStatus = true;
		}
		else
		{
			PCPP_LOG_DEBUG("Sync status field is empty!");
			_hasSyncStatus = false;
		}
	}

	VehicleAnnouncement::VehicleAnnouncement(const std::array<uint8_t, DOIP_VIN_LEN>& vin, uint16_t logicalAddress,
	                                         const std::array<uint8_t, DOIP_EID_LEN>& eid,
	                                         const std::array<uint8_t, DOIP_GID_LEN>& gid, DoIpActionCodes actionCode)
	    : _hasSyncStatus(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);
		extendLayer(DOIP_HEADER_LEN, (FIXED_LEN - DOIP_HEADER_LEN));

		setVIN(vin);
		setLogicalAddress(logicalAddress);
		setEID(eid);
		setGID(gid);
		setFurtherActionRequired(actionCode);
	}
	std::array<uint8_t, DOIP_VIN_LEN> VehicleAnnouncement::getVIN() const
	{
		return getVehicleAnnouncement()->vin;
	}
	uint16_t VehicleAnnouncement::getLogicalAddress() const
	{
		return htobe16(getVehicleAnnouncement()->logicalAddress);
	}

	std::array<uint8_t, DOIP_EID_LEN> VehicleAnnouncement::getEID() const
	{
		return getVehicleAnnouncement()->eid;
	}
	std::array<uint8_t, DOIP_GID_LEN> VehicleAnnouncement::getGID() const
	{
		return getVehicleAnnouncement()->gid;
	}
	DoIpActionCodes VehicleAnnouncement::getFurtherActionRequired() const
	{
		return getVehicleAnnouncement()->actionCode;
	}
	const DoIpSyncStatus* VehicleAnnouncement::getSyncStatus() const
	{
		return _hasSyncStatus ? reinterpret_cast<DoIpSyncStatus*>(m_Data + SYNC_STATUS_OFFSET) : nullptr;
	}

	void VehicleAnnouncement::clearSyncStatus()
	{
		if (m_DataLen == OPT_LEN)
		{
			shortenLayer(SYNC_STATUS_OFFSET, SYNC_STATUS_LEN);
			_hasSyncStatus = false;
			PCPP_LOG_INFO("Sync status has been removed successfully!");
		}
		if (m_DataLen == FIXED_LEN)
		{
			PCPP_LOG_DEBUG("doip packet has no syncStatus!");
		}
	}
	void VehicleAnnouncement::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		getVehicleAnnouncement()->vin = vin;
	}

	void VehicleAnnouncement::setLogicalAddress(uint16_t logicalAddress)
	{
		getVehicleAnnouncement()->logicalAddress = be16toh(logicalAddress);
	}

	void VehicleAnnouncement::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		getVehicleAnnouncement()->eid = eid;
	}

	void VehicleAnnouncement::setGID(const std::array<uint8_t, DOIP_GID_LEN>& gid)
	{
		getVehicleAnnouncement()->gid = gid;
	}

	void VehicleAnnouncement::setFurtherActionRequired(DoIpActionCodes action)
	{
		getVehicleAnnouncement()->actionCode = action;
	}

	void VehicleAnnouncement::setSyncStatus(DoIpSyncStatus syncStatus)
	{
		if (!_hasSyncStatus)
		{
			extendLayer(SYNC_STATUS_OFFSET, SYNC_STATUS_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		*(m_Data + SYNC_STATUS_OFFSET) = static_cast<uint8_t>(syncStatus);
		_hasSyncStatus = true;
	}

	bool VehicleAnnouncement::hasSyncStatus() const
	{
		return _hasSyncStatus;
	}

	std::string VehicleAnnouncement::getSummary() const
	{
		std::ostringstream oss;
		DoIpActionCodes actionCode = getFurtherActionRequired();
		oss << "VIN: " << std::string(reinterpret_cast<const char*>(getVIN().data()), DOIP_VIN_LEN) << "\n";
		oss << "Logical address: " << std::hex << "0x" << getLogicalAddress() << "\n";
		oss << "EID: " << pcpp::byteArrayToHexString(getEID().data(), DOIP_EID_LEN) << "\n";
		oss << "GID: " << pcpp::byteArrayToHexString(getGID().data(), DOIP_GID_LEN) << "\n";
		auto it = DoIpEnumToStringActionCodes.find(actionCode);
		if (it != DoIpEnumToStringActionCodes.end())
		{
			oss << "Further action required: " << it->second << std::hex << " (0x" << unsigned(actionCode) << ")"
			    << "\n";
		}
		else
		{
			oss << "Further action required: Unknown" << std::hex << " (0x" << unsigned(actionCode) << ")"
			    << "\n";
		}
		if (_hasSyncStatus)
		{
			DoIpSyncStatus syncStatus = *getSyncStatus();
			auto it_ = DoIpEnumToStringSyncStatus.find(syncStatus);
			if (it_ != DoIpEnumToStringSyncStatus.end())
			{
				oss << "VIN/GID sync status: " << it_->second << "\n";  // Convert enum to byte
			}
			else
			{
				oss << "VIN/GID sync status: Unknown" << std::hex << " (0x" << unsigned(syncStatus) << ")" << "\n";
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
		if (dataLen < DOIP_HEADER_LEN + DOIP_SOURCE_ADDRESS_LEN)
			throw std::runtime_error("AliveCheckResponse: insufficient payload length");
	}

	AliveCheckResponse::AliveCheckResponse(uint16_t sourceAddress)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_SOURCE_ADDRESS_LEN);
		extendLayer(DOIP_HEADER_LEN, DOIP_SOURCE_ADDRESS_LEN);
		setSourceAddress(sourceAddress);
	}

	uint16_t AliveCheckResponse::getSourceAddress() const
	{
		uint16_t _sourceAddress;
		memcpy(&_sourceAddress, (m_Data + SOURCE_ADDRESS_OFFSET), DOIP_SOURCE_ADDRESS_LEN);
		return htobe16(_sourceAddress);
	}

	void AliveCheckResponse::setSourceAddress(uint16_t sourceAddress)
	{
		uint16_t _sourceAddress = htobe16(sourceAddress);
		memcpy((m_Data + SOURCE_ADDRESS_OFFSET), &_sourceAddress, DOIP_SOURCE_ADDRESS_LEN);
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
		constexpr size_t payloadLen = DOIP_HEADER_LEN + sizeof(_powerModeCode);
		if (dataLen != payloadLen)
			throw std::runtime_error("DiagnosticPowerModeResponse: invalid payload length!");

		const uint8_t* payloadPtr = data + DOIP_HEADER_LEN;
		_powerModeCode = static_cast<DoIpDiagnosticPowerModeCodes>(*payloadPtr);
	}

	DiagnosticPowerModeResponse::DiagnosticPowerModeResponse(DoIpDiagnosticPowerModeCodes code) : _powerModeCode(code)
	{
		const size_t payloadLen = sizeof(_powerModeCode);
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), payloadLen);
		extendLayer(DOIP_HEADER_LEN, payloadLen);
		setPowerModeCode(code);
	}

	DoIpDiagnosticPowerModeCodes DiagnosticPowerModeResponse::getPowerModeCode() const
	{
		return _powerModeCode;
	}

	void DiagnosticPowerModeResponse::setPowerModeCode(DoIpDiagnosticPowerModeCodes code)
	{
		_powerModeCode = code;
		uint8_t* dataPtr = getDataPtr(DOIP_HEADER_LEN);
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
		if (dataLen < FIXED_LEN || dataLen > OPT_LEN)
		{
			throw std::runtime_error("EntityStatusResponse: Invalid payload length!");
		}

		if (dataLen > FIXED_LEN && dataLen < OPT_LEN)
		{
			throw std::runtime_error("EntityStatusResponse: Invalid MaxDataSize field length!");
		}

		if (dataLen == OPT_LEN)
		{
			_hasMaxDataSize = true;
		}
		else
		{
			PCPP_LOG_INFO("MaxDataSize field is empty !");
			_hasMaxDataSize = false;
		}
	}

	EntityStatusResponse::EntityStatusResponse(DoIpEntityStatusResponse nodeType, uint8_t maxConcurrentSockets,
	                                           uint8_t currentlyOpenSockets)
	    : _hasMaxDataSize(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);
		extendLayer(DOIP_HEADER_LEN, (FIXED_LEN - DOIP_HEADER_LEN));

		setNodeType(nodeType);
		setMaxConcurrentSockets(maxConcurrentSockets);
		setCurrentlyOpenSockets(currentlyOpenSockets);
	}
	DoIpEntityStatusResponse EntityStatusResponse::getNodeType() const
	{
		return getEntityStatusResponsePtr()->nodeType;
	}
	uint8_t EntityStatusResponse::getMaxConcurrentSockets() const
	{
		return getEntityStatusResponsePtr()->maxConcurrentSockets;
	}
	uint8_t EntityStatusResponse::getCurrentlyOpenSockets() const
	{
		return getEntityStatusResponsePtr()->currentlyOpenSockets;
	}
	const uint8_t* EntityStatusResponse::getMaxDataSize() const
	{
		return _hasMaxDataSize ? (m_Data + MAX_DATA_SIZE_OFFSET) : nullptr;
	}
	void EntityStatusResponse::setNodeType(DoIpEntityStatusResponse nodeType)
	{
		getEntityStatusResponsePtr()->nodeType = nodeType;
	}
	bool EntityStatusResponse::hasMaxDataSize() const
	{
		return _hasMaxDataSize;
	}
	void EntityStatusResponse::clearMaxDataSize()
	{
		if (m_DataLen == OPT_LEN && _hasMaxDataSize)
		{
			shortenLayer(MAX_DATA_SIZE_OFFSET, MAX_DATA_SIZE_LEN);
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
		getEntityStatusResponsePtr()->maxConcurrentSockets = sockets;
	}

	void EntityStatusResponse::setCurrentlyOpenSockets(uint8_t sockets)
	{
		getEntityStatusResponsePtr()->currentlyOpenSockets = sockets;
	}

	void EntityStatusResponse::setMaxDataSize(const std::array<uint8_t, 4>& data)
	{
		if (!_hasMaxDataSize)
		{
			extendLayer(MAX_DATA_SIZE_OFFSET, MAX_DATA_SIZE_LEN);
		}
		memcpy(m_Data + MAX_DATA_SIZE_OFFSET, &data, MAX_DATA_SIZE_LEN);
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		_hasMaxDataSize = true;
	}

	std::string EntityStatusResponse::getSummary() const
	{
		std::ostringstream oos;
		DoIpEntityStatusResponse nodeType = getNodeType();
		auto it = DoIpEnumToStringEntityStatusNodeTypes.find(nodeType);
		if (it != DoIpEnumToStringEntityStatusNodeTypes.end())
		{
			oos << "Entity status: " << it->second << std::hex << " (0x" << unsigned(nodeType) << ")" << "\n";
		}
		else
		{
			oos << "Node Type: Unknown" << std::hex << " (0x" << unsigned(nodeType) << ")\n";
		}
		oos << "Max Concurrent Socket: " << unsigned(getMaxConcurrentSockets()) << "\n";
		oos << "Currently Opened Socket: " << unsigned(getCurrentlyOpenSockets()) << "\n";
		if (_hasMaxDataSize)
		{
			oos << "Max Data Size: "
			    << "0x" << pcpp::byteArrayToHexString((m_Data + MAX_DATA_SIZE_OFFSET), MAX_DATA_SIZE_LEN) << "\n";
		}
		return oos.str();
	}

	//~~~~~~~~~~~~~~~|
	// DiagnosticBase|
	//~~~~~~~~~~~~~~~|
	DiagnosticBase::DiagnosticBase(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{
		if (dataLen < FIX_LEN)
			throw std::runtime_error("DiagnosticBase: insufficient payload length!");
	}

	uint16_t DiagnosticBase::getSourceAddress() const
	{
		return htobe16(getCommonDiagnosticHeader()->sourceAddress);
	}

	uint16_t DiagnosticBase::getTargetAddress() const
	{
		return htobe16(getCommonDiagnosticHeader()->targetAddress);
	}

	void DiagnosticBase::setSourceAddress(uint16_t sourceAddress)
	{
		getCommonDiagnosticHeader()->sourceAddress = htobe16(sourceAddress);
	}

	void DiagnosticBase::setTargetAddress(uint16_t targetAddress)
	{
		getCommonDiagnosticHeader()->targetAddress = htobe16(targetAddress);
	}

	//~~~~~~~~~~~~~~~~~~|
	// DiagnosticMessage|
	//~~~~~~~~~~~~~~~~~~|
	DiagnosticMessage::DiagnosticMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DiagnosticBase(data, dataLen, prevLayer, packet)
	{
		if (dataLen < MIN_LEN)
			throw std::runtime_error("DiagnosticBase: insufficient payload length!");
	}

	DiagnosticMessage::DiagnosticMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                     const std::vector<uint8_t>& diagData)
	{
		size_t payloadLen = DOIP_SOURCE_ADDRESS_LEN + DOIP_TARGET_ADDRESS_LEN + diagData.size();
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), payloadLen);
		extendLayer(DOIP_HEADER_LEN, payloadLen);
		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
		setDiagnosticData(diagData);
	}

	const std::vector<uint8_t> DiagnosticMessage::getDiagnosticData() const
	{
		const uint8_t* diagDataPtr = m_Data + DIAGNOSTIC_DATA_OFFSET;
		return std::vector<uint8_t>(diagDataPtr, diagDataPtr + (m_DataLen - DIAGNOSTIC_DATA_OFFSET));
	}

	void DiagnosticMessage::setDiagnosticData(const std::vector<uint8_t>& data)
	{
		const size_t newPayloadlLength = DOIP_SOURCE_ADDRESS_LEN + DOIP_TARGET_ADDRESS_LEN + data.size();
		const size_t currentDiagnosticDataLen = m_DataLen - DIAGNOSTIC_DATA_OFFSET;

		setPayloadLength(newPayloadlLength);
		// always clear the current diagnostic data and extendLayer with the new provided data
		if (currentDiagnosticDataLen > 0)
		{
			shortenLayer(DIAGNOSTIC_DATA_OFFSET, currentDiagnosticDataLen);
		}
		extendLayer(DIAGNOSTIC_DATA_OFFSET, data.size());
		uint8_t* dataPtr = m_Data + DIAGNOSTIC_DATA_OFFSET;
		memcpy(dataPtr, data.data(), data.size());
	}

	std::string DiagnosticMessage::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		oss << "Target Address: " << std::hex << "0x" << getTargetAddress() << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DiagnosticResponseMessageBase|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DiagnosticResponseMessageBase::DiagnosticResponseMessageBase(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                             Packet* packet)
	    : DiagnosticBase(data, dataLen, prevLayer, packet), _hasPreviousMessage(false)
	{
		if (dataLen < PREVIOUS_MSG_OFFSET)
			throw std::runtime_error("DiagnosticAckMessage: Invalid payload length");

		const size_t remainingData = dataLen - PREVIOUS_MSG_OFFSET;
		if (remainingData > 0)
		{
			_hasPreviousMessage = true;
		}
		else
		{
			PCPP_LOG_INFO("PreviousMessage field is empty!");
			_hasPreviousMessage = false;
		}
	}

	DiagnosticResponseMessageBase::DiagnosticResponseMessageBase(uint16_t sourceAddress, uint16_t targetAddress,
	                                                             DoIpPayloadTypes type)
	    : _hasPreviousMessage(false)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, type, (FIXED_LEN - DOIP_HEADER_LEN));
		extendLayer(DOIP_HEADER_LEN, (FIXED_LEN - DOIP_HEADER_LEN));
		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
	}

	uint8_t DiagnosticResponseMessageBase::getResponseCode() const
	{
		return static_cast<uint8_t>(*(m_Data + DIAGNOSTIC_ACK_CODE_OFFSET));
	}

	const std::vector<uint8_t> DiagnosticResponseMessageBase::getPreviousMessage() const
	{
		if (_hasPreviousMessage)
		{
			uint8_t* dataPtr = m_Data + PREVIOUS_MSG_OFFSET;
			return std::vector<uint8_t>(dataPtr, dataPtr + (m_DataLen - PREVIOUS_MSG_OFFSET));
		}
		else
		{
			return {};
		}
	}

	void DiagnosticResponseMessageBase::setResponseCode(uint8_t code)
	{
		*(m_Data + DIAGNOSTIC_ACK_CODE_OFFSET) = static_cast<uint8_t>(code);
	}

	bool DiagnosticResponseMessageBase::hasPreviousMessage() const
	{
		return _hasPreviousMessage;
	}

	void DiagnosticResponseMessageBase::setPreviousMessage(const std::vector<uint8_t>& msg)
	{
		size_t newPayloadLen = FIXED_LEN - DOIP_HEADER_LEN + msg.size();
		size_t currentPayloadLen = m_DataLen - PREVIOUS_MSG_OFFSET;
		setPayloadLength(newPayloadLen);
		// clear memory for old previous message
		if (_hasPreviousMessage)
		{
			shortenLayer(PREVIOUS_MSG_OFFSET, currentPayloadLen);
		}
		extendLayer(PREVIOUS_MSG_OFFSET, msg.size());
		uint8_t* ptr = getDataPtr(PREVIOUS_MSG_OFFSET);
		memcpy(ptr, msg.data(), msg.size());
		_hasPreviousMessage = true;
	}

	void DiagnosticResponseMessageBase::clearPreviousMessage()
	{
		if (_hasPreviousMessage)
		{
			shortenLayer(FIXED_LEN, (m_DataLen - FIXED_LEN));
			_hasPreviousMessage = false;
			PCPP_LOG_INFO("PreviousMessage has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no PreviousMessage field!");
		}
	}

	//~~~~~~~~~~~~~~~~~~~~~|
	// DiagnosticAckMessage|
	//~~~~~~~~~~~~~~~~~~~~~|
	DiagnosticAckMessage::DiagnosticAckMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DiagnosticResponseMessageBase(data, dataLen, prevLayer, packet)
	{}

	DiagnosticAckMessage::DiagnosticAckMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                           DoIpDiagnosticAckCodes ackCode)
	    : DiagnosticResponseMessageBase(sourceAddress, targetAddress, getPayloadType())
	{
		setAckCode(ackCode);
	}

	DoIpDiagnosticAckCodes DiagnosticAckMessage::getAckCode() const
	{
		return static_cast<DoIpDiagnosticAckCodes>(getResponseCode());
	}

	void DiagnosticAckMessage::setAckCode(DoIpDiagnosticAckCodes code)
	{
		setResponseCode(static_cast<uint8_t>(code));
	}
	// Summary method.
	std::string DiagnosticAckMessage::getSummary() const
	{
		std::ostringstream oss;
		DoIpDiagnosticAckCodes ackCode = getAckCode();
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		oss << "Target Address: " << std::hex << "0x" << getTargetAddress() << "\n";
		auto it = DoIpEnumToStringAckCode.find(ackCode);
		if (it != DoIpEnumToStringAckCode.end())
		{
			oss << "ACK code: " << it->second << " (0x" << unsigned(ackCode) << ")\n";
		}
		else
		{
			oss << "ACK code: Unknown" << std::hex << " (0x" << unsigned(ackCode) << ")\n";
		}
		if (_hasPreviousMessage)
		{
			oss << "Previous message: "
			    << pcpp::byteArrayToHexString(getPreviousMessage().data(), getPreviousMessage().size()) << "\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DiagnosticNackMessage|
	//~~~~~~~~~~~~~~~~~~~~~~|
	DiagnosticNackMessage::DiagnosticNackMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DiagnosticResponseMessageBase(data, dataLen, prevLayer, packet)
	{}

	DiagnosticNackMessage::DiagnosticNackMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                             DoIpDiagnosticMessageNackCodes nackCode)
	    : DiagnosticResponseMessageBase(sourceAddress, targetAddress, getPayloadType())
	{
		setNackCode(nackCode);
	}

	DoIpDiagnosticMessageNackCodes DiagnosticNackMessage::getNackCode() const
	{
		return static_cast<DoIpDiagnosticMessageNackCodes>(getResponseCode());
	}

	void DiagnosticNackMessage::setNackCode(DoIpDiagnosticMessageNackCodes code)
	{
		setResponseCode(static_cast<uint8_t>(code));
	}

	std::string DiagnosticNackMessage::getSummary() const
	{
		std::ostringstream oss;
		DoIpDiagnosticMessageNackCodes nackCode = getNackCode();
		oss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";
		oss << "Target Address: 0x" << std::hex << getTargetAddress() << "\n";

		auto it = DoIpEnumToStringDiagnosticNackCodes.find(nackCode);
		if (it != DoIpEnumToStringDiagnosticNackCodes.end())
		{
			oss << "NACK code: " << it->second << " (0x" << unsigned(nackCode) << ")\n";
		}
		else
		{
			oss << "NACK code: Unknown (0x" << unsigned(nackCode) << ")\n";
		}

		if (_hasPreviousMessage)
		{
			oss << "Previous message: "
			    << pcpp::byteArrayToHexString(getPreviousMessage().data(), getPreviousMessage().size()) << "\n";
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
