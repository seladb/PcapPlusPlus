#define LOG_MODULE PacketLogModuleDoIpLayer

#include <unordered_map>
#include <sstream>
#include <iomanip>
#include "DoIpLayer.h"
#include "GeneralUtils.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"

namespace pcpp
{

	// This unordered map provides human-readable descriptions for each activation type
	// defined in the DoIP protocol as per ISO 13400. It maps the `DoIpActivationTypes` enum values
	// to their corresponding descriptions.
	static const std::unordered_map<DoIpActivationTypes, std::string> DoIpEnumToStringActivationTypes{
		{ DoIpActivationTypes::DEFAULT,          "Default"          },
		{ DoIpActivationTypes::WWH_OBD,          "WWH-OBD"          },
		{ DoIpActivationTypes::CENTRAL_SECURITY, "Central security" },
		{ DoIpActivationTypes::UNKNOWN,          "Unknown"          },
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
		{ DoIpGenericHeaderNackCodes::UNKNOWN,                "Unknown"                  }
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
		{ DoIpActionCodes::ROUTING_ACTIVATION_REQUIRED, "Routing activation required to initiate central security" },
		{ DoIpActionCodes::UNKNOWN,                     "Unknown"		                                          }
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
		{ DoIpRoutingResponseCodes::CONFIRMATION_REQUIRED,             "Routing will be activated; confirmation required"                          },
		{ DoIpRoutingResponseCodes::UNKNOWN,                           "Unknown routing activation response code"                                  }
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
		{ DoIpDiagnosticMessageNackCodes::UNKNOWN,                  "Unknown NACK code"            }
	};

	// This unordered map provides human-readable descriptions for each power mode code
	// related to DoIP diagnostics, as per ISO 13400. It maps the `DoIpDiagnosticPowerMode` enum
	// values to their corresponding descriptions.
	static const std::unordered_map<DoIpDiagnosticPowerModeCodes, std::string> DoIpEnumToStringDiagnosticPowerModeCodes{
		{ DoIpDiagnosticPowerModeCodes::NOT_READY,     "not ready"     },
		{ DoIpDiagnosticPowerModeCodes::READY,         "ready"         },
		{ DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED, "not supported" },
		{ DoIpDiagnosticPowerModeCodes::UNKNOWN,       "unknown"       }
	};

	// This unordered map provides human-readable descriptions for the entity status codes
	// in the context of DoIP (Diagnostic over IP). It maps the `DoIpEntityStatus` enum values
	// to their corresponding descriptions, distinguishing between a "DoIP node" and a "DoIP gateway."
	static const std::unordered_map<DoIpEntityStatusResponseCode, std::string> DoIpEnumToStringEntityStatusNodeTypes{
		{ DoIpEntityStatusResponseCode::NODE,    "DoIP node"    },
		{ DoIpEntityStatusResponseCode::GATEWAY, "DoIP gateway" },
		{ DoIpEntityStatusResponseCode::UNKNOWN, "Unknown"      }
	};

	// This unordered map provides a human-readable description for the DoIP acknowledgement
	// code `ACK`, which is used to confirm the successful reception or processing of a message.
	static const std::unordered_map<DoIpDiagnosticAckCodes, std::string> DoIpEnumToStringAckCode{
		{ DoIpDiagnosticAckCodes::ACK,     "ACK"     },
        { DoIpDiagnosticAckCodes::UNKNOWN, "Unknown" }
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
		{ DoIpSyncStatus::UNKNOWN,                             "Unknown"                             }
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
		{ DoIpProtocolVersion::UnknownVersion,        "Unknown Protocol Version"                                  },
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

	DoIpLayer::DoIpLayer(size_t length)
	{
		m_DataLen = length;
		m_Protocol = DOIP;
		m_Data = new uint8_t[m_DataLen]{};
	}

	DoIpLayer::DoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet, DOIP)
	{}

	bool DoIpLayer::isDataValid(uint8_t* data, size_t dataLen)
	{
		if (data == nullptr || dataLen < DOIP_HEADER_LEN)
			return false;

		auto* doipHeader = reinterpret_cast<doiphdr*>(data);
		const uint8_t version = doipHeader->protocolVersion;
		const uint8_t inVersion = doipHeader->invertProtocolVersion;
		const uint16_t payloadTypeRaw = doipHeader->payloadType;
		const uint32_t lengthRaw = doipHeader->payloadLength;

		if (!isPayloadTypeValid(htobe16(payloadTypeRaw)))
			return false;
		// if payload type is validated, we ensure passing a valid type to isProtocolVersionValid()
		const DoIpPayloadTypes payloadType = static_cast<DoIpPayloadTypes>(htobe16(payloadTypeRaw));
		if (!isProtocolVersionValid(version, inVersion, payloadType))
			return false;

		if (!isPayloadLengthValid(htobe32(lengthRaw), dataLen))
			return false;

		return true;
	}

	DoIpLayer* DoIpLayer::parseDoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		doiphdr* doipHeader = reinterpret_cast<doiphdr*>(data);
		uint16_t payloadType = doipHeader->payloadType;
		DoIpPayloadTypes detectedPayloadType = static_cast<DoIpPayloadTypes>(htobe16(payloadType));

		switch (detectedPayloadType)
		{
		case DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST:
			return (DoIpRoutingActivationRequest::isDataLenValid(dataLen))
			           ? new DoIpRoutingActivationRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE:
			return (DoIpRoutingActivationResponse::isDataLenValid(dataLen))
			           ? new DoIpRoutingActivationResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK:
			return (DoIpGenericHeaderNack::isDataLenValid(dataLen))
			           ? new DoIpGenericHeaderNack(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID:
			return (DoIpVehicleIdentificationRequestEID::isDataLenValid(dataLen))
			           ? new DoIpVehicleIdentificationRequestEID(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN:
			return (DoIpVehicleIdentificationRequestVIN::isDataLenValid(dataLen))
			           ? new DoIpVehicleIdentificationRequestVIN(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE:
			return (DoIpVehicleAnnouncement::isDataLenValid(dataLen))
			           ? new DoIpVehicleAnnouncement(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ALIVE_CHECK_RESPONSE:
			return (DoIpAliveCheckResponse::isDataLenValid(dataLen))
			           ? new DoIpAliveCheckResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE:
			return (DoIpDiagnosticPowerModeResponse::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticPowerModeResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ENTITY_STATUS_RESPONSE:
			return (DoIpEntityStatusResponse::isDataLenValid(dataLen))
			           ? new DoIpEntityStatusResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE:
			return (DoIpDiagnosticMessage::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticMessage(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK:
			return (DoIpDiagnosticAckMessage::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticAckMessage(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK:
			return (DoIpDiagnosticNackMessage::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticNackMessage(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST:
			return (DoIpVehicleIdentificationRequest::isDataLenValid(dataLen))
			           ? new DoIpVehicleIdentificationRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ALIVE_CHECK_REQUEST:
			return (DoIpAliveCheckRequest::isDataLenValid(dataLen))
			           ? new DoIpAliveCheckRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST:
			return (DoIpDiagnosticPowerModeRequest::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticPowerModeRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ENTITY_STATUS_REQUEST:
			return (DoIpEntityStatusRequest::isDataLenValid(dataLen))
			           ? new DoIpEntityStatusRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		default:
			return nullptr;
		}
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
		return (it != DoIpEnumToStringProtocolVersion.end()) ? it->second : "Unknown Protocol Version";
	}

	void DoIpLayer::setProtocolVersion(DoIpProtocolVersion version)
	{
		getDoIpHeader()->protocolVersion = static_cast<uint8_t>(version);
	}

	void DoIpLayer::setProtocolVersion(uint8_t rawVersion)
	{
		getDoIpHeader()->protocolVersion = rawVersion;
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
		return (it != DoIpEnumToStringPayloadType.end()) ? it->second : "Unknown Payload Type";
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
		oss << "DoIP Layer, " << getPayloadTypeAsStr() << " (0x" << std::hex << std::setw(4) << std::setfill('0')
		    << static_cast<uint16_t>(getPayloadType()) << ")";
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
			size_t headerLen = getHeaderLen();

			if (m_DataLen <= headerLen)
			{
				return;
			}

			uint8_t* payload = m_Data + headerLen;
			size_t payloadLen = m_DataLen - headerLen;

			constructNextLayer<PayloadLayer>(payload, payloadLen, m_Packet);
		}
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpRoutingActivationRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpRoutingActivationRequest::DoIpRoutingActivationRequest(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                           Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpRoutingActivationRequest::DoIpRoutingActivationRequest(uint16_t sourceAddress,
	                                                           DoIpActivationTypes activationType)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);

		auto* payload = getRoutingRequest();
		payload->sourceAddress = htobe16(sourceAddress);
		payload->activationType = static_cast<uint8_t>(activationType);
		// Reserved ISO is always all zeros
		payload->reservedIso.fill(0);
	}

	uint16_t DoIpRoutingActivationRequest::getSourceAddress() const
	{
		return be16toh(getRoutingRequest()->sourceAddress);
	}

	void DoIpRoutingActivationRequest::setSourceAddress(uint16_t value)
	{
		getRoutingRequest()->sourceAddress = htobe16(value);
	}

	DoIpActivationTypes DoIpRoutingActivationRequest::getActivationType() const
	{
		auto activationType = static_cast<DoIpActivationTypes>(getRoutingRequest()->activationType);
		switch (activationType)
		{
		case DoIpActivationTypes::DEFAULT:
		case DoIpActivationTypes::WWH_OBD:
		case DoIpActivationTypes::CENTRAL_SECURITY:
			return activationType;
		default:
			return DoIpActivationTypes::UNKNOWN;
		}
	}

	void DoIpRoutingActivationRequest::setActivationType(DoIpActivationTypes activationType)
	{
		getRoutingRequest()->activationType = static_cast<uint8_t>(activationType);
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> DoIpRoutingActivationRequest::getReservedIso() const
	{
		return getRoutingRequest()->reservedIso;
	}

	void DoIpRoutingActivationRequest::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		getRoutingRequest()->reservedIso = reservedIso;
	}

	bool DoIpRoutingActivationRequest::hasReservedOem() const
	{
		return (m_DataLen == OPT_LEN);
	}

	const std::array<uint8_t, DOIP_RESERVED_OEM_LEN> DoIpRoutingActivationRequest::getReservedOem() const
	{
		std::array<uint8_t, DOIP_RESERVED_OEM_LEN> reservedOem;
		if (hasReservedOem())
		{
			memcpy(reservedOem.data(), m_Data + FIXED_LEN, DOIP_RESERVED_OEM_LEN);
			return reservedOem;
		}
		else
		{
			throw std::runtime_error("Reserved OEM field not present!");
		}
	}

	void DoIpRoutingActivationRequest::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		if (!hasReservedOem())
		{
			extendLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		memcpy((m_Data + FIXED_LEN), reservedOem.data(), DOIP_RESERVED_OEM_LEN);
	}

	void DoIpRoutingActivationRequest::clearReservedOem()
	{
		if (hasReservedOem())
		{
			shortenLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
			PCPP_LOG_DEBUG("Reserved OEM field has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("DoIP packet has no reserved OEM field!");
		}
	}

	std::string DoIpRoutingActivationRequest::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";

		auto it = DoIpEnumToStringActivationTypes.find(getActivationType());
		oss << "Activation type: " << ((it != DoIpEnumToStringActivationTypes.end()) ? it->second : "Unknown") << " (0x"
		    << std::hex << static_cast<unsigned>(getActivationType()) << ")\n";

		oss << "Reserved by ISO: " << pcpp::byteArrayToHexString(getReservedIso().data(), DOIP_RESERVED_ISO_LEN)
		    << "\n";
		if (hasReservedOem())
			oss << "Reserved by OEM: " << pcpp::byteArrayToHexString(getReservedOem().data(), DOIP_RESERVED_OEM_LEN)
			    << '\n';

		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpRoutingActivationResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpRoutingActivationResponse::DoIpRoutingActivationResponse(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                             Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpRoutingActivationResponse::DoIpRoutingActivationResponse(uint16_t logicalAddressExternalTester,
	                                                             uint16_t sourceAddress,
	                                                             DoIpRoutingResponseCodes responseCode)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));

		auto* payload = getRoutingResponse();
		payload->logicalAddressExternalTester = htobe16(logicalAddressExternalTester);
		payload->sourceAddress = htobe16(sourceAddress);
		payload->responseCode = static_cast<uint8_t>(responseCode);
		payload->reservedIso.fill(0);
	}

	uint16_t DoIpRoutingActivationResponse::getLogicalAddressExternalTester() const
	{
		return htobe16(getRoutingResponse()->logicalAddressExternalTester);
	}

	void DoIpRoutingActivationResponse::setLogicalAddressExternalTester(uint16_t addr)
	{
		getRoutingResponse()->logicalAddressExternalTester = htobe16(addr);
	}

	uint16_t DoIpRoutingActivationResponse::getSourceAddress() const
	{
		return htobe16(getRoutingResponse()->sourceAddress);
	}

	void DoIpRoutingActivationResponse::setSourceAddress(uint16_t sourceAddress)
	{
		getRoutingResponse()->sourceAddress = htobe16(sourceAddress);
	}

	DoIpRoutingResponseCodes DoIpRoutingActivationResponse::getResponseCode() const
	{
		uint8_t code = getRoutingResponse()->responseCode;
		if (code <= static_cast<uint8_t>(DoIpRoutingResponseCodes::CONFIRMATION_REQUIRED))
			return static_cast<DoIpRoutingResponseCodes>(code);
		else
			return DoIpRoutingResponseCodes::UNKNOWN;
	}

	void DoIpRoutingActivationResponse::setResponseCode(DoIpRoutingResponseCodes code)
	{
		getRoutingResponse()->responseCode = static_cast<uint8_t>(code);
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> DoIpRoutingActivationResponse::getReservedIso() const
	{
		return getRoutingResponse()->reservedIso;
	}

	void DoIpRoutingActivationResponse::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		getRoutingResponse()->reservedIso = reservedIso;
	}

	bool DoIpRoutingActivationResponse::hasReservedOem() const
	{
		return (m_DataLen == OPT_LEN);
	}

	const std::array<uint8_t, DOIP_RESERVED_OEM_LEN> DoIpRoutingActivationResponse::getReservedOem() const
	{
		std::array<uint8_t, DOIP_RESERVED_OEM_LEN> reservedOem;
		if (hasReservedOem())
		{
			memcpy(reservedOem.data(), m_Data + FIXED_LEN, DOIP_RESERVED_OEM_LEN);
			return reservedOem;
		}
		else
		{
			throw std::runtime_error("Reserved OEM field not present!");
		}
	}

	void DoIpRoutingActivationResponse::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		if (!hasReservedOem())
		{
			extendLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		memcpy((m_Data + FIXED_LEN), reservedOem.data(), DOIP_RESERVED_OEM_LEN);
	}

	void DoIpRoutingActivationResponse::clearReservedOem()
	{
		if (hasReservedOem())
		{
			shortenLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
			PCPP_LOG_DEBUG("Reserved OEM field has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no reserved OEM field!");
		}
	}

	std::string DoIpRoutingActivationResponse::getSummary() const
	{
		std::ostringstream oss;
		oss << "Logical Address (Tester): 0x" << std::hex << getLogicalAddressExternalTester() << "\n";
		oss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";

		auto it = DoIpEnumToStringRoutingResponseCodes.find(getResponseCode());
		oss << "Routing activation response code: "
		    << ((it != DoIpEnumToStringRoutingResponseCodes.end()) ? it->second : "Unknown") << " (0x" << std::hex
		    << static_cast<unsigned>(getResponseCode()) << ")\n";

		oss << "Reserved by ISO: " << pcpp::byteArrayToHexString(getReservedIso().data(), DOIP_RESERVED_ISO_LEN)
		    << "\n";
		if (hasReservedOem())
			oss << "Reserved by OEM: " << pcpp::byteArrayToHexString(getReservedOem().data(), DOIP_RESERVED_OEM_LEN)
			    << "\n";

		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpGenericHeaderNack|
	//~~~~~~~~~~~~~~~~~~~~~~|
	DoIpGenericHeaderNack::DoIpGenericHeaderNack(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpGenericHeaderNack::DoIpGenericHeaderNack(DoIpGenericHeaderNackCodes nackCode) : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);
		setNackCode(nackCode);
	}

	DoIpGenericHeaderNackCodes DoIpGenericHeaderNack::getNackCode() const
	{
		uint8_t nackCode = getGenericHeaderNack()->nackCode;
		if (nackCode <= static_cast<uint8_t>(DoIpGenericHeaderNackCodes::INVALID_PAYLOAD_LENGTH))
			return static_cast<DoIpGenericHeaderNackCodes>(nackCode);
		else
			return DoIpGenericHeaderNackCodes::UNKNOWN;
	}

	void DoIpGenericHeaderNack::setNackCode(DoIpGenericHeaderNackCodes nackCode)
	{
		getGenericHeaderNack()->nackCode = static_cast<uint8_t>(nackCode);
	}

	std::string DoIpGenericHeaderNack::getSummary() const
	{
		std::ostringstream oss;
		DoIpGenericHeaderNackCodes nackCode = getNackCode();
		auto it = DoIpEnumToStringGenericHeaderNackCodes.find(nackCode);
		oss << "Generic header nack code: " << it->second << " (0x" << std::hex
		    << static_cast<unsigned>(getGenericHeaderNack()->nackCode) << ")\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// VehicleIdentificationRequestEID |
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleIdentificationRequestEID::DoIpVehicleIdentificationRequestEID(uint8_t* data, size_t dataLen,
	                                                                         Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpVehicleIdentificationRequestEID::DoIpVehicleIdentificationRequestEID(
	    const std::array<uint8_t, DOIP_EID_LEN>& eid)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_EID_LEN);
		setEID(eid);
	}

	std::array<uint8_t, DOIP_EID_LEN> DoIpVehicleIdentificationRequestEID::getEID() const
	{
		return getVehicleIdentificationRequestEID()->eid;
	}

	void DoIpVehicleIdentificationRequestEID::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		getVehicleIdentificationRequestEID()->eid = eid;
	}

	std::string DoIpVehicleIdentificationRequestEID::getSummary() const
	{
		std::ostringstream oss;
		oss << "EID: " << pcpp::byteArrayToHexString(getEID().data(), DOIP_EID_LEN) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// VehicleIdentificationRequestVIN |
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleIdentificationRequestVIN::DoIpVehicleIdentificationRequestVIN(uint8_t* data, size_t dataLen,
	                                                                         Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpVehicleIdentificationRequestVIN::DoIpVehicleIdentificationRequestVIN(
	    const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_VIN_LEN);
		setVIN(vin);
	}

	std::array<uint8_t, DOIP_VIN_LEN> DoIpVehicleIdentificationRequestVIN::getVIN() const
	{
		return getVehicleIdentificationRequestVIN()->vin;
	}

	void DoIpVehicleIdentificationRequestVIN::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		getVehicleIdentificationRequestVIN()->vin = vin;
	}

	std::string DoIpVehicleIdentificationRequestVIN::getSummary() const
	{
		std::ostringstream oss;
		oss << "VIN: " << std::string(reinterpret_cast<const char*>(getVIN().data()), DOIP_VIN_LEN) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleAnnouncement|
	//~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleAnnouncement::DoIpVehicleAnnouncement(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpVehicleAnnouncement::DoIpVehicleAnnouncement(const std::array<uint8_t, DOIP_VIN_LEN>& vin,
	                                                 uint16_t logicalAddress,
	                                                 const std::array<uint8_t, DOIP_EID_LEN>& eid,
	                                                 const std::array<uint8_t, DOIP_GID_LEN>& gid,
	                                                 DoIpActionCodes actionCode)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);

		setVIN(vin);
		setLogicalAddress(logicalAddress);
		setEID(eid);
		setGID(gid);
		setFurtherActionRequired(actionCode);
	}
	std::array<uint8_t, DOIP_VIN_LEN> DoIpVehicleAnnouncement::getVIN() const
	{
		return getVehicleAnnouncement()->vin;
	}
	uint16_t DoIpVehicleAnnouncement::getLogicalAddress() const
	{
		return htobe16(getVehicleAnnouncement()->logicalAddress);
	}

	std::array<uint8_t, DOIP_EID_LEN> DoIpVehicleAnnouncement::getEID() const
	{
		return getVehicleAnnouncement()->eid;
	}
	std::array<uint8_t, DOIP_GID_LEN> DoIpVehicleAnnouncement::getGID() const
	{
		return getVehicleAnnouncement()->gid;
	}
	DoIpActionCodes DoIpVehicleAnnouncement::getFurtherActionRequired() const
	{
		uint8_t actionCode = getVehicleAnnouncement()->actionCode;
		if (actionCode <= static_cast<uint8_t>(DoIpActionCodes::ROUTING_ACTIVATION_REQUIRED))
			return static_cast<DoIpActionCodes>(actionCode);
		else
			return DoIpActionCodes::UNKNOWN;
	}

	DoIpSyncStatus DoIpVehicleAnnouncement::getSyncStatus() const
	{
		if (hasSyncStatus())
		{
			uint8_t syncStatus = *(m_Data + SYNC_STATUS_OFFSET);
			if (syncStatus <= static_cast<uint8_t>(DoIpSyncStatus::VIN_AND_OR_GID_ARE_NOT_SINCHRONIZED))
				return static_cast<DoIpSyncStatus>(syncStatus);
			else
				return DoIpSyncStatus::UNKNOWN;
		}
		else
		{
			throw std::runtime_error("Sync status field not present!");
		}
	}

	void DoIpVehicleAnnouncement::clearSyncStatus()
	{
		if (m_DataLen == OPT_LEN)
		{
			shortenLayer(SYNC_STATUS_OFFSET, SYNC_STATUS_LEN);
			PCPP_LOG_DEBUG("Sync status has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no syncStatus!");
		}
	}
	void DoIpVehicleAnnouncement::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		getVehicleAnnouncement()->vin = vin;
	}

	void DoIpVehicleAnnouncement::setLogicalAddress(uint16_t logicalAddress)
	{
		getVehicleAnnouncement()->logicalAddress = be16toh(logicalAddress);
	}

	void DoIpVehicleAnnouncement::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		getVehicleAnnouncement()->eid = eid;
	}

	void DoIpVehicleAnnouncement::setGID(const std::array<uint8_t, DOIP_GID_LEN>& gid)
	{
		getVehicleAnnouncement()->gid = gid;
	}

	void DoIpVehicleAnnouncement::setFurtherActionRequired(DoIpActionCodes action)
	{
		getVehicleAnnouncement()->actionCode = static_cast<uint8_t>(action);
	}

	void DoIpVehicleAnnouncement::setSyncStatus(DoIpSyncStatus syncStatus)
	{
		if (!hasSyncStatus())
		{
			extendLayer(SYNC_STATUS_OFFSET, SYNC_STATUS_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		*(m_Data + SYNC_STATUS_OFFSET) = static_cast<uint8_t>(syncStatus);
	}

	bool DoIpVehicleAnnouncement::hasSyncStatus() const
	{
		return (m_DataLen == OPT_LEN);
	}

	std::string DoIpVehicleAnnouncement::getSummary() const
	{
		std::ostringstream oss;
		oss << "VIN: " << std::string(reinterpret_cast<const char*>(getVIN().data()), DOIP_VIN_LEN) << "\n";
		oss << "Logical address: 0x" << std::hex << getLogicalAddress() << "\n";
		oss << "EID: " << pcpp::byteArrayToHexString(getEID().data(), DOIP_EID_LEN) << "\n";
		oss << "GID: " << pcpp::byteArrayToHexString(getGID().data(), DOIP_GID_LEN) << "\n";

		auto it = DoIpEnumToStringActionCodes.find(getFurtherActionRequired());
		oss << "Further action required: " << it->second << " (0x" << std::hex
		    << static_cast<unsigned>(getVehicleAnnouncement()->actionCode) << ")\n";

		if (hasSyncStatus())
		{
			auto syncStatus = getSyncStatus();
			auto itSync = DoIpEnumToStringSyncStatus.find(syncStatus);
			oss << "VIN/GID sync status: " << itSync->second << " (0x" << std::hex
			    << static_cast<unsigned>(*(m_Data + SYNC_STATUS_OFFSET)) << ")\n";
		}

		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpAliveCheckResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpAliveCheckResponse::DoIpAliveCheckResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpAliveCheckResponse::DoIpAliveCheckResponse(uint16_t sourceAddress) : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), DOIP_SOURCE_ADDRESS_LEN);
		setSourceAddress(sourceAddress);
	}

	uint16_t DoIpAliveCheckResponse::getSourceAddress() const
	{
		return htobe16(getAliveCheckResponse()->sourceAddress);
	}

	void DoIpAliveCheckResponse::setSourceAddress(uint16_t sourceAddress)
	{
		getAliveCheckResponse()->sourceAddress = htobe16(sourceAddress);
	}

	std::string DoIpAliveCheckResponse::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticPowerModeResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticPowerModeResponse::DoIpDiagnosticPowerModeResponse(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                                 Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpDiagnosticPowerModeResponse::DoIpDiagnosticPowerModeResponse(DoIpDiagnosticPowerModeCodes code)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);
		setPowerModeCode(code);
	}

	DoIpDiagnosticPowerModeCodes DoIpDiagnosticPowerModeResponse::getPowerModeCode() const
	{
		uint8_t powerModeCode = getDiagnosticPowerModeResponse()->powerModeCode;
		if (powerModeCode <= static_cast<uint8_t>(DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED))
			return static_cast<DoIpDiagnosticPowerModeCodes>(powerModeCode);
		else
			return DoIpDiagnosticPowerModeCodes::UNKNOWN;
	}

	void DoIpDiagnosticPowerModeResponse::setPowerModeCode(DoIpDiagnosticPowerModeCodes code)
	{
		getDiagnosticPowerModeResponse()->powerModeCode = static_cast<uint8_t>(code);
	}

	std::string DoIpDiagnosticPowerModeResponse::getSummary() const
	{
		std::ostringstream oss;
		DoIpDiagnosticPowerModeCodes powerModeCode = getPowerModeCode();
		auto it = DoIpEnumToStringDiagnosticPowerModeCodes.find(powerModeCode);
		oss << "Diagnostic power mode: " << it->second << " (0x" << std::hex
		    << static_cast<unsigned>(getDiagnosticPowerModeResponse()->powerModeCode) << ")\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpEntityStatusResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpEntityStatusResponse::DoIpEntityStatusResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpEntityStatusResponse::DoIpEntityStatusResponse(DoIpEntityStatusResponseCode nodeType,
	                                                   uint8_t maxConcurrentSockets, uint8_t currentlyOpenSockets)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), FIXED_LEN - DOIP_HEADER_LEN);

		setNodeType(nodeType);
		setMaxConcurrentSockets(maxConcurrentSockets);
		setCurrentlyOpenSockets(currentlyOpenSockets);
	}
	DoIpEntityStatusResponseCode DoIpEntityStatusResponse::getNodeType() const
	{
		uint8_t nodeType = getEntityStatusResponsePtr()->nodeType;
		if (nodeType <= static_cast<uint8_t>(DoIpEntityStatusResponseCode::NODE))
			return static_cast<DoIpEntityStatusResponseCode>(nodeType);
		else
			return DoIpEntityStatusResponseCode::UNKNOWN;
	}

	uint8_t DoIpEntityStatusResponse::getMaxConcurrentSockets() const
	{
		return getEntityStatusResponsePtr()->maxConcurrentSockets;
	}
	uint8_t DoIpEntityStatusResponse::getCurrentlyOpenSockets() const
	{
		return getEntityStatusResponsePtr()->currentlyOpenSockets;
	}
	uint32_t DoIpEntityStatusResponse::getMaxDataSize() const
	{
		if (!hasMaxDataSize())
			throw std::runtime_error("Max data size field not present!");

		uint32_t value;
		std::memcpy(&value, m_Data + MAX_DATA_SIZE_OFFSET, MAX_DATA_SIZE_LEN);
		return htobe32(value);
	}
	void DoIpEntityStatusResponse::setNodeType(DoIpEntityStatusResponseCode nodeType)
	{
		getEntityStatusResponsePtr()->nodeType = static_cast<uint8_t>(nodeType);
	}
	bool DoIpEntityStatusResponse::hasMaxDataSize() const
	{
		return (m_DataLen == OPT_LEN);
	}
	void DoIpEntityStatusResponse::clearMaxDataSize()
	{
		if (hasMaxDataSize())
		{
			shortenLayer(MAX_DATA_SIZE_OFFSET, MAX_DATA_SIZE_LEN);
			PCPP_LOG_DEBUG("MaxDataSize has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no MaxDataSize field!");
		}
	}
	void DoIpEntityStatusResponse::setMaxConcurrentSockets(uint8_t sockets)
	{
		getEntityStatusResponsePtr()->maxConcurrentSockets = sockets;
	}

	void DoIpEntityStatusResponse::setCurrentlyOpenSockets(uint8_t sockets)
	{
		getEntityStatusResponsePtr()->currentlyOpenSockets = sockets;
	}

	void DoIpEntityStatusResponse::setMaxDataSize(uint32_t data)
	{
		if (!hasMaxDataSize())
		{
			extendLayer(MAX_DATA_SIZE_OFFSET, MAX_DATA_SIZE_LEN);
		}
		uint32_t value = htobe32(data);
		memcpy(m_Data + MAX_DATA_SIZE_OFFSET, &value, MAX_DATA_SIZE_LEN);
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
	}

	std::string DoIpEntityStatusResponse::getSummary() const
	{
		std::ostringstream oss;
		DoIpEntityStatusResponseCode nodeType = getNodeType();
		auto it = DoIpEnumToStringEntityStatusNodeTypes.find(nodeType);
		oss << "Entity status: " << ((it != DoIpEnumToStringEntityStatusNodeTypes.end()) ? it->second : "Unknown")
		    << " (0x" << std::hex << static_cast<unsigned>(nodeType) << ")" << "\n";
		oss << "Max Concurrent Socket: " << static_cast<unsigned>(getMaxConcurrentSockets()) << "\n";
		oss << "Currently Opened Socket: " << static_cast<unsigned>(getCurrentlyOpenSockets()) << "\n";
		if (hasMaxDataSize())
		{
			oss << "Max Data Size: "
			    << "0x" << pcpp::byteArrayToHexString((m_Data + MAX_DATA_SIZE_OFFSET), MAX_DATA_SIZE_LEN) << "\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticBase|
	//~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticBase::DoIpDiagnosticBase(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	uint16_t DoIpDiagnosticBase::getSourceAddress() const
	{
		return htobe16(getCommonDiagnosticHeader()->sourceAddress);
	}

	uint16_t DoIpDiagnosticBase::getTargetAddress() const
	{
		return htobe16(getCommonDiagnosticHeader()->targetAddress);
	}

	void DoIpDiagnosticBase::setSourceAddress(uint16_t sourceAddress)
	{
		getCommonDiagnosticHeader()->sourceAddress = htobe16(sourceAddress);
	}

	void DoIpDiagnosticBase::setTargetAddress(uint16_t targetAddress)
	{
		getCommonDiagnosticHeader()->targetAddress = htobe16(targetAddress);
	}

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticMessage|
	//~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticMessage::DoIpDiagnosticMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpDiagnosticBase(data, dataLen, prevLayer, packet)
	{}

	DoIpDiagnosticMessage::DoIpDiagnosticMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                             const std::vector<uint8_t>& diagData)
	    : DoIpDiagnosticBase(MIN_LEN + diagData.size())
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), MIN_LEN + diagData.size());
		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
		setDiagnosticData(diagData);
	}

	const std::vector<uint8_t> DoIpDiagnosticMessage::getDiagnosticData() const
	{
		const uint8_t* diagDataPtr = m_Data + DIAGNOSTIC_DATA_OFFSET;
		return std::vector<uint8_t>(diagDataPtr, diagDataPtr + (m_DataLen - DIAGNOSTIC_DATA_OFFSET));
	}

	void DoIpDiagnosticMessage::setDiagnosticData(const std::vector<uint8_t>& data)
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

	std::string DoIpDiagnosticMessage::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		oss << "Target Address: " << std::hex << "0x" << getTargetAddress() << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticResponseMessageBase|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticResponseMessageBase::DoIpDiagnosticResponseMessageBase(uint8_t* data, size_t dataLen,
	                                                                     Layer* prevLayer, Packet* packet)
	    : DoIpDiagnosticBase(data, dataLen, prevLayer, packet)
	{}

	DoIpDiagnosticResponseMessageBase::DoIpDiagnosticResponseMessageBase(uint16_t sourceAddress, uint16_t targetAddress,
	                                                                     DoIpPayloadTypes type)
	    : DoIpDiagnosticBase(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, type, (FIXED_LEN - DOIP_HEADER_LEN));
		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
	}

	void DoIpDiagnosticResponseMessageBase::setResponseCode(uint8_t code)
	{
		getDiagnosticResponseMessageBase()->diagnosticCode = code;
	}

	uint8_t DoIpDiagnosticResponseMessageBase::getResponseCode() const
	{
		return static_cast<uint8_t>(getDiagnosticResponseMessageBase()->diagnosticCode);
	}

	const std::vector<uint8_t> DoIpDiagnosticResponseMessageBase::getPreviousMessage() const
	{
		if (hasPreviousMessage())
		{
			uint8_t* dataPtr = m_Data + PREVIOUS_MSG_OFFSET;
			return std::vector<uint8_t>(dataPtr, dataPtr + (m_DataLen - PREVIOUS_MSG_OFFSET));
		}
		else
		{
			return {};
		}
	}

	bool DoIpDiagnosticResponseMessageBase::hasPreviousMessage() const
	{
		return (m_DataLen > PREVIOUS_MSG_OFFSET);
	}

	void DoIpDiagnosticResponseMessageBase::setPreviousMessage(const std::vector<uint8_t>& msg)
	{
		size_t newPayloadLen = FIXED_LEN - DOIP_HEADER_LEN + msg.size();
		size_t currentPayloadLen = m_DataLen - PREVIOUS_MSG_OFFSET;
		setPayloadLength(newPayloadLen);
		// clear memory for old previous message
		if (hasPreviousMessage())
		{
			shortenLayer(PREVIOUS_MSG_OFFSET, currentPayloadLen);
		}
		extendLayer(PREVIOUS_MSG_OFFSET, msg.size());
		uint8_t* ptr = getDataPtr(PREVIOUS_MSG_OFFSET);
		memcpy(ptr, msg.data(), msg.size());
	}

	void DoIpDiagnosticResponseMessageBase::clearPreviousMessage()
	{
		if (hasPreviousMessage())
		{
			shortenLayer(FIXED_LEN, (m_DataLen - FIXED_LEN));
			PCPP_LOG_DEBUG("PreviousMessage has been removed successfully!");
		}
		else
		{
			PCPP_LOG_DEBUG("doip packet has no PreviousMessage field!");
		}
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticAckMessage|
	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticAckMessage::DoIpDiagnosticAckMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpDiagnosticResponseMessageBase(data, dataLen, prevLayer, packet)
	{}

	DoIpDiagnosticAckMessage::DoIpDiagnosticAckMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                                   DoIpDiagnosticAckCodes ackCode)
	    : DoIpDiagnosticResponseMessageBase(sourceAddress, targetAddress, getPayloadType())
	{
		setAckCode(ackCode);
	}

	DoIpDiagnosticAckCodes DoIpDiagnosticAckMessage::getAckCode() const
	{
		if (getResponseCode() == static_cast<uint8_t>(DoIpDiagnosticAckCodes::ACK))
			return DoIpDiagnosticAckCodes::ACK;
		else
			return DoIpDiagnosticAckCodes::UNKNOWN;
	}

	void DoIpDiagnosticAckMessage::setAckCode(DoIpDiagnosticAckCodes code)
	{
		setResponseCode(static_cast<uint8_t>(code));
	}
	// Summary method.
	std::string DoIpDiagnosticAckMessage::getSummary() const
	{
		std::ostringstream oss;
		DoIpDiagnosticAckCodes ackCode = getAckCode();
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		oss << "Target Address: " << std::hex << "0x" << getTargetAddress() << "\n";
		auto it = DoIpEnumToStringAckCode.find(ackCode);
		oss << "ACK code: " << it->second << " (0x" << static_cast<unsigned>(getResponseCode()) << ")\n";
		if (hasPreviousMessage())
		{
			oss << "Previous message: "
			    << pcpp::byteArrayToHexString(getPreviousMessage().data(), getPreviousMessage().size()) << "\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticNackMessage|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticNackMessage::DoIpDiagnosticNackMessage(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                     Packet* packet)
	    : DoIpDiagnosticResponseMessageBase(data, dataLen, prevLayer, packet)
	{}

	DoIpDiagnosticNackMessage::DoIpDiagnosticNackMessage(uint16_t sourceAddress, uint16_t targetAddress,
	                                                     DoIpDiagnosticMessageNackCodes nackCode)
	    : DoIpDiagnosticResponseMessageBase(sourceAddress, targetAddress, getPayloadType())
	{
		setNackCode(nackCode);
	}

	DoIpDiagnosticMessageNackCodes DoIpDiagnosticNackMessage::getNackCode() const
	{
		uint8_t nackCode = getResponseCode();
		if (nackCode <= static_cast<uint8_t>(DoIpDiagnosticMessageNackCodes::TRANSPORT_PROTOCOL_ERROR))
			return static_cast<DoIpDiagnosticMessageNackCodes>(nackCode);
		else
			return DoIpDiagnosticMessageNackCodes::UNKNOWN;
	}

	void DoIpDiagnosticNackMessage::setNackCode(DoIpDiagnosticMessageNackCodes code)
	{
		setResponseCode(static_cast<uint8_t>(code));
	}

	std::string DoIpDiagnosticNackMessage::getSummary() const
	{
		std::ostringstream oss;
		DoIpDiagnosticMessageNackCodes nackCode = getNackCode();
		oss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";
		oss << "Target Address: 0x" << std::hex << getTargetAddress() << "\n";

		auto it = DoIpEnumToStringDiagnosticNackCodes.find(nackCode);
		oss << "NACK code: " << it->second << " (0x" << static_cast<unsigned>(getResponseCode()) << ")\n";

		if (hasPreviousMessage())
		{
			oss << "Previous message: "
			    << pcpp::byteArrayToHexString(getPreviousMessage().data(), getPreviousMessage().size()) << "\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpAliveCheckRequest|
	//~~~~~~~~~~~~~~~~~~~~~~|
	DoIpAliveCheckRequest::DoIpAliveCheckRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleIdentificationRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleIdentificationRequest::DoIpVehicleIdentificationRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticPowerModeRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticPowerModeRequest::DoIpDiagnosticPowerModeRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpEntityStatusRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpEntityStatusRequest::DoIpEntityStatusRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::Version02Iso2012, getPayloadType(), 0);
	}
}  // namespace pcpp
