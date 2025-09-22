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
		{ DoIpRoutingResponseCodes::UNKNOWN,                           "Unknown"		                                                           }
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
		{ DoIpDiagnosticMessageNackCodes::UNKNOWN,                  "Unknown"                      }
	};

	// This unordered map provides human-readable descriptions for each power mode code
	// related to DoIP diagnostics, as per ISO 13400. It maps the `DoIpDiagnosticPowerMode` enum
	// values to their corresponding descriptions.
	static const std::unordered_map<DoIpDiagnosticPowerModeCodes, std::string> DoIpEnumToStringDiagnosticPowerModeCodes{
		{ DoIpDiagnosticPowerModeCodes::NOT_READY,     "Not ready"     },
		{ DoIpDiagnosticPowerModeCodes::READY,         "Ready"         },
		{ DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED, "Not supported" },
		{ DoIpDiagnosticPowerModeCodes::UNKNOWN,       "Unknown"       }
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
		{ DoIpProtocolVersion::DEFAULT_VALUE,      "Default value for vehicle identification request messages" },
		{ DoIpProtocolVersion::ISO13400_2010,      "DoIP ISO/DIS 13400-2:2010"                                 },
		{ DoIpProtocolVersion::ISO13400_2012,      "DoIP ISO 13400-2:2012"                                     },
		{ DoIpProtocolVersion::ISO13400_2019,      "DoIP ISO 13400-2:2019"                                     },
		{ DoIpProtocolVersion::ISO13400_2019_AMD1, "DoIP ISO 13400-2:2012 AMD1"                                },
		{ DoIpProtocolVersion::RESERVED_VER,       "Reserved"                                                  },
		{ DoIpProtocolVersion::UNKNOWN,            "Unknown Protocol Version"                                  },
	};

	// This unordered map provides human-readable descriptions for each payload type
	// defined in the DoIP protocol as per ISO 13400. It maps the `DoIpPayloadTypes` enum values
	// to their corresponding descriptions.
	static const std::unordered_map<DoIpPayloadTypes, std::string> DoIpEnumToStringPayloadType{
		{ DoIpPayloadTypes::GENERIC_HEADER_NACK,                     "Generic DOIP header Nack"                   },
		{ DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST,          "Vehicle identification request"             },
		{ DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID, "Vehicle identification request with EID"    },
		{ DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN, "Vehicle identification request with VIN"    },
		{ DoIpPayloadTypes::VEHICLE_ANNOUNCEMENT_MESSAGE,
         "Vehicle announcement message / vehicle identification response message"                                 },
		{ DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST,              "Routing activation request"                 },
		{ DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE,             "Routing activation response"                },
		{ DoIpPayloadTypes::ALIVE_CHECK_REQUEST,                     "Alive check request"                        },
		{ DoIpPayloadTypes::ALIVE_CHECK_RESPONSE,                    "Alive check response"                       },
		{ DoIpPayloadTypes::ENTITY_STATUS_REQUEST,                   "DOIP entity status request"                 },
		{ DoIpPayloadTypes::ENTITY_STATUS_RESPONSE,                  "DOIP entity status response"                },
		{ DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST,           "Diagnostic power mode request information"  },
		{ DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE,          "Diagnostic power mode response information" },
		{ DoIpPayloadTypes::DIAGNOSTIC_MESSAGE,                      "Diagnostic message"                         },
		{ DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_ACK,                  "Diagnostic message Ack"                     },
		{ DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NACK,                 "Diagnostic message Nack"                    }
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

		if (!isPayloadTypeValid(be16toh(payloadTypeRaw)))
			return false;
		// if payload type is validated, we ensure passing a valid type to isProtocolVersionValid()
		const DoIpPayloadTypes payloadType = static_cast<DoIpPayloadTypes>(be16toh(payloadTypeRaw));
		if (!isProtocolVersionValid(version, inVersion, payloadType))
			return false;

		if (!isPayloadLengthValid(be32toh(lengthRaw), dataLen))
			return false;

		return true;
	}

	DoIpLayer* DoIpLayer::parseDoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		doiphdr* doipHeader = reinterpret_cast<doiphdr*>(data);
		uint16_t payloadType = doipHeader->payloadType;
		DoIpPayloadTypes detectedPayloadType = static_cast<DoIpPayloadTypes>(be16toh(payloadType));

		switch (detectedPayloadType)
		{
		case DoIpPayloadTypes::GENERIC_HEADER_NACK:
			return (DoIpGenericHeaderNack::isDataLenValid(dataLen))
			           ? new DoIpGenericHeaderNack(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST:
			return (DoIpVehicleIdentificationRequest::isDataLenValid(dataLen))
			           ? new DoIpVehicleIdentificationRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID:
			return (DoIpVehicleIdentificationRequestWithEID::isDataLenValid(dataLen))
			           ? new DoIpVehicleIdentificationRequestWithEID(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN:
			return (DoIpVehicleIdentificationRequestWithVIN::isDataLenValid(dataLen))
			           ? new DoIpVehicleIdentificationRequestWithVIN(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::VEHICLE_ANNOUNCEMENT_MESSAGE:
			return (DoIpVehicleAnnouncementMessage::isDataLenValid(dataLen))
			           ? new DoIpVehicleAnnouncementMessage(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST:
			return (DoIpRoutingActivationRequest::isDataLenValid(dataLen))
			           ? new DoIpRoutingActivationRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE:
			return (DoIpRoutingActivationResponse::isDataLenValid(dataLen))
			           ? new DoIpRoutingActivationResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ALIVE_CHECK_REQUEST:
			return (DoIpAliveCheckRequest::isDataLenValid(dataLen))
			           ? new DoIpAliveCheckRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ALIVE_CHECK_RESPONSE:
			return (DoIpAliveCheckResponse::isDataLenValid(dataLen))
			           ? new DoIpAliveCheckResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ENTITY_STATUS_REQUEST:
			return (DoIpEntityStatusRequest::isDataLenValid(dataLen))
			           ? new DoIpEntityStatusRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::ENTITY_STATUS_RESPONSE:
			return (DoIpEntityStatusResponse::isDataLenValid(dataLen))
			           ? new DoIpEntityStatusResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST:
			return (DoIpDiagnosticPowerModeRequest::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticPowerModeRequest(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE:
			return (DoIpDiagnosticPowerModeResponse::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticPowerModeResponse(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE:
			return (DoIpDiagnosticMessage::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticMessage(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_ACK:
			return (DoIpDiagnosticMessageAck::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticMessageAck(data, dataLen, prevLayer, packet)
			           : nullptr;
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NACK:
			return (DoIpDiagnosticMessageNack::isDataLenValid(dataLen))
			           ? new DoIpDiagnosticMessageNack(data, dataLen, prevLayer, packet)
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
		case DoIpProtocolVersion::RESERVED_VER:
		case DoIpProtocolVersion::ISO13400_2010:
		case DoIpProtocolVersion::ISO13400_2012:
		case DoIpProtocolVersion::ISO13400_2019:
		case DoIpProtocolVersion::ISO13400_2019_AMD1:
		case DoIpProtocolVersion::DEFAULT_VALUE:
			return static_cast<DoIpProtocolVersion>(version);

		default:
			return DoIpProtocolVersion::UNKNOWN;
		}
	}

	std::string DoIpLayer::getProtocolVersionAsStr() const
	{
		return DoIpEnumToStringProtocolVersion.find(getProtocolVersion())->second;
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
		return be32toh(getDoIpHeader()->payloadLength);
	}

	void DoIpLayer::setPayloadLength(uint32_t payloadLength)
	{
		getDoIpHeader()->payloadLength = htobe32(payloadLength);
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
		if (getPayloadType() == DoIpPayloadTypes::DIAGNOSTIC_MESSAGE)
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

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpGenericHeaderNack|
	//~~~~~~~~~~~~~~~~~~~~~~|
	DoIpGenericHeaderNack::DoIpGenericHeaderNack(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpGenericHeaderNack::DoIpGenericHeaderNack(DoIpGenericHeaderNackCodes nackCode) : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));
		setNackCode(nackCode);
	}

	DoIpGenericHeaderNackCodes DoIpGenericHeaderNack::getNackCode() const
	{
		uint8_t nackCode = getGenericHeaderNack()->nackCode;
		if (nackCode <= static_cast<uint8_t>(DoIpGenericHeaderNackCodes::INVALID_PAYLOAD_LENGTH))
		{
			return static_cast<DoIpGenericHeaderNackCodes>(nackCode);
		}
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
	// DoIpVehicleIdentificationRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleIdentificationRequest::DoIpVehicleIdentificationRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleIdentificationRequestWithEID|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleIdentificationRequestWithEID::DoIpVehicleIdentificationRequestWithEID(uint8_t* data, size_t dataLen,
	                                                                                 Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpVehicleIdentificationRequestWithEID::DoIpVehicleIdentificationRequestWithEID(
	    const std::array<uint8_t, DOIP_EID_LEN>& eid)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), DOIP_EID_LEN);
		setEID(eid);
	}

	std::array<uint8_t, DOIP_EID_LEN> DoIpVehicleIdentificationRequestWithEID::getEID() const
	{
		return getVehicleIdentificationRequestWEID()->eid;
	}

	void DoIpVehicleIdentificationRequestWithEID::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		getVehicleIdentificationRequestWEID()->eid = eid;
	}

	std::string DoIpVehicleIdentificationRequestWithEID::getSummary() const
	{
		std::ostringstream oss;
		oss << "EID: " << pcpp::byteArrayToHexString(getEID().data(), DOIP_EID_LEN) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleIdentificationRequestWithVIN|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleIdentificationRequestWithVIN::DoIpVehicleIdentificationRequestWithVIN(uint8_t* data, size_t dataLen,
	                                                                                 Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpVehicleIdentificationRequestWithVIN::DoIpVehicleIdentificationRequestWithVIN(
	    const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), DOIP_VIN_LEN);
		setVIN(vin);
	}

	std::array<uint8_t, DOIP_VIN_LEN> DoIpVehicleIdentificationRequestWithVIN::getVIN() const
	{
		return getVehicleIdentificationRequestWVIN()->vin;
	}

	void DoIpVehicleIdentificationRequestWithVIN::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		getVehicleIdentificationRequestWVIN()->vin = vin;
	}

	std::string DoIpVehicleIdentificationRequestWithVIN::getSummary() const
	{
		std::ostringstream oss;
		oss << "VIN: " << std::string(reinterpret_cast<const char*>(getVIN().data()), DOIP_VIN_LEN) << "\n";
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleAnnouncementMessage|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpVehicleAnnouncementMessage::DoIpVehicleAnnouncementMessage(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                               Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpVehicleAnnouncementMessage::DoIpVehicleAnnouncementMessage(const std::array<uint8_t, DOIP_VIN_LEN>& vin,
	                                                               uint16_t logicalAddress,
	                                                               const std::array<uint8_t, DOIP_EID_LEN>& eid,
	                                                               const std::array<uint8_t, DOIP_GID_LEN>& gid,
	                                                               DoIpActionCodes actionCode)
	    : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));

		setVIN(vin);
		setLogicalAddress(logicalAddress);
		setEID(eid);
		setGID(gid);
		setFurtherActionRequired(actionCode);
	}

	std::array<uint8_t, DOIP_VIN_LEN> DoIpVehicleAnnouncementMessage::getVIN() const
	{
		return getVehicleAnnouncementMessage()->vin;
	}

	void DoIpVehicleAnnouncementMessage::setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin)
	{
		getVehicleAnnouncementMessage()->vin = vin;
	}

	uint16_t DoIpVehicleAnnouncementMessage::getLogicalAddress() const
	{
		return be16toh(getVehicleAnnouncementMessage()->logicalAddress);
	}

	void DoIpVehicleAnnouncementMessage::setLogicalAddress(uint16_t logicalAddress)
	{
		getVehicleAnnouncementMessage()->logicalAddress = htobe16(logicalAddress);
	}

	std::array<uint8_t, DOIP_EID_LEN> DoIpVehicleAnnouncementMessage::getEID() const
	{
		return getVehicleAnnouncementMessage()->eid;
	}

	void DoIpVehicleAnnouncementMessage::setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid)
	{
		getVehicleAnnouncementMessage()->eid = eid;
	}

	std::array<uint8_t, DOIP_GID_LEN> DoIpVehicleAnnouncementMessage::getGID() const
	{
		return getVehicleAnnouncementMessage()->gid;
	}

	void DoIpVehicleAnnouncementMessage::setGID(const std::array<uint8_t, DOIP_GID_LEN>& gid)
	{
		getVehicleAnnouncementMessage()->gid = gid;
	}

	DoIpActionCodes DoIpVehicleAnnouncementMessage::getFurtherActionRequired() const
	{
		uint8_t actionCode = getVehicleAnnouncementMessage()->actionCode;
		if (actionCode <= static_cast<uint8_t>(DoIpActionCodes::ROUTING_ACTIVATION_REQUIRED))
		{
			return static_cast<DoIpActionCodes>(actionCode);
		}
		return DoIpActionCodes::UNKNOWN;
	}

	void DoIpVehicleAnnouncementMessage::setFurtherActionRequired(DoIpActionCodes action)
	{
		getVehicleAnnouncementMessage()->actionCode = static_cast<uint8_t>(action);
	}

	DoIpSyncStatus DoIpVehicleAnnouncementMessage::getSyncStatus() const
	{
		if (!hasSyncStatus())
			throw std::runtime_error("Sync status field not present!");

		uint8_t syncStatus = *(m_Data + SYNC_STATUS_OFFSET);
		if (syncStatus <= static_cast<uint8_t>(DoIpSyncStatus::VIN_AND_OR_GID_ARE_NOT_SINCHRONIZED))
			return static_cast<DoIpSyncStatus>(syncStatus);

		return DoIpSyncStatus::UNKNOWN;
	}

	void DoIpVehicleAnnouncementMessage::setSyncStatus(DoIpSyncStatus syncStatus)
	{
		if (!hasSyncStatus())
		{
			extendLayer(SYNC_STATUS_OFFSET, SYNC_STATUS_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		*(m_Data + SYNC_STATUS_OFFSET) = static_cast<uint8_t>(syncStatus);
	}

	bool DoIpVehicleAnnouncementMessage::hasSyncStatus() const
	{
		return (m_DataLen == OPT_LEN);
	}

	void DoIpVehicleAnnouncementMessage::clearSyncStatus()
	{
		if (!hasSyncStatus())
		{
			PCPP_LOG_DEBUG("DoIP packet has no syncStatus!");
			return;
		}
		shortenLayer(SYNC_STATUS_OFFSET, SYNC_STATUS_LEN);
		setPayloadLength(FIXED_LEN - DOIP_HEADER_LEN);
	}

	std::string DoIpVehicleAnnouncementMessage::getSummary() const
	{
		std::ostringstream oss;
		oss << "VIN: " << std::string(reinterpret_cast<const char*>(getVIN().data()), DOIP_VIN_LEN) << "\n";
		oss << "Logical address: 0x" << std::hex << getLogicalAddress() << "\n";
		oss << "EID: " << pcpp::byteArrayToHexString(getEID().data(), DOIP_EID_LEN) << "\n";
		oss << "GID: " << pcpp::byteArrayToHexString(getGID().data(), DOIP_GID_LEN) << "\n";

		auto it = DoIpEnumToStringActionCodes.find(getFurtherActionRequired());
		oss << "Further action required: " << it->second << " (0x" << std::hex
		    << static_cast<unsigned>(getVehicleAnnouncementMessage()->actionCode) << ")\n";

		if (hasSyncStatus())
		{
			auto syncStatus = getSyncStatus();
			auto itSync = DoIpEnumToStringSyncStatus.find(syncStatus);
			oss << "VIN/GID sync status: " << itSync->second << " (0x" << std::hex
			    << static_cast<unsigned>(*(m_Data + SYNC_STATUS_OFFSET)) << ")\n";
		}

		return oss.str();
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
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));

		setSourceAddress(sourceAddress);
		setActivationType(activationType);
		// Reserved ISO is always all zeros
		setReservedIso({});
	}

	uint16_t DoIpRoutingActivationRequest::getSourceAddress() const
	{
		return be16toh(getRoutingActivationRequest()->sourceAddress);
	}

	void DoIpRoutingActivationRequest::setSourceAddress(uint16_t value)
	{
		getRoutingActivationRequest()->sourceAddress = htobe16(value);
	}

	DoIpActivationTypes DoIpRoutingActivationRequest::getActivationType() const
	{
		auto activationType = static_cast<DoIpActivationTypes>(getRoutingActivationRequest()->activationType);
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
		getRoutingActivationRequest()->activationType = static_cast<uint8_t>(activationType);
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> DoIpRoutingActivationRequest::getReservedIso() const
	{
		return getRoutingActivationRequest()->reservedIso;
	}

	void DoIpRoutingActivationRequest::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		getRoutingActivationRequest()->reservedIso = reservedIso;
	}

	std::array<uint8_t, DOIP_RESERVED_OEM_LEN> DoIpRoutingActivationRequest::getReservedOem() const
	{
		if (!hasReservedOem())
			throw std::runtime_error("Reserved OEM field not present!");

		std::array<uint8_t, DOIP_RESERVED_OEM_LEN> reservedOem;
		memcpy(reservedOem.data(), m_Data + RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
		return reservedOem;
	}

	void DoIpRoutingActivationRequest::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		if (!hasReservedOem())
		{
			extendLayer(RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		memcpy((m_Data + RESERVED_OEM_OFFSET), reservedOem.data(), DOIP_RESERVED_OEM_LEN);
	}

	bool DoIpRoutingActivationRequest::hasReservedOem() const
	{
		return (m_DataLen == OPT_LEN);
	}

	void DoIpRoutingActivationRequest::clearReservedOem()
	{
		if (!hasReservedOem())
		{
			PCPP_LOG_DEBUG("DoIP packet has no reserved OEM field!");
			return;
		}

		shortenLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
		setPayloadLength(FIXED_LEN - DOIP_HEADER_LEN);
		PCPP_LOG_DEBUG("Reserved OEM field has been removed successfully!");
	}

	std::string DoIpRoutingActivationRequest::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";

		auto it = DoIpEnumToStringActivationTypes.find(getActivationType());
		oss << "Activation type: " << it->second << " (0x" << std::hex
		    << static_cast<unsigned>(getRoutingActivationRequest()->activationType) << ")\n";

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
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));

		setLogicalAddressExternalTester(logicalAddressExternalTester);
		setSourceAddress(sourceAddress);
		setResponseCode(responseCode);
		setReservedIso({});
	}

	uint16_t DoIpRoutingActivationResponse::getLogicalAddressExternalTester() const
	{
		return be16toh(getRoutingActivationResponse()->logicalAddressExternalTester);
	}

	void DoIpRoutingActivationResponse::setLogicalAddressExternalTester(uint16_t addr)
	{
		getRoutingActivationResponse()->logicalAddressExternalTester = htobe16(addr);
	}

	uint16_t DoIpRoutingActivationResponse::getSourceAddress() const
	{
		return be16toh(getRoutingActivationResponse()->sourceAddress);
	}

	void DoIpRoutingActivationResponse::setSourceAddress(uint16_t sourceAddress)
	{
		getRoutingActivationResponse()->sourceAddress = htobe16(sourceAddress);
	}

	DoIpRoutingResponseCodes DoIpRoutingActivationResponse::getResponseCode() const
	{
		uint8_t code = getRoutingActivationResponse()->responseCode;
		if (code <= static_cast<uint8_t>(DoIpRoutingResponseCodes::CONFIRMATION_REQUIRED))
		{
			return static_cast<DoIpRoutingResponseCodes>(code);
		}
		return DoIpRoutingResponseCodes::UNKNOWN;
	}

	void DoIpRoutingActivationResponse::setResponseCode(DoIpRoutingResponseCodes code)
	{
		getRoutingActivationResponse()->responseCode = static_cast<uint8_t>(code);
	}

	std::array<uint8_t, DOIP_RESERVED_ISO_LEN> DoIpRoutingActivationResponse::getReservedIso() const
	{
		return getRoutingActivationResponse()->reservedIso;
	}

	void DoIpRoutingActivationResponse::setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso)
	{
		getRoutingActivationResponse()->reservedIso = reservedIso;
	}

	std::array<uint8_t, DOIP_RESERVED_OEM_LEN> DoIpRoutingActivationResponse::getReservedOem() const
	{
		if (!hasReservedOem())
			throw std::runtime_error("Reserved OEM field not present!");

		std::array<uint8_t, DOIP_RESERVED_OEM_LEN> reservedOem;
		memcpy(reservedOem.data(), m_Data + RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
		return reservedOem;
	}

	void DoIpRoutingActivationResponse::setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem)
	{
		if (!hasReservedOem())
		{
			extendLayer(RESERVED_OEM_OFFSET, DOIP_RESERVED_OEM_LEN);
		}
		setPayloadLength(OPT_LEN - DOIP_HEADER_LEN);
		memcpy((m_Data + RESERVED_OEM_OFFSET), reservedOem.data(), DOIP_RESERVED_OEM_LEN);
	}

	bool DoIpRoutingActivationResponse::hasReservedOem() const
	{
		return (m_DataLen == OPT_LEN);
	}

	void DoIpRoutingActivationResponse::clearReservedOem()
	{
		if (!hasReservedOem())
		{
			PCPP_LOG_DEBUG("DoIP packet has no reserved OEM field!");
			return;
		}

		shortenLayer(FIXED_LEN, DOIP_RESERVED_OEM_LEN);
		setPayloadLength(FIXED_LEN - DOIP_HEADER_LEN);
		PCPP_LOG_DEBUG("Reserved OEM field has been removed successfully!");
	}

	std::string DoIpRoutingActivationResponse::getSummary() const
	{
		std::ostringstream oss;
		oss << "Logical Address (Tester): 0x" << std::hex << getLogicalAddressExternalTester() << "\n";
		oss << "Source Address: 0x" << std::hex << getSourceAddress() << "\n";

		auto it = DoIpEnumToStringRoutingResponseCodes.find(getResponseCode());
		oss << "Routing activation response code: " << it->second << " (0x" << std::hex
		    << static_cast<unsigned>(getRoutingActivationResponse()->responseCode) << ")\n";

		oss << "Reserved by ISO: " << pcpp::byteArrayToHexString(getReservedIso().data(), DOIP_RESERVED_ISO_LEN)
		    << "\n";
		if (hasReservedOem())
			oss << "Reserved by OEM: " << pcpp::byteArrayToHexString(getReservedOem().data(), DOIP_RESERVED_OEM_LEN)
			    << "\n";

		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpAliveCheckRequest|
	//~~~~~~~~~~~~~~~~~~~~~~|
	DoIpAliveCheckRequest::DoIpAliveCheckRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), 0);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpAliveCheckResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpAliveCheckResponse::DoIpAliveCheckResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	DoIpAliveCheckResponse::DoIpAliveCheckResponse(uint16_t sourceAddress) : DoIpLayer(FIXED_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), DOIP_SOURCE_ADDRESS_LEN);
		setSourceAddress(sourceAddress);
	}

	uint16_t DoIpAliveCheckResponse::getSourceAddress() const
	{
		return be16toh(getAliveCheckResponse()->sourceAddress);
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

	//~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpEntityStatusRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpEntityStatusRequest::DoIpEntityStatusRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), 0);
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
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));

		setNodeType(nodeType);
		setMaxConcurrentSockets(maxConcurrentSockets);
		setCurrentlyOpenSockets(currentlyOpenSockets);
	}
	DoIpEntityStatusResponseCode DoIpEntityStatusResponse::getNodeType() const
	{
		uint8_t nodeType = getEntityStatusResponse()->nodeType;
		if (nodeType <= static_cast<uint8_t>(DoIpEntityStatusResponseCode::NODE))
		{
			return static_cast<DoIpEntityStatusResponseCode>(nodeType);
		}
		return DoIpEntityStatusResponseCode::UNKNOWN;
	}

	uint8_t DoIpEntityStatusResponse::getMaxConcurrentSockets() const
	{
		return getEntityStatusResponse()->maxConcurrentSockets;
	}

	uint8_t DoIpEntityStatusResponse::getCurrentlyOpenSockets() const
	{
		return getEntityStatusResponse()->currentlyOpenSockets;
	}

	uint32_t DoIpEntityStatusResponse::getMaxDataSize() const
	{
		if (!hasMaxDataSize())
			throw std::runtime_error("MaxDataSize field not present!");

		uint32_t value;
		std::memcpy(&value, m_Data + MAX_DATA_SIZE_OFFSET, MAX_DATA_SIZE_LEN);
		return be32toh(value);
	}

	void DoIpEntityStatusResponse::setNodeType(DoIpEntityStatusResponseCode nodeType)
	{
		getEntityStatusResponse()->nodeType = static_cast<uint8_t>(nodeType);
	}

	bool DoIpEntityStatusResponse::hasMaxDataSize() const
	{
		return (m_DataLen == OPT_LEN);
	}

	void DoIpEntityStatusResponse::clearMaxDataSize()
	{
		if (!hasMaxDataSize())
		{
			PCPP_LOG_DEBUG("DoIP packet has no MaxDataSize field!");
			return;
		}
		shortenLayer(MAX_DATA_SIZE_OFFSET, MAX_DATA_SIZE_LEN);
		setPayloadLength(FIXED_LEN - DOIP_HEADER_LEN);
		PCPP_LOG_DEBUG("MaxDataSize has been removed successfully!");
	}

	void DoIpEntityStatusResponse::setMaxConcurrentSockets(uint8_t sockets)
	{
		getEntityStatusResponse()->maxConcurrentSockets = sockets;
	}

	void DoIpEntityStatusResponse::setCurrentlyOpenSockets(uint8_t sockets)
	{
		getEntityStatusResponse()->currentlyOpenSockets = sockets;
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
		auto it = DoIpEnumToStringEntityStatusNodeTypes.find(getNodeType());

		oss << "Entity status: " << it->second << " (0x" << std::hex
		    << static_cast<unsigned>(getEntityStatusResponse()->nodeType) << ")" << "\n";
		oss << "Max Concurrent Socket: " << static_cast<unsigned>(getMaxConcurrentSockets()) << "\n";
		oss << "Currently Opened Socket: " << static_cast<unsigned>(getCurrentlyOpenSockets()) << "\n";
		if (hasMaxDataSize())
		{
			oss << "Max Data Size: "
			    << "0x" << pcpp::byteArrayToHexString((m_Data + MAX_DATA_SIZE_OFFSET), MAX_DATA_SIZE_LEN) << "\n";
		}
		return oss.str();
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticPowerModeRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticPowerModeRequest::DoIpDiagnosticPowerModeRequest() : DoIpLayer(DOIP_HEADER_LEN)
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), 0);
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
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), (FIXED_LEN - DOIP_HEADER_LEN));
		setPowerModeCode(code);
	}

	DoIpDiagnosticPowerModeCodes DoIpDiagnosticPowerModeResponse::getPowerModeCode() const
	{
		uint8_t powerModeCode = getDiagnosticPowerModeResponse()->powerModeCode;
		if (powerModeCode <= static_cast<uint8_t>(DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED))
		{
			return static_cast<DoIpDiagnosticPowerModeCodes>(powerModeCode);
		}
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

	//~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticBase|
	//~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticBase::DoIpDiagnosticBase(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpLayer(data, dataLen, prevLayer, packet)
	{}

	uint16_t DoIpDiagnosticBase::getSourceAddress() const
	{
		return be16toh(getCommonDiagnosticHeader()->sourceAddress);
	}

	void DoIpDiagnosticBase::setSourceAddress(uint16_t sourceAddress)
	{
		getCommonDiagnosticHeader()->sourceAddress = htobe16(sourceAddress);
	}

	uint16_t DoIpDiagnosticBase::getTargetAddress() const
	{
		return be16toh(getCommonDiagnosticHeader()->targetAddress);
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
	                                             const std::vector<uint8_t>& diagnosticData)
	    : DoIpDiagnosticBase(MIN_LEN + diagnosticData.size())
	{
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, getPayloadType(), MIN_LEN + diagnosticData.size());
		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
		setDiagnosticData(diagnosticData);
	}

	std::vector<uint8_t> DoIpDiagnosticMessage::getDiagnosticData() const
	{
		const uint8_t* diagDataPtr = m_Data + DIAGNOSTIC_DATA_OFFSET;
		return std::vector<uint8_t>(diagDataPtr, diagDataPtr + (m_DataLen - DIAGNOSTIC_DATA_OFFSET));
	}

	void DoIpDiagnosticMessage::setDiagnosticData(const std::vector<uint8_t>& data)
	{
		const size_t newPayloadLength = DOIP_SOURCE_ADDRESS_LEN + DOIP_TARGET_ADDRESS_LEN + data.size();
		const size_t currentDiagnosticDataLen = m_DataLen - DIAGNOSTIC_DATA_OFFSET;
		setPayloadLength(newPayloadLength);

		ptrdiff_t layerExtensionLen =
		    static_cast<ptrdiff_t>(data.size()) - static_cast<ptrdiff_t>(currentDiagnosticDataLen);
		if (layerExtensionLen > 0)
		{
			extendLayer(DIAGNOSTIC_DATA_OFFSET + currentDiagnosticDataLen, layerExtensionLen);
		}
		else if (layerExtensionLen < 0)
		{
			shortenLayer(DIAGNOSTIC_DATA_OFFSET + data.size(), (-1 * layerExtensionLen));
		}
		memcpy((m_Data + DIAGNOSTIC_DATA_OFFSET), data.data(), data.size());
	}

	std::string DoIpDiagnosticMessage::getSummary() const
	{
		std::ostringstream oss;
		oss << "Source Address: " << std::hex << "0x" << getSourceAddress() << "\n";
		oss << "Target Address: " << std::hex << "0x" << getTargetAddress() << "\n";
		// Diagnostic data should be parsed by nextLayer (uds layer)
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
		setHeaderFields(DoIpProtocolVersion::ISO13400_2012, type, (FIXED_LEN - DOIP_HEADER_LEN));
		setSourceAddress(sourceAddress);
		setTargetAddress(targetAddress);
	}

	void DoIpDiagnosticResponseMessageBase::setResponseCode(uint8_t code)
	{
		getDiagnosticResponseMessageBase()->diagnosticCode = code;
	}

	uint8_t DoIpDiagnosticResponseMessageBase::getResponseCode() const
	{
		return getDiagnosticResponseMessageBase()->diagnosticCode;
	}

	std::vector<uint8_t> DoIpDiagnosticResponseMessageBase::getPreviousMessage() const
	{
		if (!hasPreviousMessage())
			return {};

		const uint8_t* dataPtr = m_Data + PREVIOUS_MSG_OFFSET;
		return std::vector<uint8_t>(dataPtr, dataPtr + (m_DataLen - PREVIOUS_MSG_OFFSET));
	}

	bool DoIpDiagnosticResponseMessageBase::hasPreviousMessage() const
	{
		return (m_DataLen > FIXED_LEN);
	}

	void DoIpDiagnosticResponseMessageBase::setPreviousMessage(const std::vector<uint8_t>& msg)
	{
		const size_t newPayloadLen = FIXED_LEN - DOIP_HEADER_LEN + msg.size();
		const size_t currentPayloadLen = m_DataLen - PREVIOUS_MSG_OFFSET;
		setPayloadLength(newPayloadLen);

		int layerExtensionLen = static_cast<int>(msg.size()) - static_cast<int>(currentPayloadLen);
		if (layerExtensionLen > 0)
		{
			extendLayer(PREVIOUS_MSG_OFFSET + currentPayloadLen, layerExtensionLen);
		}
		else if (layerExtensionLen < 0)
		{
			shortenLayer(PREVIOUS_MSG_OFFSET + msg.size(), (-1 * layerExtensionLen));
		}
		memcpy((m_Data + PREVIOUS_MSG_OFFSET), msg.data(), msg.size());
	}

	void DoIpDiagnosticResponseMessageBase::clearPreviousMessage()
	{
		if (!hasPreviousMessage())
		{
			PCPP_LOG_DEBUG("DoIP packet has no PreviousMessage field!");
			return;
		}
		shortenLayer(FIXED_LEN, (m_DataLen - FIXED_LEN));
		setPayloadLength(FIXED_LEN - DOIP_HEADER_LEN);
		PCPP_LOG_DEBUG("PreviousMessage field has been removed successfully!");
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticMessageAck|
	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticMessageAck::DoIpDiagnosticMessageAck(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : DoIpDiagnosticResponseMessageBase(data, dataLen, prevLayer, packet)
	{}

	DoIpDiagnosticMessageAck::DoIpDiagnosticMessageAck(uint16_t sourceAddress, uint16_t targetAddress,
	                                                   DoIpDiagnosticAckCodes ackCode)
	    : DoIpDiagnosticResponseMessageBase(sourceAddress, targetAddress, getPayloadType())
	{
		setAckCode(ackCode);
	}

	DoIpDiagnosticAckCodes DoIpDiagnosticMessageAck::getAckCode() const
	{
		return (getResponseCode() == static_cast<uint8_t>(DoIpDiagnosticAckCodes::ACK))
		           ? DoIpDiagnosticAckCodes::ACK
		           : DoIpDiagnosticAckCodes::UNKNOWN;
	}

	void DoIpDiagnosticMessageAck::setAckCode(DoIpDiagnosticAckCodes code)
	{
		setResponseCode(static_cast<uint8_t>(code));
	}

	std::string DoIpDiagnosticMessageAck::getSummary() const
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
	// DoIpDiagnosticMessageNack|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	DoIpDiagnosticMessageNack::DoIpDiagnosticMessageNack(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                     Packet* packet)
	    : DoIpDiagnosticResponseMessageBase(data, dataLen, prevLayer, packet)
	{}

	DoIpDiagnosticMessageNack::DoIpDiagnosticMessageNack(uint16_t sourceAddress, uint16_t targetAddress,
	                                                     DoIpDiagnosticMessageNackCodes nackCode)
	    : DoIpDiagnosticResponseMessageBase(sourceAddress, targetAddress, getPayloadType())
	{
		setNackCode(nackCode);
	}

	DoIpDiagnosticMessageNackCodes DoIpDiagnosticMessageNack::getNackCode() const
	{
		uint8_t nackCode = getResponseCode();
		if (nackCode <= static_cast<uint8_t>(DoIpDiagnosticMessageNackCodes::TRANSPORT_PROTOCOL_ERROR))
		{
			return static_cast<DoIpDiagnosticMessageNackCodes>(nackCode);
		}
		return DoIpDiagnosticMessageNackCodes::UNKNOWN;
	}

	void DoIpDiagnosticMessageNack::setNackCode(DoIpDiagnosticMessageNackCodes code)
	{
		setResponseCode(static_cast<uint8_t>(code));
	}

	std::string DoIpDiagnosticMessageNack::getSummary() const
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
}  // namespace pcpp
