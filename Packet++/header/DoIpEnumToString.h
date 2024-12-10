#pragma once

#include <unordered_map>
#include "DoIpEnums.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @brief Mapping of DoIP Protocol Versions to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each version of the
	 * DoIP protocol as defined in ISO 13400. It maps the `DoIpProtocolVersion` enum values
	 * to their corresponding descriptions.
	 */
	static const std::unordered_map<DoIpProtocolVersion, std::string> DoIpEnumToStringProtocolVersion{
		{ DoIpProtocolVersion::defaultVersion,        "Default value for vehicle identification request messages" },
		{ DoIpProtocolVersion::version01Iso2010,      "DoIP ISO/DIS 13400-2:2010"                                 },
		{ DoIpProtocolVersion::version02Iso2012,      "DoIP ISO 13400-2:2012"                                     },
		{ DoIpProtocolVersion::version03Iso2019,      "DoIP ISO 13400-2:2019"                                     },
		{ DoIpProtocolVersion::version04Iso2019_AMD1, "DoIP ISO 13400-2:2012 AMD1"                                },
		{ DoIpProtocolVersion::reservedVersion,       "Reserved"                                                  },
	};

	/**
	 * @brief Mapping of DoIP Payload Types to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each payload type
	 * defined in the DoIP protocol as per ISO 13400. It maps the `DoIpPayloadTypes` enum values
	 * to their corresponding descriptions.
	 */
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

	/**
	 * @brief Mapping of DoIP Activation Types to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each activation type
	 * defined in the DoIP protocol as per ISO 13400. It maps the `DoIpActivationTypes` enum values
	 * to their corresponding descriptions.
	 */
	static const std::unordered_map<DoIpActivationTypes, std::string> DoIpEnumToStringActivationTypes{
		{ DoIpActivationTypes::Default,          "Default"          },
		{ DoIpActivationTypes::WWH_OBD,          "WWH-OBD"          },
		{ DoIpActivationTypes::CENTRAL_SECURITY, "Central security" },
	};

	/**
	 * @brief Mapping of DoIP Generic Header Nack Codes to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each Nack code related to
	 * the DoIP Generic Header as per ISO 13400. It maps the `DoIpGenericHeaderNackCodes` enum
	 * values to their corresponding descriptions.
	 */
	static const std::unordered_map<DoIpGenericHeaderNackCodes, std::string> DoIpEnumToStringGenericHeaderNackCodes{
		{ DoIpGenericHeaderNackCodes::INCORRECT_PATTERN,      "Incorrect pattern format" },
		{ DoIpGenericHeaderNackCodes::INKNOWN_PAYLOAD_TYPE,   "Unknown payload type"     },
		{ DoIpGenericHeaderNackCodes::INVALID_PAYLOAD_LENGTH, "Invalid payload length"   },
		{ DoIpGenericHeaderNackCodes::MESSAGE_TOO_LARGE,      "Message too large"        },
		{ DoIpGenericHeaderNackCodes::OUT_OF_MEMORY,          "Out of memory"            },
	};

	/**
	 * @brief Mapping of DoIP Action Codes to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each action code related to
	 * the DoIP announcement message, as per ISO 13400. It maps the `DoIpActionCodes` enum
	 * values to their corresponding descriptions.
	 */
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

	/**
	 * @brief Mapping of DoIP Routing Response Codes to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each routing response code
	 * related to the DoIP routing activation process, as per ISO 13400. It maps the `DoIpRoutingResponseCodes` enum
	 * values to their corresponding descriptions.
	 */
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

	/**
	 * @brief Mapping of DoIP Diagnostic Message Nack Codes to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each NACK (negative acknowledgment) code
	 * related to DoIP diagnostic messages, as per ISO 13400. It maps the `DoIpDiagnosticMessageNackCodes` enum
	 * values to their corresponding descriptions.
	 */
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

	/**
	 * @brief Mapping of DoIP Diagnostic Power Mode Codes to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for each power mode code
	 * related to DoIP diagnostics, as per ISO 13400. It maps the `DoIpDiagnosticPowerMode` enum
	 * values to their corresponding descriptions.
	 */
	static const std::unordered_map<DoIpDiagnosticPowerModeCodes, std::string> DoIpEnumToStringDiagnosticPowerModeCodes{
		{ DoIpDiagnosticPowerModeCodes::NOT_READY,     "not ready"     },
		{ DoIpDiagnosticPowerModeCodes::READY,         "ready"         },
		{ DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED, "not supported" },
	};

	/**
	 * @brief Mapping of DoIP Entity Status Codes to their respective string descriptions.
	 *
	 * This unordered map provides human-readable descriptions for the entity status codes
	 * in the context of DoIP (Diagnostic over IP). It maps the `DoIpEntityStatus` enum values
	 * to their corresponding descriptions, distinguishing between a "DoIP node" and a "DoIP gateway."
	 */
	static const std::unordered_map<DoIpEntityStatus, std::string> DoIpEnumToStringEntityStatusNodeTypes{
		{ DoIpEntityStatus::NODE,    "DoIp node"    },
		{ DoIpEntityStatus::GATEWAY, "DoIP gateway" },
	};

	/**
	 * @brief Mapping of DoIP Acknowledgement Codes to their string representations.
	 *
	 * This unordered map provides a human-readable description for the DoIP acknowledgement
	 * code `ACK`, which is used to confirm the successful reception or processing of a message.
	 */
	static const std::unordered_map<DoIpDiagnosticAckCodes, std::string> DoIpEnumToStringAckCode{
		{ DoIpDiagnosticAckCodes::ACK, "ACK" },
	};

	/**
	 * @brief A mapping of DoIP synchronization statuses to their corresponding string descriptions.
	 *
	 * This unordered map provides a human-readable string for each synchronization status
	 * defined in the `DoIpSyncStatus` enumeration. It is used to convert synchronization status
	 * values to their respective descriptions for logging or display purposes.
	 */
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
}  // namespace pcpp
