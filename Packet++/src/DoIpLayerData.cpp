#include "DoIpLayerData.h"
#include "DoIpLayer.h"
#include "GeneralUtils.h"

namespace pcpp
{
	/// @brief Mapping of DoIP Activation Types to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each activation type
	/// defined in the DoIP protocol as per ISO 13400. It maps the `DoIpActivationTypes` enum values
	/// to their corresponding descriptions.
	const std::unordered_map<DoIpActivationTypes, std::string> DoIpEnumToStringActivationTypes{
		{ DoIpActivationTypes::Default,          "Default"          },
		{ DoIpActivationTypes::WWH_OBD,          "WWH-OBD"          },
		{ DoIpActivationTypes::CENTRAL_SECURITY, "Central security" },
	};

	/// @brief Mapping of DoIP Generic Header Nack Codes to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each Nack code related to
	/// the DoIP Generic Header as per ISO 13400. It maps the `DoIpGenericHeaderNackCodes` enum
	/// values to their corresponding descriptions.
	const std::unordered_map<DoIpGenericHeaderNackCodes, std::string> DoIpEnumToStringGenericHeaderNackCodes{
		{ DoIpGenericHeaderNackCodes::INCORRECT_PATTERN,      "Incorrect pattern format" },
		{ DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE,   "Unknown payload type"     },
		{ DoIpGenericHeaderNackCodes::INVALID_PAYLOAD_LENGTH, "Invalid payload length"   },
		{ DoIpGenericHeaderNackCodes::MESSAGE_TOO_LARGE,      "Message too large"        },
		{ DoIpGenericHeaderNackCodes::OUT_OF_MEMORY,          "Out of memory"            },
	};

	/// @brief Mapping of DoIP Action Codes to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each action code related to
	/// the DoIP announcement message, as per ISO 13400. It maps the `DoIpActionCodes` enum
	/// values to their corresponding descriptions.
	const std::unordered_map<DoIpActionCodes, std::string> DoIpEnumToStringActionCodes{
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

	/// @brief Mapping of DoIP Routing Response Codes to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each routing response code
	/// related to the DoIP routing activation process, as per ISO 13400. It maps the `DoIpRoutingResponseCodes`
	/// enum values to their corresponding descriptions.
	const std::unordered_map<DoIpRoutingResponseCodes, std::string> DoIpEnumToStringRoutingResponseCodes{
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

	/// @brief Mapping of DoIP Diagnostic Message Nack Codes to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each NACK (negative acknowledgment) code
	/// related to DoIP diagnostic messages, as per ISO 13400. It maps the `DoIpDiagnosticMessageNackCodes` enum
	/// values to their corresponding descriptions.
	const std::unordered_map<DoIpDiagnosticMessageNackCodes, std::string> DoIpEnumToStringDiagnosticNackCodes{
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

	/// @brief Mapping of DoIP Diagnostic Power Mode Codes to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for each power mode code
	/// related to DoIP diagnostics, as per ISO 13400. It maps the `DoIpDiagnosticPowerMode` enum
	/// values to their corresponding descriptions.
	const std::unordered_map<DoIpDiagnosticPowerModeCodes, std::string> DoIpEnumToStringDiagnosticPowerModeCodes{
		{ DoIpDiagnosticPowerModeCodes::NOT_READY,     "not ready"     },
		{ DoIpDiagnosticPowerModeCodes::READY,         "ready"         },
		{ DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED, "not supported" },
	};

	/// @brief Mapping of DoIP Entity Status Codes to their respective string descriptions.
	///
	/// This unordered map provides human-readable descriptions for the entity status codes
	/// in the context of DoIP (Diagnostic over IP). It maps the `DoIpEntityStatus` enum values
	/// to their corresponding descriptions, distinguishing between a "DoIP node" and a "DoIP gateway."
	const std::unordered_map<DoIpEntityStatus, std::string> DoIpEnumToStringEntityStatusNodeTypes{
		{ DoIpEntityStatus::NODE,    "DoIp node"    },
		{ DoIpEntityStatus::GATEWAY, "DoIP gateway" },
	};

	/// @brief Mapping of DoIP Acknowledgement Codes to their string representations.
	///
	/// This unordered map provides a human-readable description for the DoIP acknowledgement
	/// code `ACK`, which is used to confirm the successful reception or processing of a message.
	const std::unordered_map<DoIpDiagnosticAckCodes, std::string> DoIpEnumToStringAckCode{
		{ DoIpDiagnosticAckCodes::ACK, "ACK" },
	};

	/// @brief A mapping of DoIP synchronization statuses to their corresponding string descriptions.
	///
	/// This unordered map provides a human-readable string for each synchronization status
	/// defined in the `DoIpSyncStatus` enumeration. It is used to convert synchronization status
	/// values to their respective descriptions for logging or display purposes.
	const std::unordered_map<DoIpSyncStatus, std::string> DoIpEnumToStringSyncStatus{
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

	RoutingActivationRequestData::RoutingActivationRequestData()
	    : sourceAddress(0x0000), activationType(DoIpActivationTypes::Default), reservedIso{}, reservedOem(nullptr) {};

	DoIpPayloadTypes RoutingActivationRequestData::getType() const
	{
		return DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST;
	}

	std::string RoutingActivationRequestData::toString() const
	{
		std::stringstream os;
		os << "sourceAddress: " << std::hex << "0x" << htobe16(sourceAddress) << "\n";
		auto it = DoIpEnumToStringActivationTypes.find(activationType);
		if (it != DoIpEnumToStringActivationTypes.end())
		{
			os << "activation type: " << it->second << std::hex << " (0x" << unsigned(activationType) << ")" << "\n";
		}
		else
		{
			os << "activation type: Unknown" << std::hex << " (0x" << unsigned(activationType) << ")" << "\n";
		}
		os << "reserved by ISO: " << pcpp::byteArrayToHexString(reservedIso.data(), DOIP_RESERVED_ISO_LEN) << "\n";
		if (reservedOem)
		{
			os << "Reserved by OEM: " << pcpp::byteArrayToHexString(reservedOem->data(), DOIP_RESERVED_OEM_LEN) << '\n';
		}
		return os.str();
	}

	std::vector<uint8_t> RoutingActivationRequestData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(sourceAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((sourceAddress >> 8) & 0xFF));
		data.push_back(static_cast<uint8_t>(activationType));
		data.insert(data.end(), reservedIso.begin(), reservedIso.end());
		if (reservedOem)
		{
			data.insert(data.end(), reservedOem->begin(), reservedOem->end());
		}
		return data;
	}

	// buildFromLayer implementation
	bool RoutingActivationRequestData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve routing activation request data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength = sizeof(sourceAddress) + sizeof(activationType) + DOIP_RESERVED_ISO_LEN;

		if (doipLayer.getDataLen() - sizeof(doiphdr) < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for routing activation request payload");
			return false;
		}

		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		sourceAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);
		dataPtr += sizeof(sourceAddress);

		activationType = static_cast<DoIpActivationTypes>(dataPtr[0]);
		dataPtr += sizeof(activationType);

		std::copy(dataPtr, dataPtr + DOIP_RESERVED_ISO_LEN, reservedIso.begin());
		dataPtr += DOIP_RESERVED_ISO_LEN;

		if (doipLayer.getDataLen() - (sizeof(doiphdr) + fixedFieldLength) == DOIP_RESERVED_OEM_LEN)
		{
			reservedOem = std::unique_ptr<std::array<uint8_t, DOIP_RESERVED_OEM_LEN>>(
			    new std::array<uint8_t, DOIP_RESERVED_OEM_LEN>());
			std::copy(dataPtr, dataPtr + DOIP_RESERVED_OEM_LEN, reservedOem->begin());
		}
		else
		{
			PCPP_LOG_DEBUG("Reserved OEM field is empty or has invalid size !");
			reservedOem.reset();
		}
		return true;
	}

	// Routing Response function definition
	RoutingActivationResponseData::RoutingActivationResponseData()
	    : logicalAddressExternalTester(0x0000), sourceAddress(0x0000),
	      responseCode(DoIpRoutingResponseCodes::CONFIRMATION_REQUIRED), reservedIso{}, reservedOem(nullptr)
	{}

	DoIpPayloadTypes RoutingActivationResponseData::getType() const
	{
		return DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE;
	}

	std::string RoutingActivationResponseData::toString() const
	{
		std::stringstream os;
		os << "logical address of external tester: " << std::hex << "0x" << htobe16(logicalAddressExternalTester)
		   << "\n";
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << "\n";
		auto it = DoIpEnumToStringRoutingResponseCodes.find(responseCode);
		if (it != DoIpEnumToStringRoutingResponseCodes.end())
		{
			os << "routing activation response code: " << it->second << std::hex << " (0x" << unsigned(responseCode)
			   << ")" << "\n";
		}
		else
		{
			os << "routing activation response code: Unknown" << std::hex << " (0x" << unsigned(responseCode) << ")"
			   << "\n";
		}
		os << "reserved by ISO: " << pcpp::byteArrayToHexString(reservedIso.data(), DOIP_RESERVED_ISO_LEN) << "\n";
		if (reservedOem)
		{
			os << "Reserved by OEM: " << pcpp::byteArrayToHexString(reservedOem->data(), DOIP_RESERVED_OEM_LEN) << "\n";
		}
		return os.str();
	}
	std::vector<uint8_t> RoutingActivationResponseData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(logicalAddressExternalTester & 0xFF));
		data.push_back(static_cast<uint8_t>((logicalAddressExternalTester >> 8) & 0xFF));

		data.push_back(static_cast<uint8_t>(sourceAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((sourceAddress >> 8) & 0xFF));

		data.push_back(static_cast<uint8_t>(responseCode));  // Convert enum to byte
		data.insert(data.end(), reservedIso.begin(), reservedIso.end());
		if (reservedOem)
		{
			data.insert(data.end(), reservedOem->begin(), reservedOem->end());
		}
		return data;
	}

	bool RoutingActivationResponseData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve routing activation response data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		if (doipLayer.getDataLen() - sizeof(doiphdr) <
		    sizeof(logicalAddressExternalTester) + sizeof(sourceAddress) + sizeof(responseCode) + DOIP_RESERVED_ISO_LEN)
		{
			PCPP_LOG_ERROR("Insufficient data length for routing activation response payload");
			return false;
		}

		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		logicalAddressExternalTester = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);
		dataPtr += sizeof(logicalAddressExternalTester);

		sourceAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);
		dataPtr += sizeof(sourceAddress);

		responseCode = static_cast<DoIpRoutingResponseCodes>(dataPtr[0]);
		dataPtr += sizeof(responseCode);

		std::copy(dataPtr, dataPtr + DOIP_RESERVED_ISO_LEN, reservedIso.begin());
		dataPtr += DOIP_RESERVED_ISO_LEN;

		if (doipLayer.getDataLen() - (sizeof(doiphdr) + sizeof(logicalAddressExternalTester) + sizeof(sourceAddress) +
		                              sizeof(responseCode) + DOIP_RESERVED_ISO_LEN) ==
		    DOIP_RESERVED_OEM_LEN)
		{
			reservedOem = std::unique_ptr<std::array<uint8_t, DOIP_RESERVED_OEM_LEN>>(
			    new std::array<uint8_t, DOIP_RESERVED_OEM_LEN>());
			std::copy(dataPtr, dataPtr + DOIP_RESERVED_OEM_LEN, reservedOem->begin());
		}
		else
		{
			PCPP_LOG_DEBUG("Reserved OEM field is empty or has invalid size !");
			reservedOem.reset();  // Clear reservedOem if not present
		}

		return true;
	}

	// Generic header nack function definition
	GenericHeaderNackData::GenericHeaderNackData() : genericNackCode(DoIpGenericHeaderNackCodes::INVALID_PAYLOAD_LENGTH)
	{}

	DoIpPayloadTypes GenericHeaderNackData::getType() const
	{
		return DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK;
	}

	std::string GenericHeaderNackData::toString() const
	{
		std::stringstream os;
		auto it = DoIpEnumToStringGenericHeaderNackCodes.find(genericNackCode);
		if (it != DoIpEnumToStringGenericHeaderNackCodes.end())
		{
			os << "generic header nack code: " << it->second << std::hex << " (0x" << unsigned(genericNackCode) << ")"
			   << "\n";
		}
		else
		{
			os << "generic header nack code: Unknown" << std::hex << " (0x" << unsigned(genericNackCode) << ")" << "\n";
		}
		return os.str();
	}
	std::vector<uint8_t> GenericHeaderNackData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(genericNackCode));  // Convert enum to byte
		return data;
	}

	// buildFromLayer fun implementation
	bool GenericHeaderNackData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Generic Header NACK data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		// Validate data length (1 byte is expected for genericNackCode)
		if (doipLayer.getDataLen() - sizeof(doiphdr) < 1)
		{
			PCPP_LOG_ERROR("Insufficient data length for Generic Header NACK payload");
			return false;
		}

		// Extract the NACK code (1 byte)
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		genericNackCode = static_cast<DoIpGenericHeaderNackCodes>(dataPtr[0]);

		return true;
	}

	// vehicle ideentification with EID functions definition
	VehicleIdentificationRequestEIDData::VehicleIdentificationRequestEIDData() : eid{}
	{}
	DoIpPayloadTypes VehicleIdentificationRequestEIDData::getType() const
	{
		return DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID;
	}
	std::string VehicleIdentificationRequestEIDData::toString() const
	{
		std::stringstream os;
		os << "EID: " << pcpp::byteArrayToHexString(eid.data(), DOIP_EID_LEN) << "\n";
		return os.str();
	}
	std::vector<uint8_t> VehicleIdentificationRequestEIDData::getData() const
	{
		// Copy each field's data into the vector
		return std::vector<uint8_t>(eid.begin(), eid.end());
	}

	bool VehicleIdentificationRequestEIDData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Vehicle Identification Request with EID data from " +
			               doipLayer.getPayloadTypeAsStr());
			return false;
		}

		// Validate data length (must at least accommodate EID length)
		if (doipLayer.getDataLen() - sizeof(doiphdr) != DOIP_EID_LEN)
		{
			PCPP_LOG_ERROR("Insufficient data length for Vehicle Identification Request with EID payload");
			return false;
		}

		// Extract the EID
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		std::copy(dataPtr, dataPtr + DOIP_EID_LEN, eid.begin());

		return true;
	}

	// vehicle ideentification with VIN functions definition
	VehicleIdentificationRequestVINData::VehicleIdentificationRequestVINData() : vin{}
	{}
	DoIpPayloadTypes VehicleIdentificationRequestVINData::getType() const
	{
		return DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN;
	}
	std::string VehicleIdentificationRequestVINData::toString() const
	{
		std::stringstream os;
		os << "VIN: " << std::string(reinterpret_cast<const char*>(vin.data()), vin.size()) << "\n";
		return os.str();
	}
	std::vector<uint8_t> VehicleIdentificationRequestVINData::getData() const
	{
		// Copy each field's data into the vector
		return std::vector<uint8_t>(vin.begin(), vin.end());
	}

	bool VehicleIdentificationRequestVINData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Vehicle Identification Request with VIN data from " +
			               doipLayer.getPayloadTypeAsStr());
			return false;
		}

		// Validate data length (must at least accommodate VIN length)
		if (doipLayer.getDataLen() - sizeof(doiphdr) != DOIP_VIN_LEN)
		{
			PCPP_LOG_ERROR("Insufficient data length for Vehicle Identification Request with EID payload");
			return false;
		}

		// Extract the VIN
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		std::copy(dataPtr, dataPtr + DOIP_VIN_LEN, vin.begin());

		return true;
	}

	// vehicle announcement functions definition
	VehicleAnnouncementData::VehicleAnnouncementData()
	    : vin{},                                                               // Initialize VIN to all zeros
	      logicalAddress(0),                                                   // Set logical address to 0
	      eid{},                                                               // Initialize EID to all zeros
	      gid{},                                                               // Initialize GID to all zeros
	      furtherActionRequired(DoIpActionCodes::NO_FURTHER_ACTION_REQUIRED),  // No further action required
	      syncStatus(DoIpSyncStatus::NON_INITIALIZED)                          // not initialized sync status field
	{};

	DoIpPayloadTypes VehicleAnnouncementData::getType() const
	{
		return DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE;
	}

	std::string VehicleAnnouncementData::toString() const
	{
		std::stringstream os;
		os << "VIN: " << std::string(reinterpret_cast<const char*>(vin.data()), vin.size()) << "\n";
		os << "logical address: " << std::hex << "0x" << htobe16(logicalAddress) << "\n";
		os << "EID: " << pcpp::byteArrayToHexString(eid.data(), DOIP_EID_LEN) << "\n";
		os << "GID: " << pcpp::byteArrayToHexString(gid.data(), DOIP_GID_LEN) << "\n";
		auto it = DoIpEnumToStringActionCodes.find(furtherActionRequired);
		if (it != DoIpEnumToStringActionCodes.end())
		{
			os << "further action required:" << it->second << std::hex << " (0x" << unsigned(furtherActionRequired)
			   << ")" << "\n";
		}
		else
		{
			os << "further action required: Unknown" << std::hex << " (0x" << unsigned(furtherActionRequired) << ")"
			   << "\n";
		}

		auto it_ = DoIpEnumToStringSyncStatus.find(syncStatus);
		if (it_ != DoIpEnumToStringSyncStatus.end())
		{
			os << "VIN/GID sync status: " << it_->second << "\n";  // Convert enum to byte
		}
		else
		{
			os << "VIN/GID sync status: Unknown" << std::hex << " (0x" << unsigned(syncStatus) << ")" << "\n";
		}

		return os.str();
	}

	std::vector<uint8_t> VehicleAnnouncementData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), vin.begin(), vin.end());
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&logicalAddress),
		            reinterpret_cast<const uint8_t*>(&logicalAddress) + sizeof(logicalAddress));
		data.insert(data.end(), eid.begin(), eid.end());
		data.insert(data.end(), gid.begin(), gid.end());
		data.push_back(static_cast<uint8_t>(furtherActionRequired));  // Convert enum to byte
		// optional field can be non-initialised
		if (syncStatus != DoIpSyncStatus::NON_INITIALIZED)
		{
			data.push_back(static_cast<uint8_t>(syncStatus));  // Convert enum to byte
		}
		return data;
	}

	bool VehicleAnnouncementData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Vehicle Announcement data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		// Validate minimum data length
		size_t fixedFieldLength =
		    DOIP_VIN_LEN + sizeof(logicalAddress) + DOIP_EID_LEN + DOIP_GID_LEN + 1;  // 1 for furtherActionRequired
		if (doipLayer.getDataLen() - sizeof(doiphdr) < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Vehicle Announcement payload");
			return false;
		}

		// Parse fields from payload
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));

		// VIN
		std::copy(dataPtr, dataPtr + DOIP_VIN_LEN, vin.begin());
		dataPtr += DOIP_VIN_LEN;

		// Logical Address
		logicalAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);
		dataPtr += sizeof(logicalAddress);

		// EID
		std::copy(dataPtr, dataPtr + DOIP_EID_LEN, eid.begin());
		dataPtr += DOIP_EID_LEN;

		// GID
		std::copy(dataPtr, dataPtr + DOIP_GID_LEN, gid.begin());
		dataPtr += DOIP_GID_LEN;

		// Further Action Required
		furtherActionRequired = static_cast<DoIpActionCodes>(*dataPtr);
		dataPtr += sizeof(furtherActionRequired);

		// Optional Sync Status
		if (doipLayer.getDataLen() - sizeof(doiphdr) > fixedFieldLength)
		{
			syncStatus = static_cast<DoIpSyncStatus>(*dataPtr);
		}
		else
		{
			syncStatus = DoIpSyncStatus::NON_INITIALIZED;
		}

		return true;
	}

	// alive check response functions definition
	AliveCheckResponseData::AliveCheckResponseData() : sourceAddress(0x0000)
	{}
	DoIpPayloadTypes AliveCheckResponseData::getType() const
	{
		return DoIpPayloadTypes::ALIVE_CHECK_RESPONSE;
	}
	std::string AliveCheckResponseData::toString() const
	{
		std::stringstream os;
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << "\n";
		return os.str();
	}
	std::vector<uint8_t> AliveCheckResponseData::getData() const
	{
		std::vector<uint8_t> data;

		data.push_back(static_cast<uint8_t>(sourceAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((sourceAddress >> 8) & 0xFF));

		return data;
	}

	bool AliveCheckResponseData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Alive Check Response data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		// Validate minimum data length
		constexpr size_t fixedFieldLength = sizeof(sourceAddress);
		if (doipLayer.getDataLen() - sizeof(doiphdr) != fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Alive Check Response payload");
			return false;
		}

		// Parse sourceAddress from payload
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		sourceAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);

		return true;
	}

	// Diagnostic Power Mode Response functions definition
	DiagnosticPowerModeResponseData::DiagnosticPowerModeResponseData()
	    : powerModeCode(DoIpDiagnosticPowerModeCodes::NOT_READY)
	{}

	DoIpPayloadTypes DiagnosticPowerModeResponseData::getType() const
	{
		return DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE;
	}

	std::string DiagnosticPowerModeResponseData::toString() const
	{
		std::stringstream os;
		auto it = DoIpEnumToStringDiagnosticPowerModeCodes.find(powerModeCode);
		if (it != DoIpEnumToStringDiagnosticPowerModeCodes.end())
		{
			os << "diagnostic power mode: " << it->second << std::hex << " (0x" << unsigned(powerModeCode) << ")"
			   << "\n";
		}
		else
		{
			os << "diagnostic power mode: Unknown" << std::hex << " (0x" << unsigned(powerModeCode) << ")" << "\n";
		}
		return os.str();
	}

	std::vector<uint8_t> DiagnosticPowerModeResponseData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(powerModeCode));  // Convert enum to byte
		return data;
	}

	bool DiagnosticPowerModeResponseData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic Power Mode Response data from " +
			               doipLayer.getPayloadTypeAsStr());
			return false;
		}

		// Validate minimum data length
		constexpr size_t fixedFieldLength = sizeof(powerModeCode);
		if (doipLayer.getDataLen() - sizeof(doiphdr) < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic Power Mode Response payload");
			return false;
		}

		// Parse powerModeCode from payload
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		powerModeCode = static_cast<DoIpDiagnosticPowerModeCodes>(dataPtr[0]);

		return true;
	}

	// Entity status response functions definitions
	EntityStatusResponseData::EntityStatusResponseData()
	    : nodeType(DoIpEntityStatus::GATEWAY), maxConcurrentSockets(0), currentlyOpenSockets(0), maxDataSize(nullptr)
	{}

	DoIpPayloadTypes EntityStatusResponseData::getType() const
	{
		return DoIpPayloadTypes::ENTITY_STATUS_RESPONSE;
	}

	std::string EntityStatusResponseData::toString() const
	{
		std::stringstream os;
		auto it = DoIpEnumToStringEntityStatusNodeTypes.find(nodeType);
		if (it != DoIpEnumToStringEntityStatusNodeTypes.end())
		{
			os << "Entity status: " << it->second << std::hex << " (0x" << unsigned(nodeType) << ")" << "\n";
		}
		else
		{
			os << "Node Type: Unknown" << std::hex << " (0x" << unsigned(nodeType) << ")" << "\n";
		}
		os << "maximum Concurrent Socket: " << unsigned(maxConcurrentSockets) << "\n";
		os << "currently Opened Socket: " << unsigned(currentlyOpenSockets) << "\n";
		if (maxDataSize)
		{
			os << "maximum Data Size: "
			   << "0x" << pcpp::byteArrayToHexString(maxDataSize->data(), 4) << "\n";
		}

		return os.str();
	}

	std::vector<uint8_t> EntityStatusResponseData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(nodeType));
		data.push_back(static_cast<uint8_t>(maxConcurrentSockets));
		data.push_back(static_cast<uint8_t>(currentlyOpenSockets));

		// optional field
		if (maxDataSize)
		{
			data.insert(data.end(), maxDataSize->begin(), maxDataSize->end());
		}
		return data;
	}

	bool EntityStatusResponseData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Entity Status Response data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength =
		    sizeof(nodeType) + sizeof(maxConcurrentSockets) + sizeof(currentlyOpenSockets);
		constexpr size_t optionalFieldLength = 4;  // Length of maxDataSize field
		size_t totalDataLength = doipLayer.getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Entity Status Response fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		nodeType = static_cast<DoIpEntityStatus>(dataPtr[0]);
		maxConcurrentSockets = dataPtr[1];
		currentlyOpenSockets = dataPtr[2];

		// Parse optional maxDataSize field if present
		if (totalDataLength == (fixedFieldLength + optionalFieldLength))
		{
			maxDataSize = std::unique_ptr<std::array<uint8_t, optionalFieldLength>>(
			    new std::array<uint8_t, optionalFieldLength>());
			std::copy(dataPtr + fixedFieldLength, dataPtr + fixedFieldLength + optionalFieldLength,
			          maxDataSize->begin());
		}
		else
		{
			// Optional field not present
			maxDataSize = nullptr;
		}

		return true;
	}

	// Diagnostic Message functions definitions
	DiagnosticMessageData::DiagnosticMessageData()
	    : sourceAddress(0x0000), targetAddress(0x0000), diagnosticData{ 0x22, 0xf1, 0x68 }
	{}
	DoIpPayloadTypes DiagnosticMessageData::getType() const
	{
		return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE;
	}
	std::string DiagnosticMessageData::toString() const
	{
		std::stringstream os;
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << "\n";
		os << "target address: " << std::hex << "0x" << htobe16(targetAddress) << "\n";
		return os.str();
	}
	std::vector<uint8_t> DiagnosticMessageData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(sourceAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((sourceAddress >> 8) & 0xFF));

		data.push_back(static_cast<uint8_t>(targetAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((targetAddress >> 8) & 0xFF));

		data.insert(data.end(), diagnosticData.data(), diagnosticData.data() + diagnosticData.size());

		return data;
	}

	bool DiagnosticMessageData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic Message data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength = sizeof(sourceAddress) + sizeof(targetAddress) + 2;  // SI + DID
		size_t totalDataLength = doipLayer.getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic Message fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		sourceAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);

		dataPtr += sizeof(sourceAddress);
		targetAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);

		dataPtr += sizeof(targetAddress);

		// Parse diagnosticData field (remaining data after fixed fields)
		size_t diagnosticDataLength = totalDataLength - fixedFieldLength;
		diagnosticData.resize(diagnosticDataLength);
		std::copy(dataPtr, dataPtr + diagnosticDataLength, diagnosticData.begin());

		return true;
	}

	// Diagnostic Ack Message functions definitions
	DiagnosticAckMessageData::DiagnosticAckMessageData()
	    : sourceAddress(0x0000), targetAddress(0x0000), ackCode(DoIpDiagnosticAckCodes::ACK),
	      previousMessage{ 0x22, 0xf1, 0x01, 0x02 }
	{}
	DoIpPayloadTypes DiagnosticAckMessageData::getType() const
	{
		return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK;
	}
	std::string DiagnosticAckMessageData::toString() const
	{
		std::stringstream os;
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << "\n";
		os << "target address: " << std::hex << "0x" << htobe16(targetAddress) << "\n";
		auto it = DoIpEnumToStringAckCode.find(ackCode);
		if (it != DoIpEnumToStringAckCode.end())
		{
			os << "ack code: " << it->second << " (0x" << unsigned(ackCode) << ")" << "\n";
		}
		else
		{
			os << "Ack code: Unknown" << std::hex << " (0x" << unsigned(ackCode) << ")" << "\n";
		}
		if (!previousMessage.empty())
		{
			os << "previous message: " << pcpp::byteArrayToHexString(previousMessage.data(), previousMessage.size())
			   << "\n";
		}
		return os.str();
	}
	std::vector<uint8_t> DiagnosticAckMessageData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(sourceAddress & 0xFF));  // Low byte
		data.push_back(static_cast<uint8_t>((sourceAddress >> 8) & 0xFF));

		data.push_back(static_cast<uint8_t>(targetAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((targetAddress >> 8) & 0xFF));

		data.push_back(static_cast<uint8_t>(ackCode));

		if (!previousMessage.empty())
		{
			data.insert(data.end(), previousMessage.begin(), previousMessage.end());
		}
		return data;
	}

	bool DiagnosticAckMessageData::buildFromLayer(const DoIpLayer& doipLayer)
	{
		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic Acknowledgment Message data from " +
			               doipLayer.getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength = sizeof(sourceAddress) + sizeof(targetAddress) + sizeof(ackCode);
		size_t totalDataLength = doipLayer.getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic Acknowledgment Message fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		sourceAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);

		dataPtr += sizeof(sourceAddress);
		targetAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);

		dataPtr += sizeof(targetAddress);
		ackCode = static_cast<DoIpDiagnosticAckCodes>(dataPtr[0]);

		dataPtr += sizeof(ackCode);
		// Check if there is any data left for the optional previousMessage field
		size_t remainingDataLength = totalDataLength - fixedFieldLength;
		if (remainingDataLength > 0)
		{
			previousMessage.resize(remainingDataLength);
			std::copy(dataPtr, dataPtr + remainingDataLength, previousMessage.begin());
		}
		else
		{
			previousMessage.clear();
		}
		return true;
	}

	// Diagnostic Nack Message functions definitions
	DiagnosticNackMessageData::DiagnosticNackMessageData()
	    : sourceAddress(0x0000), targetAddress(0x0000),
	      nackCode(DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS), previousMessage{ 0x22, 0xf1, 0x01, 0x02 }
	{}
	DoIpPayloadTypes DiagnosticNackMessageData::getType() const
	{
		return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK;
	}
	std::string DiagnosticNackMessageData::toString() const
	{
		std::stringstream os;
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << "\n";
		os << "target address: " << std::hex << "0x" << htobe16(targetAddress) << "\n";
		auto it = DoIpEnumToStringDiagnosticNackCodes.find(nackCode);
		if (it != DoIpEnumToStringDiagnosticNackCodes.end())
		{
			os << "nack code: " << it->second << std::hex << " (0x" << unsigned(nackCode) << ")" << "\n";
		}
		else
		{
			os << "nack code: Unknown" << std::hex << " (0x" << unsigned(nackCode) << ")" << "\n";
		}
		if (!previousMessage.empty())
		{
			os << "previous message: " << pcpp::byteArrayToHexString(previousMessage.data(), previousMessage.size())
			   << "\n";
		}
		return os.str();
	}
	std::vector<uint8_t> DiagnosticNackMessageData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(sourceAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((sourceAddress >> 8) & 0xFF));

		data.push_back(static_cast<uint8_t>(targetAddress & 0xFF));
		data.push_back(static_cast<uint8_t>((targetAddress >> 8) & 0xFF));

		data.push_back(static_cast<uint8_t>(nackCode));
		if (!previousMessage.empty())
		{
			data.insert(data.end(), reinterpret_cast<const uint8_t*>(&previousMessage),
			            reinterpret_cast<const uint8_t*>(&previousMessage) + sizeof(previousMessage));
		}
		return data;
	}

	bool DiagnosticNackMessageData::buildFromLayer(const DoIpLayer& doipLayer)
	{

		if (doipLayer.getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic NACK Message data from " + doipLayer.getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength = sizeof(sourceAddress) + sizeof(targetAddress) + sizeof(nackCode);
		size_t totalDataLength = doipLayer.getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic NACK Message fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer.getDataPtr(sizeof(doiphdr));
		sourceAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);

		dataPtr += sizeof(sourceAddress);
		targetAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);

		dataPtr += sizeof(targetAddress);
		nackCode = static_cast<DoIpDiagnosticMessageNackCodes>(dataPtr[0]);

		dataPtr += sizeof(nackCode);
		// Check if there is any data left for the optional previousMessage field
		size_t remainingDataLength = totalDataLength - fixedFieldLength;
		if (remainingDataLength > 0)
		{
			previousMessage.resize(remainingDataLength);
			std::copy(dataPtr, dataPtr + remainingDataLength, previousMessage.begin());
		}
		else
		{
			// Ensure previousMessage is empty when not provided
			previousMessage.clear();
		}

		return true;
	}

}  // namespace pcpp
