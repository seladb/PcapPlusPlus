#include "DoIpLayerData.h"
#include "DoIpLayer.h"
/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	RoutingActivationRequestData::RoutingActivationRequestData()
	    : sourceAddress(0x0000), activationType(DoIpActivationTypes::Default), reservedIso{}, reservedOem(nullptr) {};

	DoIpPayloadTypes RoutingActivationRequestData::getType() const
	{
		return DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST;
	}

	std::string RoutingActivationRequestData::toString() const
	{
		std::stringstream os;
		os << "sourceAddress: " << std::hex << "0x" << htobe16(sourceAddress) << std::endl;
		os << "activation type: " << DoIpEnumToStringActivationTypes.at(activationType) << std::hex << " (0x"
		   << unsigned(activationType) << ")" << std::endl;
		os << "reserved by ISO: " << pcpp::byteArrayToHexString(reservedIso.data(), DOIP_RESERVED_ISO_LEN) << std::endl;
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
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&sourceAddress),
		            reinterpret_cast<const uint8_t*>(&sourceAddress) + sizeof(sourceAddress));
		data.push_back(static_cast<uint8_t>(activationType));  // Convert enum to byte
		data.insert(data.end(), reservedIso.begin(), reservedIso.end());
		if (reservedOem)
		{
			data.insert(data.end(), reservedOem->begin(), reservedOem->end());
		}
		return data;
	}

	// buildFromLayer implementation
	bool RoutingActivationRequestData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input data buffer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve routing activation request data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
		sourceAddress = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);
		activationType = static_cast<DoIpActivationTypes>(dataPtr[2]);
		std::copy(dataPtr + 3, dataPtr + 3 + DOIP_RESERVED_ISO_LEN, reservedIso.begin());
		if (doipLayer->getDataLen() - sizeof(doiphdr) >=
		    sizeof(sourceAddress) + sizeof(activationType) + DOIP_RESERVED_ISO_LEN + DOIP_RESERVED_OEM_LEN)
		{
			reservedOem = std::unique_ptr<std::array<uint8_t, DOIP_RESERVED_OEM_LEN>>(
			    new std::array<uint8_t, DOIP_RESERVED_OEM_LEN>());
			std::copy(dataPtr + 3 + DOIP_RESERVED_ISO_LEN, dataPtr + 3 + DOIP_RESERVED_ISO_LEN + DOIP_RESERVED_OEM_LEN,
			          reservedOem->begin());
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
		   << std::endl;
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << std::endl;
		os << "routing activation response code: " << DoIpEnumToStringRoutingResponseCodes.at(responseCode) << std::hex
		   << " (0x" << unsigned(responseCode) << ")" << std::endl;
		os << "reserved by ISO: " << pcpp::byteArrayToHexString(reservedIso.data(), DOIP_RESERVED_ISO_LEN) << std::endl;
		if (reservedOem)
		{
			os << "Reserved by OEM: " << pcpp::byteArrayToHexString(reservedOem->data(), DOIP_RESERVED_OEM_LEN)
			   << std::endl;
		}
		return os.str();
	}
	std::vector<uint8_t> RoutingActivationResponseData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&logicalAddressExternalTester),
		            reinterpret_cast<const uint8_t*>(&logicalAddressExternalTester) +
		                sizeof(logicalAddressExternalTester));
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&sourceAddress),
		            reinterpret_cast<const uint8_t*>(&sourceAddress) + sizeof(sourceAddress));
		data.push_back(static_cast<uint8_t>(responseCode));  // Convert enum to byte
		data.insert(data.end(), reservedIso.begin(), reservedIso.end());
		if (reservedOem)
		{
			data.insert(data.end(), reservedOem->begin(), reservedOem->end());
		}
		return data;
	}

	bool RoutingActivationResponseData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input data buffer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve routing activation response data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}

		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
		if (!dataPtr)
		{
			PCPP_LOG_ERROR("Data pointer is null");
			return false;
		}

		logicalAddressExternalTester = static_cast<uint16_t>(dataPtr[1] << 8 | dataPtr[0]);
		sourceAddress = static_cast<uint16_t>(dataPtr[3] << 8 | dataPtr[2]);
		responseCode = static_cast<DoIpRoutingResponseCodes>(dataPtr[4]);

		std::copy(dataPtr + 5, dataPtr + 5 + DOIP_RESERVED_ISO_LEN, reservedIso.begin());

		if (doipLayer->getDataLen() - sizeof(doiphdr) >= 5 + DOIP_RESERVED_ISO_LEN + DOIP_RESERVED_OEM_LEN)
		{
			reservedOem = std::unique_ptr<std::array<uint8_t, DOIP_RESERVED_OEM_LEN>>(
			    new std::array<uint8_t, DOIP_RESERVED_OEM_LEN>());
			std::copy(dataPtr + 5 + DOIP_RESERVED_ISO_LEN, dataPtr + 5 + DOIP_RESERVED_ISO_LEN + DOIP_RESERVED_OEM_LEN,
			          reservedOem->begin());
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
		os << "generic header nack code: " << DoIpEnumToStringGenericHeaderNackCodes.at(genericNackCode) << std::hex
		   << " (0x" << unsigned(genericNackCode) << ")" << std::endl;
		;
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
	bool GenericHeaderNackData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Generic Header NACK data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}

		// Validate data length (1 byte is expected for genericNackCode)
		if (doipLayer->getDataLen() - sizeof(doiphdr) < 1)
		{
			PCPP_LOG_ERROR("Insufficient data length for Generic Header NACK payload");
			return false;
		}

		// Extract the NACK code (1 byte)
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
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
		os << "EID: " << pcpp::byteArrayToHexString(eid.data(), DOIP_EID_LEN) << std::endl;
		return os.str();
	}
	std::vector<uint8_t> VehicleIdentificationRequestEIDData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), eid.begin(), eid.end());
		return data;
	}

	bool VehicleIdentificationRequestEIDData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Vehicle Identification Request with EID data from " +
			               doipLayer->getPayloadTypeAsStr());
			return false;
		}

		// Validate data length (must at least accommodate EID length)
		if (doipLayer->getDataLen() - sizeof(doiphdr) < DOIP_EID_LEN)
		{
			PCPP_LOG_ERROR("Insufficient data length for Vehicle Identification Request with EID payload");
			return false;
		}

		// Extract the EID
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
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
		os << "VIN: " << std::string(reinterpret_cast<const char*>(vin.data()), vin.size()) << std::endl;
		return os.str();
	}
	std::vector<uint8_t> VehicleIdentificationRequestVINData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), vin.begin(), vin.end());
		return data;
	}

	bool VehicleIdentificationRequestVINData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Vehicle Identification Request with VIN data from " +
			               doipLayer->getPayloadTypeAsStr());
			return false;
		}

		// Validate data length (must at least accommodate VIN length)
		if (doipLayer->getDataLen() - sizeof(doiphdr) < DOIP_VIN_LEN)
		{
			PCPP_LOG_ERROR("Insufficient data length for Vehicle Identification Request with EID payload");
			return false;
		}

		// Extract the VIN
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
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
		os << "VIN: " << std::string(reinterpret_cast<const char*>(vin.data()), vin.size()) << std::endl;
		os << "logical address: " << std::hex << "0x" << htobe16(logicalAddress) << std::endl;
		os << "EID: " << pcpp::byteArrayToHexString(eid.data(), DOIP_EID_LEN) << std::endl;
		os << "GID: " << pcpp::byteArrayToHexString(gid.data(), DOIP_GID_LEN) << std::endl;
		os << "further action required:" << DoIpEnumToStringActionCodes.at(furtherActionRequired) << std::hex << " (0x"
		   << unsigned(furtherActionRequired) << ")" << std::endl;
		os << "VIN/GID sync status: " << DoIpEnumToStringSyncStatus.at(syncStatus)
		   << std::endl;  // Convert enum to byte
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

	bool VehicleAnnouncementData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Vehicle Announcement data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}

		// Validate minimum data length
		size_t expectedMinLength =
		    DOIP_VIN_LEN + sizeof(logicalAddress) + DOIP_EID_LEN + DOIP_GID_LEN + 1;  // 1 for furtherActionRequired
		if (doipLayer->getDataLen() - sizeof(doiphdr) < expectedMinLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Vehicle Announcement payload");
			return false;
		}

		// Parse fields from payload
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));

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
		dataPtr += 1;

		// Optional Sync Status
		if (doipLayer->getDataLen() - sizeof(doiphdr) > expectedMinLength)
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
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << std::endl;
		return os.str();
	}
	std::vector<uint8_t> AliveCheckResponseData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&sourceAddress),
		            reinterpret_cast<const uint8_t*>(&sourceAddress) + sizeof(sourceAddress));
		return data;
	}

	bool AliveCheckResponseData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Alive Check Response data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}

		// Validate minimum data length
		constexpr size_t requiredLength = sizeof(sourceAddress);
		if (doipLayer->getDataLen() - sizeof(doiphdr) < requiredLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Alive Check Response payload");
			return false;
		}

		// Parse sourceAddress from payload
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
		sourceAddress = *reinterpret_cast<uint16_t*>(dataPtr);

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
		os << "diagnostic power mode: " << DoIpEnumToStringDiagnosticPowerModeCodes.at(powerModeCode) << std::hex
		   << " (0x" << unsigned(powerModeCode) << ")" << std::endl;
		return os.str();
	}

	std::vector<uint8_t> DiagnosticPowerModeResponseData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(powerModeCode));  // Convert enum to byte
		return data;
	}

	bool DiagnosticPowerModeResponseData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic Power Mode Response data from " +
			               doipLayer->getPayloadTypeAsStr());
			return false;
		}

		// Validate minimum data length
		constexpr size_t requiredLength = sizeof(powerModeCode);
		if (doipLayer->getDataLen() - sizeof(doiphdr) < requiredLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic Power Mode Response payload");
			return false;
		}

		// Parse powerModeCode from payload
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
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
		os << "Entity status: " << DoIpEnumToStringEntityStatusNodeTypes.at(nodeType) << std::hex << " (0x"
		   << unsigned(nodeType) << ")" << std::endl;
		os << "maximum Concurrent Socket: " << unsigned(maxConcurrentSockets) << std::endl;
		os << "currently Opened Socket: " << unsigned(currentlyOpenSockets) << std::endl;
		if (maxDataSize)
		{
			os << "maximum Data Size: "
			   << "0x" << pcpp::byteArrayToHexString(maxDataSize->data(), 4) << std::endl;
		}

		return os.str();
	}

	std::vector<uint8_t> EntityStatusResponseData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.push_back(static_cast<uint8_t>(nodeType));  // Convert enum to byte
		data.push_back(static_cast<uint8_t>(maxConcurrentSockets));
		data.push_back(static_cast<uint8_t>(currentlyOpenSockets));
		// optional field
		if (maxDataSize)
		{
			data.insert(data.end(), maxDataSize->begin(), maxDataSize->end());
		}
		return data;
	}

	bool EntityStatusResponseData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Entity Status Response data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength =
		    sizeof(nodeType) + sizeof(maxConcurrentSockets) + sizeof(currentlyOpenSockets);
		constexpr size_t optionalFieldLength = 4;  // Length of maxDataSize field
		size_t totalDataLength = doipLayer->getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Entity Status Response fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
		nodeType = static_cast<DoIpEntityStatus>(dataPtr[0]);
		maxConcurrentSockets = dataPtr[1];
		currentlyOpenSockets = dataPtr[2];

		// Parse optional maxDataSize field if present
		if (totalDataLength >= fixedFieldLength + optionalFieldLength)
		{
			maxDataSize = std::unique_ptr<std::array<uint8_t, optionalFieldLength>>(
			    new std::array<uint8_t, optionalFieldLength>());
			std::copy(dataPtr + fixedFieldLength, dataPtr + fixedFieldLength + optionalFieldLength,
			          maxDataSize->begin());
		}
		else
		{
			maxDataSize = nullptr;  // Optional field not present
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
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << std::endl;
		os << "target address: " << std::hex << "0x" << htobe16(targetAddress) << std::endl;
		return os.str();
	}
	std::vector<uint8_t> DiagnosticMessageData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&sourceAddress),
		            reinterpret_cast<const uint8_t*>(&sourceAddress) + sizeof(sourceAddress));
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&targetAddress),
		            reinterpret_cast<const uint8_t*>(&targetAddress) + sizeof(targetAddress));
		data.insert(data.end(), diagnosticData.data(), diagnosticData.data() + diagnosticData.size());
		return data;
	}

	bool DiagnosticMessageData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic Message data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength = sizeof(sourceAddress) + sizeof(targetAddress) + 2;  // SI + DID
		size_t totalDataLength = doipLayer->getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic Message fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
		sourceAddress = *reinterpret_cast<uint16_t*>(dataPtr);
		targetAddress = *reinterpret_cast<uint16_t*>(dataPtr + sizeof(sourceAddress));

		// Parse diagnosticData field (remaining data after fixed fields)
		size_t diagnosticDataLength = totalDataLength - fixedFieldLength;
		diagnosticData.resize(diagnosticDataLength);
		std::copy(dataPtr + fixedFieldLength, dataPtr + fixedFieldLength + diagnosticDataLength,
		          diagnosticData.begin());

		return true;
	}

	// Diagnostic Ack Message functions definitions
	DiagnosticAckMessageData::DiagnosticAckMessageData()
	    : sourceAddress(0x0000), targetAddress(0x0000), ackCode(DoIpDiagnosticAckCodes::ACK),
	      previousMessage{ 0x22, 0xf1, 01, 0x02 }
	{}
	DoIpPayloadTypes DiagnosticAckMessageData::getType() const
	{
		return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK;
	}
	std::string DiagnosticAckMessageData::toString() const
	{
		std::stringstream os;
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << std::endl;
		os << "target address: " << std::hex << "0x" << htobe16(targetAddress) << std::endl;
		os << "ack code: " << DoIpEnumToStringAckCode.at(ackCode) << " (0x" << unsigned(ackCode) << ")" << std::endl;

		return os.str();
	}
	std::vector<uint8_t> DiagnosticAckMessageData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&sourceAddress),
		            reinterpret_cast<const uint8_t*>(&sourceAddress) + sizeof(sourceAddress));
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&targetAddress),
		            reinterpret_cast<const uint8_t*>(&targetAddress) + sizeof(targetAddress));
		data.push_back(static_cast<uint8_t>(ackCode));
		if (!previousMessage.empty())
		{
			data.insert(data.end(), previousMessage.begin(), previousMessage.end());
		}
		return data;
	}

	bool DiagnosticAckMessageData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic Acknowledgment Message data from " +
			               doipLayer->getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength = sizeof(sourceAddress) + sizeof(targetAddress) + sizeof(ackCode);
		size_t totalDataLength = doipLayer->getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic Acknowledgment Message fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
		sourceAddress = (*reinterpret_cast<uint16_t*>(dataPtr));
		targetAddress = (*reinterpret_cast<uint16_t*>(dataPtr + sizeof(sourceAddress)));
		ackCode = static_cast<DoIpDiagnosticAckCodes>(
		    *reinterpret_cast<uint8_t*>(dataPtr + sizeof(sourceAddress) + sizeof(targetAddress)));

		// Check if there is any data left for the optional previousMessage field
		size_t remainingDataLength = totalDataLength - fixedFieldLength;
		if (remainingDataLength > 0)
		{
			previousMessage.resize(remainingDataLength);
			std::copy(dataPtr + fixedFieldLength, dataPtr + fixedFieldLength + remainingDataLength,
			          previousMessage.begin());
		}
		else
		{
			previousMessage.clear();  // Ensure previousMessage is empty when not provided
		}
		return true;
	}

	// Diagnostic Nack Message functions definitions
	DiagnosticNackMessageData::DiagnosticNackMessageData()
	    : sourceAddress(0x0000), targetAddress(0x0000),
	      nackCode(DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS), previousMessage{ 0x22, 0xf1, 01, 0x02 }
	{}
	DoIpPayloadTypes DiagnosticNackMessageData::getType() const
	{
		return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK;
	}
	std::string DiagnosticNackMessageData::toString() const
	{
		std::stringstream os;
		os << "source address: " << std::hex << "0x" << htobe16(sourceAddress) << std::endl;
		os << "target address: " << std::hex << "0x" << htobe16(targetAddress) << std::endl;
		os << "nack code: " << DoIpEnumToStringDiagnosticNackCodes.at(nackCode) << std::hex << " (0x"
		   << unsigned(nackCode) << ")" << std::endl;
		return os.str();
	}
	std::vector<uint8_t> DiagnosticNackMessageData::getData() const
	{
		std::vector<uint8_t> data;
		// Copy each field's data into the vector
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&sourceAddress),
		            reinterpret_cast<const uint8_t*>(&sourceAddress) + sizeof(sourceAddress));
		data.insert(data.end(), reinterpret_cast<const uint8_t*>(&targetAddress),
		            reinterpret_cast<const uint8_t*>(&targetAddress) + sizeof(targetAddress));
		data.push_back(static_cast<uint8_t>(nackCode));
		if (!previousMessage.empty())
		{
			data.insert(data.end(), reinterpret_cast<const uint8_t*>(&previousMessage),
			            reinterpret_cast<const uint8_t*>(&previousMessage) + sizeof(previousMessage));
		}
		return data;
	}

	bool DiagnosticNackMessageData::buildFromLayer(DoIpLayer* doipLayer)
	{
		if (!doipLayer)
		{
			PCPP_LOG_ERROR("Input DoIpLayer is null");
			return false;
		}

		if (doipLayer->getPayloadType() != getType())
		{
			PCPP_LOG_ERROR("Cannot retrieve Diagnostic NACK Message data from " + doipLayer->getPayloadTypeAsStr());
			return false;
		}

		constexpr size_t fixedFieldLength = sizeof(sourceAddress) + sizeof(targetAddress) + sizeof(nackCode);
		size_t totalDataLength = doipLayer->getDataLen() - sizeof(doiphdr);

		if (totalDataLength < fixedFieldLength)
		{
			PCPP_LOG_ERROR("Insufficient data length for Diagnostic NACK Message fixed fields");
			return false;
		}

		// Parse fixed fields
		uint8_t* dataPtr = doipLayer->getDataPtr(sizeof(doiphdr));
		sourceAddress = (*reinterpret_cast<uint16_t*>(dataPtr));
		targetAddress = (*reinterpret_cast<uint16_t*>(dataPtr + sizeof(sourceAddress)));
		nackCode = static_cast<DoIpDiagnosticMessageNackCodes>(
		    *reinterpret_cast<uint8_t*>(dataPtr + sizeof(sourceAddress) + sizeof(targetAddress)));

		// Check if there is any data left for the optional previousMessage field
		size_t remainingDataLength = totalDataLength - fixedFieldLength;
		if (remainingDataLength > 0)
		{
			previousMessage.resize(remainingDataLength);
			std::copy(dataPtr + fixedFieldLength, dataPtr + fixedFieldLength + remainingDataLength,
			          previousMessage.begin());
		}
		else
		{
			previousMessage.clear();  // Ensure previousMessage is empty when not provided
		}

		return true;
	}

}  // namespace pcpp
