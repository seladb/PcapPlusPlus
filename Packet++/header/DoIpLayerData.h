#pragma once

#include <vector>
#include <memory>
#include <array>
#include "Logger.h"
#include "GeneralUtils.h"
#include "DoIpEnumToString.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus library
 */
namespace pcpp
{
/**
 * @brief Length of the External Identifier (EID) field.
 */
#define DOIP_EID_LEN 6

/**
 * @brief Length of the Group Identifier (GID) field.
 */
#define DOIP_GID_LEN 6

/**
 * @brief Length of the Vehicle Identification Number (VIN) field.
 */
#define DOIP_VIN_LEN 17

/**
 * @brief Length of the Reserved ISO field.
 */
#define DOIP_RESERVED_ISO_LEN 4

/**
 * @brief Length of the Reserved OEM field.
 */
#define DOIP_RESERVED_OEM_LEN 4

	// forward declaration for DoIpLayer class
	class DoIpLayer;

	/**
	 * \brief A pure abstract class representing the basic structure of DoIP messages.
	 *
	 * This interface defines methods to retrieve the type, string representation,
	 * and binary data of DoIP messages. All DoIP message classes must implement this interface.
	 */
	class IDoIpMessageData
	{
	public:
		virtual ~IDoIpMessageData() = default;

		/**
		 * \brief Returns the type of the DoIP message.
		 * \return The type of the message as a `DoIpPayloadTypes` enum.
		 */
		virtual DoIpPayloadTypes getType() const = 0;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return The string representation of the message.
		 */
		virtual std::string toString() const = 0;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return The message data as a vector of bytes.
		 */
		virtual std::vector<uint8_t> getData() const = 0;

		/**
		 * \brief build IDoIpMessageData from DoIpLayer
		 * @param[in] doipLayer pointer to doipLayer to retrieve data from
		 * \return true if encapsulating process is done successufly else false.
		 *
		 * @exception Logs an error and returns `false` if:
		 * - The input layer is null.
		 * - The payload type of doipLayer does not match the expected type for IDoIpMessageData.
		 * - The input data length is insufficient for parsing all required fields.
		 */
		virtual bool buildFromLayer(DoIpLayer* doipLayer) = 0;
	};

	/**
	 * @class RoutingActivationRequestData
	 * \brief Represents a Routing Activation Request message in DoIP.
	 *
	 * This class encapsulates data for a Routing Activation Request message,
	 * including source address, activation type, and reserved fields.
	 */
	class RoutingActivationRequestData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the RoutingActivationRequestData class.
		 *
		 * Initializes a `RoutingActivationRequestData` instance with default values:
		 * - `sourceAddress` is set to `0x0000`.
		 * - `activationType` is set to `DoIpActivationTypes::Default`.
		 * - `reservedIso` and `reservedOem` fields are zero-initialized.
		 * This constructor provides a default initialization state for routing activation request
		 * data, ensuring compliance with the DoIP protocol requirements.
		 */
		RoutingActivationRequestData();

		uint16_t sourceAddress;             /**< Source address of the message. */
		DoIpActivationTypes activationType; /**< The activation type (e.g., activate, deactivate). */
		std::array<uint8_t, DOIP_RESERVED_ISO_LEN> reservedIso;                  /**< Reserved ISO bytes. */
		std::unique_ptr<std::array<uint8_t, DOIP_RESERVED_OEM_LEN>> reservedOem; /**< Reserved OEM bytes. */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Routing Activation Request message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Routing Activation Request data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Routing Activation Request payload type. It extracts the source address, activation
		 * type, reserved ISO bytes, and optionally reserved OEM bytes if present.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Routing Activation Request data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note This method overrides the base class implementation and adds specific parsing
		 * logic for the Routing Activation Request message.
		 *
		 * The following fields are parsed:
		 * - `sourceAddress`: The source address of the message.
		 * - `activationType`: The type of activation requested.
		 * - `reservedIso`: Reserved bytes as defined by ISO specifications.
		 * - `reservedOem`: Reserved bytes as defined by OEM specifications, only if present.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class RoutingActivationResponseData
	 * \brief Represents a Routing Activation Response message in DoIP.
	 *
	 * This class encapsulates data for a Routing Activation Response message,
	 * including logical address, source address, response code, and reserved fields.
	 */
	class RoutingActivationResponseData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the RoutingActivationResponseData class.
		 * Initializes a `RoutingActivationResponseData` instance with default values:
		 * - `logicalAddressExternalTester` is set to `0x0000`.
		 * - `sourceAddress` is set to `0x0000`.
		 * - `responseCode` is set to DoIpRoutingResponseCodes::CONFIRMATION_REQUIRED.
		 * - `reservedIso` fields is zero-initialized.
		 * This constructor provides a default initialization state for routing activation response
		 * data, ensuring compliance with the DoIP protocol requirements.
		 */
		RoutingActivationResponseData();

		uint16_t logicalAddressExternalTester;                  /**< Logical address of the external tester. */
		uint16_t sourceAddress;                                 /**< Source address of the message. */
		DoIpRoutingResponseCodes responseCode;                  /**< Response code indicating success or failure. */
		std::array<uint8_t, DOIP_RESERVED_ISO_LEN> reservedIso; /**< Reserved ISO bytes. */
		std::unique_ptr<std::array<uint8_t, DOIP_RESERVED_OEM_LEN>> reservedOem; /**< Reserved OEM bytes. */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Routing Activation Response message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */

		std::vector<uint8_t> getData() const override;
		/**
		 * @brief Parses the Routing Activation Response data from a DoIpLayer.
		 *
		 * This method validates and extracts the necessary fields from the provided
		 * DoIpLayer. It ensures the layer corresponds to the Routing Activation Response
		 * payload type and parses fields including the logical tester address, source
		 * address, response code, and reserved fields.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Routing Activation Response data.
		 * @return `true` if parsing was successful, `false` otherwise.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class GenericHeaderNackData
	 * \brief Represents a Generic Header Negative Acknowledgment message in DoIP.
	 *
	 * This class encapsulates data for a Generic Header NACK message, including
	 * the NACK code to indicate the failure.
	 */
	class GenericHeaderNackData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the GenericHeaderNackData class.
		 *
		 * This constructor initializes a `GenericHeaderNackData` instance with default values:
		 * - `genericNackCode` is set to `DoIpGenericHeaderNackCodes::INVALID_PAYLOAD_LENGTH`.
		 */
		GenericHeaderNackData();

		DoIpGenericHeaderNackCodes genericNackCode; /**< The NACK code indicating the error. */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Generic Header NACK message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */

		std::vector<uint8_t> getData() const override;
		/**
		 * @brief Parses and initializes the Generic Header NACK data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Generic Header NACK payload type. It extracts the `genericNackCode` field from the layer.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Generic Header NACK data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method checks for null pointers and verifies that the payload type matches
		 * `DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK`. Logs an error in case of invalid data.
		 *
		 * The following field is parsed:
		 * - `genericNackCode`: The NACK code indicating the type of error.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 *  @class VehicleIdentificationRequestEIDData
	 * \brief Represents a Vehicle Identification Request with EID message in DoIP.
	 *
	 * This class encapsulates data for a Vehicle Identification Request message
	 * that includes the Electronic Identifier (EID).
	 */
	class VehicleIdentificationRequestEIDData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the VehicleIdentificationRequestEIDData class.
		 *
		 * This constructor initializes a `VehicleIdentificationRequestEIDData` instance with default values:
		 * - `eid` (Entity Identifier) is initialized to all zeros.
		 */
		VehicleIdentificationRequestEIDData();

		std::array<uint8_t, DOIP_EID_LEN> eid; /**< Electronic Identifier (EID). */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Vehicle Identification Request EID message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Vehicle Identification Request with EID data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Vehicle Identification Request with EID payload type. It extracts the EID field from the layer.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Vehicle Identification Request with EID data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method checks for null pointers and verifies that the payload type matches
		 * `DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID`. Logs an error if the data is invalid.
		 *
		 * The following field is parsed:
		 * - `eid`: The EID (Extended Identifier), extracted as a byte array of length `DOIP_EID_LEN`.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class VehicleIdentificationRequestVINData
	 * \brief Represents a Vehicle Identification Request with VIN message in DoIP.
	 *
	 * This class encapsulates data for a Vehicle Identification Request message
	 * that includes the Vehicle Identification Number (VIN).
	 */
	class VehicleIdentificationRequestVINData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the VehicleIdentificationRequestVINData class.
		 *
		 * This constructor initializes a `VehicleIdentificationRequestVINData` instance with default values:
		 * - `vin` (Vehicle Identification Number) is initialized to all zeros.
		 */
		VehicleIdentificationRequestVINData();

		std::array<uint8_t, DOIP_VIN_LEN> vin; /**< Vehicle Identification Number (VIN). */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Vehicle Identification Request VIN message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Vehicle Identification Request with VIN data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Vehicle Identification Request with VIN payload type. It extracts the VIN (Vehicle Identification Number)
		 * field from the payload data and populates the class instance.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Vehicle Identification Request with VIN data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method performs the following checks:
		 * - Ensures the `doipLayer` is not null.
		 * - Validates that the payload type matches `DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN`.
		 * - Checks that the data length is sufficient to extract the VIN field.
		 *
		 * Logs errors if the data is invalid or the payload is incompatible.
		 *
		 * The following field is parsed:
		 * - `vin`: The Vehicle Identification Number (VIN), extracted as a byte array of length `DOIP_VIN_LEN`.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class VehicleAnnouncementData
	 * \brief Represents a Vehicle Announcement message in DoIP.
	 *
	 * This class encapsulates data for a Vehicle Announcement message, including
	 * VIN, logical address, EID, GID, and further action required.
	 */
	class VehicleAnnouncementData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the VehicleAnnouncementData class.
		 *
		 * This constructor initializes a `VehicleAnnouncementData` instance with default values:
		 * - `vin` is initialized to all zeros.
		 * - `logicalAddress` is set to `0`.
		 * - `eid` (Entity Identifier) is initialized to all zeros.
		 * - `gid` (Group Identifier) is initialized to all zeros.
		 * - `furtherActionRequired` is set to `DoIpActionCodes::NO_FURTHER_ACTION_REQUIRED`.
		 * - `syncStatus` is set to `DoIpSyncStatus::NON_INITIALIZED`, indicating that the sync status is uninitialized.
		 */
		VehicleAnnouncementData();

		std::array<uint8_t, DOIP_VIN_LEN> vin; /**< Vehicle Identification Number (VIN). */
		uint16_t logicalAddress;               /**< Logical address of the vehicle. */
		std::array<uint8_t, DOIP_EID_LEN> eid; /**< Electronic Identifier (EID). */
		std::array<uint8_t, DOIP_GID_LEN> gid; /**< Group Identifier (GID). */
		DoIpActionCodes furtherActionRequired; /**< Action required after the announcement. */
		DoIpSyncStatus syncStatus;             /**< version and invert version are synchronized */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Vehicle Announcement message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Vehicle Announcement data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Announcement Message payload type. It extracts fields such as VIN, logical address, EID, GID,
		 * further action required, and synchronization status from the payload data.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Vehicle Announcement data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method performs the following checks:
		 * - Ensures the `doipLayer` is not null.
		 * - Validates that the payload type matches `DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE`.
		 * - Checks that the data length is sufficient to extract all required fields.
		 *
		 * Logs errors if the data is invalid or the payload is incompatible.
		 *
		 * The following fields are parsed:
		 * - `vin`: Vehicle Identification Number (VIN).
		 * - `logicalAddress`: Logical address of the vehicle.
		 * - `eid`: End Identifier.
		 * - `gid`: Group Identifier.
		 * - `furtherActionRequired`: Further action required code.
		 * - `syncStatus`: VIN/GID synchronization status (if present).
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class AliveCheckResponseData
	 * \brief Represents an Alive Check Response message in DoIP.
	 *
	 * This class encapsulates data for an Alive Check Response message,
	 * including the source address.
	 */
	class AliveCheckResponseData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the AliveCheckResponseData class.
		 *
		 * This constructor initializes an `AliveCheckResponseData` instance with default values:
		 * - `sourceAddress` is set to `0x0000`.
		 */
		AliveCheckResponseData();

		uint16_t sourceAddress; /**< Source address of the Alive Check Response message. */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::ALIVE_CHECK_RESPONSE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Alive Check Response message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Alive Check Response data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Alive Check Response payload type. It extracts the `sourceAddress` field from the payload data.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Alive Check Response data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method performs the following checks:
		 * - Ensures the `doipLayer` is not null.
		 * - Validates that the payload type matches `DoIpPayloadTypes::ALIVE_CHECK_RESPONSE`.
		 * - Checks that the data length is sufficient to extract the `sourceAddress`.
		 *
		 * Logs errors if the data is invalid or the payload is incompatible.
		 *
		 * The following field is parsed:
		 * - `sourceAddress`: The source address of the response.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class DiagnosticPowerModeResponseData
	 * \brief Represents a Diagnostic Power Mode Response message in DoIP.
	 *
	 * This class encapsulates data for a Diagnostic Power Mode Response message,
	 * including a power mode code indicating the current power mode.
	 */
	class DiagnosticPowerModeResponseData : public IDoIpMessageData
	{
	public:
		/** @brief Default constructor for the DiagnosticPowerModeResponseData class.
		 *
		 * Initializes a DiagnosticPowerModeResponseData instance with the power mode
		 * response code set to `NOT_READY`. This indicates that the system is not yet
		 * ready to respond to diagnostic power mode requests.
		 */
		DiagnosticPowerModeResponseData();

		DoIpDiagnosticPowerModeCodes powerModeCode; /**< Code representing the power mode. */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Diagnostic Power Mode Response message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Diagnostic Power Mode Response data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Diagnostic Power Mode Response payload type. It extracts the `powerModeCode` field from the payload data.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Diagnostic Power Mode Response data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method performs the following checks:
		 * - Ensures the `doipLayer` is not null.
		 * - Validates that the payload type matches `DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE`.
		 * - Checks that the data length is sufficient to extract the `powerModeCode`.
		 *
		 * Logs errors if the data is invalid or the payload is incompatible.
		 *
		 * The following field is parsed:
		 * - `powerModeCode`: The diagnostic power mode response code.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class EntityStatusResponseData
	 * \brief Represents an Entity Status Response message in DoIP.
	 *
	 * This class encapsulates data for an Entity Status Response message,
	 * including status, maximum concurrent sockets, open sockets, and maximum data size.
	 */
	class EntityStatusResponseData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the EntityStatusResponseData class.
		 *
		 * Initializes an `EntityStatusResponseData` instance with the following default values:
		 * - `status`: Set to `DoIpEntityStatus::GATEWAY`, indicating the entity is acting as a gateway.
		 * - `maxConcurrentSockets`: Set to `0`, meaning no concurrent sockets are allowed by default.
		 * - `currentlyOpenSockets`: Set to `0`, indicating no sockets are currently open.
		 * - `maxDataSize`: Set to `nullptr`, meaning no data for this field. can be assigned after object
		 * creation by :
		 * @code
		 * EntityStatusResponseData data;
		 * data.maxDataSize = std::unique_ptr<std::array<uint8_t, 4>>(new std::array<uint8_t, 4> {0x00, 0x01, 0x02,
		 * 0x03})
		 */
		EntityStatusResponseData();

		DoIpEntityStatus nodeType;    /**< Status of the entity. */
		uint8_t maxConcurrentSockets; /**< Maximum number of concurrent sockets. */
		uint8_t currentlyOpenSockets; /**< Number of currently open sockets. */
		std::unique_ptr<std::array<uint8_t, 4>>
		    maxDataSize; /**< Maximum data size that can be handled (4 bytes optional). */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::ENTITY_STATUS_RESPONSE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Entity Status Response message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Entity Status Response data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Entity Status Response payload type. It extracts fields such as `nodeType`,
		 * `maxConcurrentSockets`, `currentlyOpenSockets`, and optionally `maxDataSize` from the payload data.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Entity Status Response data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method performs the following checks:
		 * - Ensures the `doipLayer` is not null.
		 * - Validates that the payload type matches `DoIpPayloadTypes::ENTITY_STATUS_RESPONSE`.
		 * - Checks that the data length is sufficient for the fixed fields and optional `maxDataSize`.
		 *
		 * Logs errors if the data is invalid or the payload is incompatible.
		 *
		 * The following fields are parsed:
		 * - `nodeType`: Entity status indicating the role of the entity.
		 * - `maxConcurrentSockets`: Maximum allowed concurrent sockets.
		 * - `currentlyOpenSockets`: Number of currently open sockets.
		 * - `maxDataSize` (optional): Maximum data size supported (4 bytes).
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class DiagnosticMessageData
	 * \brief Represents a Diagnostic Message in DoIP.
	 * This class encapsulates data for a Diagnostic Message, including source
	 * and target addresses, as well as diagnostic data.
	 */
	class DiagnosticMessageData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the DiagnosticMessageData class.
		 *
		 * Initializes a `DiagnosticMessageData` instance with the following default values:
		 * - `sourceAddress`: Set to `0x0000`.
		 * - `targetAddress`: Set to `0x0000`.
		 * - `diagnosticData`: Initialized to `{0x22, 0xf1, 0x68}` as a default diagnostic payload.
		 */
		DiagnosticMessageData();

		uint16_t sourceAddress;              /**< Source address of the message. */
		uint16_t targetAddress;              /**< Target address for the diagnostic message. */
		std::vector<uint8_t> diagnosticData; /**< Diagnostic message data with dynamic length*/

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::DIAGNOSTIC_MESSAGE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Diagnostic Message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Diagnostic Message data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Diagnostic Message payload type. It extracts fields such as `sourceAddress`,
		 * `targetAddress`, and `diagnosticData` from the payload data.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Diagnostic Message data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method performs the following checks:
		 * - Ensures the `doipLayer` is not null.
		 * - Validates that the payload type matches `DoIpPayloadTypes::DIAGNOSTIC_MESSAGE`.
		 * - Checks that the data length is sufficient for the fixed fields and dynamic `diagnosticData`.
		 *
		 * Logs errors if the data is invalid or the payload is incompatible.
		 *
		 * The following fields are parsed:
		 * - `sourceAddress`: Source address of the diagnostic message (2 bytes).
		 * - `targetAddress`: Target address of the diagnostic message (2 bytes).
		 * - `diagnosticData`: Variable length data representing the diagnostic payload.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class DiagnosticAckMessageData
	 * \brief Represents a Diagnostic Acknowledgment Message in DoIP.
	 *
	 * This class encapsulates data for a Diagnostic Acknowledgment Message,
	 * including source and target addresses, as well as the acknowledgment code.
	 */
	class DiagnosticAckMessageData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the DiagnosticAckMessageData class.
		 *
		 * Initializes a `DiagnosticAckMessageData` instance with the following default values:
		 * - `sourceAddress`: Set to `0x0000`.
		 * - `targetAddress`: Set to `0x0000`.
		 * - `ackCode`: Set to `DoIpDiagnosticAckCodes::ACK`.
		 * - `previousMessage`: Initialized to `{0x22, 0xf1, 0x01, 0x02}`.
		 */
		DiagnosticAckMessageData();

		uint16_t sourceAddress;               /**< Source address of the acknowledgment message. */
		uint16_t targetAddress;               /**< Target address of the acknowledgment message. */
		DoIpDiagnosticAckCodes ackCode;       /**< Acknowledgment code. */
		std::vector<uint8_t> previousMessage; /**< Previous acknowlged message. */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::DIAGNOSTIC_ACK_MESSAGE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Diagnostic Acknowledgment Message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Parses and initializes the Diagnostic Acknowledgment Message data from a DoIpLayer.
		 *
		 * This method validates the provided DoIpLayer to ensure it corresponds to the
		 * Diagnostic Acknowledgment Message payload type. It extracts fields such as `sourceAddress`,
		 * `targetAddress`, `ackCode`, and `previousMessage` from the payload data.
		 *
		 * @param[in] doipLayer Pointer to the DoIpLayer containing the Diagnostic Acknowledgment Message data.
		 * @return `true` if parsing and initialization were successful, `false` otherwise.
		 *
		 * @note The method performs the following checks:
		 * - Ensures the `doipLayer` is not null.
		 * - Validates that the payload type matches `DoIpPayloadTypes::DIAGNOSTIC_ACK_MESSAGE`.
		 * - Checks that the data length is sufficient for the fixed fields and the dynamic `previousMessage`.
		 *
		 * Logs errors if the data is invalid or the payload is incompatible.
		 *
		 * The following fields are parsed:
		 * - `sourceAddress`: Source address of the acknowledgment message (2 bytes).
		 * - `targetAddress`: Target address of the acknowledgment message (2 bytes).
		 * - `ackCode`: Acknowledgment code (1 byte, converted from enum).
		 * - `previousMessage`: std::vector representing the previous message.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};

	/**
	 * @class DiagnosticNackMessageData
	 * \brief Represents a Diagnostic Negative Acknowledgment Message in DoIP.
	 *
	 * This class encapsulates data for a Diagnostic Negative Acknowledgment
	 * Message, including source and target addresses, as well as the NACK code.
	 */
	class DiagnosticNackMessageData : public IDoIpMessageData
	{
	public:
		/**
		 * @brief Default constructor for the DiagnosticNackMessageData class.
		 *
		 * Initializes a `DiagnosticNackMessageData` instance with default values:
		 * - `sourceAddress` is set to `0x0000`.
		 * - `targetAddress` is set to `0x0000`.
		 * - `nackCode` is set to `DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS`.
		 * - `previousMessage` is set to {0x22, 0xf1, 01, 0x02} as the non acknowledged diagnostic
		 * message starts with these four bytes
		 */
		DiagnosticNackMessageData();

		uint16_t sourceAddress;                  /**< Source address of the NACK message. */
		uint16_t targetAddress;                  /**< Target address of the NACK message. */
		DoIpDiagnosticMessageNackCodes nackCode; /**< Negative acknowledgment code. */
		std::vector<uint8_t> previousMessage;    /**< Previous acknowlged message. */

		/**
		 * \brief Returns the type of the message.
		 * \return `DoIpPayloadTypes::DIAGNOSTIC_NACK_MESSAGE`.
		 */
		DoIpPayloadTypes getType() const override;

		/**
		 * \brief Converts the message data to a human-readable string.
		 * \return A string representation of the Diagnostic Negative Acknowledgment Message.
		 */
		std::string toString() const override;

		/**
		 * \brief Retrieves the raw binary data of the message.
		 * \return A vector of bytes representing the message data.
		 */
		std::vector<uint8_t> getData() const override;

		/**
		 * @brief Builds the message data from the given DoIpLayer.
		 *
		 * This method parses the `DoIpLayer` to extract the relevant message data, including:
		 * - sourceAddress
		 * - targetAddress
		 * - nackCode
		 * - previousMessage (optional)
		 *
		 * @param doipLayer The layer containing the message data to be parsed.
		 * @return `true` if the message was successfully built from the layer, `false` otherwise.
		 */
		bool buildFromLayer(DoIpLayer* doipLayer) override;
	};
}  // namespace pcpp
