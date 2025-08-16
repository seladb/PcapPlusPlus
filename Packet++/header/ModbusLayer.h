#pragma once

#include "Layer.h"

/// @file
/// This file contains classes for parsing, creating and editing Modbus packets.

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

#pragma pack(push, 1)
	/// @struct modbus_header
	/// MODBUS Application Protocol header
	struct modbus_header
	{
		/// For synchronization between messages of server and client
		uint16_t transactionId;
		/// 0 for Modbus/TCP
		uint16_t protocolId;
		/// Number of remaining bytes in this frame starting from the unit id
		uint16_t length;
		/// Unit identifier
		uint8_t unitId;
		/// Function code
		uint8_t functionCode;
	};
#pragma pack(pop)
	static_assert(sizeof(modbus_header) == 8, "modbus_header size is not 8 bytes");

	/// @class ModbusLayer
	/// Represents the MODBUS Application Protocol layer
	class ModbusLayer : public Layer
	{
	public:
		// @brief Enum class representing Modbus function codes.
		// This enumeration defines the standard Modbus function codes used in request and response PDUs.
		// Each value corresponds to a specific operation defined by the Modbus protocol.
		enum class ModbusFunctionCode : uint8_t
		{
			/** Read coil status (0x01) */
			READ_COILS = 1,

			/** Read discrete input status (0x02) */
			READ_DISCRETE_INPUTS = 2,

			/** Read holding registers (0x03) */
			READ_HOLDING_REGISTERS = 3,

			/** Read input registers (0x04) */
			READ_INPUT_REGISTERS = 4,

			/** Write a single coil (0x05) */
			WRITE_SINGLE_COIL = 5,

			/** Write a single holding register (0x06) */
			WRITE_SINGLE_REGISTER = 6,

			/** Write multiple coils (0x0F) */
			WRITE_MULTIPLE_COILS = 15,

			/** Write multiple holding registers (0x10) */
			WRITE_MULTIPLE_REGISTERS = 16,

			/** Report slave ID (0x11) */
			REPORT_SLAVE_ID = 17,

			/** Limit to check if the function code is valid */
			FUNCTION_CODE_LIMIT,

			/** Unknown or unsupported function code (0xFF) */
			UNKNOWN_FUNCTION = 0xFF
		};

		/// @struct ModbusReadInputRegisters
		/// Represents a Modbus request to read input registers.
		struct ModbusReadInputRegisters
		{
			uint16_t startingAddress;  ///< Starting address of the input registers to read
			uint16_t quantity;         ///< Number of input registers to read
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		ModbusLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Modbus)
		{}

		/// A constructor that creates the layer from user inputs
		/// @param[in] transactionId Transaction ID
		/// @param[in] unitId Unit ID
		/// @param[in] functionCode Function code
		ModbusLayer(uint16_t transactionId, uint8_t unitId, ModbusFunctionCode functionCode);

		/// @brief  Check if a port is a valid MODBUS port
		/// @param port Port number to check
		/// @note MODBUS uses port 502, so this function checks if the port is equal to 502
		/// @return true if the port is valid, false otherwise
		static bool isModbusPort(uint16_t port)
		{
			return port == 502;
		}

		/// @return MODBUS message type
		uint16_t getTransactionId() const;

		/// @return MODBUS protocol id
		uint16_t getProtocolId() const;

		/// @return MODBUS remaining bytes in frame starting from the unit id
		/// @note This is the length of the MODBUS payload + unit_id, not the entire packet
		uint16_t getLength() const;

		/// @return MODBUS unit id
		uint8_t getUnitId() const;

		/// @return MODBUS function code
		ModbusFunctionCode getFunctionCode() const;

		/// @brief set the MODBUS transaction id
		/// @param transactionId transaction id
		void setTransactionId(uint16_t transactionId);

		/// @brief set the MODBUS header unit id
		/// @param unitId unit id
		void setUnitId(uint8_t unitId);

		/// @brief set the MODBUS header function code
		/// @param functionCode function code
		void setFunctionCode(ModbusFunctionCode functionCode);

		// Overridden methods

		/// Does nothing for this layer (ModbusLayer is always last)
		void parseNextLayer() override
		{}

		/// @brief Get the length of the MODBUS header
		/// @return Length of the MODBUS header in bytes
		size_t getHeaderLen() const override
		{
			return sizeof(modbus_header);
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// @return A string representation of the layer most important data (should look like the layer description in
		/// Wireshark)
		std::string toString() const override;

		/// @return The OSI Model layer this protocol belongs to
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	private:
		/// @return A pointer to the MODBUS header
		modbus_header* getModbusHeader() const;

		/// @brief Get the size of the function data based on the function code
		/// @param functionCode The MODBUS function code
		/// @return The size of the function data in bytes, or -1 if unsupported
		int16_t getFunctionDataSize(ModbusFunctionCode functionCode) const;
	};

}  // namespace pcpp
