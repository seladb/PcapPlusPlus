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

	/// @enum modbus_function_code
	enum modbus_function_code
	{
		MODBUS_READ_COILS = 1,
		MODBUS_READ_DISCRETE_INPUTS = 2,
		MODBUS_READ_HOLDING_REGISTERS = 3,
		MODBUS_READ_INPUT_REGISTERS = 4,
		MODBUS_WRITE_SINGLE_COIL = 5,
		MODBUS_WRITE_SINGLE_REGISTER = 6,
		MODBUS_WRITE_MULTIPLE_COILS = 15,
		MODBUS_WRITE_MULTIPLE_REGISTERS = 16
	};

	/// @class ModbusLayer
	/// Represents the MODBUS Application Protocol layer
	class ModbusLayer : public Layer
	{
	public:
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
		ModbusLayer(uint16_t transactionId, uint8_t unitId, uint8_t functionCode);

		/// @brief  Check if a port is a valid MODBUS port
		/// @param port
		/// @return true if the port is valid, false otherwise
		static bool isModbusPort(uint16_t port)
		{
			return port == 502;
		}

		/// @return A pointer to the MODBUS header
		modbus_header* getModbusHeader() const;

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
		modbus_function_code getFunctionCode() const;

		/// @brief set the MODBUS transaction id
		/// @param transactionId transaction id
		void setTransactionId(uint16_t transactionId);

		/// @brief set the MODBUS header unit id
		/// @param unitId unit id
		void setUnitId(uint8_t unitId);

		/// @brief set the MODBUS header function code
		/// @param functionCode function code
		void setFunctionCode(uint8_t functionCode);

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

		/// Each layer can compute field values automatically using this method. This is an abstract method
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
	};

}  // namespace pcpp
