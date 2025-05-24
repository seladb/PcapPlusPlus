#pragma once

#include "Layer.h"

/// @file
/// This file contains classes for parsing, creating and editing Modbus packets.

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

#pragma pack(push, 1)
	/// @struct modbus_common_header
	/// MODBUS Application Protocol header
	struct modbus_common_header
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
	static_assert(sizeof(modbus_common_header) == 8, "modbus_common_header size is not 8 bytes");

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

		/// @return A pointer to the MODBUS header
		modbus_common_header* getModbusHeader() const;

		/// @return MODBUS message type
		uint16_t getTransactionId();

		/// @return MODBUS protocol id
		uint16_t getProtocolId();

		/// @return MODBUS remaining bytes in frame starting from the unit id
		/// @note This is the length of the MODBUS payload + unit_id, not the entire packet
		uint16_t getLength();

		/// @return MODBUS unit id
		uint8_t getUnitId();

		/// @return MODBUS function code
		uint8_t getFunctionCode();

		/// @brief set the MODBUS transaction id
		/// @param transactionId transaction id
		void setTransactionId(uint16_t transactionId);

		/// @brief set the MODBUS header unit id
		/// @param unitId unit id
		void setUnitId(uint8_t unitId);

		/// @brief set the MODBUS header function code
		/// @param functionCode function code
		void setFunctionCode(uint8_t functionCode);
	};

}  // namespace pcpp
