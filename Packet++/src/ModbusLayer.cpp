#include "ModbusLayer.h"
#include "EndianPortable.h"
#include <iostream>
#include <iomanip>
#include <cstring>

namespace pcpp
{
	ModbusLayer::ModbusLayer(uint16_t transactionId, uint8_t unitId, ModbusLayer::ModbusFunctionCode functionCode)
	{
		const size_t headerLen = sizeof(modbus_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);

		// Initialize the header fields to default values
		modbus_header* header = getModbusHeader();
		header->transactionId = htobe16(transactionId);
		header->protocolId = 0;       // 0 for Modbus/TCP
		header->length = htobe16(2);  // minimum length of the MODBUS payload + unit_id
		header->unitId = unitId;
		header->functionCode = static_cast<uint8_t>(functionCode);
	}

	modbus_header* ModbusLayer::getModbusHeader() const
	{
		return (modbus_header*)m_Data;
	}

	uint16_t ModbusLayer::getTransactionId() const
	{
		return be16toh(getModbusHeader()->transactionId);
	}

	uint16_t ModbusLayer::getProtocolId() const
	{
		return be16toh(getModbusHeader()->protocolId);
	}

	uint16_t ModbusLayer::getLength() const
	{
		return be16toh(getModbusHeader()->length);
	}

	uint8_t ModbusLayer::getUnitId() const
	{
		return getModbusHeader()->unitId;
	}

	ModbusLayer::ModbusFunctionCode ModbusLayer::getFunctionCode() const
	{
		return static_cast<ModbusLayer::ModbusFunctionCode>(getModbusHeader()->functionCode);
	}

	void ModbusLayer::setTransactionId(uint16_t transactionId)
	{
		getModbusHeader()->transactionId = htobe16(transactionId);
	}

	void ModbusLayer::setUnitId(uint8_t unitId)
	{
		getModbusHeader()->unitId = unitId;
	}

	void ModbusLayer::setFunctionCode(ModbusLayer::ModbusFunctionCode functionCode)
	{
		if (functionCode >= ModbusLayer::ModbusFunctionCode::MODBUS_FUNCTION_CODE_LIMIT)
		{
			return;
		}
		getModbusHeader()->functionCode = static_cast<uint8_t>(functionCode);
	}

	std::string ModbusLayer::toString() const
	{
		return "Modbus Layer, Transaction ID: " + std::to_string(getTransactionId()) +
		       ", Protocol ID: " + std::to_string(getProtocolId()) + ", Length: " + std::to_string(getLength()) +
		       ", Unit ID: " + std::to_string(getUnitId()) +
		       ", Function Code: " + std::to_string(static_cast<uint8_t>(getFunctionCode()));
	}

}  // namespace pcpp
