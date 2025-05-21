
#include "ModbusLayer.h"

namespace pcpp
{
	ModbusLayer::ModbusLayer()
	{
		const size_t headerLen = sizeof(modbus_common_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);

		// Initialize the header fields to default values
		modbus_common_header* header = getModbusHeader();
		header->transactionId = 0;
		header->protocolId = 0;  // 0 for Modbus/TCP
		header->length = 2;      // minimum length of the MODBUS payload + unit_id
		header->unitId = 0;
		header->functionCode = 0;
	}

	modbus_common_header* ModbusLayer::getModbusHeader() const
	{
		return (modbus_common_header*)m_Data;
	}

	uint16_t ModbusLayer::getTransactionId()
	{
		return getModbusHeader()->transactionId;
	}

	uint16_t ModbusLayer::getProtocolId()
	{
		return getModbusHeader()->protocolId;
	}

	uint16_t ModbusLayer::getLength()
	{
		return getModbusHeader()->length;
	}

	uint8_t ModbusLayer::getUnitId()
	{
		return getModbusHeader()->unitId;
	}

	uint8_t ModbusLayer::getFunctionCode()
	{
		return getModbusHeader()->functionCode;
	}

	void ModbusLayer::setTransactionId(uint16_t transactionId)
	{
		getModbusHeader()->transactionId = transactionId;
	}

	void ModbusLayer::setUnitId(uint8_t unitId)
	{
		getModbusHeader()->unitId = unitId;
	}

	void ModbusLayer::setFunctionCode(uint8_t functionCode)
	{
		getModbusHeader()->functionCode = functionCode;
	}

}  // namespace pcpp
