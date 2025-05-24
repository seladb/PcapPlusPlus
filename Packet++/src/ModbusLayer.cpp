#include "ModbusLayer.h"
#include "EndianPortable.h"

namespace pcpp
{
	ModbusLayer::ModbusLayer(uint16_t transactionId, uint8_t unitId, uint8_t functionCode)
	{
		const size_t headerLen = sizeof(modbus_common_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);

		// Initialize the header fields to default values
		modbus_common_header* header = getModbusHeader();
		header->transactionId = htobe16(transactionId);
		header->protocolId = 0;  // 0 for Modbus/TCP
		header->length = 2;      // minimum length of the MODBUS payload + unit_id
		header->unitId = unitId;
		header->functionCode = functionCode;
	}

	modbus_common_header* ModbusLayer::getModbusHeader() const
	{
		return (modbus_common_header*)m_Data;
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

	uint8_t ModbusLayer::getFunctionCode() const
	{
		return getModbusHeader()->functionCode;
	}

	void ModbusLayer::setTransactionId(uint16_t transactionId)
	{
		getModbusHeader()->transactionId = htobe16(transactionId);
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
