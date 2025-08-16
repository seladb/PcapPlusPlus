#include "ModbusLayer.h"
#include "EndianPortable.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include "Logger.h"

namespace pcpp
{
	ModbusLayer::ModbusLayer(uint16_t transactionId, uint8_t unitId, ModbusLayer::ModbusFunctionCode functionCode)
	{
		const int16_t pduSize = getFunctionDataSize(functionCode);
		if (pduSize < 0)
		{
			PCPP_LOG_ERROR("Unsupported function code: " << static_cast<int>(functionCode));
			return;
		}

		const size_t headerLen = sizeof(modbus_header);

		m_DataLen = headerLen + pduSize;
		m_Data = new uint8_t[m_DataLen]{};
		memset(m_Data, 0, m_DataLen);

		// Initialize the header fields to default values
		modbus_header* header = getModbusHeader();
		header->transactionId = htobe16(transactionId);
		header->protocolId = 0;                 // 0 for Modbus/TCP
		header->length = htobe16(pduSize + 2);  // Length includes unitId and functionCode
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
		ModbusLayer::ModbusFunctionCode functionCode =
		    static_cast<ModbusLayer::ModbusFunctionCode>(getModbusHeader()->functionCode);
		if (functionCode >= ModbusLayer::ModbusFunctionCode::FUNCTION_CODE_LIMIT)
		{
			return ModbusLayer::ModbusFunctionCode::UNKNOWN_FUNCTION;
		}
		return functionCode;
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
		if (functionCode >= ModbusLayer::ModbusFunctionCode::FUNCTION_CODE_LIMIT)
		{
			PCPP_LOG_ERROR("Invalid Modbus function code: " << static_cast<int>(functionCode));
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

	int16_t ModbusLayer::getFunctionDataSize(ModbusFunctionCode functionCode) const
	{
		switch (functionCode)
		{
			// currently supported function codes
		case ModbusFunctionCode::READ_INPUT_REGISTERS:
			return sizeof(ModbusReadInputRegisters);
		default:
			return -1;  // For unsupported or unknown function codes
		}
	}
}  // namespace pcpp
