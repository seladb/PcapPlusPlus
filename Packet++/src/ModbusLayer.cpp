#include "ModbusLayer.h"
#include "EndianPortable.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include "Logger.h"

namespace pcpp
{
	ModbusLayer::ModbusLayer(uint16_t transactionId, uint8_t unitId)
	{
		const int16_t pduSize = sizeof(ModbusReadInputRegisters);  // Currently only supporting Read Input Registers
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
		header->functionCode = static_cast<uint8_t>(ModbusFunctionCode::ReadInputRegisters);
	}

	modbus_header* ModbusLayer::getModbusHeader() const
	{
		return reinterpret_cast<modbus_header*>(m_Data);
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
		switch (getModbusHeader()->functionCode)
		{
		case 1:
			return ModbusFunctionCode::ReadCoils;
		case 2:
			return ModbusFunctionCode::ReadDiscreteInputs;
		case 3:
			return ModbusFunctionCode::ReadHoldingRegisters;
		case 4:
			return ModbusFunctionCode::ReadInputRegisters;
		case 5:
			return ModbusFunctionCode::WriteSingleCoil;
		case 6:
			return ModbusFunctionCode::WriteSingleHoldingRegister;
		case 15:
			return ModbusFunctionCode::WriteMultipleCoils;
		case 16:
			return ModbusFunctionCode::WriteMultipleHoldingRegisters;
		case 17:
			return ModbusFunctionCode::ReadSlaveId;
		default:
			return ModbusFunctionCode::UnknownFunction;
		}
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
