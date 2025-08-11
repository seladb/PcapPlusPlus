#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "ModbusLayer.h"
#include "EndianPortable.h"
#include "SystemUtils.h"

PTF_TEST_CASE(ModbusLayerCreationTest)
{

	timeval time;
	gettimeofday(&time, nullptr);

	// Transaction ID: 0, Unit ID: 10, Function Code: 17
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ModbusRequest.dat");

	pcpp::Packet realPacket(&rawPacket1);
	PTF_ASSERT_TRUE(realPacket.isPacketOfType(pcpp::Modbus));
	pcpp::ModbusLayer* modbusLayerFromRealPacket = realPacket.getLayerOfType<pcpp::ModbusLayer>();

	pcpp::ModbusLayer modbusLayer(17, 255, pcpp::ModbusLayer::ModbusFunctionCode::READ_INPUT_REGISTERS);

	PTF_ASSERT_BUF_COMPARE(modbusLayer.getData(), modbusLayerFromRealPacket->getData(), modbusLayer.getHeaderLen());
	PTF_ASSERT_EQUAL(modbusLayer.getDataLen(), modbusLayerFromRealPacket->getDataLen());
	PTF_ASSERT_EQUAL(modbusLayer.getOsiModelLayer(), pcpp::OsiModelApplicationLayer);

	modbusLayer.setTransactionId(54321);
	PTF_ASSERT_EQUAL(modbusLayer.getTransactionId(), 54321);
	modbusLayer.setUnitId(2);
	PTF_ASSERT_EQUAL(modbusLayer.getUnitId(), 2);
	modbusLayer.setFunctionCode(pcpp::ModbusLayer::ModbusFunctionCode::WRITE_SINGLE_REGISTER);
	PTF_ASSERT_EQUAL(static_cast<uint8_t>(modbusLayer.getFunctionCode()),
	                 static_cast<uint8_t>(pcpp::ModbusLayer::ModbusFunctionCode::WRITE_SINGLE_REGISTER));

	// just to pass the codecov
	modbusLayer.computeCalculateFields();

}  // ModbusLayerCreationTest

PTF_TEST_CASE(ModbusLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ModbusRequest.dat");

	pcpp::Packet packet(&rawPacket1);
	PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::Modbus));

	pcpp::ModbusLayer* modbusLayer = packet.getLayerOfType<pcpp::ModbusLayer>();
	PTF_ASSERT_NOT_NULL(modbusLayer);
	PTF_ASSERT_EQUAL(modbusLayer->getTransactionId(), 17);
	PTF_ASSERT_EQUAL(modbusLayer->getProtocolId(), 0);
	PTF_ASSERT_EQUAL(modbusLayer->getLength(), 6);
	PTF_ASSERT_EQUAL(modbusLayer->getUnitId(), 255);
	PTF_ASSERT_EQUAL(static_cast<uint8_t>(modbusLayer->getFunctionCode()),
	                 static_cast<uint8_t>(pcpp::ModbusLayer::ModbusFunctionCode::READ_INPUT_REGISTERS));

	PTF_ASSERT_EQUAL(modbusLayer->toString(),
	                 "Modbus Layer, Transaction ID: 17, Protocol ID: 0, Length: 6, Unit ID: 255, Function Code: 4");
}  // ModbusLayerParsingTest
