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

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ModbusRequest.dat");

	pcpp::Packet realPacket(&rawPacket1);
	PTF_ASSERT_TRUE(realPacket.isPacketOfType(pcpp::Modbus));

	pcpp::ModbusLayer* modbusLayerFromRealPacket = realPacket.getLayerOfType<pcpp::ModbusLayer>();

	pcpp::ModbusLayer modbusLayer(12345, 1, 3);

	PTF_ASSERT_EQUAL(modbusLayer.getTransactionId(), 12345);
	PTF_ASSERT_EQUAL(modbusLayer.getProtocolId(), 0);
	PTF_ASSERT_EQUAL(modbusLayer.getLength(), 2);  // minimum length of the MODBUS payload + unit_id
	PTF_ASSERT_EQUAL(modbusLayer.getUnitId(), 1);
	PTF_ASSERT_EQUAL(modbusLayer.getFunctionCode(), 3);
	PTF_ASSERT_EQUAL(modbusLayer.getHeaderLen(), sizeof(pcpp::modbus_header));

	PTF_ASSERT_EQUAL(modbusLayer.getOsiModelLayer(), pcpp::OsiModelApplicationLayer);

	modbusLayer.setTransactionId(54321);
	PTF_ASSERT_EQUAL(modbusLayer.getTransactionId(), 54321);
	modbusLayer.setUnitId(2);
	PTF_ASSERT_EQUAL(modbusLayer.getUnitId(), 2);
	modbusLayer.setFunctionCode(6);
	PTF_ASSERT_EQUAL(modbusLayer.getFunctionCode(), 6);

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
	PTF_ASSERT_EQUAL(modbusLayer->getTransactionId(), 1);
	PTF_ASSERT_EQUAL(modbusLayer->getProtocolId(), 0);
	PTF_ASSERT_EQUAL(modbusLayer->getLength(), 6);
	PTF_ASSERT_EQUAL(modbusLayer->getUnitId(), 10);
	PTF_ASSERT_EQUAL(modbusLayer->getFunctionCode(), 1);

	PTF_ASSERT_EQUAL(modbusLayer->toString(),
	                 "Modbus Layer, Transaction ID: 1, Protocol ID: 0, Length: 6, Unit ID: 10, Function Code: 1");
}  // ModbusLayerParsingTest
