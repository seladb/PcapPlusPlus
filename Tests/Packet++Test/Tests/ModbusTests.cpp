#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "ModbusLayer.h"
#include "EndianPortable.h"
#include "SystemUtils.h"

PTF_TEST_CASE(ModbusLayerCreationTest)
{
	pcpp::ModbusLayer modbusLayer(12345, 1, 3);

	PTF_ASSERT_EQUAL(modbusLayer.getTransactionId(), 12345);
	PTF_ASSERT_EQUAL(modbusLayer.getProtocolId(), 0);
	PTF_ASSERT_EQUAL(modbusLayer.getLength(), 2);  // minimum length of the MODBUS payload + unit_id
	PTF_ASSERT_EQUAL(modbusLayer.getUnitId(), 1);
	PTF_ASSERT_EQUAL(modbusLayer.getFunctionCode(), 3);
	PTF_ASSERT_EQUAL(modbusLayer.getHeaderLen(), sizeof(pcpp::modbus_common_header));

	PTF_ASSERT_EQUAL(modbusLayer.toString(),
	                 "Modbus Layer, Transaction ID: 12345, Protocol ID: 0, Length: 2, Unit ID: 1, Function Code: 3");
	PTF_ASSERT_EQUAL(modbusLayer.getOsiModelLayer(), pcpp::OsiModelApplicationLayer);
}  // ModbusLayerCreationTest

PTF_TEST_CASE(ModbusLayerParsingTest)
{
	// Create a ModbusLayer from dat file
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ModbusPacket.dat");
	pcpp::Packet modbusPacket(&rawPacket1);
	PTF_ASSERT_TRUE(modbusPacket.isPacketOfType(pcpp::Modbus));
	pcpp::ModbusLayer* modbusLayer = modbusPacket.getLayerOfType<pcpp::ModbusLayer>();

	PTF_ASSERT_NOT_NULL(modbusLayer);
	PTF_ASSERT_EQUAL(modbusLayer->getTransactionId(), 12345);
	PTF_ASSERT_EQUAL(modbusLayer->getProtocolId(), 0);
	PTF_ASSERT_EQUAL(modbusLayer->getLength(), 2);  // minimum length of the MODBUS payload + unit_id
	PTF_ASSERT_EQUAL(modbusLayer->getUnitId(), 1);
	PTF_ASSERT_EQUAL(modbusLayer->getFunctionCode(), 3);
	PTF_ASSERT_EQUAL(modbusLayer->getHeaderLen(), sizeof(pcpp::modbus_common_header));
}  // ModbusLayerParsingTest