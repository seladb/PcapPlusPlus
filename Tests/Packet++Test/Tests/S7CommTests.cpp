#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "S7CommLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(S7CommLayerTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/S7comm.dat");

	pcpp::Packet S7CommLayerTest(&rawPacket1);
	PTF_ASSERT_TRUE(S7CommLayerTest.isPacketOfType(pcpp::S7COMM));
	auto *S7CommLayer = S7CommLayerTest.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(S7CommLayer);

	PTF_ASSERT_EQUAL(S7CommLayer->getProtocolId(), 0x32);
	PTF_ASSERT_EQUAL(S7CommLayer->getMsgType(), 0x07);
	PTF_ASSERT_EQUAL(S7CommLayer->getPduRef(), 0xfd0b);
	PTF_ASSERT_EQUAL(S7CommLayer->getParamLength(), 12);
	PTF_ASSERT_EQUAL(S7CommLayer->getDataLength(), 212);
	PTF_ASSERT_EQUAL(S7CommLayer->getHeaderLen(), 0xea);
	PTF_ASSERT_EQUAL(S7CommLayer->toString(), "S7Comm Layer, Job Request");

	PTF_ASSERT_EQUAL(S7CommLayer->getParameter()->getDataLength(), 12);
	uint8_t expectedParameterData[] = {0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00};
	PTF_ASSERT_BUF_COMPARE(S7CommLayer->getParameter()->getData(), expectedParameterData, 12);

	pcpp::S7CommLayer newS7commPacket(0x09, 0xfd0c, 13, 213);

	PTF_ASSERT_EQUAL(newS7commPacket.getMsgType(), 0x09);
	PTF_ASSERT_EQUAL(newS7commPacket.getPduRef(), 0xfd0c);
	PTF_ASSERT_EQUAL(newS7commPacket.getParamLength(), 13);
	PTF_ASSERT_EQUAL(newS7commPacket.getDataLength(), 213);

	newS7commPacket.setMsgType(0x06);
	newS7commPacket.setPduRef(0xfd0a);
	newS7commPacket.setParamLength(15);
	newS7commPacket.setDataLength(215);

	PTF_ASSERT_EQUAL(newS7commPacket.getMsgType(), 0x06);
	PTF_ASSERT_EQUAL(newS7commPacket.getPduRef(), 0xfd0a);
	PTF_ASSERT_EQUAL(newS7commPacket.getParamLength(), 15);
	PTF_ASSERT_EQUAL(newS7commPacket.getDataLength(), 215);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/s7comm_error_code.dat");

	pcpp::Packet S7CommLayerErrorTest(&rawPacket2);
	PTF_ASSERT_TRUE(S7CommLayerErrorTest.isPacketOfType(pcpp::S7COMM));
	auto *s7commErrorLayer = S7CommLayerErrorTest.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(s7commErrorLayer);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getProtocolId(), 0x32);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getMsgType(), 0x03);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getPduRef(), 0x0000);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getParamLength(), 2);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getDataLength(), 68);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorClass(), 0x00);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorCode(), 0x00);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getHeaderLen(), 0x52);

	PTF_ASSERT_EQUAL(s7commErrorLayer->toString(), "S7Comm Layer, Job Request");

	s7commErrorLayer->setErrorCode(0x06);
	s7commErrorLayer->setErrorClass(0x07);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorClass(), 0x07);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorCode(), 0x06);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getParameter()->getDataLength(), 2);
	uint8_t expectedErrorParameterData[] = {0x04, 0x01};
	PTF_ASSERT_BUF_COMPARE(s7commErrorLayer->getParameter()->getData(), expectedErrorParameterData, 2);
} // S7CommLayerTest
