#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "S7CommLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(S7CommLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/S7comm.dat");

	pcpp::Packet S7CommLayerTest(&rawPacket1);
	PTF_ASSERT_TRUE(S7CommLayerTest.isPacketOfType(pcpp::S7COMM));
	auto *S7CommLayer = S7CommLayerTest.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(S7CommLayer);

	PTF_ASSERT_EQUAL(S7CommLayer->getProtocolId(), 50);
	PTF_ASSERT_EQUAL(S7CommLayer->getMsgType(), 7);
	PTF_ASSERT_EQUAL(S7CommLayer->getPduRef(), 64779);
	PTF_ASSERT_EQUAL(S7CommLayer->getParamLength(), 12);
	PTF_ASSERT_EQUAL(S7CommLayer->getDataLength(), 212);
	PTF_ASSERT_EQUAL(S7CommLayer->getHeaderLen(), 234);
	PTF_ASSERT_EQUAL(S7CommLayer->toString(), "S7Comm Layer");

	PTF_ASSERT_EQUAL(S7CommLayer->getParameter()->getDataLength(), 12);
	uint8_t expectedParameterData[] = {0, 1, 18, 8, 18, 132, 1, 1, 0, 0, 0, 0};
	PTF_ASSERT_BUF_COMPARE(S7CommLayer->getParameter()->getData(), expectedParameterData, 12);
} // S7CommLayerParsingTest

PTF_TEST_CASE(S7CommLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	pcpp::S7CommLayer newS7commPacket(9, 64780, 13, 213);

	PTF_ASSERT_EQUAL(newS7commPacket.getMsgType(), 9);
	PTF_ASSERT_EQUAL(newS7commPacket.getPduRef(), 64780);
	PTF_ASSERT_EQUAL(newS7commPacket.getParamLength(), 13);
	PTF_ASSERT_EQUAL(newS7commPacket.getDataLength(), 213);

	newS7commPacket.setMsgType(6);
	newS7commPacket.setPduRef(64778);
	newS7commPacket.setDataLength(215);

	PTF_ASSERT_EQUAL(newS7commPacket.getMsgType(), 6);
	PTF_ASSERT_EQUAL(newS7commPacket.getPduRef(), 64778);
	PTF_ASSERT_EQUAL(newS7commPacket.getDataLength(), 215);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/s7comm_ack_data.dat");

	pcpp::Packet S7CommLayerErrorTest(&rawPacket2);
	PTF_ASSERT_TRUE(S7CommLayerErrorTest.isPacketOfType(pcpp::S7COMM));
	auto *s7commErrorLayer = S7CommLayerErrorTest.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(s7commErrorLayer);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getProtocolId(), 50);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getMsgType(), 3);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getPduRef(), 0);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getParamLength(), 2);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getDataLength(), 68);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorClass(), 0);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorCode(), 0);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getHeaderLen(), 82);

	PTF_ASSERT_EQUAL(s7commErrorLayer->toString(), "S7Comm Layer");

	s7commErrorLayer->setErrorCode(6);
	s7commErrorLayer->setErrorClass(7);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorClass(), 7);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorCode(), 6);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getParameter()->getDataLength(), 2);
	uint8_t expectedErrorParameterData[] = {4, 1};
	PTF_ASSERT_BUF_COMPARE(s7commErrorLayer->getParameter()->getData(), expectedErrorParameterData, 2);
} // S7CommLayerCreationTest
