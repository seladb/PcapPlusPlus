#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "S7commLayer.h"
#include "SystemUtils.h"
#include <stdio.h>

PTF_TEST_CASE(S7commLayerTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/S7comm.dat");

	pcpp::Packet S7commLayerTest(&rawPacket1);
	PTF_ASSERT_TRUE(S7commLayerTest.isPacketOfType(pcpp::S7COMM));
	auto *s7commLayer = S7commLayerTest.getLayerOfType<pcpp::S7commLayer>();
	PTF_ASSERT_NOT_NULL(s7commLayer);

	PTF_ASSERT_EQUAL(s7commLayer->getProtocolId(), 0x32);
	PTF_ASSERT_EQUAL(s7commLayer->getMsgType(), 0x07);
	PTF_ASSERT_EQUAL(s7commLayer->getReserved(), htobe16(0));
	PTF_ASSERT_EQUAL(s7commLayer->getPduRef(), 0xfd0b);
	PTF_ASSERT_EQUAL(s7commLayer->getParamLength(), 12);
	PTF_ASSERT_EQUAL(s7commLayer->getDataLength(), 212);
	PTF_ASSERT_EQUAL(s7commLayer->getHeaderLen(), 0xea);
	PTF_ASSERT_EQUAL(s7commLayer->toString(),
					 "S7comm Layer, msg_type: 7, pdu_ref: 64779, param_length: 12, data_length: 212");

	pcpp::S7commLayer newS7commPacket(0x09, 0xfd0c, 13, 213);

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

	pcpp::Packet S7commLayerErrorTest(&rawPacket2);
	PTF_ASSERT_TRUE(S7commLayerErrorTest.isPacketOfType(pcpp::S7COMM));
	auto *s7commErrorLayer = S7commLayerErrorTest.getLayerOfType<pcpp::S7commLayer>();
	PTF_ASSERT_NOT_NULL(s7commErrorLayer);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getProtocolId(), 0x32);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getMsgType(), 0x03);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getReserved(), htobe16(0));
	PTF_ASSERT_EQUAL(s7commErrorLayer->getPduRef(), 0x0000);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getParamLength(), 2);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getDataLength(), 68);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorClass(), 0x00);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorCode(), 0x00);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getHeaderLen(), 0x52);

	PTF_ASSERT_EQUAL(
		s7commErrorLayer->toString(),
		"S7comm Layer, msg_type: 3, pdu_ref: 0, param_length: 2, data_length: 68, error class: 0, error code: 0");

	s7commErrorLayer->setErrorCode(0x06);
	s7commErrorLayer->setErrorClass(0x07);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorClass(), 0x07);
	PTF_ASSERT_EQUAL(s7commErrorLayer->getErrorCode(), 0x06);
} // S7commLayerTest
