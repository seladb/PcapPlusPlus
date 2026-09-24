#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "S7CommLayer.h"
#include "SystemUtils.h"

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(S7CommLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/S7comm.dat");

	pcpp::Packet s7CommLayerTest(rawPacket1.get());
	PTF_ASSERT_TRUE(s7CommLayerTest.isPacketOfType(pcpp::S7COMM));
	auto* S7CommLayer = s7CommLayerTest.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(S7CommLayer);

	PTF_ASSERT_EQUAL(S7CommLayer->getProtocolId(), 50);
	PTF_ASSERT_EQUAL(S7CommLayer->getMsgType(), 7);
	PTF_ASSERT_EQUAL(S7CommLayer->getPduRef(), 64779);
	PTF_ASSERT_EQUAL(S7CommLayer->getParamLength(), 12);
	PTF_ASSERT_EQUAL(S7CommLayer->getDataLength(), 212);
	PTF_ASSERT_EQUAL(S7CommLayer->getHeaderLen(), 234);
	PTF_ASSERT_EQUAL(S7CommLayer->toString(), "S7Comm Layer, Userdata");

	PTF_ASSERT_EQUAL(S7CommLayer->getParameter()->getDataLength(), 12);
	uint8_t expectedParameterData[] = { 0, 1, 18, 8, 18, 132, 1, 1, 0, 0, 0, 0 };
	PTF_ASSERT_BUF_COMPARE(S7CommLayer->getParameter()->getData(), expectedParameterData, 12);

	auto rawPacket2 = createPacketFromHexResource("PacketExamples/s7comm_ack_data.dat");

	pcpp::Packet s7CommLayerTest2(rawPacket2.get());
	PTF_ASSERT_TRUE(s7CommLayerTest2.isPacketOfType(pcpp::S7COMM));
	auto* s7commLayer = s7CommLayerTest2.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(s7commLayer);
	PTF_ASSERT_EQUAL(s7commLayer->getProtocolId(), 50);
	PTF_ASSERT_EQUAL(s7commLayer->getMsgType(), 3);
	PTF_ASSERT_EQUAL(s7commLayer->getPduRef(), 0);
	PTF_ASSERT_EQUAL(s7commLayer->getParamLength(), 2);
	PTF_ASSERT_EQUAL(s7commLayer->getDataLength(), 68);
	PTF_ASSERT_EQUAL(s7commLayer->getErrorClass(), 0);
	PTF_ASSERT_EQUAL(s7commLayer->getErrorCode(), 0);
	PTF_ASSERT_EQUAL(s7commLayer->getHeaderLen(), 82);

	PTF_ASSERT_EQUAL(s7commLayer->toString(), "S7Comm Layer, Ack-Data");

	s7commLayer->setErrorCode(6);
	s7commLayer->setErrorClass(7);
	PTF_ASSERT_EQUAL(s7commLayer->getErrorClass(), 7);
	PTF_ASSERT_EQUAL(s7commLayer->getErrorCode(), 6);
	PTF_ASSERT_EQUAL(s7commLayer->getParameter()->getDataLength(), 2);
	uint8_t expectedErrorParameterData[] = { 4, 1 };
	PTF_ASSERT_BUF_COMPARE(s7commLayer->getParameter()->getData(), expectedErrorParameterData, 2);
}  // S7CommLayerParsingTest

PTF_TEST_CASE(S7CommLayerMalformedTest)
{
	// the Ack-Data header is only present for message type 0x03
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/S7comm.dat");

	pcpp::Packet userDataPacket(rawPacket1.get());
	auto* userDataLayer = userDataPacket.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(userDataLayer);
	PTF_ASSERT_EQUAL(userDataLayer->getMsgType(), 7);
	PTF_ASSERT_EQUAL(userDataLayer->getErrorClass(), 0);
	PTF_ASSERT_EQUAL(userDataLayer->getErrorCode(), 0);

	{
		SuppressLogs suppressLogs;
		userDataLayer->setErrorClass(7);
		userDataLayer->setErrorCode(6);
	}
	PTF_ASSERT_EQUAL(userDataLayer->getErrorClass(), 0);
	PTF_ASSERT_EQUAL(userDataLayer->getErrorCode(), 0);

	// an Ack-Data message carrying only the 10 byte base header, which is the smallest
	// layer isDataValid() accepts, and a parameter length that runs past the packet
	auto rawPacket2 = createPacketFromHexResource("PacketExamples/s7comm_ack_data_truncated.dat");

	pcpp::Packet truncatedPacket(rawPacket2.get());
	auto* truncatedLayer = truncatedPacket.getLayerOfType<pcpp::S7CommLayer>();
	PTF_ASSERT_NOT_NULL(truncatedLayer);
	PTF_ASSERT_EQUAL(truncatedLayer->getMsgType(), 3);
	PTF_ASSERT_EQUAL(truncatedLayer->getHeaderLen(), 10);
	PTF_ASSERT_EQUAL(truncatedLayer->getErrorClass(), 0);
	PTF_ASSERT_EQUAL(truncatedLayer->getErrorCode(), 0);

	PTF_ASSERT_EQUAL(truncatedLayer->getParamLength(), 65535);
	PTF_ASSERT_EQUAL(truncatedLayer->getParameter()->getDataLength(), 0);
}  // S7CommLayerMalformedTest

PTF_TEST_CASE(S7CommLayerCreationTest)
{
	pcpp::S7CommLayer newS7commLayer(1, 64780, 12, 212);

	PTF_ASSERT_EQUAL(newS7commLayer.getMsgType(), 1);
	PTF_ASSERT_EQUAL(newS7commLayer.getPduRef(), 64780);
	PTF_ASSERT_EQUAL(newS7commLayer.getParamLength(), 12);
	PTF_ASSERT_EQUAL(newS7commLayer.getDataLength(), 212);
	PTF_ASSERT_EQUAL(newS7commLayer.getHeaderLen(), 234);
	PTF_ASSERT_EQUAL(newS7commLayer.toString(), "S7Comm Layer, Job Request");

	newS7commLayer.setMsgType(6);
	newS7commLayer.setPduRef(64778);

	PTF_ASSERT_EQUAL(newS7commLayer.getMsgType(), 6);
	PTF_ASSERT_EQUAL(newS7commLayer.getPduRef(), 64778);
	PTF_ASSERT_EQUAL(newS7commLayer.toString(), "S7Comm Layer, Unknown message");

	newS7commLayer.setMsgType(2);
	PTF_ASSERT_EQUAL(newS7commLayer.toString(), "S7Comm Layer, Ack");

	pcpp::S7CommLayer newS7commLayer2(3, 0, 2, 68, 0x81, 2);

	PTF_ASSERT_EQUAL(newS7commLayer2.getMsgType(), 3);
	PTF_ASSERT_EQUAL(newS7commLayer2.getErrorClass(), 0x81);
	PTF_ASSERT_EQUAL(newS7commLayer2.getErrorCode(), 2);
	PTF_ASSERT_EQUAL(newS7commLayer2.getHeaderLen(), 82);
	PTF_ASSERT_EQUAL(newS7commLayer2.toString(), "S7Comm Layer, Ack-Data");
}  // S7CommLayerCreationTest
