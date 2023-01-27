#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "S7commLayer.h"


#include <stdio.h>


using namespace std;

PTF_TEST_CASE(S7commPacketNoOptionsParsing) {
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/S7comm.dat");

	pcpp::Packet S7commPacketNoOptions(&rawPacket1);
	PTF_ASSERT_TRUE(S7commPacketNoOptions.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(S7commPacketNoOptions.isPacketOfType(pcpp::S7COMM));
	auto *s7commLayer = S7commPacketNoOptions.getLayerOfType<pcpp::S7commLayer>();
	PTF_ASSERT_NOT_NULL(s7commLayer);

	PTF_ASSERT_EQUAL(s7commLayer->getS7commHeader()->protocol_id, 0x32);
	PTF_ASSERT_EQUAL(s7commLayer->getS7commHeader()->msg_type, 0x07);
	PTF_ASSERT_EQUAL(s7commLayer->getS7commHeader()->reserved, htobe16(0));
	PTF_ASSERT_EQUAL(s7commLayer->getS7commHeader()->pdu_ref, htobe16(0xfd0b));
	PTF_ASSERT_EQUAL(s7commLayer->getS7commHeader()->param_length, htobe16(12));
	PTF_ASSERT_EQUAL(s7commLayer->getS7commHeader()->data_length, htobe16(212));

} // S7commPacketNoOptionsParsing
