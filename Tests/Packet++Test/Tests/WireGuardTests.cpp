#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "WireGuardLayer.h"
#include "SystemUtils.h"
#include <cstring>
#include "EndianPortable.h"

PTF_TEST_CASE(WireGuardHandshakeInitParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WireGuardHandshakeInitiation.dat");

	pcpp::Packet wgHandShakeInitPacket(&rawPacket1);

	PTF_ASSERT_TRUE(wgHandShakeInitPacket.isPacketOfType(pcpp::WireGuard));

	pcpp::WireGuardLayer* wgLayer = wgHandShakeInitPacket.getLayerOfType<pcpp::WireGuardLayer>();
	PTF_ASSERT_NOT_NULL(wgLayer);

	PTF_ASSERT_EQUAL(wgLayer->getMessageTypeAsString(), "Handshake Initiation");
	PTF_ASSERT_EQUAL(wgLayer->toString(), "WireGuard Layer, " + wgLayer->getMessageTypeAsString() + " message");

	pcpp::WireGuardHandshakeInitiationLayer* wgHandShakeInitLayer =
	    wgHandShakeInitPacket.getLayerOfType<pcpp::WireGuardHandshakeInitiationLayer>();
	PTF_ASSERT_NOT_NULL(wgHandShakeInitLayer);

	PTF_ASSERT_TRUE(wgHandShakeInitLayer->getWireGuardMessageType() ==
	                pcpp::WireGuardLayer::WireGuardMessageType::HandshakeInitiation);

	PTF_ASSERT_EQUAL(wgHandShakeInitLayer->getSenderIndex(), be32toh(818952152));

	std::array<uint8_t, 32> expectedPublicKey = { 0x5f, 0xce, 0xc7, 0xc8, 0xe5, 0xc8, 0xe2, 0xe3, 0xf7, 0x98, 0x9e,
		                                          0xef, 0x60, 0xc2, 0x28, 0xd8, 0x23, 0x29, 0xd6, 0x02, 0xb6, 0xb1,
		                                          0xe2, 0xbb, 0x9d, 0x06, 0x8f, 0x89, 0xcf, 0x9d, 0x4d, 0x45 };
	PTF_ASSERT_TRUE(wgHandShakeInitLayer->getInitiatorEphemeral() == expectedPublicKey);

	std::array<uint8_t, 48> expectedStaticKey = { 0x32, 0x78, 0x0f, 0x6d, 0x27, 0x26, 0x4f, 0x7b, 0x98, 0x70,
		                                          0x1f, 0xdc, 0x27, 0xa4, 0xec, 0x00, 0xae, 0xb6, 0xbe, 0xcd,
		                                          0xbe, 0xf2, 0x33, 0x2f, 0x1b, 0x40, 0x84, 0xca, 0xdb, 0x93,
		                                          0x82, 0x39, 0x35, 0xc0, 0x12, 0xae, 0x25, 0x5e, 0x7b, 0x25,
		                                          0xef, 0xf1, 0x39, 0x40, 0xc3, 0x21, 0xfa, 0x6b };
	PTF_ASSERT_TRUE(wgHandShakeInitLayer->getEncryptedInitiatorStatic() == expectedStaticKey);

	std::array<uint8_t, 28> expectedTimestamp = { 0xd6, 0x6a, 0x2a, 0x87, 0xb0, 0x61, 0xdb, 0x14, 0x30, 0x17,
		                                          0x3e, 0x93, 0x7f, 0x56, 0x93, 0x49, 0xde, 0x28, 0x56, 0xdc,
		                                          0x5f, 0x26, 0x16, 0x76, 0x3e, 0xee, 0xaf, 0xc0 };
	PTF_ASSERT_TRUE(wgHandShakeInitLayer->getEncryptedTimestamp() == expectedTimestamp);

	std::array<uint8_t, 16> expectedMac1 = { 0x53, 0x3b, 0x01, 0xdd, 0x96, 0x5e, 0x7e, 0xc7,
		                                     0x69, 0x76, 0xe2, 0x8f, 0x68, 0x3d, 0x67, 0x12 };
	PTF_ASSERT_TRUE(wgHandShakeInitLayer->getMac1() == expectedMac1);

	std::array<uint8_t, 16> expectedMac2 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PTF_ASSERT_TRUE(wgHandShakeInitLayer->getMac2() == expectedMac2);
}

PTF_TEST_CASE(WireGuardHandshakeRespParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WireGuardHandshakeResponse.dat");

	pcpp::Packet wgHandShakeResponsePacket(&rawPacket1);

	PTF_ASSERT_TRUE(wgHandShakeResponsePacket.isPacketOfType(pcpp::WireGuard));
	pcpp::WireGuardLayer* wgLayer = wgHandShakeResponsePacket.getLayerOfType<pcpp::WireGuardLayer>();
	PTF_ASSERT_NOT_NULL(wgLayer);
	PTF_ASSERT_EQUAL(wgLayer->getMessageTypeAsString(), "Handshake Response");
	PTF_ASSERT_EQUAL(wgLayer->toString(), "WireGuard Layer, " + wgLayer->getMessageTypeAsString() + " message");

	pcpp::WireGuardHandshakeResponseLayer* wgHandShakeResponseLayer =
	    wgHandShakeResponsePacket.getLayerOfType<pcpp::WireGuardHandshakeResponseLayer>();
	PTF_ASSERT_NOT_NULL(wgHandShakeResponseLayer);

	PTF_ASSERT_TRUE(wgHandShakeResponseLayer->getWireGuardMessageType() ==
	                pcpp::WireGuardLayer::WireGuardMessageType::HandshakeResponse);

	PTF_ASSERT_EQUAL(wgHandShakeResponseLayer->getSenderIndex(), be32toh(2877158406));
	PTF_ASSERT_EQUAL(wgHandShakeResponseLayer->getReceiverIndex(), be32toh(818952152));

	std::array<uint8_t, 32> expectedResponderEphemeral = { 0xb1, 0x8d, 0x55, 0x50, 0xbd, 0x40, 0x42, 0xa3,
		                                                   0x7a, 0x46, 0x82, 0x3a, 0xc0, 0x8d, 0xb1, 0xec,
		                                                   0x66, 0x83, 0x9b, 0xc0, 0xca, 0x2d, 0x64, 0xbc,
		                                                   0x15, 0xcd, 0x80, 0x23, 0x2b, 0x66, 0x23, 0x2f };
	PTF_ASSERT_TRUE(wgHandShakeResponseLayer->getResponderEphemeral() == expectedResponderEphemeral);

	std::array<uint8_t, 16> encryptedEmptyData = { 0xae, 0xc2, 0x4a, 0xf8, 0x91, 0x8d, 0xe1, 0x06,
		                                           0x0f, 0xf5, 0xc9, 0x8e, 0x86, 0x5d, 0x5f, 0x35 };

	PTF_ASSERT_TRUE(wgHandShakeResponseLayer->getEncryptedEmpty() == encryptedEmptyData);

	std::array<uint8_t, 16> expectedMac1 = { 0xf2, 0x72, 0x21, 0x4c, 0x52, 0x60, 0x11, 0x0d,
		                                     0xc4, 0xc6, 0x1e, 0x32, 0xcd, 0xd8, 0x54, 0x21 };
	PTF_ASSERT_TRUE(wgHandShakeResponseLayer->getMac1() == expectedMac1);

	std::array<uint8_t, 16> expectedMac2 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PTF_ASSERT_TRUE(wgHandShakeResponseLayer->getMac2() == expectedMac2);
}

PTF_TEST_CASE(WireGuardTransportDataParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WireGuardTransportData.dat");

	pcpp::Packet wgTransportDataPacket(&rawPacket1);
	PTF_ASSERT_TRUE(wgTransportDataPacket.isPacketOfType(pcpp::WireGuard));
	pcpp::WireGuardLayer* wgLayer = wgTransportDataPacket.getLayerOfType<pcpp::WireGuardLayer>();
	PTF_ASSERT_NOT_NULL(wgLayer);
	PTF_ASSERT_EQUAL(wgLayer->getMessageTypeAsString(), "Transport Data");
	PTF_ASSERT_EQUAL(wgLayer->toString(), "WireGuard Layer, " + wgLayer->getMessageTypeAsString() + " message");

	pcpp::WireGuardTransportDataLayer* wgTransportDataLayer =
	    wgTransportDataPacket.getLayerOfType<pcpp::WireGuardTransportDataLayer>();
	PTF_ASSERT_NOT_NULL(wgTransportDataLayer);

	PTF_ASSERT_TRUE(wgTransportDataLayer->getWireGuardMessageType() ==
	                pcpp::WireGuardLayer::WireGuardMessageType::TransportData);

	PTF_ASSERT_EQUAL(wgTransportDataLayer->getReceiverIndex(), be32toh(2877158406));

	uint64_t expectedCounter = 0x0000000000000000;
	PTF_ASSERT_EQUAL(wgTransportDataLayer->getCounter(), be32toh(expectedCounter));

	uint8_t expectedEncryptedData[112] = { 0xa4, 0xeb, 0xc1, 0x2e, 0xe3, 0xf9, 0x90, 0xda, 0x18, 0x03, 0x3a, 0x07, 0x89,
		                                   0xc0, 0x4e, 0x27, 0x00, 0xf6, 0xf5, 0xc2, 0x71, 0xd4, 0x2a, 0xc4, 0xb4, 0xd6,
		                                   0x26, 0x2e, 0x66, 0x65, 0x49, 0xb4, 0x45, 0xa7, 0x43, 0x6e, 0x82, 0x9b, 0xff,
		                                   0xb6, 0xac, 0x65, 0xf0, 0x56, 0x48, 0xbc, 0x0c, 0x39, 0x1f, 0xe7, 0xc5, 0x88,
		                                   0x48, 0x74, 0x37, 0x61, 0x27, 0x16, 0x49, 0x40, 0x18, 0x8f, 0x03, 0xdb, 0xa6,
		                                   0x7a, 0xf8, 0x38, 0x8e, 0xaa, 0xb7, 0x6c, 0x59, 0x36, 0x28, 0xbf, 0x9d, 0xc7,
		                                   0xbe, 0x03, 0x34, 0x6d, 0x91, 0x2e, 0x91, 0x6d, 0xad, 0x86, 0x25, 0x45, 0x45,
		                                   0x47, 0x01, 0x36, 0x4f, 0x2d, 0x24, 0x86, 0xd7, 0xce, 0xd4, 0xc8, 0x64, 0x2c,
		                                   0xe5, 0x47, 0xdd, 0xb2, 0x6e, 0xf6, 0xa4, 0x6b };
	PTF_ASSERT_TRUE(std::memcmp(wgTransportDataLayer->getEncryptedData(), expectedEncryptedData,
	                            sizeof(expectedEncryptedData)) == 0);
}

PTF_TEST_CASE(WireGuardCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WireGuardHandshakeInitiation.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/WireGuardHandshakeResponse.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/WireGuardTransportData.dat");

	uint8_t origBuffer[1500];

	// create WireGuard Handshake Initiation message
	memcpy(origBuffer, buffer1, bufferLength1);

	uint8_t expectedPublicKeyInit[32] = { 0x5f, 0xce, 0xc7, 0xc8, 0xe5, 0xc8, 0xe2, 0xe3, 0xf7, 0x98, 0x9e,
		                                  0xef, 0x60, 0xc2, 0x28, 0xd8, 0x23, 0x29, 0xd6, 0x02, 0xb6, 0xb1,
		                                  0xe2, 0xbb, 0x9d, 0x06, 0x8f, 0x89, 0xcf, 0x9d, 0x4d, 0x45 };

	uint8_t expectedStaticKeyInit[48] = { 0x32, 0x78, 0x0f, 0x6d, 0x27, 0x26, 0x4f, 0x7b, 0x98, 0x70, 0x1f, 0xdc,
		                                  0x27, 0xa4, 0xec, 0x00, 0xae, 0xb6, 0xbe, 0xcd, 0xbe, 0xf2, 0x33, 0x2f,
		                                  0x1b, 0x40, 0x84, 0xca, 0xdb, 0x93, 0x82, 0x39, 0x35, 0xc0, 0x12, 0xae,
		                                  0x25, 0x5e, 0x7b, 0x25, 0xef, 0xf1, 0x39, 0x40, 0xc3, 0x21, 0xfa, 0x6b };
	uint8_t expectedTimestampInit[28] = { 0xd6, 0x6a, 0x2a, 0x87, 0xb0, 0x61, 0xdb, 0x14, 0x30, 0x17,
		                                  0x3e, 0x93, 0x7f, 0x56, 0x93, 0x49, 0xde, 0x28, 0x56, 0xdc,
		                                  0x5f, 0x26, 0x16, 0x76, 0x3e, 0xee, 0xaf, 0xc0 };

	uint8_t expectedMac1Init[16] = { 0x53, 0x3b, 0x01, 0xdd, 0x96, 0x5e, 0x7e, 0xc7,
		                             0x69, 0x76, 0xe2, 0x8f, 0x68, 0x3d, 0x67, 0x12 };

	uint8_t expectedMac2Init[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	pcpp::WireGuardHandshakeInitiationLayer newHandshakeInitMessage(be32toh(818952152), expectedPublicKeyInit,
	                                                                expectedStaticKeyInit, expectedTimestampInit,
	                                                                expectedMac1Init, expectedMac2Init);
	pcpp::Packet wgHandshakeInitPacket(&rawPacket1);
	pcpp::WireGuardHandshakeInitiationLayer* origHandshakeInitMessage =
	    dynamic_cast<pcpp::WireGuardHandshakeInitiationLayer*>(wgHandshakeInitPacket.detachLayer(pcpp::WireGuard));
	PTF_ASSERT_NOT_NULL(origHandshakeInitMessage);
	PTF_ASSERT_EQUAL(newHandshakeInitMessage.getDataLen(), origHandshakeInitMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newHandshakeInitMessage.getData(), origHandshakeInitMessage->getData(),
	                       origHandshakeInitMessage->getDataLen());
	PTF_ASSERT_TRUE(wgHandshakeInitPacket.addLayer(&newHandshakeInitMessage));

	PTF_ASSERT_EQUAL(wgHandshakeInitPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(wgHandshakeInitPacket.getRawPacket()->getRawData(), origBuffer, bufferLength1);
	delete origHandshakeInitMessage;

	// create WireGuard Handshake Response message
	memcpy(origBuffer, buffer2, bufferLength2);
	uint8_t expectedResponderEphemeralResp[32] = { 0xb1, 0x8d, 0x55, 0x50, 0xbd, 0x40, 0x42, 0xa3, 0x7a, 0x46, 0x82,
		                                           0x3a, 0xc0, 0x8d, 0xb1, 0xec, 0x66, 0x83, 0x9b, 0xc0, 0xca, 0x2d,
		                                           0x64, 0xbc, 0x15, 0xcd, 0x80, 0x23, 0x2b, 0x66, 0x23, 0x2f };

	uint8_t encryptedEmptyDataResp[16] = { 0xae, 0xc2, 0x4a, 0xf8, 0x91, 0x8d, 0xe1, 0x06,
		                                   0x0f, 0xf5, 0xc9, 0x8e, 0x86, 0x5d, 0x5f, 0x35 };

	uint8_t expectedMac1Resp[16] = { 0xf2, 0x72, 0x21, 0x4c, 0x52, 0x60, 0x11, 0x0d,
		                             0xc4, 0xc6, 0x1e, 0x32, 0xcd, 0xd8, 0x54, 0x21 };

	uint8_t expectedMac2Resp[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	pcpp::WireGuardHandshakeResponseLayer newHandshakeRespMessage(
	    be32toh(2877158406), be32toh(818952152), expectedResponderEphemeralResp, encryptedEmptyDataResp,
	    expectedMac1Resp, expectedMac2Resp);
	pcpp::Packet wgHandshakeRespPacket(&rawPacket2);
	pcpp::WireGuardHandshakeResponseLayer* origHandshakeRespMessage =
	    dynamic_cast<pcpp::WireGuardHandshakeResponseLayer*>(wgHandshakeRespPacket.detachLayer(pcpp::WireGuard));
	PTF_ASSERT_NOT_NULL(origHandshakeRespMessage);
	PTF_ASSERT_EQUAL(newHandshakeRespMessage.getDataLen(), origHandshakeRespMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newHandshakeRespMessage.getData(), origHandshakeRespMessage->getData(),
	                       origHandshakeRespMessage->getDataLen());
	PTF_ASSERT_TRUE(wgHandshakeRespPacket.addLayer(&newHandshakeRespMessage));

	PTF_ASSERT_EQUAL(wgHandshakeRespPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(wgHandshakeRespPacket.getRawPacket()->getRawData(), origBuffer, bufferLength2);
	delete origHandshakeRespMessage;

	// create WireGuard Transport Data message

	memcpy(origBuffer, buffer3, bufferLength3);

	uint64_t expectedCounterTransport = 0x0000000000000000;
	uint8_t expectedEncryptedDataTransport[112] = {
		0xa4, 0xeb, 0xc1, 0x2e, 0xe3, 0xf9, 0x90, 0xda, 0x18, 0x03, 0x3a, 0x07, 0x89, 0xc0, 0x4e, 0x27,
		0x00, 0xf6, 0xf5, 0xc2, 0x71, 0xd4, 0x2a, 0xc4, 0xb4, 0xd6, 0x26, 0x2e, 0x66, 0x65, 0x49, 0xb4,
		0x45, 0xa7, 0x43, 0x6e, 0x82, 0x9b, 0xff, 0xb6, 0xac, 0x65, 0xf0, 0x56, 0x48, 0xbc, 0x0c, 0x39,
		0x1f, 0xe7, 0xc5, 0x88, 0x48, 0x74, 0x37, 0x61, 0x27, 0x16, 0x49, 0x40, 0x18, 0x8f, 0x03, 0xdb,
		0xa6, 0x7a, 0xf8, 0x38, 0x8e, 0xaa, 0xb7, 0x6c, 0x59, 0x36, 0x28, 0xbf, 0x9d, 0xc7, 0xbe, 0x03,
		0x34, 0x6d, 0x91, 0x2e, 0x91, 0x6d, 0xad, 0x86, 0x25, 0x45, 0x45, 0x47, 0x01, 0x36, 0x4f, 0x2d,
		0x24, 0x86, 0xd7, 0xce, 0xd4, 0xc8, 0x64, 0x2c, 0xe5, 0x47, 0xdd, 0xb2, 0x6e, 0xf6, 0xa4, 0x6b
	};

	pcpp::WireGuardTransportDataLayer newTransportDataMessage(be32toh(2877158406), expectedCounterTransport,
	                                                          expectedEncryptedDataTransport, 112);
	pcpp::Packet wgTransportDataPacket(&rawPacket3);

	pcpp::WireGuardTransportDataLayer* origTransportDataMessage =
	    dynamic_cast<pcpp::WireGuardTransportDataLayer*>(wgTransportDataPacket.detachLayer(pcpp::WireGuard));
	PTF_ASSERT_NOT_NULL(origTransportDataMessage);
	PTF_ASSERT_EQUAL(newTransportDataMessage.getDataLen(), origTransportDataMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newTransportDataMessage.getData(), origTransportDataMessage->getData(),
	                       origTransportDataMessage->getDataLen());
	PTF_ASSERT_TRUE(wgTransportDataPacket.addLayer(&newTransportDataMessage));

	PTF_ASSERT_EQUAL(wgTransportDataPacket.getRawPacket()->getRawDataLen(), bufferLength3);
	PTF_ASSERT_BUF_COMPARE(wgTransportDataPacket.getRawPacket()->getRawData(), origBuffer, bufferLength3);
	delete origTransportDataMessage;
}
