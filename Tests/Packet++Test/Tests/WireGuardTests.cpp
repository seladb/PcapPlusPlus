#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "WireGuardLayer.h"

PTF_TEST_CASE(WGHandshakeInitParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WireGuardHandshakeInitiation.dat");

	pcpp::Packet wgPacket(&rawPacket1);
	PTF_ASSERT_TRUE(wgPacket.isPacketOfType(pcpp::WIREGUARD));
	pcpp::WireGuardLayer* wgLayer = wgPacket.getLayerOfType<pcpp::WireGuardLayer>();
	PTF_ASSERT_NOT_NULL(wgLayer);
	PTF_ASSERT_TRUE(wgLayer->getHeaderLen() == sizeof(pcpp::wg_handshake_initiation));

	const pcpp::wg_handshake_initiation* handshakeInit = wgLayer->getHandshakeInitiation();
	PTF_ASSERT_NOT_NULL(handshakeInit);
	PTF_ASSERT_EQUAL(handshakeInit->common.messageType, pcpp::HandshakeInitiation);
	PTF_ASSERT_EQUAL(handshakeInit->senderIndex, 818952152);

	uint8_t expectedPublicKey[32] = { 0x5f, 0xce, 0xc7, 0xc8, 0xe5, 0xc8, 0xe2, 0xe3, 0xf7, 0x98, 0x9e,
		                              0xef, 0x60, 0xc2, 0x28, 0xd8, 0x23, 0x29, 0xd6, 0x02, 0xb6, 0xb1,
		                              0xe2, 0xbb, 0x9d, 0x06, 0x8f, 0x89, 0xcf, 0x9d, 0x4d, 0x45 };
	PTF_ASSERT_TRUE(std::memcmp(handshakeInit->initiatorEphemeral, expectedPublicKey, sizeof(expectedPublicKey)) == 0);

	uint8_t expectedStaticKey[48] = { 0x32, 0x78, 0x0f, 0x6d, 0x27, 0x26, 0x4f, 0x7b, 0x98, 0x70, 0x1f, 0xdc,
		                              0x27, 0xa4, 0xec, 0x00, 0xae, 0xb6, 0xbe, 0xcd, 0xbe, 0xf2, 0x33, 0x2f,
		                              0x1b, 0x40, 0x84, 0xca, 0xdb, 0x93, 0x82, 0x39, 0x35, 0xc0, 0x12, 0xae,
		                              0x25, 0x5e, 0x7b, 0x25, 0xef, 0xf1, 0x39, 0x40, 0xc3, 0x21, 0xfa, 0x6b };
	PTF_ASSERT_TRUE(
	    std::memcmp(handshakeInit->encryptedInitiatorStatic, expectedStaticKey, sizeof(expectedStaticKey)) == 0);

	uint8_t expectedTimestamp[28] = { 0xd6, 0x6a, 0x2a, 0x87, 0xb0, 0x61, 0xdb, 0x14, 0x30, 0x17,
		                              0x3e, 0x93, 0x7f, 0x56, 0x93, 0x49, 0xde, 0x28, 0x56, 0xdc,
		                              0x5f, 0x26, 0x16, 0x76, 0x3e, 0xee, 0xaf, 0xc0 };
	PTF_ASSERT_TRUE(std::memcmp(handshakeInit->encryptedTimestamp, expectedTimestamp, sizeof(expectedTimestamp)) == 0);

	uint8_t expectedMac1[16] = { 0x53, 0x3b, 0x01, 0xdd, 0x96, 0x5e, 0x7e, 0xc7,
		                         0x69, 0x76, 0xe2, 0x8f, 0x68, 0x3d, 0x67, 0x12 };
	PTF_ASSERT_TRUE(std::memcmp(handshakeInit->mac1, expectedMac1, sizeof(expectedMac1)) == 0);

	uint8_t expectedMac2[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PTF_ASSERT_TRUE(std::memcmp(handshakeInit->mac2, expectedMac2, sizeof(expectedMac2)) == 0);
}

PTF_TEST_CASE(WGHandshakeRespParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WireGuardHandshakeResponse.dat");

	pcpp::Packet wgPacket(&rawPacket1);
	PTF_ASSERT_TRUE(wgPacket.isPacketOfType(pcpp::WIREGUARD));
	pcpp::WireGuardLayer* wgLayer = wgPacket.getLayerOfType<pcpp::WireGuardLayer>();
	PTF_ASSERT_NOT_NULL(wgLayer);

	PTF_ASSERT_TRUE(wgLayer->getHeaderLen() == sizeof(pcpp::wg_handshake_response));

	const pcpp::wg_handshake_response* handshakeResponse = wgLayer->getHandshakeResponse();
	PTF_ASSERT_NOT_NULL(handshakeResponse);
	PTF_ASSERT_EQUAL(handshakeResponse->common.messageType, pcpp::HandshakeResponse);
	PTF_ASSERT_EQUAL(handshakeResponse->senderIndex, 2877158406);
	PTF_ASSERT_EQUAL(handshakeResponse->receiverIndex, 818952152);

	uint8_t expectedResponderEphemeral[32] = { 0xb1, 0x8d, 0x55, 0x50, 0xbd, 0x40, 0x42, 0xa3, 0x7a, 0x46, 0x82,
		                                       0x3a, 0xc0, 0x8d, 0xb1, 0xec, 0x66, 0x83, 0x9b, 0xc0, 0xca, 0x2d,
		                                       0x64, 0xbc, 0x15, 0xcd, 0x80, 0x23, 0x2b, 0x66, 0x23, 0x2f };
	PTF_ASSERT_TRUE(std::memcmp(handshakeResponse->responderEphemeral, expectedResponderEphemeral,
	                            sizeof(expectedResponderEphemeral)) == 0);

	uint8_t expectedMac1[16] = { 0xf2, 0x72, 0x21, 0x4c, 0x52, 0x60, 0x11, 0x0d,
		                         0xc4, 0xc6, 0x1e, 0x32, 0xcd, 0xd8, 0x54, 0x21 };
	PTF_ASSERT_TRUE(std::memcmp(handshakeResponse->mac1, expectedMac1, sizeof(expectedMac1)) == 0);

	uint8_t expectedMac2[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PTF_ASSERT_TRUE(std::memcmp(handshakeResponse->mac2, expectedMac2, sizeof(expectedMac2)) == 0);
}

PTF_TEST_CASE(WGTransportDataParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WireGuardTransportData.dat");

	pcpp::Packet wgPacket(&rawPacket1);
	PTF_ASSERT_TRUE(wgPacket.isPacketOfType(pcpp::WIREGUARD));
	pcpp::WireGuardLayer* wgLayer = wgPacket.getLayerOfType<pcpp::WireGuardLayer>();
	PTF_ASSERT_NOT_NULL(wgLayer);
	PTF_ASSERT_TRUE(wgLayer->getHeaderLen() >= sizeof(pcpp::wg_transport_data));

	const pcpp::wg_transport_data* transportData = wgLayer->getTransportData();
	PTF_ASSERT_NOT_NULL(transportData);
	PTF_ASSERT_EQUAL(transportData->common.messageType, pcpp::TransportData);
	PTF_ASSERT_EQUAL(transportData->receiverIndex, 2877158406);

	uint8_t expectedCounter[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PTF_ASSERT_TRUE(std::memcmp(&transportData->counter, &expectedCounter, sizeof(expectedCounter)) == 0);

	uint8_t expectedEncryptedData[112] = { 0xa4, 0xeb, 0xc1, 0x2e, 0xe3, 0xf9, 0x90, 0xda, 0x18, 0x03, 0x3a, 0x07, 0x89,
		                                   0xc0, 0x4e, 0x27, 0x00, 0xf6, 0xf5, 0xc2, 0x71, 0xd4, 0x2a, 0xc4, 0xb4, 0xd6,
		                                   0x26, 0x2e, 0x66, 0x65, 0x49, 0xb4, 0x45, 0xa7, 0x43, 0x6e, 0x82, 0x9b, 0xff,
		                                   0xb6, 0xac, 0x65, 0xf0, 0x56, 0x48, 0xbc, 0x0c, 0x39, 0x1f, 0xe7, 0xc5, 0x88,
		                                   0x48, 0x74, 0x37, 0x61, 0x27, 0x16, 0x49, 0x40, 0x18, 0x8f, 0x03, 0xdb, 0xa6,
		                                   0x7a, 0xf8, 0x38, 0x8e, 0xaa, 0xb7, 0x6c, 0x59, 0x36, 0x28, 0xbf, 0x9d, 0xc7,
		                                   0xbe, 0x03, 0x34, 0x6d, 0x91, 0x2e, 0x91, 0x6d, 0xad, 0x86, 0x25, 0x45, 0x45,
		                                   0x47, 0x01, 0x36, 0x4f, 0x2d, 0x24, 0x86, 0xd7, 0xce, 0xd4, 0xc8, 0x64, 0x2c,
		                                   0xe5, 0x47, 0xdd, 0xb2, 0x6e, 0xf6, 0xa4, 0x6b };
	PTF_ASSERT_TRUE(std::memcmp(transportData->encryptedData, expectedEncryptedData, sizeof(expectedEncryptedData)) ==
	                0);
}
