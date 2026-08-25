#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "QuicLayer.h"
#include <algorithm>
#include <vector>

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(QuicV1ParsingTest)
{
	// Initial packet with empty token
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_initial.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicInitialLayer = quicPacket.getLayerOfType<pcpp::QuicV1InitialLayer>();
		PTF_ASSERT_NOT_NULL(quicInitialLayer);
		PTF_ASSERT_EQUAL(quicInitialLayer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::Initial, enumclass);
		PTF_ASSERT_EQUAL(quicInitialLayer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicInitialLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicInitialLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicInitialLayer->getDestinationConnectionId().toString(), "c5fc34");
		PTF_ASSERT_EQUAL(quicInitialLayer->getSourceConnectionId().toString(), "2e05f87969a4940b");
		PTF_ASSERT_EQUAL(quicInitialLayer->getLength(), 1231);
		PTF_ASSERT_EQUAL(quicInitialLayer->getToken().toString(), "");
		auto protectedPayload = quicInitialLayer->getProtectedPayload();
		PTF_ASSERT_EQUAL(protectedPayload.length, 1231);
		std::array<uint8_t, 5> expectedFirstBytes = { 0x87, 0x3e, 0x73, 0xbf, 0xb2 };
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data, expectedFirstBytes.data(), 5);
		std::array<uint8_t, 5> expectedLastBytes = { 0x4a, 0x48, 0xdd, 0xba, 0xab };
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data + protectedPayload.length - 5, expectedLastBytes.data(), 5);
		PTF_ASSERT_EQUAL(quicInitialLayer->getHeaderLen(), 1252);
		PTF_ASSERT_EQUAL(quicInitialLayer->toString(), "QUIC v1 Layer, Initial message");
	}

	// Initial packet with non-empty token
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_initial_0rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicInitialLayer = quicPacket.getLayerOfType<pcpp::QuicV1InitialLayer>();
		PTF_ASSERT_NOT_NULL(quicInitialLayer);
		PTF_ASSERT_EQUAL(quicInitialLayer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::Initial, enumclass);
		PTF_ASSERT_EQUAL(quicInitialLayer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicInitialLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicInitialLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicInitialLayer->getDestinationConnectionId().toString(), "3c548c2db5aa5e4f64702c3961");
		PTF_ASSERT_EQUAL(quicInitialLayer->getSourceConnectionId().toString(), "4c8342");
		PTF_ASSERT_EQUAL(quicInitialLayer->getLength(), 553);
		PTF_ASSERT_EQUAL(
		    quicInitialLayer->getToken().toString(),
		    "005ea37af85124745e1e7fb3d92a3a17301eeb117b050f57d46eeac87ca3900689e621300e73cbb68ce705c6ea8df47d61d89af11c00db114c51f16bcc871f6f440f8aabe701");
		auto protectedPayload = quicInitialLayer->getProtectedPayload();
		PTF_ASSERT_EQUAL(protectedPayload.length, 553);
		std::array<uint8_t, 5> expectedFirstBytes = { 0x69, 0x45, 0xbf, 0xf0, 0xad };
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data, expectedFirstBytes.data(), 5);
		std::array<uint8_t, 5> expectedLastBytes = { 0x2a, 0x09, 0x1f, 0xc1, 0x65 };
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data + protectedPayload.length - 5, expectedLastBytes.data(), 5);
		PTF_ASSERT_EQUAL(quicInitialLayer->getHeaderLen(), 650);
	}

	// Handshake
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_handshake_1rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicHandshakeLayer = quicPacket.getLayerOfType<pcpp::QuicV1HandshakeLayer>();
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::Handshake, enumclass);
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicHandshakeLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getDestinationConnectionId().toString(), "f147b631d2ec8eb3");
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getSourceConnectionId().toString(), "3bccd4");
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getLength(), 72);
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getHeaderLen(), 92);
		PTF_ASSERT_EQUAL(quicHandshakeLayer->toString(), "QUIC v1 Layer, Handshake message");
		std::array<uint8_t, 72> expectedProtectedPayload = {
			0xf0, 0x2f, 0xcf, 0xe6, 0x46, 0xd7, 0x05, 0x6d, 0x15, 0xfc, 0x2e, 0x2e, 0xc4, 0xf2, 0x08, 0x8c, 0xd8, 0xdc,
			0x3b, 0xe6, 0x06, 0x1b, 0xb4, 0xd9, 0xea, 0x51, 0xc7, 0xc0, 0xaf, 0x42, 0x21, 0xe8, 0x71, 0x0c, 0xfc, 0x3c,
			0xa4, 0x4f, 0x92, 0x91, 0x61, 0x4a, 0xfe, 0xc9, 0xbf, 0xcb, 0x87, 0x27, 0x69, 0x91, 0x6b, 0xcd, 0x0a, 0x04,
			0xdb, 0x18, 0xaa, 0x1f, 0x82, 0xe8, 0xbe, 0x09, 0x29, 0xc4, 0xe2, 0x6f, 0xf4, 0x3f, 0xad, 0x45, 0x69, 0x03
		};
		auto protectedPayload = quicHandshakeLayer->getProtectedPayload();
		PTF_ASSERT_EQUAL(protectedPayload.length, expectedProtectedPayload.size());
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data, expectedProtectedPayload.data(), expectedProtectedPayload.size());
	}

	// 0-RTT packet
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_initial_0rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicZeroRttLayer = quicPacket.getLayerOfType<pcpp::QuicV1ZeroRttLayer>();
		PTF_ASSERT_NOT_NULL(quicZeroRttLayer);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::ZeroRTT, enumclass);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicZeroRttLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getDestinationConnectionId().toString(), "3c548c2db5aa5e4f64702c3961");
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getSourceConnectionId().toString(), "4c8342");
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getLength(), 439);
		auto protectedPayload = quicZeroRttLayer->getProtectedPayload();
		PTF_ASSERT_EQUAL(protectedPayload.length, 439);
		std::array<uint8_t, 5> expectedFirstBytes = { 0xda, 0xd9, 0x53, 0x89, 0x4e };
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data, expectedFirstBytes.data(), 5);
		std::array<uint8_t, 5> expectedLastBytes = { 0x26, 0xd0, 0x09, 0xc3, 0x31 };
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data + protectedPayload.length - 5, expectedLastBytes.data(), 5);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getHeaderLen(), 464);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->toString(), "QUIC v1 Layer, 0-RTT message");
	}

	// Retry
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_retry.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicRetryLayer = quicPacket.getLayerOfType<pcpp::QuicV1RetryLayer>();
		PTF_ASSERT_NOT_NULL(quicRetryLayer);
		PTF_ASSERT_EQUAL(quicRetryLayer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::Retry, enumclass);
		PTF_ASSERT_EQUAL(quicRetryLayer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicRetryLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicRetryLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicRetryLayer->getDestinationConnectionId().toString(), "");
		PTF_ASSERT_EQUAL(quicRetryLayer->getSourceConnectionId().toString(), "f067a5502a4262b5");
		PTF_ASSERT_EQUAL(quicRetryLayer->getRetryToken().toString(), "746f6b656e");
		PTF_ASSERT_EQUAL(quicRetryLayer->getRetryIntegrityTag().toString(), "04a265ba2eff4d829058fb3f0f2496ba");
		PTF_ASSERT_EQUAL(quicRetryLayer->getHeaderLen(), 36);
		PTF_ASSERT_EQUAL(quicRetryLayer->toString(), "QUIC v1 Layer, Retry message");
	}

	// Version negotiation
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_version_negotiation.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicVersionNegotiationLayer = quicPacket.getLayerOfType<pcpp::QuicV1VersionNegotiationLayer>();
		PTF_ASSERT_NOT_NULL(quicVersionNegotiationLayer);
		PTF_ASSERT_EQUAL(quicVersionNegotiationLayer->getPacketType(),
		                 pcpp::QuicV1Layer::QuicPacketType::VersionNegotiation, enumclass);
		PTF_ASSERT_EQUAL(quicVersionNegotiationLayer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::LongHeader,
		                 enumclass);
		PTF_ASSERT_EQUAL(quicVersionNegotiationLayer->getVersion(), 0);
		PTF_ASSERT_EQUAL(quicVersionNegotiationLayer->getDestinationConnectionId().toString(), "9aac5a49ba87a849");
		PTF_ASSERT_EQUAL(quicVersionNegotiationLayer->getSourceConnectionId().toString(), "f92f4336fa951ba1");
		std::vector<uint32_t> expectedSupportedVersions = { 0x45474716, 1 };
		PTF_ASSERT_VECTORS_EQUAL(quicVersionNegotiationLayer->getSupportedVersions(), expectedSupportedVersions);
		PTF_ASSERT_EQUAL(quicVersionNegotiationLayer->getHeaderLen(), 31);
		PTF_ASSERT_EQUAL(quicVersionNegotiationLayer->toString(), "QUIC v1 Layer, Version Negotiation message");
	}

	// 1-RTT
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_handshake_1rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicOneRttLayer = quicPacket.getLayerOfType<pcpp::QuicV1OneRttLayer>();
		PTF_ASSERT_NOT_NULL(quicOneRttLayer);
		PTF_ASSERT_EQUAL(quicOneRttLayer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::OneRtt, enumclass);
		PTF_ASSERT_EQUAL(quicOneRttLayer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::ShortHeader, enumclass);
		PTF_ASSERT_TRUE(quicOneRttLayer->getFixedBit());
		PTF_ASSERT_FALSE(quicOneRttLayer->getSpinBit());
		PTF_ASSERT_FALSE(quicOneRttLayer->getKeyPhaseBit());
		PTF_ASSERT_EQUAL(quicOneRttLayer->getHeaderLen(), 55);
		PTF_ASSERT_EQUAL(quicOneRttLayer->toString(), "QUIC v1 Layer, 1-RTT message");
		auto protectedPayload = quicOneRttLayer->getProtectedPayload();
		PTF_ASSERT_EQUAL(protectedPayload.length, 54);
		std::array<uint8_t, 54> expectedProtectedPayload = {
			0xf1, 0x47, 0xb6, 0x31, 0xd2, 0xec, 0x8e, 0xb3, 0xd1, 0x2a, 0x62, 0x4d, 0xc8, 0x01, 0x39, 0xce, 0x72, 0xc5,
			0xec, 0x28, 0x11, 0x19, 0x01, 0x7f, 0x6c, 0xe6, 0xea, 0x0a, 0xfc, 0x23, 0xf1, 0x88, 0x69, 0x49, 0xb7, 0xad,
			0x65, 0xfb, 0xe8, 0x43, 0x67, 0x04, 0x06, 0xd9, 0xdc, 0xa4, 0x21, 0xa6, 0x00, 0x29, 0x1a, 0x6d, 0xe9, 0xe4
		};
		PTF_ASSERT_BUF_COMPARE(protectedPayload.data, expectedProtectedPayload.data(), expectedProtectedPayload.size());
	}

	// Varint length (1/2/4/8 bytes)
	{
		std::vector<std::tuple<std::vector<uint8_t>, uint64_t>> lengthBytesAndExpectedLengths = {
			{ { 0x25 },			                               37            }, // 1 byte length
			{ { 0x41, 0x2C },			                         300           }, // 2 byte length
			{ { 0x80, 0x01, 0x86, 0xA0 },                         100'000       }, // 4 byte length
			{ { 0xC0, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00 }, 5000000000ULL }  // 8 byte length
		};

		for (const auto& lengthBytesAndExpectedLength : lengthBytesAndExpectedLengths)
		{
			auto bytes = std::vector<uint8_t>{
				0xC0, 0x00, 0x00, 0x00, 0x01,  // long header, Initial packet type, version = 1
				0x00,                          // DCIDLen = 0
				0x00,                          // SCIDLen = 0
				0x00                           // TokenLength varint (1-byte form), value = 0
			};
			const auto& lengthBytes = std::get<0>(lengthBytesAndExpectedLength);
			bytes.insert(bytes.end(), lengthBytes.begin(), lengthBytes.end());  // Length varint
			bytes.insert(bytes.end(), { 0x01, 0x02, 0x03 });                    // truncated trailing payload
			auto buffer = std::make_unique<uint8_t[]>(bytes.size());
			std::copy(bytes.begin(), bytes.end(), buffer.get());
			std::unique_ptr<pcpp::QuicV1Layer> layer(
			    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), bytes.size(), nullptr, nullptr));
			PTF_ASSERT_NOT_NULL(layer.get());
			auto initialLayer = dynamic_cast<pcpp::QuicV1InitialLayer*>(layer.get());
			PTF_ASSERT_NOT_NULL(initialLayer);
			PTF_ASSERT_EQUAL(initialLayer->getLength(), std::get<1>(lengthBytesAndExpectedLength));
			PTF_ASSERT_EQUAL(initialLayer->getHeaderLen(), bytes.size());
		}
	}
}  // QuicV1ParsingTest

namespace
{
	std::unique_ptr<uint8_t[]> makeBuffer(std::initializer_list<uint8_t> bytes)
	{
		auto buffer = std::make_unique<uint8_t[]>(bytes.size());
		std::copy(bytes.begin(), bytes.end(), buffer.get());
		return buffer;
	}
}  // namespace

PTF_TEST_CASE(QuicV1MalformedPacketsTest)
{
	// nullptr / too-short buffers
	{
		PTF_ASSERT_NULL(pcpp::QuicV1Layer::parseQuicLayer(nullptr, 10, nullptr, nullptr));

		auto oneByte = makeBuffer({ 0x80 });
		PTF_ASSERT_NULL(pcpp::QuicV1Layer::parseQuicLayer(oneByte.get(), 0, nullptr, nullptr));
		PTF_ASSERT_NULL(pcpp::QuicV1Layer::parseQuicLayer(oneByte.get(), 1, nullptr, nullptr));

		auto tooShortLongHeader = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x01 });
		PTF_ASSERT_NULL(pcpp::QuicV1Layer::parseQuicLayer(tooShortLongHeader.get(), 5, nullptr, nullptr));
	}

	// Smallest possible valid short-header (1-RTT) packet
	{
		// headerForm=0 (short header), fixedBit=1, spinBit=0, keyPhase=0, pnLength=0
		auto buffer = makeBuffer({ 0x40, 0x01 });
		size_t dataLen = 2;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		PTF_ASSERT_EQUAL(layer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::OneRtt, enumclass);
		PTF_ASSERT_EQUAL(layer->getHeaderForm(), pcpp::QuicV1Layer::QuicHeaderForm::ShortHeader, enumclass);
		PTF_ASSERT_EQUAL(layer->getHeaderLen(), dataLen);

		auto oneRttLayer = dynamic_cast<pcpp::QuicV1OneRttLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(oneRttLayer);
		PTF_ASSERT_TRUE(oneRttLayer->getFixedBit());
		PTF_ASSERT_FALSE(oneRttLayer->getSpinBit());
		PTF_ASSERT_FALSE(oneRttLayer->getKeyPhaseBit());
	}

	// Long header with invalid version
	{
		// Initial (longPacketType=0), version=2, destinationConnectionIdLength=0
		auto buffer = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00 });
		PTF_ASSERT_NULL(pcpp::QuicV1Layer::parseQuicLayer(buffer.get(), 6, nullptr, nullptr));
	}

	// Long-header packet with DCID length but no data
	{
		// Initial (longPacketType=0), version=1, destinationConnectionIdLength=8 (but none present)
		auto buffer = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x01, 0x08 });
		size_t dataLen = 6;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto initialLayer = dynamic_cast<pcpp::QuicV1InitialLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(initialLayer);
		PTF_ASSERT_EQUAL(initialLayer->getDestinationConnectionId().toString(), "");
		PTF_ASSERT_EQUAL(initialLayer->getSourceConnectionId().toString(), "");
		PTF_ASSERT_EQUAL(initialLayer->getToken().toString(), "");
		PTF_ASSERT_EQUAL(initialLayer->getLength(), 0);
		PTF_ASSERT_EQUAL(initialLayer->getHeaderLen(), 6);
	}

	// DCID claims more than is captured
	{
		// Initial (longPacketType=0), version=1, destinationConnectionIdLength=255 (but DCID is 1 byte long)
		auto buffer = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xAA });
		size_t dataLen = 7;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto initialLayer = dynamic_cast<pcpp::QuicV1InitialLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(initialLayer);
		PTF_ASSERT_EQUAL(initialLayer->getDestinationConnectionId().toString(), "");
		PTF_ASSERT_EQUAL(initialLayer->getSourceConnectionId().toString(), "");
	}

	// SCID length present but no data
	{
		// DCID length=1 ("aa"), then SCID length byte = 5, then nothing
		auto bufferAtBoundary = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xAA, 0x05 });
		size_t dataLenAtBoundary = 8;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(bufferAtBoundary.release(), dataLenAtBoundary, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto initialLayer = dynamic_cast<pcpp::QuicV1InitialLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(initialLayer);
		PTF_ASSERT_EQUAL(initialLayer->getDestinationConnectionId().toString(), "aa");
		PTF_ASSERT_EQUAL(initialLayer->getSourceConnectionId().toString(), "");
	}

	// SCID claims more than is captured
	{
		// same as above, plus one trailing byte -> SCID clamped to what's available
		auto bufferOneMore = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xAA, 0x05, 0xBB });
		size_t dataLenOneMore = 9;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(bufferOneMore.release(), dataLenOneMore, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto initialLayer2 = dynamic_cast<pcpp::QuicV1InitialLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(initialLayer2);
		PTF_ASSERT_EQUAL(initialLayer2->getSourceConnectionId().toString(), "");
	}

	// Token length claims more than is captured
	{
		// DCIDLen=0, SCIDLen=0, tokenLength varint (2-byte form) = 10, but no bytes follow
		auto buffer = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x0A });
		size_t dataLen = 9;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto initialLayer = dynamic_cast<pcpp::QuicV1InitialLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(initialLayer);
		PTF_ASSERT_EQUAL(initialLayer->getToken().toString(), "");
		// Length can't be located either, since it sits right after the (unreadable) token
		PTF_ASSERT_EQUAL(initialLayer->getLength(), 0);
		PTF_ASSERT_EQUAL(initialLayer->getHeaderLen(), dataLen);
	}

	// Length field reports the protocol-declared value verbatim even when it exceeds the captured bytes
	{
		// DCIDLen=0, SCIDLen=0, tokenLength=0 (1 byte), Length varint (2-byte) = 1000,
		// followed by only 3 more bytes (simulating a truncated capture)
		auto buffer = makeBuffer({ 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x43, 0xE8, 0x01, 0x02, 0x03 });
		size_t dataLen = 13;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto initialLayer = dynamic_cast<pcpp::QuicV1InitialLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(initialLayer);
		PTF_ASSERT_EQUAL(initialLayer->getLength(), 1000);
		PTF_ASSERT_EQUAL(initialLayer->getHeaderLen(), dataLen);
	}

	// Version Negotiation takes priority over longPacketType when version == 0
	{
		auto buffer = makeBuffer({
		    0x80,                    // headerForm=1, fixedBit=0, longPacketType bits read as 0 ("Initial")
		    0x00, 0x00, 0x00, 0x00,  // version = 0 -> Version Negotiation
		    0x02, 0x11, 0x22,        // DCIDLen=2, DCID
		    0x02, 0x33, 0x44,        // SCIDLen=2, SCID
		    0x00, 0x00, 0x00, 0x01,  // one full supported version = 1
		    0xAA, 0xBB               // trailing partial version (< 4 bytes) - must be ignored
		});
		size_t dataLen = 17;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		PTF_ASSERT_EQUAL(layer->getPacketType(), pcpp::QuicV1Layer::QuicPacketType::VersionNegotiation, enumclass);
		auto vnLayer = dynamic_cast<pcpp::QuicV1VersionNegotiationLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(vnLayer);
		PTF_ASSERT_EQUAL(vnLayer->getVersion(), 0);
		PTF_ASSERT_EQUAL(vnLayer->getDestinationConnectionId().toString(), "1122");
		PTF_ASSERT_EQUAL(vnLayer->getSourceConnectionId().toString(), "3344");
		std::vector<uint32_t> expectedVersions = { 1 };
		PTF_ASSERT_VECTORS_EQUAL(vnLayer->getSupportedVersions(), expectedVersions);
		PTF_ASSERT_EQUAL(vnLayer->getHeaderLen(), 17);
	}

	// Version Negotiation packet where the DCID is valid but there isn't enough data left to
	// safely read the SCID length - getSrcConIdOffsetAndLength() throws, and
	// getSupportedVersions() must catch it and return an empty list rather than propagate
	{
		auto buffer = makeBuffer({
		    0x80,                    // headerForm=1, fixedBit=0, longPacketType bits ignored
		    0x00, 0x00, 0x00, 0x00,  // version = 0 -> Version Negotiation
		    0x00,                    // DCIDLen = 0 (valid, empty DCID)
		    0xAA                     // one trailing byte - not enough to safely read a SCID length
		});
		size_t dataLen = 7;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto vnLayer = dynamic_cast<pcpp::QuicV1VersionNegotiationLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(vnLayer);
		PTF_ASSERT_EQUAL(vnLayer->getDestinationConnectionId().toString(), "");
		PTF_ASSERT_EQUAL(vnLayer->getSourceConnectionId().toString(), "");
		std::vector<uint32_t> expectedVersions = {};
		PTF_ASSERT_VECTORS_EQUAL(vnLayer->getSupportedVersions(), expectedVersions);
	}

	// Retry packet truncated before the 16-byte integrity tag
	{
		auto buffer = makeBuffer({
		    0xF0,                         // headerForm=1, fixedBit=1, longPacketType=3 (Retry)
		    0x00, 0x00, 0x00, 0x01,       // version = 1
		    0x00,                         // DCIDLen = 0
		    0x02, 0x55, 0x66,             // SCIDLen=2, SCID
		    0x01, 0x02, 0x03, 0x04, 0x05  // only 5 bytes left - not enough for a 16-byte tag
		});
		size_t dataLen = 14;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto retryLayer = dynamic_cast<pcpp::QuicV1RetryLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(retryLayer);
		PTF_ASSERT_EQUAL(retryLayer->getSourceConnectionId().toString(), "5566");
		PTF_ASSERT_EQUAL(retryLayer->getRetryToken().toString(), "");
		PTF_ASSERT_EQUAL(retryLayer->getRetryIntegrityTag().toString(), "");
		PTF_ASSERT_EQUAL(retryLayer->getHeaderLen(), 14);
	}

	// Retry packet with exactly 16 bytes left after the SCID
	{
		auto buffer = makeBuffer({
		    0xF0,                    // headerForm=1, fixedBit=1, longPacketType=3 (Retry)
		    0x00, 0x00, 0x00, 0x01,  // version = 1
		    0x00,                    // DCIDLen = 0
		    0x02, 0x77, 0x88,        // SCIDLen=2, SCID
		    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10  // exactly 16 bytes: the integrity tag, no token
		});
		size_t dataLen = 25;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto retryLayer = dynamic_cast<pcpp::QuicV1RetryLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(retryLayer);
		PTF_ASSERT_EQUAL(retryLayer->getSourceConnectionId().toString(), "7788");
		PTF_ASSERT_EQUAL(retryLayer->getRetryToken().toString(), "");
		PTF_ASSERT_EQUAL(retryLayer->getRetryIntegrityTag().toString(), "0102030405060708090a0b0c0d0e0f10");
		PTF_ASSERT_EQUAL(retryLayer->getHeaderLen(), dataLen);
	}

	// Retry packet where the DCID is valid but there isn't enough data left to safely read the
	// SCID length - getSrcConIdOffsetAndLength() throws, and getRetryTokenOffset() must catch
	// it and fall back to m_DataLen rather than propagate the exception
	{
		auto buffer = makeBuffer({
		    0xF0,                    // headerForm=1, fixedBit=1, longPacketType=3 (Retry)
		    0x00, 0x00, 0x00, 0x01,  // version = 1
		    0x00,                    // DCIDLen = 0 (valid, empty DCID)
		    0xAA                     // one trailing byte - not enough to safely read a SCID length
		});
		size_t dataLen = 7;
		std::unique_ptr<pcpp::QuicV1Layer> layer(
		    pcpp::QuicV1Layer::parseQuicLayer(buffer.release(), dataLen, nullptr, nullptr));
		PTF_ASSERT_NOT_NULL(layer.get());
		auto retryLayer = dynamic_cast<pcpp::QuicV1RetryLayer*>(layer.get());
		PTF_ASSERT_NOT_NULL(retryLayer);
		PTF_ASSERT_EQUAL(retryLayer->getDestinationConnectionId().toString(), "");
		PTF_ASSERT_EQUAL(retryLayer->getSourceConnectionId().toString(), "");
		PTF_ASSERT_EQUAL(retryLayer->getRetryToken().toString(), "");
		PTF_ASSERT_EQUAL(retryLayer->getRetryIntegrityTag().toString(), "");
	}
}  // QuicV1MalformedPacketsTest
