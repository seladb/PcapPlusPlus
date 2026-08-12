#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "QuicLayer.h"

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(QuicParsingTest)
{
	// Initial packet with empty token
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_initial.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicInitialLayer = quicPacket.getLayerOfType<pcpp::QuicInitialLayer>();
		PTF_ASSERT_NOT_NULL(quicInitialLayer);
		PTF_ASSERT_EQUAL(quicInitialLayer->getPacketType(), pcpp::QuicLayer::QuicPacketType::Initial, enumclass);
		PTF_ASSERT_EQUAL(quicInitialLayer->getHeaderForm(), pcpp::QuicLayer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicInitialLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicInitialLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicInitialLayer->getDestinationConnectionId().toString(), "c5fc34");
		PTF_ASSERT_EQUAL(quicInitialLayer->getSourceConnectionId().toString(), "2e05f87969a4940b");
		PTF_ASSERT_EQUAL(quicInitialLayer->getLength(), 1231);
		PTF_ASSERT_EQUAL(quicInitialLayer->getToken().toString(), "");
	}
	// Initial packet with non-empty token
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_initial_0rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicInitialLayer = quicPacket.getLayerOfType<pcpp::QuicInitialLayer>();
		PTF_ASSERT_NOT_NULL(quicInitialLayer);
		PTF_ASSERT_EQUAL(quicInitialLayer->getPacketType(), pcpp::QuicLayer::QuicPacketType::Initial, enumclass);
		PTF_ASSERT_EQUAL(quicInitialLayer->getHeaderForm(), pcpp::QuicLayer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicInitialLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicInitialLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicInitialLayer->getDestinationConnectionId().toString(), "3c548c2db5aa5e4f64702c3961");
		PTF_ASSERT_EQUAL(quicInitialLayer->getSourceConnectionId().toString(), "4c8342");
		PTF_ASSERT_EQUAL(quicInitialLayer->getLength(), 553);
		PTF_ASSERT_EQUAL(quicInitialLayer->getToken().toString(), "005ea37af85124745e1e7fb3d92a3a17301eeb117b050f57d46eeac87ca3900689e621300e73cbb68ce705c6ea8df47d61d89af11c00db114c51f16bcc871f6f440f8aabe701");
	}
	// Handshake
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_handshake_1rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicHandshakeLayer = quicPacket.getLayerOfType<pcpp::QuicHandshakeLayer>();
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getPacketType(), pcpp::QuicLayer::QuicPacketType::Handshake, enumclass);
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getHeaderForm(), pcpp::QuicLayer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicHandshakeLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getDestinationConnectionId().toString(), "f147b631d2ec8eb3");
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getSourceConnectionId().toString(), "3bccd4");
		PTF_ASSERT_EQUAL(quicHandshakeLayer->getLength(), 72);
	}
	// 0-RTT packet
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_initial_0rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicZeroRttLayer = quicPacket.getLayerOfType<pcpp::QuicZeroRttLayer>();
		PTF_ASSERT_NOT_NULL(quicZeroRttLayer);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getPacketType(), pcpp::QuicLayer::QuicPacketType::ZeroRTT, enumclass);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getHeaderForm(), pcpp::QuicLayer::QuicHeaderForm::LongHeader, enumclass);
		PTF_ASSERT_TRUE(quicZeroRttLayer->getFixedBit());
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getVersion(), 1);
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getDestinationConnectionId().toString(), "3c548c2db5aa5e4f64702c3961");
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getSourceConnectionId().toString(), "4c8342");
		PTF_ASSERT_EQUAL(quicZeroRttLayer->getLength(), 439);
	}
	// 1-RTT
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/quic_handshake_1rtt.dat");
		pcpp::Packet quicPacket(rawPacket.get());

		auto quicOneRttLayer = quicPacket.getLayerOfType<pcpp::QuicOneRttLayer>();
		PTF_ASSERT_NOT_NULL(quicOneRttLayer);
		PTF_ASSERT_EQUAL(quicOneRttLayer->getPacketType(), pcpp::QuicLayer::QuicPacketType::OneRtt, enumclass);
		PTF_ASSERT_EQUAL(quicOneRttLayer->getHeaderForm(), pcpp::QuicLayer::QuicHeaderForm::ShortHeader, enumclass);
		PTF_ASSERT_TRUE(quicOneRttLayer->getFixedBit());
		PTF_ASSERT_FALSE(quicOneRttLayer->getSpinBit());
		PTF_ASSERT_FALSE(quicOneRttLayer->getKeyPhaseBit());
	}
}