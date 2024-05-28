#include "../TestDefinition.h"
#include "GeneralUtils.h"
#include "GvcpLayer.h"
#include <vector>

PTF_TEST_CASE(GvcpBasicTest)
{
	using namespace pcpp;

	{
		std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};
		GvcpRequestLayer gvcpRequestLayer(GvcpCommand::DiscoveredCmd, payload.data(), payload.size(), 1, 2);
		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);

		GvcpRequestHeader *header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoveredCmd));
		PTF_ASSERT_EQUAL(header->flag, 1);
		PTF_ASSERT_EQUAL(header->requestId, 2);
		PTF_ASSERT_EQUAL(header->dataSize, payload.size());
	}
	{
		std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(GvcpResponseStatus::Success, GvcpCommand::DiscoveredAck,
												  payload.data(), payload.size(), 2);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->status), uint16_t(GvcpResponseStatus::Success));
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoveredAck));
		PTF_ASSERT_EQUAL(header->ackId, 2);
		PTF_ASSERT_EQUAL(header->dataSize, payload.size());

	}
}

PTF_TEST_CASE(GvcpDiscoveryAck)
{
	try
	{
		using namespace pcpp;

		uint8_t *data = new uint8_t[513];

		const char *hexPayload =
			"0000000300f8000100020000800000000000623fab1e4da10000000700000007000000000000000000000000c0fe07660000000000"
			"00000000000000ffffff0000000000000000000000000000000000506572636970696f000000000000000000000000000000000000"
			"000000000000504d3830322d47492d4531000000000000000000000000000000000000000000302e302e303b302e302e3000000000"
			"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000003230373030303132343534360000000000000000000000000000000000000000";
		auto dataLen = pcpp::hexStringToByteArray(hexPayload, data, 513);

		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(data, dataLen);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->status), uint16_t(GvcpResponseStatus::Success));
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoveredAck));
		PTF_ASSERT_EQUAL(header->ackId, 1);
		PTF_ASSERT_EQUAL(header->dataSize, dataLen - sizeof(GvcpAckHeader));

		auto discoveryBody = gvcpAcknowledgeLayer.getGvcpDiscoveryBody();
		PTF_ASSERT_TRUE(discoveryBody != nullptr);
		PTF_ASSERT_EQUAL(discoveryBody->getMacAddress(), pcpp::MacAddress("62:3f:ab:1e:4d:a1"));
		PTF_ASSERT_EQUAL(discoveryBody->getIpAddress(), pcpp::IPv4Address("192.254.7.102"));
		PTF_ASSERT_EQUAL(discoveryBody->getManufacturerName(), "Percipio");
		PTF_ASSERT_EQUAL(discoveryBody->getModelName(), "PM802-GI-E1");
		PTF_ASSERT_EQUAL(discoveryBody->getSerialNumber(), "207000124546");

		delete[] data;
	}
	catch (...)
	{
		std::cout << "Exception occurred" << std::endl;
	}
}