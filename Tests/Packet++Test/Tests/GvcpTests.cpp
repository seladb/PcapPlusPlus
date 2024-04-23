#include "../TestDefinition.h"
#include "GvcpLayer.h"
#include <vector>

PTF_TEST_CASE(GvcpBasicTest)
{
	using namespace pcpp;

	// create a unique pointer of a buffer
	std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};

	{
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
