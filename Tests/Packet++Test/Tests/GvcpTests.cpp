#include "../TestDefinition.h"
#include "GvcpLayer.h"
#include <vector>

PTF_TEST_CASE(GvcpBasicTest)
{
	using namespace pcpp;

	// create a unique pointer of a buffer
	std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};

	{
		GvcpRequestLayer gvcpRequestLayer(GvcpCommand::DiscoverdCmd, payload.data(), payload.size(), 1, 2);
		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);

		GvcpRequestHeader *header = gvcpRequestLayer.getHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoverdCmd));
		PTF_ASSERT_EQUAL(header->flag, 1);
		PTF_ASSERT_EQUAL(header->requestId, 2);
		PTF_ASSERT_EQUAL(header->dataSize, payload.size());
	}
	{
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(GvcpResponseStatus::Success, GvcpCommand::DiscoverdAck,
												  payload.data(), payload.size(), 2);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer.getHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->status), uint16_t(GvcpResponseStatus::Success));
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoverdAck));
		PTF_ASSERT_EQUAL(header->ackId, 2);
		PTF_ASSERT_EQUAL(header->dataSize, payload.size());
	}
}