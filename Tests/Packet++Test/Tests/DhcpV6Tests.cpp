#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "DhcpV6Layer.h"


PTF_TEST_CASE(DhcpV6ParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/dhcpv6_1.dat");

	pcpp::Packet dhcpv6Packet(&rawPacket1);
	pcpp::DhcpV6Layer* dhcpv6Layer = dhcpv6Packet.getLayerOfType<pcpp::DhcpV6Layer>();
	PTF_ASSERT_NOT_NULL(dhcpv6Layer);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getMessageType(), pcpp::DHCPV6_SOLICIT);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getMessageTypeAsString(), "Solicit");
	PTF_ASSERT_EQUAL(dhcpv6Layer->getTransactionID(), 0x9a0006);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getOptionCount(), 6);
	PTF_ASSERT_EQUAL(dhcpv6Layer->toString(), "DHCPv6 Layer, Solicit message");

	pcpp::DhcpV6OptionType optTypeArr[] = {
		pcpp::DHCPV6_OPT_CLIENTID,
		pcpp::DHCPV6_OPT_ORO,
		pcpp::DHCPV6_OPT_ELAPSED_TIME,
		pcpp::DHCPV6_OPT_USER_CLASS,
		pcpp::DHCPV6_OPT_VENDOR_CLASS,
		pcpp::DHCPV6_OPT_IA_NA
	};
	size_t optDataSizeArr[] = { 18, 14, 2, 10, 51, 12 };
	std::string optDataAsHexString[] = {
		"000200000009464745313934373134515300",
		"0017001800f300f2003b00f20027",
		"0000",
		"6578722d636f6e666967",
		"00000009002d505845436c69656e743a417263683a30303030393a554e44493a3030333031303a5049443a4e43532d35353038",
		"1d00fcea00000e1000001518"
	};

	pcpp::DhcpV6Option dhcpOption = dhcpv6Layer->getFirstOptionData();
	for (size_t i = 0; i < dhcpv6Layer->getOptionCount(); i++)
	{
		PTF_ASSERT_TRUE(dhcpOption.isNotNull());
		PTF_ASSERT_EQUAL(dhcpOption.getType(), optTypeArr[i]);
		PTF_ASSERT_EQUAL(dhcpOption.getDataSize(), optDataSizeArr[i]);
		PTF_ASSERT_EQUAL(dhcpOption.getTotalSize(), optDataSizeArr[i] + 4);
		PTF_ASSERT_EQUAL(dhcpOption.getValueAsHexString(), optDataAsHexString[i]);
		dhcpOption = dhcpv6Layer->getNextOptionData(dhcpOption);
	}
}