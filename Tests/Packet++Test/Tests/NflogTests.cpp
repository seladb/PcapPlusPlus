#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "MacAddress.h"
#include "Packet.h"
#include "NflogLayer.h"
#include "IPv4Layer.h"
#include "SystemUtils.h"


PTF_TEST_CASE(NflogPacketParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/nflogPacket.dat", pcpp::LINKTYPE_NFLOG);

	pcpp::Packet nflogPacket(&rawPacket1);

	PTF_ASSERT_TRUE(nflogPacket.isPacketOfType(pcpp::NFLOG));
	PTF_ASSERT_EQUAL(nflogPacket.getFirstLayer()->getProtocol(), pcpp::NFLOG, enum);
	pcpp::NflogLayer* nflogLayer = nflogPacket.getLayerOfType<pcpp::NflogLayer>();
	PTF_ASSERT_NOT_NULL(nflogLayer->getNextLayer());

	pcpp::nflog_header* nflog_hdr = nflogLayer->getNflogHeader();
	PTF_ASSERT_EQUAL(nflog_hdr->address_family, pcpp::IPv4);
	PTF_ASSERT_EQUAL(nflog_hdr->version, 0);
	PTF_ASSERT_EQUAL(be16toh(nflog_hdr->resource_id), 42);

	pcpp::nflog_packet_header* pck_hdr = nflogLayer->getPacketHeader();
    PTF_ASSERT_EQUAL(pck_hdr->hardware_protocol, 0);
    PTF_ASSERT_EQUAL((int)pck_hdr->netfilter_hook, 3);
    PTF_ASSERT_EQUAL(nflogLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);

	std::pair<uint8_t*, int> $payloadInfo = nflogLayer->getTlvByType(pcpp::NflogTlvType::NFULA_PAYLOAD);
	PTF_ASSERT_EQUAL($payloadInfo.second, 65);
	PTF_ASSERT_EQUAL($payloadInfo.first[0], 'E');

}
