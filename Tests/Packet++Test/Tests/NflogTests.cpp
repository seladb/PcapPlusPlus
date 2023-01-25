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

	PTF_ASSERT_EQUAL(nflogLayer->getFamily(), pcpp::IPv4);
	PTF_ASSERT_EQUAL(nflogLayer->getVersion(), 0);
	PTF_ASSERT_EQUAL(be16toh(nflogLayer->getResourceId()), 42);

	pcpp::nflog_packet_header* pck_hdr = nflogLayer->getPacketHeader();
	PTF_ASSERT_EQUAL(pck_hdr->hardwareProtocol, 0);
	PTF_ASSERT_EQUAL((int)pck_hdr->netfilterHook, 3);
	PTF_ASSERT_EQUAL(nflogLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);

	pcpp::NflogTlv $payloadInfo = nflogLayer->getTlvByType(pcpp::NflogTlvType::NFULA_PAYLOAD);
	PTF_ASSERT_EQUAL($payloadInfo.getTotalSize(), 65);
	PTF_ASSERT_EQUAL($payloadInfo.getValue()[0], 'E');

	nflogLayer->setVersion(1);
	PTF_ASSERT_EQUAL(nflogLayer->getVersion(), 1);

	pcpp::NflogLayer* new_layer = new pcpp::NflogLayer();
	PTF_ASSERT_EQUAL(new_layer->getResourceId(), 0);

	delete new_layer;

}
