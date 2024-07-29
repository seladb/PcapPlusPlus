#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "MacAddress.h"
#include "Packet.h"
#include "NflogLayer.h"
#include "IPv4Layer.h"
#include "SystemUtils.h"
#include "GeneralUtils.h"

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
	PTF_ASSERT_EQUAL(nflogLayer->getResourceId(), 42);

	PTF_ASSERT_EQUAL(nflogLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);

	pcpp::NflogTlvType expectedTypes[6] = { pcpp::NflogTlvType::NFULA_PACKET_HDR,
		                                    pcpp::NflogTlvType::NFULA_PREFIX,
		                                    pcpp::NflogTlvType::NFULA_IFINDEX_OUTDEV,
		                                    pcpp::NflogTlvType::NFULA_UID,
		                                    pcpp::NflogTlvType::NFULA_GID,
		                                    pcpp::NflogTlvType::NFULA_PAYLOAD };

	int optSizes[6] = { 8, 8, 8, 8, 8, 68 };
	std::string optDataAsHexString[6] = {
		"0800010000000300",
		"05000a0000000000",
		"0800050000000002",
		"08000b0000000000",
		"08000e0000000000",
		"410009004500003d021040004011208f0a00020f0a000203a542003500294156c04e0100000100000000000003777777076578616d706c65036e657400000100012f0a31"
	};

	for (int i = 0; i < 6; i++)
	{
		pcpp::NflogTlv tlv = nflogLayer->getTlvByType(expectedTypes[i]);

		PTF_ASSERT_EQUAL(tlv.getTotalSize(), optSizes[i]);
		PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(tlv.getRecordBasePtr(), optSizes[i]), optDataAsHexString[i]);
	}

	/// sum of all TLVs before payload + size of nflog_header + size of (recordLength + recordType) variables of payload
	/// TLV
	PTF_ASSERT_EQUAL(nflogLayer->getHeaderLen(), 48);
}
