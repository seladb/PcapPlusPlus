#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "NbnsLayer.h"

using namespace std;

PTF_TEST_CASE(NbnsPacketNoOptionsParsing) {
    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/nbns.dat");
    pcpp::Packet NbnsPacketNoOptions(&rawPacket1);
    PTF_ASSERT_TRUE(NbnsPacketNoOptions.isPacketOfType(pcpp::IPv4));
	//cout << NbnsPacketNoOptions.isPacketOfType(pcpp::IPv4) << endl;
    PTF_ASSERT_TRUE(NbnsPacketNoOptions.isPacketOfType(pcpp::NBNS));
	//cout << NbnsPacketNoOptions.getLayerOfType<pcpp::NbnsLayer>() << endl;
    auto *nbnsLayer = NbnsPacketNoOptions.getLayerOfType<pcpp::NbnsLayer>();
	if (nbnsLayer == nullptr){
		cout << "null" << endl;
	}


   PTF_ASSERT_NOT_NULL(nbnsLayer);

   PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->transaction_id, htobe16(0x8000));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->flags, htobe16(0x2910));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->question, htobe16(0x0001));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->answer, htobe16(0x0000));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->authority, htobe16(0x0000));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional, htobe16(0x0001));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[0], htobe16(0x2046));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[1], htobe16(0x4745));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[2], htobe16(0x4a46));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[3], htobe16(0x4446));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[4], htobe16(0x4545));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[5], htobe16(0x4244));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[6], htobe16(0x4343));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[7], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[8], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[9], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[10], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[11], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[12], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[13], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[14], htobe16(0x4143));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[15], htobe16(0x4141));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_name[16], htobe16(0x4100));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_type, htobe16(0x0020));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->queries_class, htobe16(0x0001));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_vista, 0xc0);
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_name, 0x0c);
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_type, htobe16(0x0020));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_class, htobe16(0x001));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_time_to_live, htobe32(0x000493e0));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_data_length, htobe16(0x006));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_flags, htobe16(0x000));
    PTF_ASSERT_EQUAL(nbnsLayer->getNbnsHeader()->additional_records_address, htobe32(0xc0a87281));

} // NbnsPacketNoOptionsParsing
