#include "../TestDefinition.h"
#include "../Common/TestUtils.h"
#include "IPReassembly.h"
#include "IPv6Layer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "EndianPortable.h"

static void ipReassemblyOnFragmentsClean(const pcpp::IPReassembly::PacketKey* key, void* userCookie)
{
	pcpp::PointerVector<pcpp::IPReassembly::PacketKey>* packetsRemoved =
	    (pcpp::PointerVector<pcpp::IPReassembly::PacketKey>*)userCookie;
	packetsRemoved->pushBack(key->clone());
}

PTF_TEST_CASE(TestIPFragmentationSanity)
{
	std::vector<pcpp::RawPacket> packetStream;
	std::string errMsg;

	// basic IPv4 reassembly test
	// ==========================

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg));

	pcpp::IPReassembly ipReassembly;
	pcpp::IPReassembly::ReassemblyStatus status;

	PTF_ASSERT_EQUAL(ipReassembly.getMaxCapacity(), PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 0);

	pcpp::Packet* result = nullptr;

	PTF_PRINT_VERBOSE("basic IPv4 reassembly test - iterating over packet stream");
	for (size_t i = 0; i < packetStream.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
			PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 1);
		}
		else if (i < (packetStream.size() - 1))
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
			PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 1);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
			PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 0);
		}
	}

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_reassembled.txt", bufferLength);

	PTF_ASSERT_NOT_NULL(buffer);
	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_TRUE(result->isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(result->isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(result->isPacketOfType(pcpp::HTTPRequest));
	pcpp::HttpRequestLayer* httpReq = result->getLayerOfType<pcpp::HttpRequestLayer>();
	PTF_ASSERT_NOT_NULL(httpReq);
	PTF_ASSERT_EQUAL(httpReq->getUrl(), "js.bizographics.com/convert_data.js?partner_id=29");
	PTF_ASSERT_EQUAL(httpReq->getFieldCount(), 10);

	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_EQUAL(bufferLength, result->getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;
	delete[] buffer;

	// basic IPv6 reassembly test
	// ==========================

	pcpp::PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT_TRUE(reader.open());

	pcpp::RawPacketVector packet1Frags;

	PTF_ASSERT_EQUAL(reader.getNextPackets(packet1Frags, 7), 7);

	reader.close();

	result = nullptr;

	PTF_PRINT_VERBOSE("basic IPv6 reassembly test - iterating over packet stream");
	for (size_t i = 0; i < packet1Frags.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		pcpp::Packet packet(packet1Frags.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
			PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 1);
		}
		else if (i < (packet1Frags.size() - 1))
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
			PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 1);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
			PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 0);
		}
	}

	PTF_ASSERT_NOT_NULL(result);
	// small fix for payload length which is wrong in the original packet
	result->getLayerOfType<pcpp::IPv6Layer>()->getIPv6Header()->payloadLength = htobe16(737);

	bufferLength = 0;
	buffer = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", bufferLength);

	PTF_ASSERT_NOT_NULL(buffer);
	PTF_ASSERT_EQUAL(bufferLength, result->getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;
	delete[] buffer;

	// non-fragment test
	// ==================

	packetStream.clear();
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/VlanPackets.pcap", packetStream, errMsg));

	PTF_PRINT_VERBOSE("non-fragment test - iterating over packet stream");
	for (size_t i = 0; i < 20; i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);

		PTF_ASSERT_EQUAL(result, &packet, ptr);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::NON_FRAGMENT, enum);
	}

	// non-IP test
	// ==================

	PTF_PRINT_VERBOSE("non-IP test - iterating over packet stream");
	for (size_t i = 20; i < packetStream.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);

		PTF_ASSERT_EQUAL(result, &packet, ptr);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::NON_IP_PACKET, enum);
	}
}  // TestIPFragmentationSanity

PTF_TEST_CASE(TestIPFragOutOfOrder)
{
	std::vector<pcpp::RawPacket> packetStream;
	std::string errMsg;

	pcpp::IPReassembly ipReassembly;
	pcpp::IPReassembly::ReassemblyStatus status;

	pcpp::Packet* result = nullptr;

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_reassembled.txt", bufferLength);

	// First use-case: first and second fragments are swapped
	// ======================================================

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg));

	// swap first and second packet
	std::swap(packetStream[0], packetStream[1]);

	PTF_PRINT_VERBOSE("First use-case: iterating over packet stream");
	for (size_t i = 0; i < packetStream.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);

		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
		}
		else if (i == 1)
		{
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
		}
		else if (i < (packetStream.size() - 1))
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
		}
	}

	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_EQUAL(result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;
	result = nullptr;

	packetStream.clear();

	// Second use-case: 6th and 10th fragments are swapped, as well as 3rd and 7th
	// ===========================================================================

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg));

	// swap 6th and 10th fragments
	std::swap(packetStream[5], packetStream[9]);

	// swap 3rd and 7th fragments
	std::swap(packetStream[2], packetStream[6]);

	PTF_PRINT_VERBOSE("Second use-case: iterating over packet stream");
	for (size_t i = 0; i < packetStream.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);

		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 2 || i == 3 || i == 4 || i == 5 || i == 7 || i == 8)
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
		}
		else if (i == 0)
		{
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
		}
		else if (i < (packetStream.size() - 1))
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
		}
	}

	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_EQUAL(result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;
	result = nullptr;

	packetStream.clear();

	// Third use-case: last fragment comes before the end
	// ==================================================

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg));

	// swap 6th and last fragments
	std::swap(packetStream[5], packetStream[10]);

	PTF_PRINT_VERBOSE("Third use-case: iterating over packet stream");
	for (size_t i = 0; i < packetStream.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);

		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i >= 5 && i < (packetStream.size() - 1))
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
		}
		else if (i == 0)
		{
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
		}
		else if (i < 5)
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
		}
	}

	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_EQUAL(result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;
	result = nullptr;

	packetStream.clear();

	// Fourth use-case: last fragment comes first
	// ==========================================

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg));

	// move last frag from the end to the beginning
	pcpp::RawPacket lastFrag = packetStream.at(10);
	packetStream.insert(packetStream.begin(), lastFrag);
	packetStream.erase(packetStream.begin() + 11);

	PTF_PRINT_VERBOSE("Fourth use-case: iterating over packet stream");
	for (size_t i = 0; i < packetStream.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);

		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
		}
		else if (i == 1)
		{
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
		}
		else if (i < (packetStream.size() - 1))
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
		}
	}

	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_EQUAL(result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;
	result = nullptr;

	packetStream.clear();

	// Fifth use-case: fragments come in reverse order
	// ===============================================

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg));

	// reverse order of fragments
	for (size_t i = 1; i < packetStream.size(); i++)
	{
		pcpp::RawPacket curFrag = packetStream.at(i);
		packetStream.insert(packetStream.begin(), curFrag);
		packetStream.erase(packetStream.begin() + i + 1);
	}

	PTF_PRINT_VERBOSE("Fifth use-case: iterating over packet stream");
	for (size_t i = 0; i < packetStream.size(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);

		pcpp::Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i < (packetStream.size() - 1))
		{
			PTF_ASSERT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(result);
			PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
		}
	}

	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_EQUAL(result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;

	packetStream.clear();

	delete[] buffer;

	// Sixth use-case: IPv6: fragments 1 and 3 are swapped, as well as fragments 6 and 7
	// =================================================================================

	pcpp::PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT_TRUE(reader.open());

	pcpp::RawPacketVector packet1Frags;

	PTF_ASSERT_EQUAL(reader.getNextPackets(packet1Frags, 7), 7);

	reader.close();

	result = nullptr;

	result = ipReassembly.processPacket(packet1Frags.at(2), status);
	PTF_ASSERT_NULL(result);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
	result = ipReassembly.processPacket(packet1Frags.at(1), status);
	PTF_ASSERT_NULL(result);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
	result = ipReassembly.processPacket(packet1Frags.at(0), status);
	PTF_ASSERT_NULL(result);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	result = ipReassembly.processPacket(packet1Frags.at(3), status);
	PTF_ASSERT_NULL(result);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
	result = ipReassembly.processPacket(packet1Frags.at(4), status);
	PTF_ASSERT_NULL(result);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
	result = ipReassembly.processPacket(packet1Frags.at(6), status);
	PTF_ASSERT_NULL(result);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
	result = ipReassembly.processPacket(packet1Frags.at(5), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", buffer2Length);

	// small fix for payload length which is wrong in the original packet
	result->getLayerOfType<pcpp::IPv6Layer>()->getIPv6Header()->payloadLength = htobe16(737);

	PTF_ASSERT_EQUAL(result->getRawPacket()->getRawDataLen(), buffer2Length);
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer2, buffer2Length);

	delete result;

	delete[] buffer2;
}  // TestIPFragOutOfOrder

PTF_TEST_CASE(TestIPFragPartialData)
{
	std::vector<pcpp::RawPacket> packetStream;
	std::string errMsg;

	pcpp::IPReassembly ipReassembly;
	pcpp::IPReassembly::ReassemblyStatus status;

	// IPv4 partial data
	// ~~~~~~~~~~~~~~~~~

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_partial.txt", bufferLength);

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg));

	for (size_t i = 0; i < 6; i++)
	{
		pcpp::Packet packet(&packetStream.at(i));
		ipReassembly.processPacket(&packet, status);
	}

	pcpp::IPReassembly::IPv4PacketKey ip4Key(16991, pcpp::IPv4Address(std::string("172.16.133.54")),
	                                         pcpp::IPv4Address(std::string("216.137.33.81")));
	pcpp::Packet* partialPacket = ipReassembly.getCurrentPacket(ip4Key);

	PTF_ASSERT_NOT_NULL(partialPacket);
	PTF_ASSERT_EQUAL(partialPacket->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT_BUF_COMPARE(partialPacket->getRawPacket()->getRawData(), buffer, bufferLength);

	delete partialPacket;
	delete[] buffer;

	// IPv6 partial data
	// ~~~~~~~~~~~~~~~~~

	bufferLength = 0;
	buffer = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1_partial.txt", bufferLength);

	pcpp::PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT_TRUE(reader.open());

	pcpp::RawPacketVector packet1PartialFrags;

	PTF_ASSERT_EQUAL(reader.getNextPackets(packet1PartialFrags, 5), 5);

	reader.close();

	for (size_t i = 0; i < 5; i++)
	{
		pcpp::Packet packet(packet1PartialFrags.at(i));
		ipReassembly.processPacket(&packet, status);
	}

	pcpp::IPReassembly::IPv6PacketKey ip6Key(0x2c5323, pcpp::IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")),
	                                         pcpp::IPv6Address(std::string("ff02::fb")));
	partialPacket = ipReassembly.getCurrentPacket(ip6Key);
	PTF_ASSERT_EQUAL(partialPacket->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT_BUF_COMPARE(partialPacket->getRawPacket()->getRawData(), buffer, bufferLength);

	PTF_ASSERT_NOT_NULL(partialPacket);

	delete partialPacket;
	delete[] buffer;
}  // TestIPFragPartialData

PTF_TEST_CASE(TestIPFragMultipleFrags)
{
	pcpp::PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PTF_ASSERT_TRUE(reader.open());

	pcpp::PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT_TRUE(reader2.open());

	pcpp::RawPacketVector ip4Packet1Frags;
	pcpp::RawPacketVector ip4Packet2Frags;
	pcpp::RawPacketVector ip4Packet3Frags;
	pcpp::RawPacketVector ip4Packet4Frags;
	pcpp::RawPacketVector ip4Packet5Vec;
	pcpp::RawPacketVector ip4Packet6Frags;
	pcpp::RawPacketVector ip4Packet7Vec;
	pcpp::RawPacketVector ip4Packet8Frags;
	pcpp::RawPacketVector ip4Packet9Vec;
	pcpp::RawPacketVector ip6Packet1Frags;
	pcpp::RawPacketVector ip6Packet2Frags;
	pcpp::RawPacketVector ip6Packet3Frags;
	pcpp::RawPacketVector ip6Packet4Frags;

	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet1Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet2Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet3Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet4Frags, 10), 10);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet5Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet4Frags, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet6Frags, 10), 10);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet7Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet6Frags, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet8Frags, 8), 8);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet9Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet8Frags, 2), 2);

	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet1Frags, 7), 7);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet2Frags, 13), 13);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet3Frags, 9), 9);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet4Frags, 7), 7);

	reader.close();
	reader2.close();

	pcpp::Packet* ip4Packet1;
	pcpp::Packet* ip4Packet2;
	pcpp::Packet* ip4Packet3;
	pcpp::Packet* ip4Packet4;
	pcpp::Packet* ip4Packet5;
	pcpp::Packet* ip4Packet6;
	pcpp::Packet* ip4Packet7;
	pcpp::Packet* ip4Packet8;
	pcpp::Packet* ip4Packet9;
	pcpp::Packet* ip6Packet1;
	pcpp::Packet* ip6Packet2;
	pcpp::Packet* ip6Packet3;
	pcpp::Packet* ip6Packet4;

	pcpp::IPReassembly ipReassembly;

	pcpp::IPReassembly::ReassemblyStatus status;

	// read 1st frag in each packet

	ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip4Packet1);
	ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip4Packet2);
	ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip4Packet3);
	ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip4Packet4);
	ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);

	PTF_ASSERT_NULL(ip4Packet6);
	ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip4Packet8);
	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(0), status);

	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip6Packet1);
	ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip6Packet2);

	ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip6Packet3);
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FIRST_FRAGMENT, enum);
	PTF_ASSERT_NULL(ip6Packet4);

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 10);

	// read 2nd - 5th frag in each packet

	PTF_PRINT_VERBOSE("read 2nd - 5th frag in each packet");
	for (int i = 1; i < 5; i++)
	{
		PTF_PRINT_VERBOSE("Frag#" << i + 1);

		ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet1);
		ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet2);
		ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet3);
		ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet4);
		ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet6);
		ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet8);
		ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip6Packet1);
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip6Packet2);
		ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip6Packet3);
		ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip6Packet4);
	}

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 10);

	// read 6th frag in IPv4 packets 1,2,3

	ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(5), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet1);
	ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(5), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet2);
	ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(5), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet3);

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 7);

	// read IPv4 packet5

	ip4Packet5 = ipReassembly.processPacket(ip4Packet5Vec.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::NON_FRAGMENT, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet5);
	PTF_ASSERT_EQUAL(ip4Packet5->getRawPacket(), ip4Packet5Vec.at(0), ptr);

	// read 6th - 7th frag in IPv6 packets 1,4

	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(5), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
	PTF_ASSERT_NULL(ip6Packet1);
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(5), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
	PTF_ASSERT_NULL(ip6Packet4);
	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(6), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip6Packet1);
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(6), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip6Packet4);

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 5);

	// read 6th - 9th frag in IPv4 packets 4,6,8 and IPv6 packet 2

	PTF_PRINT_VERBOSE("read 6th - 9th frag in IPv4 packets 4,6,8 and IPv6 packet 2");
	for (int i = 5; i < 9; i++)
	{
		PTF_PRINT_VERBOSE("Frag#" << i + 1);

		ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet4);
		ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet6);
		ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip4Packet8);
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip6Packet2);
	}

	// read 6th - 9th frag in IPv6 packet 3

	PTF_PRINT_VERBOSE("read 6th - 8th frag in IPv6 packet 3");
	for (int i = 5; i < 8; i++)
	{
		PTF_PRINT_VERBOSE("Frag#" << i + 1);
		ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip6Packet3);
	}

	ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(8), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip6Packet3);

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 4, enum);

	// read IPv4 packet7

	ip4Packet7 = ipReassembly.processPacket(ip4Packet7Vec.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::NON_FRAGMENT, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet7);
	PTF_ASSERT_EQUAL(ip4Packet7->getRawPacket(), ip4Packet7Vec.at(0), ptr);

	// read 10th frag in IPv4 packets 4,6,8

	ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(9), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet4);
	ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(9), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet6);
	ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(9), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet8);

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 1);

	// read IPv4 packet 9

	ip4Packet9 = ipReassembly.processPacket(ip4Packet9Vec.at(0), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::NON_FRAGMENT, enum);
	PTF_ASSERT_NOT_NULL(ip4Packet9);
	PTF_ASSERT_EQUAL(ip4Packet9->getRawPacket(), ip4Packet9Vec.at(0), ptr);

	// read 11th frag in IPv4 packets 4,6 (duplicated last frag)

	PTF_ASSERT_NULL(ipReassembly.processPacket(ip4Packet4Frags.at(10), status));
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);
	PTF_ASSERT_NULL(ipReassembly.processPacket(ip4Packet6Frags.at(10), status));
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT, enum);

	// read 10th - 13th frag in IPv6 packet 2

	PTF_PRINT_VERBOSE("read 10th - 12th frag in IPv6 packet 2");
	for (int i = 9; i < 12; i++)
	{
		PTF_PRINT_VERBOSE("Frag#" << i + 1);
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::FRAGMENT, enum);
		PTF_ASSERT_NULL(ip6Packet2);
	}

	ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(12), status);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);
	PTF_ASSERT_NOT_NULL(ip6Packet2);

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 2);

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet1.txt", buffer1Length);
	PTF_ASSERT_EQUAL(ip4Packet1->getRawPacket()->getRawDataLen(), buffer1Length);
	PTF_ASSERT_BUF_COMPARE(ip4Packet1->getRawPacket()->getRawData(), buffer1, buffer1Length);

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet4.txt", buffer4Length);
	PTF_ASSERT_EQUAL(ip4Packet4->getRawPacket()->getRawDataLen(), buffer4Length);
	PTF_ASSERT_BUF_COMPARE(ip4Packet4->getRawPacket()->getRawData(), buffer4, buffer4Length);

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet6.txt", buffer6Length);
	PTF_ASSERT_EQUAL(ip4Packet6->getRawPacket()->getRawDataLen(), buffer6Length);
	PTF_ASSERT_BUF_COMPARE(ip4Packet6->getRawPacket()->getRawData(), buffer6, buffer6Length);

	int buffer61Length = 0;
	uint8_t* buffer61 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", buffer61Length);
	// small fix for payload length which is wrong in the original packet
	ip6Packet1->getLayerOfType<pcpp::IPv6Layer>()->getIPv6Header()->payloadLength = htobe16(737);
	PTF_ASSERT_EQUAL(ip6Packet1->getRawPacket()->getRawDataLen(), buffer61Length);
	PTF_ASSERT_BUF_COMPARE(ip6Packet1->getRawPacket()->getRawData(), buffer61, buffer61Length);

	int buffer62Length = 0;
	uint8_t* buffer62 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet2.txt", buffer62Length);
	// small fix for payload length which is wrong in the original packet
	ip6Packet2->getLayerOfType<pcpp::IPv6Layer>()->getIPv6Header()->payloadLength = htobe16(1448);
	PTF_ASSERT_EQUAL(ip6Packet2->getRawPacket()->getRawDataLen(), buffer62Length);
	PTF_ASSERT_BUF_COMPARE(ip6Packet2->getRawPacket()->getRawData(), buffer62, buffer62Length);

	delete ip4Packet1;
	delete ip4Packet2;
	delete ip4Packet3;
	delete ip4Packet4;
	delete ip4Packet5;
	delete ip4Packet6;
	delete ip4Packet7;
	delete ip4Packet8;
	delete ip4Packet9;
	delete ip6Packet1;
	delete ip6Packet2;
	delete ip6Packet3;
	delete ip6Packet4;

	delete[] buffer1;
	delete[] buffer4;
	delete[] buffer6;
	delete[] buffer61;
	delete[] buffer62;
}  // TestIPFragMultipleFrags

PTF_TEST_CASE(TestIPFragMapOverflow)
{
	pcpp::PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PTF_ASSERT_TRUE(reader.open());

	pcpp::PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT_TRUE(reader2.open());

	pcpp::RawPacketVector ip4Packet1Frags;
	pcpp::RawPacketVector ip4Packet2Frags;
	pcpp::RawPacketVector ip4Packet3Frags;
	pcpp::RawPacketVector ip4Packet4Frags;
	pcpp::RawPacketVector ip4Packet5Vec;
	pcpp::RawPacketVector ip4Packet6Frags;
	pcpp::RawPacketVector ip4Packet7Vec;
	pcpp::RawPacketVector ip4Packet8Frags;
	pcpp::RawPacketVector ip4Packet9Vec;
	pcpp::RawPacketVector ip6Packet1Frags;
	pcpp::RawPacketVector ip6Packet2Frags;
	pcpp::RawPacketVector ip6Packet3Frags;
	pcpp::RawPacketVector ip6Packet4Frags;

	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet1Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet2Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet3Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet4Frags, 10), 10);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet5Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet4Frags, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet6Frags, 10), 10);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet7Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet6Frags, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet8Frags, 8), 8);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet9Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet8Frags, 2), 2);

	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet1Frags, 7), 7);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet2Frags, 13), 13);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet3Frags, 9), 9);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet4Frags, 7), 7);

	pcpp::PointerVector<pcpp::IPReassembly::PacketKey> packetsRemovedFromIPReassemblyEngine;

	pcpp::IPReassembly ipReassembly(ipReassemblyOnFragmentsClean, &packetsRemovedFromIPReassemblyEngine, 3);

	PTF_ASSERT_EQUAL(ipReassembly.getMaxCapacity(), 3);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 0);

	pcpp::IPReassembly::ReassemblyStatus status;

	ipReassembly.processPacket(ip6Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet3Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(1), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(0), status);
	ipReassembly.processPacket(ip6Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(2), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(1), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(3), status);
	ipReassembly.processPacket(ip4Packet6Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet8Frags.at(0), status);

	PTF_ASSERT_EQUAL(ipReassembly.getMaxCapacity(), 3);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 3);

	PTF_ASSERT_EQUAL(packetsRemovedFromIPReassemblyEngine.size(), 5);

	pcpp::IPReassembly::IPv4PacketKey* ip4Key = nullptr;
	pcpp::IPReassembly::IPv6PacketKey* ip6Key = nullptr;

	// 1st packet removed should be ip6Packet1Frags
	ip6Key = dynamic_cast<pcpp::IPReassembly::IPv6PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(0));
	PTF_ASSERT_NOT_NULL(ip6Key);
	PTF_ASSERT_EQUAL(ip6Key->getFragmentID(), 0x2c5323);
	PTF_ASSERT_EQUAL(ip6Key->getSrcIP(), pcpp::IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")));
	PTF_ASSERT_EQUAL(ip6Key->getDstIP(), pcpp::IPv6Address(std::string("ff02::fb")));

	// 2nd packet removed should be ip4Packet2Frags
	ip4Key = dynamic_cast<pcpp::IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(1));
	PTF_ASSERT_NOT_NULL(ip4Key);
	PTF_ASSERT_EQUAL(ip4Key->getIpID(), 0x1ea1);
	PTF_ASSERT_EQUAL(ip4Key->getSrcIP(), pcpp::IPv4Address(std::string("10.118.213.212")));
	PTF_ASSERT_EQUAL(ip4Key->getDstIP(), pcpp::IPv4Address(std::string("10.118.213.211")));

	// 3rd packet removed should be ip4Packet3Frags
	ip4Key = dynamic_cast<pcpp::IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(2));
	PTF_ASSERT_NOT_NULL(ip4Key);
	PTF_ASSERT_EQUAL(ip4Key->getIpID(), 0x1ea2);
	PTF_ASSERT_EQUAL(ip4Key->getSrcIP(), pcpp::IPv4Address(std::string("10.118.213.212")));
	PTF_ASSERT_EQUAL(ip4Key->getDstIP(), pcpp::IPv4Address(std::string("10.118.213.211")));

	// 4th packet removed should be ip6Packet2Frags
	ip6Key = dynamic_cast<pcpp::IPReassembly::IPv6PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(3));
	PTF_ASSERT_NOT_NULL(ip6Key);
	PTF_ASSERT_EQUAL(ip6Key->getFragmentID(), 0x98d687d1);
	PTF_ASSERT_EQUAL(ip6Key->getSrcIP(), pcpp::IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")));
	PTF_ASSERT_EQUAL(ip6Key->getDstIP(), pcpp::IPv6Address(std::string("ff02::fb")));

	// 5th packet removed should be ip4Packet4Frags
	ip4Key = dynamic_cast<pcpp::IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(4));
	PTF_ASSERT_NOT_NULL(ip4Key);
	PTF_ASSERT_EQUAL(ip4Key->getIpID(), 0x1ea3);
	PTF_ASSERT_EQUAL(ip4Key->getSrcIP(), pcpp::IPv4Address(std::string("10.118.213.212")));
	PTF_ASSERT_EQUAL(ip4Key->getDstIP(), pcpp::IPv4Address(std::string("10.118.213.211")));
}  // TestIPFragMapOverflow

PTF_TEST_CASE(TestIPFragRemove)
{
	pcpp::PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PTF_ASSERT_TRUE(reader.open());

	pcpp::PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT_TRUE(reader2.open());

	pcpp::RawPacketVector ip4Packet1Frags;
	pcpp::RawPacketVector ip4Packet2Frags;
	pcpp::RawPacketVector ip4Packet3Frags;
	pcpp::RawPacketVector ip4Packet4Frags;
	pcpp::RawPacketVector ip4Packet5Vec;
	pcpp::RawPacketVector ip4Packet6Frags;
	pcpp::RawPacketVector ip4Packet7Vec;
	pcpp::RawPacketVector ip4Packet8Frags;
	pcpp::RawPacketVector ip4Packet9Vec;
	pcpp::RawPacketVector ip6Packet1Frags;
	pcpp::RawPacketVector ip6Packet2Frags;
	pcpp::RawPacketVector ip6Packet3Frags;
	pcpp::RawPacketVector ip6Packet4Frags;

	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet1Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet2Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet3Frags, 6), 6);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet4Frags, 10), 10);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet5Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet4Frags, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet6Frags, 10), 10);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet7Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet6Frags, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet8Frags, 8), 8);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet9Vec, 1), 1);
	PTF_ASSERT_EQUAL(reader.getNextPackets(ip4Packet8Frags, 2), 2);

	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet1Frags, 7), 7);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet2Frags, 13), 13);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet3Frags, 9), 9);
	PTF_ASSERT_EQUAL(reader2.getNextPackets(ip6Packet4Frags, 7), 7);

	pcpp::IPReassembly ipReassembly;

	pcpp::IPReassembly::ReassemblyStatus status;

	ipReassembly.processPacket(ip4Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip6Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet3Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(1), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(2), status);
	ipReassembly.processPacket(ip6Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet6Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(1), status);
	ipReassembly.processPacket(ip6Packet3Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(3), status);
	ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	ipReassembly.processPacket(ip6Packet4Frags.at(0), status);

	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 10);

	pcpp::IPReassembly::IPv4PacketKey ip4Key;
	ip4Key.setSrcIP(pcpp::IPv4Address(std::string("10.118.213.212")));
	ip4Key.setDstIP(pcpp::IPv4Address(std::string("10.118.213.211")));

	ip4Key.setIpID(0x1ea0);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 9);

	ip4Key.setIpID(0x1ea5);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 8);

	// IPv4 key doesn't exist
	ip4Key.setIpID(0x1ea9);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 8);

	ip4Key.setIpID(0x1ea4);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 7);

	pcpp::IPReassembly::IPv6PacketKey ip6Key;
	ip6Key.setSrcIP(pcpp::IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")));
	ip6Key.setDstIP(pcpp::IPv6Address(std::string("ff02::fb")));

	ip6Key.setFragmentID(0x98d687d1);
	ipReassembly.removePacket(ip6Key);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 6);

	// IPv6 key doesn't exist
	ip6Key.setFragmentID(0xaaaaaaaa);
	ipReassembly.removePacket(ip6Key);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 6);

	ip6Key.setFragmentID(0x2c5323);
	ipReassembly.removePacket(ip6Key);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 5);

	ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	PTF_ASSERT_EQUAL(ipReassembly.getCurrentCapacity(), 6);
}  // TestIPFragRemove

PTF_TEST_CASE(TestIPFragWithPadding)
{
	std::vector<pcpp::RawPacket> packetStream;
	std::string errMsg;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/frag_with_padding.pcap", packetStream, errMsg));

	pcpp::IPReassembly ipReassembly;
	pcpp::IPReassembly::ReassemblyStatus status;

	pcpp::Packet* result = nullptr;

	for (auto rawPacket : packetStream)
	{
		pcpp::Packet packet(&rawPacket);
		result = ipReassembly.processPacket(&packet, status);
	}

	PTF_ASSERT_NOT_NULL(result);
	PTF_ASSERT_EQUAL(status, pcpp::IPReassembly::REASSEMBLED, enum);

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_with_padding_defragmented.dat", bufferLength);
	PTF_ASSERT_NOT_NULL(buffer);

	PTF_ASSERT_EQUAL(bufferLength, result->getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(result->getRawPacket()->getRawData(), buffer, bufferLength);

	delete result;
	delete[] buffer;
}  // TestIPFragWithPadding
