#include "../TestDefinition.h"
#include "../Common/TestUtils.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include "EndianPortable.h"
#include "SystemUtils.h"
#include "TcpReassembly.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"
#include "PcapFileDevice.h"

// ~~~~~~~~~~~~~~~~~~
// TcpReassemblyStats
// ~~~~~~~~~~~~~~~~~~

struct TcpReassemblyStats
{
	std::string reassembledData;
	int numOfDataPackets;
	int8_t curSide;
	int numOfMessagesFromSide[2];
	bool connectionsStarted;
	bool connectionsEnded;
	bool connectionsEndedManually;
	size_t totalMissingBytes;
	pcpp::ConnectionData connData;

	TcpReassemblyStats()
	{
		clear();
	}

	void clear()
	{
		reassembledData = "";
		numOfDataPackets = 0;
		curSide = -1;
		numOfMessagesFromSide[0] = 0;
		numOfMessagesFromSide[1] = 0;
		connectionsStarted = false;
		connectionsEnded = false;
		connectionsEndedManually = false;
		totalMissingBytes = 0;
	}
};

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// TcpReassemblyMultipleConnStats
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct TcpReassemblyMultipleConnStats
{
	typedef std::vector<uint32_t> FlowKeysList;
	typedef std::map<uint32_t, TcpReassemblyStats> Stats;

	Stats stats;
	FlowKeysList flowKeysList;

	std::vector<timeval> timestamps;
	void clear()
	{
		stats.clear();
		flowKeysList.clear();
	}

	pcpp::TcpReassembly* tcpReassmbly = nullptr;
};

// ~~~~~~~~~~~~~~~~~~~~
// readFileIntoString()
// ~~~~~~~~~~~~~~~~~~~~

static std::string readFileIntoString(const std::string& fileName)
{
	std::ifstream infile(fileName.c_str(), std::ios::binary);
	std::ostringstream ostrm;
	ostrm << infile.rdbuf();
	std::string res = ostrm.str();

	return res;
}

// ~~~~~~~~~~~~~~~~~~~~
// getPayloadLen()
// ~~~~~~~~~~~~~~~~~~~~

static size_t getPayloadLen(pcpp::RawPacket& rawPacket)
{
	pcpp::Packet packet(&rawPacket);

	pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == nullptr)
		throw std::runtime_error("TCP Layer not found");

	pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == nullptr)
		throw std::runtime_error("IPv4 Layer not found");

	return be16toh(ipLayer->getIPv4Header()->totalLength) - ipLayer->getHeaderLen() - tcpLayer->getHeaderLen();
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// tcpReassemblyMsgReadyCallback()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie)
{
	TcpReassemblyMultipleConnStats::Stats& stats = ((TcpReassemblyMultipleConnStats*)userCookie)->stats;

	TcpReassemblyMultipleConnStats::Stats::iterator iter = stats.find(tcpData.getConnectionData().flowKey);
	if (iter == stats.end())
	{
		stats.insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyStats()));
		iter = stats.find(tcpData.getConnectionData().flowKey);
	}

	iter->second.totalMissingBytes += tcpData.getMissingByteCount();

	if (sideIndex != iter->second.curSide)
	{
		iter->second.numOfMessagesFromSide[sideIndex]++;
		iter->second.curSide = sideIndex;
	}

	((TcpReassemblyMultipleConnStats*)userCookie)->timestamps.push_back(tcpData.getTimeStamp());
	iter->second.numOfDataPackets++;
	iter->second.reassembledData += std::string((char*)tcpData.getData(), tcpData.getDataLength());
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// tcpReassemblyManuallyCloseConnMsgReadyCallback()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static void tcpReassemblyManuallyCloseConnMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData,
                                                           void* userCookie)
{
	TcpReassemblyMultipleConnStats::Stats& stats = static_cast<TcpReassemblyMultipleConnStats*>(userCookie)->stats;

	auto iter = stats.find(tcpData.getConnectionData().flowKey);
	if (iter == stats.end())
	{
		stats.insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyStats()));
		iter = stats.find(tcpData.getConnectionData().flowKey);
	}

	iter->second.totalMissingBytes += tcpData.getMissingByteCount();

	if (sideIndex != iter->second.curSide)
	{
		iter->second.numOfMessagesFromSide[sideIndex]++;
		iter->second.curSide = sideIndex;
	}

	static_cast<TcpReassemblyMultipleConnStats*>(userCookie)->timestamps.push_back(tcpData.getTimeStamp());
	iter->second.numOfDataPackets++;
	iter->second.reassembledData += std::string((char*)tcpData.getData(), tcpData.getDataLength());

	// if numOfDataPackets hits 10, close the connection manually
	if (iter->second.numOfDataPackets >= 10)
	{
		// clang-format off
		static_cast<TcpReassemblyMultipleConnStats*>(userCookie)->tcpReassmbly->closeConnection(tcpData.getConnectionData().flowKey);
		// clang-format on
	}
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// tcpReassemblyConnectionStartCallback()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie)
{
	TcpReassemblyMultipleConnStats::Stats& stats = ((TcpReassemblyMultipleConnStats*)userCookie)->stats;

	TcpReassemblyMultipleConnStats::Stats::iterator iter = stats.find(connectionData.flowKey);
	if (iter == stats.end())
	{
		stats.insert(std::make_pair(connectionData.flowKey, TcpReassemblyStats()));
		iter = stats.find(connectionData.flowKey);
	}

	TcpReassemblyMultipleConnStats::FlowKeysList& flowKeys =
	    ((TcpReassemblyMultipleConnStats*)userCookie)->flowKeysList;
	if (std::find(flowKeys.begin(), flowKeys.end(), connectionData.flowKey) == flowKeys.end())
		flowKeys.push_back(connectionData.flowKey);

	iter->second.connectionsStarted = true;
	iter->second.connData = connectionData;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// tcpReassemblyConnectionEndCallback()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData,
                                               pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	TcpReassemblyMultipleConnStats::Stats& stats = ((TcpReassemblyMultipleConnStats*)userCookie)->stats;

	TcpReassemblyMultipleConnStats::Stats::iterator iter = stats.find(connectionData.flowKey);
	if (iter == stats.end())
	{
		stats.insert(std::make_pair(connectionData.flowKey, TcpReassemblyStats()));
		iter = stats.find(connectionData.flowKey);
	}

	TcpReassemblyMultipleConnStats::FlowKeysList& flowKeys =
	    ((TcpReassemblyMultipleConnStats*)userCookie)->flowKeysList;
	if (std::find(flowKeys.begin(), flowKeys.end(), connectionData.flowKey) == flowKeys.end())
		flowKeys.push_back(connectionData.flowKey);

	if (reason == pcpp::TcpReassembly::TcpReassemblyConnectionClosedManually)
		iter->second.connectionsEndedManually = true;
	else
		iter->second.connectionsEnded = true;
	iter->second.connData = connectionData;
}

// ~~~~~~~~~~~~~~~~~~~
// tcpReassemblyTest()
// ~~~~~~~~~~~~~~~~~~~

static bool tcpReassemblyTest(const std::vector<pcpp::RawPacket>& packetStream, TcpReassemblyMultipleConnStats& results,
                              bool monitorOpenCloseConns, bool closeConnsManually)
{
	pcpp::TcpReassembly* tcpReassembly = nullptr;

	if (monitorOpenCloseConns)
		tcpReassembly =
		    new pcpp::TcpReassembly(tcpReassemblyMsgReadyCallback, &results, tcpReassemblyConnectionStartCallback,
		                            tcpReassemblyConnectionEndCallback);
	else
		tcpReassembly = new pcpp::TcpReassembly(tcpReassemblyMsgReadyCallback, &results);

	for (auto iter : packetStream)
	{
		pcpp::Packet packet(&iter);
		tcpReassembly->reassemblePacket(packet);
	}

	// for(TcpReassemblyMultipleConnStats::Stats::iterator iter = results.stats.begin(); iter != results.stats.end();
	// iter++)
	//{
	//	// replace \r\n with \n
	//	size_t index = 0;
	//	while (true)
	//	{
	//		 index = iter->second.reassembledData.find("\r\n", index);
	//		 if (index == string::npos) break;
	//		 iter->second.reassembledData.replace(index, 2, "\n");
	//		 index += 1;
	//	}
	// }

	if (closeConnsManually)
		tcpReassembly->closeAllConnections();

	delete tcpReassembly;

	return true;
}

// ~~~~~~~~~~~~~~~~~~~
// tcpReassemblyTestManuallyCloseConnOnMsgReady()
// ~~~~~~~~~~~~~~~~~~~

static bool tcpReassemblyTestManuallyCloseConnOnMsgReady(const std::vector<pcpp::RawPacket>& packetStream,
                                                         TcpReassemblyMultipleConnStats& results)
{
	results.tcpReassmbly =
	    new pcpp::TcpReassembly(tcpReassemblyManuallyCloseConnMsgReadyCallback, &results,
	                            tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);

	for (auto iter : packetStream)
	{
		pcpp::Packet packet(&iter);
		results.tcpReassmbly->reassemblePacket(packet);
	}

	results.tcpReassmbly->closeAllConnections();

	delete results.tcpReassmbly;

	return true;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// tcpReassemblyAddRetransmissions()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static pcpp::RawPacket tcpReassemblyAddRetransmissions(pcpp::RawPacket rawPacket, int beginning, int numOfBytes)
{
	pcpp::Packet packet(&rawPacket);

	pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == nullptr)
		throw std::runtime_error("TCP Layer not found");

	pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == nullptr)
		throw std::runtime_error("IPv4 Layer not found");

	int tcpPayloadSize =
	    be16toh(ipLayer->getIPv4Header()->totalLength) - ipLayer->getHeaderLen() - tcpLayer->getHeaderLen();

	if (numOfBytes <= 0)
		numOfBytes = tcpPayloadSize - beginning;

	uint8_t* newPayload = new uint8_t[numOfBytes];

	if (beginning + numOfBytes <= tcpPayloadSize)
	{
		memcpy(newPayload, tcpLayer->getLayerPayload() + beginning, numOfBytes);
	}
	else
	{
		int bytesToCopy = tcpPayloadSize - beginning;
		memcpy(newPayload, tcpLayer->getLayerPayload() + beginning, bytesToCopy);
		for (int i = bytesToCopy; i < numOfBytes; i++)
		{
			newPayload[i] = '*';
		}
	}

	pcpp::Layer* layerToRemove = tcpLayer->getNextLayer();
	if (layerToRemove != nullptr)
		packet.removeLayer(layerToRemove->getProtocol());

	tcpLayer->getTcpHeader()->sequenceNumber = htobe32(be32toh(tcpLayer->getTcpHeader()->sequenceNumber) + beginning);

	pcpp::PayloadLayer newPayloadLayer(newPayload, numOfBytes);
	packet.addLayer(&newPayloadLayer);

	packet.computeCalculateFields();

	delete[] newPayload;

	return *(packet.getRawPacket());
}

// ~~~~~~~~~~~~~~~~~~~~~
// ~~~~~~~~~~~~~~~~~~~~~
// Test Cases start here
// ~~~~~~~~~~~~~~~~~~~~~
// ~~~~~~~~~~~~~~~~~~~~~

PTF_TEST_CASE(TestTcpReassemblySanity)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 19);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 2);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);
	pcpp::IPv4Address expectedSrcIP(std::string("10.0.0.1"));
	pcpp::IPv4Address expectedDstIP(std::string("81.218.72.15"));
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.dstIP, expectedDstIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1491516383);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 915793);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1491516383915793000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1491516399);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 576245);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1491516399576245000);
	// clang-format on

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblySanity

PTF_TEST_CASE(TestTcpReassemblyRetran)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

	// retransmission includes exact same data
	pcpp::RawPacket retPacket1 = tcpReassemblyAddRetransmissions(packetStream.at(4), 0, 0);
	// retransmission includes 10 bytes less than original data (missing bytes are from the beginning)
	pcpp::RawPacket retPacket2 = tcpReassemblyAddRetransmissions(packetStream.at(10), 10, 0);
	// retransmission includes 20 bytes less than original data (missing bytes are from the end)
	pcpp::RawPacket retPacket3 = tcpReassemblyAddRetransmissions(packetStream.at(13), 0, 1340);
	// retransmission includes 10 bytes more than original data (original data + 10 bytes)
	pcpp::RawPacket retPacket4 = tcpReassemblyAddRetransmissions(packetStream.at(21), 0, 1430);
	// retransmission includes 10 bytes less in the beginning and 20 bytes more at the end
	pcpp::RawPacket retPacket5 = tcpReassemblyAddRetransmissions(packetStream.at(28), 10, 1370);
	// retransmission includes 10 bytes less in the beginning and 15 bytes less at the end
	pcpp::RawPacket retPacket6 = tcpReassemblyAddRetransmissions(packetStream.at(34), 10, 91);

	packetStream.insert(packetStream.begin() + 5, retPacket1);
	packetStream.insert(packetStream.begin() + 12, retPacket2);
	packetStream.insert(packetStream.begin() + 16, retPacket3);
	packetStream.insert(packetStream.begin() + 25, retPacket4);
	packetStream.insert(packetStream.begin() + 33, retPacket5);
	packetStream.insert(packetStream.begin() + 40, retPacket6);

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, false, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 21);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 2);

	std::string expectedReassemblyData =
	    readFileIntoString(std::string("PcapExamples/one_tcp_stream_retransmission_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyRetran

PTF_TEST_CASE(TestTcpReassemblyMissingData)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));
	size_t expectedLoss = 0;

	// remove 20 bytes from the beginning
	pcpp::RawPacket missPacket1 = tcpReassemblyAddRetransmissions(packetStream.at(3), 20, 0);
	packetStream.insert(packetStream.begin() + 4, missPacket1);
	packetStream.erase(packetStream.begin() + 3);
	expectedLoss += 20;

	// remove 30 bytes from the end
	pcpp::RawPacket missPacket2 = tcpReassemblyAddRetransmissions(packetStream.at(20), 0, 1390);
	packetStream.insert(packetStream.begin() + 21, missPacket2);
	packetStream.erase(packetStream.begin() + 20);
	expectedLoss += 30;

	// remove whole packets
	expectedLoss += getPayloadLen(*(packetStream.begin() + 28));
	expectedLoss += getPayloadLen(*(packetStream.begin() + 30));
	packetStream.erase(packetStream.begin() + 28);
	packetStream.erase(packetStream.begin() + 30);

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, false, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.begin()->second.totalMissingBytes, expectedLoss);
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 17);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 2);

	std::string expectedReassemblyData =
	    readFileIntoString(std::string("PcapExamples/one_tcp_stream_missing_data_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData.clear();

	// test flow without SYN packet
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

	// remove SYN and SYN/ACK packets
	packetStream.erase(packetStream.begin());
	packetStream.erase(packetStream.begin());

	tcpReassemblyTest(packetStream, tcpReassemblyResults, false, true);

	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 19);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 2);

	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyMissingData

PTF_TEST_CASE(TestTcpReassemblyOutOfOrder)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

	// swap 2 consequent packets
	std::swap(packetStream[9], packetStream[10]);

	// swap 2 non-consequent packets
	pcpp::RawPacket oooPacket1 = packetStream[18];
	packetStream.erase(packetStream.begin() + 18);
	packetStream.insert(packetStream.begin() + 23, oooPacket1);

	// reverse order of all packets in message
	for (int i = 0; i < 12; i++)
	{
		pcpp::RawPacket oooPacketTemp = packetStream[35];
		packetStream.erase(packetStream.begin() + 35);
		packetStream.insert(packetStream.begin() + 24 + i, oooPacketTemp);
	}

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 19);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 2);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);

	std::string expectedReassemblyData =
	    readFileIntoString(std::string("PcapExamples/one_tcp_stream_out_of_order_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData.clear();

	// test out-of-order + missing data
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

	// reverse order of all packets in message
	for (int i = 0; i < 12; i++)
	{
		pcpp::RawPacket oooPacketTemp = packetStream[35];
		packetStream.erase(packetStream.begin() + 35);
		packetStream.insert(packetStream.begin() + 24 + i, oooPacketTemp);
	}

	// remove one packet
	packetStream.erase(packetStream.begin() + 29);

	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 18);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 2);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);

	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_missing_data_output_ooo.txt"));

	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyOutOfOrder

PTF_TEST_CASE(TestTcpReassemblyOOOWithManualClose)
{
	// out-of-order packets
	{
		std::string errMsg;
		std::vector<pcpp::RawPacket> packetStream;
		PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

		// swap 2 consequent packets
		std::swap(packetStream[9], packetStream[10]);

		// swap 2 non-consequent packets
		pcpp::RawPacket oooPacket1 = packetStream[18];
		packetStream.erase(packetStream.begin() + 18);
		packetStream.insert(packetStream.begin() + 23, oooPacket1);

		// reverse order of all packets in message
		for (int i = 0; i < 12; i++)
		{
			pcpp::RawPacket oooPacketTemp = packetStream[35];
			packetStream.erase(packetStream.begin() + 35);
			packetStream.insert(packetStream.begin() + 24 + i, oooPacketTemp);
		}

		TcpReassemblyMultipleConnStats tcpReassemblyResults;
		tcpReassemblyTestManuallyCloseConnOnMsgReady(packetStream, tcpReassemblyResults);

		TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
		PTF_ASSERT_EQUAL(stats.size(), 1);
		PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 13);
		PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
		PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 1);
		PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
		PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
		PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);

		std::string expectedReassemblyData =
		    readFileIntoString(std::string("PcapExamples/one_tcp_stream_out_of_order_with_manual_close_output.txt"));
		PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
	}

	// out-of-order + missing data
	{
		std::string errMsg;
		std::vector<pcpp::RawPacket> packetStream;
		PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

		// swap 2 consequent packets
		std::swap(packetStream[9], packetStream[10]);

		// remove one packet
		packetStream.erase(packetStream.begin() + 13);

		TcpReassemblyMultipleConnStats tcpReassemblyResults;
		tcpReassemblyTestManuallyCloseConnOnMsgReady(packetStream, tcpReassemblyResults);
		TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;

		PTF_ASSERT_EQUAL(stats.size(), 1);
		PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 10);
		PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
		PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 1);
		PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
		PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
		PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);

		std::string expectedReassemblyData =
		    readFileIntoString(std::string("PcapExamples/one_tcp_stream_missing_date_with_manual_close_output.txt"));

		PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
	}
}  // TestTcpReassemblyOOOWithManualClose

PTF_TEST_CASE(TestTcpReassemblyWithFIN_RST)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;
	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	std::string expectedReassemblyData;

	// test fin packet in end of connection
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_http_stream_fin.pcap", packetStream, errMsg));
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 5);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData.clear();

	// test rst packet in end of connection
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_http_stream_rst.pcap", packetStream, errMsg));
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_rst_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData.clear();

	// test rst packet without fin in end of connection
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_rst.pcap", packetStream, errMsg));
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 0);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 0);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 0);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEndedManually);

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData.clear();

	// test fin packet in end of connection that has also data
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg));
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 6);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData.clear();

	// test missing data before fin
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg));

	// move second packet of server->client message to the end of the message (after FIN)
	pcpp::RawPacket oooPacketTemp = packetStream[6];
	packetStream.erase(packetStream.begin() + 6);
	packetStream.insert(packetStream.begin() + 12, oooPacketTemp);

	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 5);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output2.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyWithFIN_RST

PTF_TEST_CASE(TestTcpReassemblyMalformedPkts)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;
	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	std::string expectedReassemblyData;

	// test retransmission with new data but payload doesn't really contain all the new data
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg));

	// take one of the packets and increase the IPv4 total length field
	pcpp::Packet malPacket(&packetStream.at(8));
	pcpp::IPv4Layer* ipLayer = malPacket.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	ipLayer->getIPv4Header()->totalLength = be16toh(htobe16(ipLayer->getIPv4Header()->totalLength) + 40);

	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 6);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyMalformedPkts

PTF_TEST_CASE(TestTcpReassemblyMultipleConns)
{
	TcpReassemblyMultipleConnStats results;
	std::string errMsg;
	std::string expectedReassemblyData;

	pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &results, tcpReassemblyConnectionStartCallback,
	                                  tcpReassemblyConnectionEndCallback);

	std::vector<pcpp::RawPacket> packetStream;
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/three_http_streams.pcap", packetStream, errMsg));

	pcpp::RawPacket finPacket1 = packetStream.at(13);
	pcpp::RawPacket finPacket2 = packetStream.at(15);

	packetStream.erase(packetStream.begin() + 13);
	packetStream.erase(packetStream.begin() + 14);

	pcpp::TcpReassembly::ReassemblyStatus expectedStatuses[26] = {
		pcpp::TcpReassembly::TcpMessageHandled,       pcpp::TcpReassembly::TcpMessageHandled,
		pcpp::TcpReassembly::TcpMessageHandled,       pcpp::TcpReassembly::TcpMessageHandled,
		pcpp::TcpReassembly::Ignore_PacketWithNoData, pcpp::TcpReassembly::TcpMessageHandled,
		pcpp::TcpReassembly::TcpMessageHandled,       pcpp::TcpReassembly::Ignore_PacketWithNoData,
		pcpp::TcpReassembly::TcpMessageHandled,       pcpp::TcpReassembly::TcpMessageHandled,
		pcpp::TcpReassembly::Ignore_PacketWithNoData, pcpp::TcpReassembly::TcpMessageHandled,
		pcpp::TcpReassembly::TcpMessageHandled,       pcpp::TcpReassembly::Ignore_PacketWithNoData,
		pcpp::TcpReassembly::TcpMessageHandled,       pcpp::TcpReassembly::FIN_RSTWithNoData,
		pcpp::TcpReassembly::Ignore_PacketWithNoData, pcpp::TcpReassembly::FIN_RSTWithNoData,
		pcpp::TcpReassembly::Ignore_PacketWithNoData, pcpp::TcpReassembly::Ignore_PacketWithNoData,
		pcpp::TcpReassembly::TcpMessageHandled,       pcpp::TcpReassembly::Ignore_PacketWithNoData,
		pcpp::TcpReassembly::FIN_RSTWithNoData,       pcpp::TcpReassembly::FIN_RSTWithNoData,
		pcpp::TcpReassembly::Ignore_PacketWithNoData, pcpp::TcpReassembly::Ignore_PacketWithNoData,
	};

	int statusIndex = 0;

	for (auto iter : packetStream)
	{
		pcpp::Packet packet(&iter);
		pcpp::TcpReassembly::ReassemblyStatus status = tcpReassembly.reassemblePacket(packet);
		PTF_ASSERT_EQUAL(status, expectedStatuses[statusIndex++], enum);
	}

	TcpReassemblyMultipleConnStats::Stats& stats = results.stats;
	PTF_ASSERT_EQUAL(stats.size(), 3);
	PTF_ASSERT_EQUAL(results.flowKeysList.size(), 3);

	TcpReassemblyMultipleConnStats::Stats::iterator iter = stats.begin();

	PTF_ASSERT_EQUAL(iter->second.numOfDataPackets, 2);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(iter->second.connectionsStarted);
	PTF_ASSERT_TRUE(iter->second.connectionsEnded);
	PTF_ASSERT_FALSE(iter->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_1_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, iter->second.reassembledData);

	++iter;

	PTF_ASSERT_EQUAL(iter->second.numOfDataPackets, 2);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(iter->second.connectionsStarted);
	PTF_ASSERT_TRUE(iter->second.connectionsEnded);
	PTF_ASSERT_FALSE(iter->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_2_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, iter->second.reassembledData);

	++iter;

	PTF_ASSERT_EQUAL(iter->second.numOfDataPackets, 2);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(iter->second.connectionsStarted);
	PTF_ASSERT_FALSE(iter->second.connectionsEnded);
	PTF_ASSERT_FALSE(iter->second.connectionsEndedManually);
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_3_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, iter->second.reassembledData);

	// test getConnectionInformation and isConnectionOpen

	const pcpp::TcpReassembly::ConnectionInfoList& managedConnections = tcpReassembly.getConnectionInformation();
	PTF_ASSERT_EQUAL(managedConnections.size(), 3);

	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn1 =
	    managedConnections.find(results.flowKeysList[0]);
	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn2 =
	    managedConnections.find(results.flowKeysList[1]);
	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn3 =
	    managedConnections.find(results.flowKeysList[2]);
	PTF_ASSERT_TRUE(iterConn1 != managedConnections.end());
	PTF_ASSERT_TRUE(iterConn2 != managedConnections.end());
	PTF_ASSERT_TRUE(iterConn3 != managedConnections.end());
	PTF_ASSERT_GREATER_THAN(tcpReassembly.isConnectionOpen(iterConn1->second), 0);
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn2->second), 0);
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn3->second), 0);

	// test Connection Information data
	pcpp::IPv4Address expectedSrcIP("172.16.133.132");
	pcpp::IPv4Address expectedDstIP("98.139.161.29");
	PTF_ASSERT_EQUAL(iterConn1->second.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(iterConn1->second.dstIP, expectedDstIP);
	PTF_ASSERT_EQUAL(iterConn1->second.srcPort, 54615);
	PTF_ASSERT_EQUAL(iterConn1->second.dstPort, 80);
	PTF_ASSERT_EQUAL(iterConn1->second.flowKey, results.flowKeysList[0]);
	PTF_ASSERT_EQUAL(iterConn1->second.startTime.tv_sec, 1361916156);
	PTF_ASSERT_EQUAL(iterConn1->second.startTime.tv_usec, 677488);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(iterConn1->second.startTimePrecise.time_since_epoch()).count(), 1361916156677488000);
	PTF_ASSERT_EQUAL(iterConn1->second.endTime.tv_sec, 1361916156);
	PTF_ASSERT_EQUAL(iterConn1->second.endTime.tv_usec, 766111);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(iterConn1->second.endTimePrecise.time_since_epoch()).count(), 1361916156766111000);
	// clang-format on

	// test the return of invalid connection flowKey
	pcpp::ConnectionData dummyConn;
	dummyConn.flowKey = 0x12345678;
	PTF_ASSERT_LOWER_THAN(tcpReassembly.isConnectionOpen(dummyConn), 0);

	// close flow manually and verify it's closed

	tcpReassembly.closeConnection(iter->first);
	PTF_ASSERT_FALSE(iter->second.connectionsEnded);
	PTF_ASSERT_TRUE(iter->second.connectionsEndedManually);

	// now send FIN packets of conn 3 and verify they are ignored

	pcpp::TcpReassembly::ReassemblyStatus status = tcpReassembly.reassemblePacket(&finPacket1);
	PTF_ASSERT_EQUAL(status, pcpp::TcpReassembly::Ignore_PacketOfClosedFlow, enum);
	status = tcpReassembly.reassemblePacket(&finPacket2);
	PTF_ASSERT_EQUAL(status, pcpp::TcpReassembly::Ignore_PacketOfClosedFlow, enum);

	PTF_ASSERT_FALSE(iter->second.connectionsEnded);
	PTF_ASSERT_TRUE(iter->second.connectionsEndedManually);
}  // TestTcpReassemblyMultipleConns

PTF_TEST_CASE(TestTcpReassemblyIPv6)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_ipv6_http_stream.pcap", packetStream, errMsg));

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 10);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 3);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 3);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);
	pcpp::IPv6Address expectedSrcIP("2001:618:400::5199:cc70");
	pcpp::IPv6Address expectedDstIP("2001:618:1:8000::5");
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.dstIP, expectedDstIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1147551796);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 702602);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1147551796702602000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1147551797);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 29966);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1147551797029966000);
	// clang-format on

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyIPv6

PTF_TEST_CASE(TestTcpReassemblyIPv6MultConns)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;
	std::string expectedReassemblyData;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/four_ipv6_http_streams.pcap", packetStream, errMsg));

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 4);

	TcpReassemblyMultipleConnStats::Stats::iterator iter = stats.begin();

	pcpp::IPv6Address expectedSrcIP("2001:618:400::5199:cc70");
	pcpp::IPv6Address expectedDstIP1("2001:618:1:8000::5");
	pcpp::IPv6Address expectedDstIP2("2001:638:902:1:202:b3ff:feee:5dc2");

	PTF_ASSERT_EQUAL(iter->second.numOfDataPackets, 14);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[0], 3);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[1], 3);
	PTF_ASSERT_TRUE(iter->second.connectionsStarted);
	PTF_ASSERT_FALSE(iter->second.connectionsEnded);
	PTF_ASSERT_TRUE(iter->second.connectionsEndedManually);
	PTF_ASSERT_EQUAL(iter->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(iter->second.connData.dstIP, expectedDstIP1);
	PTF_ASSERT_EQUAL(iter->second.connData.srcPort, 35995);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1147551795);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 526632);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1147551795526632000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1147551797);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 111060);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1147551797111060000);
	// clang-format on
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream4.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, iter->second.reassembledData);

	++iter;

	PTF_ASSERT_EQUAL(iter->second.numOfDataPackets, 10);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(iter->second.connectionsStarted);
	PTF_ASSERT_FALSE(iter->second.connectionsEnded);
	PTF_ASSERT_TRUE(iter->second.connectionsEndedManually);
	PTF_ASSERT_EQUAL(iter->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(iter->second.connData.dstIP, expectedDstIP1);
	PTF_ASSERT_EQUAL(iter->second.connData.srcPort, 35999);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1147551795);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 526632);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1147551795526632000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1147551797);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 111060);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1147551797111060000);
	// clang-format on

	++iter;

	PTF_ASSERT_EQUAL(iter->second.numOfDataPackets, 2);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[0], 1);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[1], 1);
	PTF_ASSERT_TRUE(iter->second.connectionsStarted);
	PTF_ASSERT_FALSE(iter->second.connectionsEnded);
	PTF_ASSERT_TRUE(iter->second.connectionsEndedManually);
	PTF_ASSERT_EQUAL(iter->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(iter->second.connData.dstIP, expectedDstIP2);
	PTF_ASSERT_EQUAL(iter->second.connData.srcPort, 40426);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1147551795);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 526632);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1147551795526632000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1147551797);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 111060);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1147551797111060000);
	// clang-format on
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream3.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, iter->second.reassembledData);

	++iter;

	PTF_ASSERT_EQUAL(iter->second.numOfDataPackets, 13);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[0], 4);
	PTF_ASSERT_EQUAL(iter->second.numOfMessagesFromSide[1], 4);
	PTF_ASSERT_TRUE(iter->second.connectionsStarted);
	PTF_ASSERT_FALSE(iter->second.connectionsEnded);
	PTF_ASSERT_TRUE(iter->second.connectionsEndedManually);
	PTF_ASSERT_EQUAL(iter->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(iter->second.connData.dstIP, expectedDstIP1);
	PTF_ASSERT_EQUAL(iter->second.connData.srcPort, 35997);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1147551795);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 526632);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1147551795526632000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1147551797);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 111060);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1147551797111060000);
	// clang-format on

	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream2.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, iter->second.reassembledData);
}  // TestTcpReassemblyIPv6MultConns

PTF_TEST_CASE(TestTcpReassemblyIPv6_OOO)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_ipv6_http_stream.pcap", packetStream, errMsg));

	// swap 2 non-consequent packets
	pcpp::RawPacket oooPacket1 = packetStream[10];
	packetStream.erase(packetStream.begin() + 10);
	packetStream.insert(packetStream.begin() + 12, oooPacket1);

	// swap additional 2 non-consequent packets
	oooPacket1 = packetStream[15];
	packetStream.erase(packetStream.begin() + 15);
	packetStream.insert(packetStream.begin() + 17, oooPacket1);

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 10);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 3);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 3);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);
	pcpp::IPv6Address expectedSrcIP("2001:618:400::5199:cc70");
	pcpp::IPv6Address expectedDstIP("2001:618:1:8000::5");
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.dstIP, expectedDstIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1147551796);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 702602);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1147551796702602000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1147551797);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 29966);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1147551797029966000);
	// clang-format on

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyIPv6_OOO

PTF_TEST_CASE(TestTcpReassemblyCleanup)
{
	TcpReassemblyMultipleConnStats results;
	std::string errMsg;

	pcpp::TcpReassemblyConfiguration config(true, 2, 1);
	pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &results, tcpReassemblyConnectionStartCallback,
	                                  tcpReassemblyConnectionEndCallback, config);

	std::vector<pcpp::RawPacket> packetStream;
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/three_http_streams.pcap", packetStream, errMsg));

	pcpp::RawPacket lastPacket = packetStream.back();

	packetStream.pop_back();

	for (auto iter : packetStream)
	{
		pcpp::Packet packet(&iter);
		tcpReassembly.reassemblePacket(packet);
	}

	pcpp::TcpReassembly::ConnectionInfoList managedConnections =
	    tcpReassembly.getConnectionInformation();  // make a copy of list
	PTF_ASSERT_EQUAL(managedConnections.size(), 3);
	PTF_ASSERT_EQUAL(results.flowKeysList.size(), 3);

	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn1 =
	    managedConnections.find(results.flowKeysList[0]);
	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn2 =
	    managedConnections.find(results.flowKeysList[1]);
	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn3 =
	    managedConnections.find(results.flowKeysList[2]);
	PTF_ASSERT_TRUE(iterConn1 != managedConnections.end());
	PTF_ASSERT_TRUE(iterConn2 != managedConnections.end());
	PTF_ASSERT_TRUE(iterConn3 != managedConnections.end());
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn1->second), 0);
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn2->second), 0);
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn3->second), 0);

	std::this_thread::sleep_for(std::chrono::seconds(3));

	tcpReassembly.reassemblePacket(&lastPacket);  // automatic cleanup of 1 item
	PTF_ASSERT_EQUAL(tcpReassembly.getConnectionInformation().size(), 2);

	tcpReassembly.purgeClosedConnections();  // manually initiated cleanup of 1 item
	PTF_ASSERT_EQUAL(tcpReassembly.getConnectionInformation().size(), 1);

	tcpReassembly.purgeClosedConnections(0xFFFFFFFF);  // manually initiated cleanup of all items
	PTF_ASSERT_EQUAL(tcpReassembly.getConnectionInformation().size(), 0);

	const TcpReassemblyMultipleConnStats::FlowKeysList& flowKeys = results.flowKeysList;
	iterConn1 = managedConnections.find(flowKeys[0]);
	iterConn2 = managedConnections.find(flowKeys[1]);
	iterConn3 = managedConnections.find(flowKeys[2]);
	PTF_ASSERT_TRUE(iterConn1 != managedConnections.end());
	PTF_ASSERT_TRUE(iterConn2 != managedConnections.end());
	PTF_ASSERT_TRUE(iterConn3 != managedConnections.end());
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn1->second), -1);
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn2->second), -1);
	PTF_ASSERT_EQUAL(tcpReassembly.isConnectionOpen(iterConn3->second), -1);
}  // TestTcpReassemblyCleanup

PTF_TEST_CASE(TestTcpReassemblyMaxOOOFrags)
{
	TcpReassemblyMultipleConnStats results1;
	TcpReassemblyMultipleConnStats results2;
	std::string errMsg;

	pcpp::TcpReassemblyConfiguration config1(true, 5, 30);
	// the fourth argument is the max allowed out-of-order fragments, so we only allow 5
	pcpp::TcpReassemblyConfiguration config2(true, 5, 30, 5);
	pcpp::TcpReassembly tcpReassembly1(tcpReassemblyMsgReadyCallback, &results1, tcpReassemblyConnectionStartCallback,
	                                   tcpReassemblyConnectionEndCallback, config1);
	pcpp::TcpReassembly tcpReassembly2(tcpReassemblyMsgReadyCallback, &results2, tcpReassemblyConnectionStartCallback,
	                                   tcpReassemblyConnectionEndCallback, config2);

	std::vector<pcpp::RawPacket> packetStream;
	PTF_ASSERT_TRUE(
	    readPcapIntoPacketVec("PcapExamples/unidirectional_tcp_stream_with_missing_packet.pcap", packetStream, errMsg));

	for (auto iter : packetStream)
	{
		pcpp::Packet packet(&iter);
		tcpReassembly1.reassemblePacket(packet);
		tcpReassembly2.reassemblePacket(packet);
	}

	pcpp::TcpReassembly::ConnectionInfoList managedConnections1 = tcpReassembly1.getConnectionInformation();
	pcpp::TcpReassembly::ConnectionInfoList managedConnections2 =
	    tcpReassembly2.getConnectionInformation();  // make a copy of list
	PTF_ASSERT_EQUAL(managedConnections1.size(), 1);
	PTF_ASSERT_EQUAL(managedConnections2.size(), 1);
	PTF_ASSERT_EQUAL(results1.flowKeysList.size(), 1);
	PTF_ASSERT_EQUAL(results2.flowKeysList.size(), 1);

	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn1 =
	    managedConnections1.find(results1.flowKeysList[0]);
	pcpp::TcpReassembly::ConnectionInfoList::const_iterator iterConn2 =
	    managedConnections2.find(results2.flowKeysList[0]);
	PTF_ASSERT_TRUE(iterConn1 != managedConnections1.end());
	PTF_ASSERT_TRUE(iterConn2 != managedConnections2.end());
	PTF_ASSERT_EQUAL(tcpReassembly1.isConnectionOpen(iterConn1->second), 1);
	PTF_ASSERT_EQUAL(tcpReassembly2.isConnectionOpen(iterConn2->second), 1);
	// The second data packet is incomplete so we stopped at one
	PTF_ASSERT_EQUAL(results1.stats.begin()->second.numOfDataPackets, 1);
	// We hit the fragment limit so skipped the missing fragment and continued to the end
	PTF_ASSERT_EQUAL(results2.stats.begin()->second.numOfDataPackets, 7);

	// Close the connections, forcing cleanup
	tcpReassembly1.closeAllConnections();
	tcpReassembly2.closeAllConnections();

	// Everything should be processed now
	PTF_ASSERT_EQUAL(results1.stats.begin()->second.numOfDataPackets, 7);
	PTF_ASSERT_EQUAL(results2.stats.begin()->second.numOfDataPackets, 7);
}  // TestTcpReassemblyCleanup

PTF_TEST_CASE(TestTcpReassemblyMaxSeq)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream_max_seq.pcap", packetStream, errMsg));

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 19);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[0], 2);
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfMessagesFromSide[1], 2);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEndedManually);
	pcpp::IPv4Address expectedSrcIP(std::string("10.0.0.1"));
	pcpp::IPv4Address expectedDstIP(std::string("81.218.72.15"));
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.srcIP, expectedSrcIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.dstIP, expectedDstIP);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_sec, 1491516383);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.startTime.tv_usec, 915793);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.startTimePrecise.time_since_epoch()).count(), 1491516383915793000);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_sec, 1491516399);
	PTF_ASSERT_EQUAL(stats.begin()->second.connData.endTime.tv_usec, 576245);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats.begin()->second.connData.endTimePrecise.time_since_epoch()).count(), 1491516399576245000);
	// clang-format on

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyMaxSeq

PTF_TEST_CASE(TestTcpReassemblyDisableOOOCleanup)  // TestTcpReassemblyDisableBaseOutOfOrderBufferCleanupCondition
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;
	TcpReassemblyMultipleConnStats results1;
	TcpReassemblyMultipleConnStats results2;
	pcpp::TcpReassemblyConfiguration config1(true, 5, 30, 20, true);
	pcpp::TcpReassemblyConfiguration config2(true, 5, 30, 20, false);
	pcpp::TcpReassembly tcpReassembly1(tcpReassemblyMsgReadyCallback, &results1, tcpReassemblyConnectionStartCallback,
	                                   tcpReassemblyConnectionEndCallback, config1);
	pcpp::TcpReassembly tcpReassembly2(tcpReassemblyMsgReadyCallback, &results2, tcpReassemblyConnectionStartCallback,
	                                   tcpReassemblyConnectionEndCallback, config2);
	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg));

	// unserting a data packet from reverse direction b/w swap 2 consequent data packets
	std::swap(packetStream[12], packetStream[13]);
	std::swap(packetStream[13], packetStream[18]);

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	for (auto iter : packetStream)
	{
		pcpp::Packet packet(&iter);
		tcpReassembly1.reassemblePacket(packet);
		tcpReassembly2.reassemblePacket(packet);
	}

	tcpReassembly1.closeAllConnections();
	tcpReassembly2.closeAllConnections();

	TcpReassemblyMultipleConnStats::Stats& stats1 = results1.stats;
	TcpReassemblyMultipleConnStats::Stats& stats2 = results2.stats;
	PTF_ASSERT_EQUAL(stats1.size(), 1);
	PTF_ASSERT_EQUAL(stats2.size(), 1);
	PTF_ASSERT_EQUAL(stats1.begin()->second.numOfDataPackets, 18);
	PTF_ASSERT_EQUAL(stats2.begin()->second.numOfDataPackets, 19);

	packetStream.clear();
	tcpReassemblyResults.clear();
}  // TestTcpReassemblyDisableOOOCleanup

PTF_TEST_CASE(TestTcpReassemblyTimeStamps)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(
	    readPcapIntoPacketVec("PcapExamples/unidirectional_tcp_stream_with_missing_packet.pcap", packetStream, errMsg));

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.begin()->second.numOfDataPackets, 7);
	std::ifstream expectedOutput("PcapExamples/timestamp_output.txt");
	for (long unsigned int i = 0; i < tcpReassemblyResults.timestamps.size(); i++)
	{
		timeval t = tcpReassemblyResults.timestamps[i];
		std::string expected;
		expectedOutput >> expected;
		const int expUsec = std::stoll(expected) % 1000000;
		const int expSec = std::stoll(expected) / 1000000;
		PTF_ASSERT_EQUAL(t.tv_usec, expUsec);
		PTF_ASSERT_EQUAL(t.tv_sec, expSec);
	}
	expectedOutput.close();
	packetStream.clear();
	tcpReassemblyResults.clear();
}  // TestTcpReassemblyTimeStamps

PTF_TEST_CASE(TestTcpReassemblyFinReset)
{
	std::string errMsg;

	std::vector<pcpp::RawPacket> packetStream;
	PTF_ASSERT_TRUE(
	    readPcapIntoPacketVec("PcapExamples/one_tcp_stream_fin_rst_close_packet.pcap", packetStream, errMsg));

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats.size(), 1);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsStarted);
	PTF_ASSERT_TRUE(stats.begin()->second.connectionsEnded);
	PTF_ASSERT_FALSE(stats.begin()->second.connectionsEndedManually);
}  // TestTcpReassemblyFinReset

PTF_TEST_CASE(TestTcpReassemblyHighPrecision)
{
	std::string errMsg;
	std::vector<pcpp::RawPacket> packetStream;

	PTF_ASSERT_TRUE(readPcapIntoPacketVec("PcapExamples/three_http_streams.pcap", packetStream, errMsg));

	for (auto& packet : packetStream)
	{
		auto timestamp = packet.getPacketTimeStamp();
		timestamp.tv_nsec += 55;
		packet.setPacketTimeStamp(timestamp);
	}

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	auto flowKeys = tcpReassemblyResults.flowKeysList;

	TcpReassemblyMultipleConnStats::Stats& stats = tcpReassemblyResults.stats;
	PTF_ASSERT_EQUAL(stats[flowKeys[2]].numOfDataPackets, 2);
	PTF_ASSERT_EQUAL(stats[flowKeys[2]].connData.startTime.tv_sec, 1361916156);
	PTF_ASSERT_EQUAL(stats[flowKeys[2]].connData.startTime.tv_usec, 716947);
	// clang-format off
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats[flowKeys[2]].connData.startTimePrecise.time_since_epoch()).count(), 1361916156716947055);
	PTF_ASSERT_EQUAL(stats[flowKeys[2]].connData.endTime.tv_sec, 1361916156);
	PTF_ASSERT_EQUAL(stats[flowKeys[2]].connData.endTime.tv_usec, 800214);
	PTF_ASSERT_EQUAL(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(stats[flowKeys[2]].connData.endTimePrecise.time_since_epoch()).count(), 1361916156800214055);
	// clang-format on

	std::string expectedReassemblyData =
	    readFileIntoString(std::string("PcapExamples/three_http_streams_conn_1_output.txt"));
	PTF_ASSERT_EQUAL(expectedReassemblyData, stats.begin()->second.reassembledData);
}  // TestTcpReassemblyHighPrecision
