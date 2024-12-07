#pragma once

#include <unordered_map>

#include <functional>
#include <sstream>
#include "HttpLayer.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "SystemUtils.h"

/**
 * An auxiliary struct for encapsulating rate stats
 */
struct Rate
{
	double currentRate;  // periodic rate
	double totalRate;    // overlal rate

	void clear()
	{
		currentRate = 0;
		totalRate = 0;
	}
};

/**
 * A struct for collecting general HTTP stats
 */
struct HttpGeneralStats
{
	// total number of HTTP flows
	int numOfHttpFlows;
	// rate of HTTP flows
	Rate httpFlowRate;
	// total number of HTTP flows that contains at least on HTTP pipelining transaction
	int numOfHttpPipeliningFlows;
	// total number of HTTP transactions
	int numOfHttpTransactions;
	// rate of HTTP transactions
	Rate httpTransactionsRate;
	// average number of HTTP transactions per flow
	double averageNumOfHttpTransactionsPerFlow;
	// total number of HTTP packets
	int numOfHttpPackets;
	// rate of HTTP packets
	Rate httpPacketRate;
	// average number of HTTP packets per flow
	double averageNumOfPacketsPerFlow;
	// total HTTP traffic in bytes
	int amountOfHttpTraffic;
	// average number of HTTP traffic per flow
	double averageAmountOfDataPerFlow;
	// rate of HTTP traffic
	Rate httpTrafficRate;
	// total stats collection time
	double sampleTime;

	void clear()
	{
		numOfHttpFlows = 0;
		httpFlowRate.clear();
		numOfHttpPipeliningFlows = 0;
		numOfHttpTransactions = 0;
		httpTransactionsRate.clear();
		averageNumOfHttpTransactionsPerFlow = 0;
		numOfHttpPackets = 0;
		httpPacketRate.clear();
		averageNumOfPacketsPerFlow = 0;
		amountOfHttpTraffic = 0;
		averageAmountOfDataPerFlow = 0;
		httpTrafficRate.clear();
		sampleTime = 0;
	}
};

/**
 * A base struct for collecting stats on HTTP messages
 */
struct HttpMessageStats
{
	// total number of HTTP messages of that type (request/response)
	int numOfMessages;
	// rate of HTTP messages of that type
	Rate messageRate;
	// total size (in bytes) of data in headers
	int totalMessageHeaderSize;
	// average header size
	double averageMessageHeaderSize;

	virtual ~HttpMessageStats()
	{}

	virtual void clear()
	{
		numOfMessages = 0;
		messageRate.clear();
		totalMessageHeaderSize = 0;
		averageMessageHeaderSize = 0;
	}
};

/**
 * A struct for collecting stats on all HTTP requests
 */
struct HttpRequestStats : HttpMessageStats
{
	// a map for counting the different HTTP methods seen in traffic
	std::unordered_map<pcpp::HttpRequestLayer::HttpMethod, int, std::hash<int>> methodCount;
	// a map for counting the hostnames seen in traffic
	std::unordered_map<std::string, int> hostnameCount;

	void clear() override
	{
		HttpMessageStats::clear();
		methodCount.clear();
		hostnameCount.clear();
	}
};

/**
 * A struct for collecting stats on all HTTP responses
 */
struct HttpResponseStats : HttpMessageStats
{
	// a map for counting the different status codes seen in traffic
	std::unordered_map<std::string, int> statusCodeCount;
	// a map for counting the content-types seen in traffic
	std::unordered_map<std::string, int> contentTypeCount;
	// total number of responses containing the "content-length" field
	int numOfMessagesWithContentLength;
	// total body size extracted by responses containing "content-length" field
	int totalContentLengthSize;
	// average body size
	double averageContentLengthSize;

	void clear() override
	{
		HttpMessageStats::clear();
		numOfMessagesWithContentLength = 0;
		totalContentLengthSize = 0;
		averageContentLengthSize = 0;
		statusCodeCount.clear();
		contentTypeCount.clear();
	}
};

/**
 * The HTTP stats collector. Should be called for every packet arriving and also periodically to calculate rates
 */
class HttpStatsCollector
{
public:
	/**
	 * C'tor - clear all structures
	 */
	explicit HttpStatsCollector(uint16_t dstPort)
	{
		clear();
		m_DstPort = dstPort;
	}

	/**
	 * Collect stats for a single packet
	 */
	void collectStats(pcpp::Packet* httpPacket)
	{
		// verify packet is TCP
		if (!httpPacket->isPacketOfType(pcpp::TCP))
			return;

		// verify packet is port 80
		pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();
		if (!(tcpLayer->getDstPort() == m_DstPort || tcpLayer->getSrcPort() == m_DstPort))
			return;

		// collect general HTTP traffic stats on this packet
		uint32_t hashVal = collectHttpTrafficStats(httpPacket);

		// if packet is an HTTP request - collect HTTP request stats on this packet
		if (httpPacket->isPacketOfType(pcpp::HTTPRequest))
		{
			pcpp::HttpRequestLayer* req = httpPacket->getLayerOfType<pcpp::HttpRequestLayer>();
			pcpp::TcpLayer* tcpLayer1 = httpPacket->getLayerOfType<pcpp::TcpLayer>();
			collectHttpGeneralStats(tcpLayer1, req, hashVal);
			collectRequestStats(req);
		}
		// if packet is an HTTP response - collect HTTP response stats on this packet
		else if (httpPacket->isPacketOfType(pcpp::HTTPResponse))
		{
			pcpp::HttpResponseLayer* res = httpPacket->getLayerOfType<pcpp::HttpResponseLayer>();
			pcpp::TcpLayer* tcpLayer1 = httpPacket->getLayerOfType<pcpp::TcpLayer>();
			collectHttpGeneralStats(tcpLayer1, res, hashVal);
			collectResponseStats(res);
		}

		// calculate current sample time which is the time-span from start time until current time
		m_GeneralStats.sampleTime = getCurTime() - m_StartTime;
	}

	/**
	 * Calculate rates. Should be called periodically
	 */
	void calcRates()
	{
		// getting current machine time
		double curTime = getCurTime();

		// getting time from last rate calculation until now
		double diffSec = curTime - m_LastCalcRateTime;

		// calculating current rates which are the changes from last rate calculation until now divided by the time
		// passed from last rate calculation until now
		if (diffSec != 0)
		{
			m_GeneralStats.httpTrafficRate.currentRate =
			    (m_GeneralStats.amountOfHttpTraffic - m_PrevGeneralStats.amountOfHttpTraffic) / diffSec;
			m_GeneralStats.httpPacketRate.currentRate =
			    (m_GeneralStats.numOfHttpPackets - m_PrevGeneralStats.numOfHttpPackets) / diffSec;
			m_GeneralStats.httpFlowRate.currentRate =
			    (m_GeneralStats.numOfHttpFlows - m_PrevGeneralStats.numOfHttpFlows) / diffSec;
			m_GeneralStats.httpTransactionsRate.currentRate =
			    (m_GeneralStats.numOfHttpTransactions - m_PrevGeneralStats.numOfHttpTransactions) / diffSec;
			m_RequestStats.messageRate.currentRate =
			    (m_RequestStats.numOfMessages - m_PrevRequestStats.numOfMessages) / diffSec;
			m_ResponseStats.messageRate.currentRate =
			    (m_ResponseStats.numOfMessages - m_PrevResponseStats.numOfMessages) / diffSec;
		}

		// getting the time from the beginning of stats collection until now
		double diffSecTotal = curTime - m_StartTime;

		// calculating total rate which is the change from beginning of stats collection until now divided by time
		// passed from beginning of stats collection until now
		if (diffSecTotal != 0)
		{
			m_GeneralStats.httpTrafficRate.totalRate = m_GeneralStats.amountOfHttpTraffic / diffSecTotal;
			m_GeneralStats.httpPacketRate.totalRate = m_GeneralStats.numOfHttpPackets / diffSecTotal;
			m_GeneralStats.httpFlowRate.totalRate = m_GeneralStats.numOfHttpFlows / diffSecTotal;
			m_GeneralStats.httpTransactionsRate.totalRate = m_GeneralStats.numOfHttpTransactions / diffSecTotal;
			m_RequestStats.messageRate.totalRate = m_RequestStats.numOfMessages / diffSecTotal;
			m_ResponseStats.messageRate.totalRate = m_ResponseStats.numOfMessages / diffSecTotal;
		}

		// saving current numbers for using them in the next rate calculation
		m_PrevGeneralStats = m_GeneralStats;
		m_PrevRequestStats = m_RequestStats;
		m_PrevResponseStats = m_ResponseStats;

		// saving the current time for using in the next rate calculation
		m_LastCalcRateTime = curTime;
	}

	/**
	 * Clear all stats collected so far
	 */
	void clear()
	{
		m_GeneralStats.clear();
		m_PrevGeneralStats.clear();
		m_RequestStats.clear();
		m_PrevRequestStats.clear();
		m_ResponseStats.clear();
		m_PrevResponseStats.clear();
		m_LastCalcRateTime = getCurTime();
		m_StartTime = m_LastCalcRateTime;
	}

	/**
	 * Get HTTP general stats
	 */
	HttpGeneralStats& getGeneralStats()
	{
		return m_GeneralStats;
	}

	/**
	 * Get HTTP request stats
	 */
	HttpRequestStats& getRequestStats()
	{
		return m_RequestStats;
	}

	/**
	 * Get HTTP response stats
	 */
	HttpResponseStats& getResponseStats()
	{
		return m_ResponseStats;
	}

private:
	/**
	 * Auxiliary data collected for each flow for help calculating stats on this flow
	 */
	struct HttpFlowData
	{
		// number of transactions that were started (request has arrived) but weren't closed yet (response hasn't
		// arrived yet)
		int numOfOpenTransactions;
		// the last HTTP message seen on this flow (request, response or neither). Used to identify HTTP pipelining
		pcpp::ProtocolType lastSeenMessage;
		// was HTTP pipelining identified on this flow
		bool httpPipeliningFlow;
		// the current TCP sequence number from client to server. Used to identify TCP re-transmission
		uint32_t curSeqNumberRequests;
		// the current TCP sequence number from server to client. Used to identify TCP re-transmission
		uint32_t curSeqNumberResponses;

		void clear()
		{
			numOfOpenTransactions = 0;
			lastSeenMessage = pcpp::UnknownProtocol;
			httpPipeliningFlow = false;
		}
	};

	/**
	 * Collect stats relevant for every HTTP packet (request, response or any other)
	 * This method calculates and returns the flow key for this packet
	 */
	uint32_t collectHttpTrafficStats(pcpp::Packet* httpPacket)
	{
		pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();

		// count traffic
		m_GeneralStats.amountOfHttpTraffic += tcpLayer->getLayerPayloadSize();

		// count packet num
		m_GeneralStats.numOfHttpPackets++;

		// calculate a hash key for this flow to be used in the flow table
		uint32_t hashVal = pcpp::hash5Tuple(httpPacket);

		// if flow is a new flow (meaning it's not already in the flow table)
		if (m_FlowTable.find(hashVal) == m_FlowTable.end())
		{
			// count this new flow
			m_GeneralStats.numOfHttpFlows++;
			m_FlowTable[hashVal].clear();
		}

		// calculate averages
		if (m_FlowTable.size() != 0)
		{
			m_GeneralStats.averageAmountOfDataPerFlow =
			    static_cast<double>(m_GeneralStats.amountOfHttpTraffic) / static_cast<double>(m_FlowTable.size());
			m_GeneralStats.averageNumOfPacketsPerFlow =
			    static_cast<double>(m_GeneralStats.numOfHttpPackets) / static_cast<double>(m_FlowTable.size());
		}

		return hashVal;
	}

	/**
	 * Collect stats relevant for HTTP messages (requests or responses)
	 */
	void collectHttpGeneralStats(pcpp::TcpLayer* tcpLayer, pcpp::HttpMessage* message, uint32_t flowKey)
	{
		// if num of current opened transaction is negative it means something went completely wrong
		if (m_FlowTable[flowKey].numOfOpenTransactions < 0)
			return;

		if (message->getProtocol() == pcpp::HTTPRequest)
		{
			// if new packet seq number is smaller than previous seen seq number current it means this packet is
			// a re-transmitted packet and should be ignored
			if (m_FlowTable[flowKey].curSeqNumberRequests >=
			    pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber))
				return;

			// a new request - increase num of open transactions
			m_FlowTable[flowKey].numOfOpenTransactions++;

			// if the previous message seen on this flow is HTTP request and if flow is not already marked as HTTP
			// pipelining - mark it as so and increase number of HTTP pipelining flows
			if (!m_FlowTable[flowKey].httpPipeliningFlow && m_FlowTable[flowKey].lastSeenMessage == pcpp::HTTPRequest)
			{
				m_FlowTable[flowKey].httpPipeliningFlow = true;
				m_GeneralStats.numOfHttpPipeliningFlows++;
			}

			// set last seen message on flow as HTTP request
			m_FlowTable[flowKey].lastSeenMessage = pcpp::HTTPRequest;

			// set last seen sequence number
			m_FlowTable[flowKey].curSeqNumberRequests = pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber);
		}
		else if (message->getProtocol() == pcpp::HTTPResponse)
		{
			// if new packet seq number is smaller than previous seen seq number current it means this packet is
			// a re-transmitted packet and should be ignored
			if (m_FlowTable[flowKey].curSeqNumberResponses >=
			    pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber))
				return;

			// a response - decrease num of open transactions
			m_FlowTable[flowKey].numOfOpenTransactions--;

			// if the previous message seen on this flow is HTTP response and if flow is not already marked as HTTP
			// pipelining - mark it as so and increase number of HTTP pipelining flows
			if (!m_FlowTable[flowKey].httpPipeliningFlow && m_FlowTable[flowKey].lastSeenMessage == pcpp::HTTPResponse)
			{
				m_FlowTable[flowKey].httpPipeliningFlow = true;
				m_GeneralStats.numOfHttpPipeliningFlows++;
			}

			// set last seen message on flow as HTTP response
			m_FlowTable[flowKey].lastSeenMessage = pcpp::HTTPResponse;

			if (m_FlowTable[flowKey].numOfOpenTransactions >= 0)
			{
				// a transaction was closed - increase number of complete transactions
				m_GeneralStats.numOfHttpTransactions++;

				// calc average transactions per flow
				if (m_FlowTable.size() != 0)
					m_GeneralStats.averageNumOfHttpTransactionsPerFlow =
					    static_cast<double>(m_GeneralStats.numOfHttpTransactions) /
					    static_cast<double>(m_FlowTable.size());
			}

			// set last seen sequence number
			m_FlowTable[flowKey].curSeqNumberResponses = pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber);
		}
	}

	/**
	 * Collect stats relevant for HTTP request messages
	 */
	void collectRequestStats(pcpp::HttpRequestLayer* req)
	{
		m_RequestStats.numOfMessages++;
		m_RequestStats.totalMessageHeaderSize += req->getHeaderLen();
		if (m_RequestStats.numOfMessages != 0)
			m_RequestStats.averageMessageHeaderSize = static_cast<double>(m_RequestStats.totalMessageHeaderSize) /
			                                          static_cast<double>(m_RequestStats.numOfMessages);

		// extract hostname and add to hostname count map
		pcpp::HeaderField* hostField = req->getFieldByName(PCPP_HTTP_HOST_FIELD);
		if (hostField != nullptr)
			m_RequestStats.hostnameCount[hostField->getFieldValue()]++;

		m_RequestStats.methodCount[req->getFirstLine()->getMethod()]++;
	}

	/**
	 * Collect stats relevant for HTTP response messages
	 */
	void collectResponseStats(pcpp::HttpResponseLayer* res)
	{
		m_ResponseStats.numOfMessages++;
		m_ResponseStats.totalMessageHeaderSize += res->getHeaderLen();
		if (m_ResponseStats.numOfMessages != 0)
			m_ResponseStats.averageMessageHeaderSize = static_cast<double>(m_ResponseStats.totalMessageHeaderSize) /
			                                           static_cast<double>(m_ResponseStats.numOfMessages);

		// extract content-length (if exists)
		pcpp::HeaderField* contentLengthField = res->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
		if (contentLengthField != nullptr)
		{
			m_ResponseStats.numOfMessagesWithContentLength++;
			m_ResponseStats.totalContentLengthSize += atoi(contentLengthField->getFieldValue().c_str());
			if (m_ResponseStats.numOfMessagesWithContentLength != 0)
				m_ResponseStats.averageContentLengthSize =
				    static_cast<double>(m_ResponseStats.totalContentLengthSize) /
				    static_cast<double>(m_ResponseStats.numOfMessagesWithContentLength);
		}

		// extract content-type and add to content-type map
		pcpp::HeaderField* contentTypeField = res->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
		if (contentTypeField != nullptr)
		{
			std::string contentType = contentTypeField->getFieldValue();

			// sometimes content-type contains also the charset it uses.
			// for example: "application/javascript; charset=UTF-8"
			// remove charset as it's not relevant for these stats
			size_t charsetPos = contentType.find(";");
			if (charsetPos != std::string::npos)
				contentType.resize(charsetPos);

			m_ResponseStats.contentTypeCount[contentType]++;
		}

		// collect status code - create one string from status code and status description (for example: 200 OK)
		std::ostringstream stream;
		stream << res->getFirstLine()->getStatusCodeAsInt();
		std::string statusCode = stream.str() + " " + res->getFirstLine()->getStatusCodeString();
		m_ResponseStats.statusCodeCount[statusCode]++;
	}

	double getCurTime(void)
	{
		struct timeval tv;

		gettimeofday(&tv, nullptr);

		return ((static_cast<double>(tv.tv_sec)) + static_cast<double>(tv.tv_usec / 1000000.0));
	}

	HttpGeneralStats m_GeneralStats;
	HttpGeneralStats m_PrevGeneralStats;
	HttpRequestStats m_RequestStats;
	HttpRequestStats m_PrevRequestStats;
	HttpResponseStats m_ResponseStats;
	HttpResponseStats m_PrevResponseStats;

	std::unordered_map<uint32_t, HttpFlowData> m_FlowTable;

	double m_LastCalcRateTime;
	double m_StartTime;
	uint16_t m_DstPort;
};
