#pragma once

#include <map>
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
	double currentRate; // periodic rate
	double totalRate;	 // overlal rate
};

/**
 * A struct for collecting general HTTP stats
 */
struct HttpGeneralStats
{
	int numOfHttpFlows; // total number of HTTP flows
	Rate httpFlowRate; // rate of HTTP flows
	int numOfHttpPipeliningFlows; // total number of HTTP flows that contains at least on HTTP pipelining transaction
	int numOfHttpTransactions; // total number of HTTP transactions
	Rate httpTransactionsRate; // rate of HTTP transactions
	double averageNumOfHttpTransactionsPerFlow; // average number of HTTP transactions per flow
	int numOfHttpPackets; // total number of HTTP packets
	Rate httpPacketRate; // rate of HTTP packets
	double averageNumOfPacketsPerFlow; // average number of HTTP packets per flow
	int amountOfHttpTraffic; // total HTTP traffic in bytes
	double averageAmountOfDataPerFlow; // average number of HTTP traffic per flow
	Rate httpTrafficRate; // rate of HTTP traffic
	double sampleTime; // total stats collection time

	void clear()
	{
		memset(this, 0, sizeof(HttpGeneralStats));
	}
};


/**
 * A base struct for collecting stats on HTTP messages
 */
struct HttpMessageStats
{
	int numOfMessages; // total number of HTTP messages of that type (request/response)
	Rate messageRate; // rate of HTTP messages of that type
	int totalMessageHeaderSize; // total size (in bytes) of data in headers
	double averageMessageHeaderSize; // average header size

	virtual ~HttpMessageStats() {}

	virtual void clear()
	{
		memset(this, 0, sizeof(HttpMessageStats));
	}
};


/**
 * A struct for collecting stats on all HTTP requests
 */
struct HttpRequestStats : HttpMessageStats
{
	std::map<pcpp::HttpRequestLayer::HttpMethod, int> methodCount; // a map for counting the different HTTP methods seen in traffic
	std::map<std::string, int> hostnameCount; // a map for counting the hostnames seen in traffic

	void clear()
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
	std::map<std::string, int> statusCodeCount; // a map for counting the different status codes seen in traffic
	std::map<std::string, int> contentTypeCount; // a map for counting the content-types seen in traffic
	int numOfMessagesWithContentLength; // total number of responses containing the "content-length" field
	int totalConentLengthSize; // total body size extracted by responses containing "content-length" field
	double averageContentLengthSize; // average body size

	void clear()
	{
		HttpMessageStats::clear();
		numOfMessagesWithContentLength = 0;
		totalConentLengthSize = 0;
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
	HttpStatsCollector()
	{
		clear();
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
		if (!(tcpLayer->getTcpHeader()->portDst == htons(80) || tcpLayer->getTcpHeader()->portSrc == htons(80)))
			return;

		// collect general HTTP traffic stats on this packet
		uint32_t hashVal = collectHttpTrafficStats(httpPacket);

		// if packet is an HTTP request - collect HTTP request stats on this packet
		if (httpPacket->isPacketOfType(pcpp::HTTPRequest))
		{
			pcpp::HttpRequestLayer* req = httpPacket->getLayerOfType<pcpp::HttpRequestLayer>();
			pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();
			collectHttpGeneralStats(tcpLayer, req, hashVal);
			collectRequestStats(req);
		}
		// if packet is an HTTP response - collect HTTP response stats on this packet
		else if (httpPacket->isPacketOfType(pcpp::HTTPResponse))
		{
			pcpp::HttpResponseLayer* res = httpPacket->getLayerOfType<pcpp::HttpResponseLayer>();
			pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();
			collectHttpGeneralStats(tcpLayer, res, hashVal);
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

		// calculating current rates which are the changes from last rate calculation until now divided by the time passed from
		// last rate calculation until now
		if (diffSec != 0)
		{
			m_GeneralStats.httpTrafficRate.currentRate = (m_GeneralStats.amountOfHttpTraffic - m_PrevGeneralStats.amountOfHttpTraffic) / diffSec;
			m_GeneralStats.httpPacketRate.currentRate = (m_GeneralStats.numOfHttpPackets - m_PrevGeneralStats.numOfHttpPackets) / diffSec;
			m_GeneralStats.httpFlowRate.currentRate = (m_GeneralStats.numOfHttpFlows - m_PrevGeneralStats.numOfHttpFlows) / diffSec;
			m_GeneralStats.httpTransactionsRate.currentRate = (m_GeneralStats.numOfHttpTransactions - m_PrevGeneralStats.numOfHttpTransactions) / diffSec;
			m_RequestStats.messageRate.currentRate = (m_RequestStats.numOfMessages - m_PrevRequestStats.numOfMessages) / diffSec;
			m_ResponseStats.messageRate.currentRate = (m_ResponseStats.numOfMessages - m_PrevResponseStats.numOfMessages) / diffSec;
		}

		// getting the time from the beginning of stats collection until now
		double diffSecTotal = curTime - m_StartTime;

		// calculating total rate which is the change from beginning of stats collection until now divided by time passed from
		// beginning of stats collection until now
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
	HttpGeneralStats& getGeneralStats() { return m_GeneralStats; }

	/**
	 * Get HTTP request stats
	 */
	HttpRequestStats& getRequestStats() { return m_RequestStats; }

	/**
	 * Get HTTP response stats
	 */
	HttpResponseStats& getResponseStats() { return m_ResponseStats; }

private:

	/**
	 * Auxiliary data collected for each flow for help calculating stats on this flow
	 */
	struct HttpFlowData
	{
		int numOfOpenTransactions; // number of transactions that were started (request has arrived) but weren't closed yet (response hasn't arrived yet)
		pcpp::ProtocolType lastSeenMessage; // the last HTTP message seen on this flow (request, response or neither). Used to identify HTTP pipelining
		bool httpPipeliningFlow; // was HTTP pipelining identified on this flow
		uint32_t curSeqNumberRequests; // the current TCP sequence number from client to server. Used to identify TCP re-transmission
		uint32_t curSeqNumberResponses; // the current TCP sequence number from server to client. Used to identify TCP re-transmission

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
			m_GeneralStats.averageAmountOfDataPerFlow = (double)m_GeneralStats.amountOfHttpTraffic / (double)m_FlowTable.size();
			m_GeneralStats.averageNumOfPacketsPerFlow = (double)m_GeneralStats.numOfHttpPackets / (double)m_FlowTable.size();
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
			if (m_FlowTable[flowKey].curSeqNumberRequests >= ntohl(tcpLayer->getTcpHeader()->sequenceNumber))
				return;

			// a new request - increase num of open transactions
			m_FlowTable[flowKey].numOfOpenTransactions++;

			// if the previous message seen on this flow is HTTP request and if flow is not already marked as HTTP pipelining -
			// mark it as so and increase number of HTTP pipelining flows
			if (!m_FlowTable[flowKey].httpPipeliningFlow && m_FlowTable[flowKey].lastSeenMessage == pcpp::HTTPRequest)
			{
				m_FlowTable[flowKey].httpPipeliningFlow = true;
				m_GeneralStats.numOfHttpPipeliningFlows++;
			}

			// set last seen message on flow as HTTP request
			m_FlowTable[flowKey].lastSeenMessage = pcpp::HTTPRequest;

			// set last seen sequence number
			m_FlowTable[flowKey].curSeqNumberRequests = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
		}
		else if (message->getProtocol() == pcpp::HTTPResponse)
		{
			// if new packet seq number is smaller than previous seen seq number current it means this packet is
			// a re-transmitted packet and should be ignored
			if (m_FlowTable[flowKey].curSeqNumberResponses >= ntohl(tcpLayer->getTcpHeader()->sequenceNumber))
				return;

			// a response - decrease num of open transactions
			m_FlowTable[flowKey].numOfOpenTransactions--;

			// if the previous message seen on this flow is HTTP response and if flow is not already marked as HTTP pipelining -
			// mark it as so and increase number of HTTP pipelining flows
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
					m_GeneralStats.averageNumOfHttpTransactionsPerFlow = (double)m_GeneralStats.numOfHttpTransactions / (double)m_FlowTable.size();
			}

			// set last seen sequence number
			m_FlowTable[flowKey].curSeqNumberResponses = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
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
			m_RequestStats.averageMessageHeaderSize = (double)m_RequestStats.totalMessageHeaderSize / (double)m_RequestStats.numOfMessages;

		// extract hostname and add to hostname count map
		pcpp::HeaderField* hostField = req->getFieldByName(PCPP_HTTP_HOST_FIELD);
		if (hostField != NULL)
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
			m_ResponseStats.averageMessageHeaderSize = (double)m_ResponseStats.totalMessageHeaderSize / (double)m_ResponseStats.numOfMessages;

		// extract content-length (if exists)
		pcpp::HeaderField* contentLengthField = res->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
		if (contentLengthField != NULL)
		{
			m_ResponseStats.numOfMessagesWithContentLength++;
			m_ResponseStats.totalConentLengthSize += atoi(contentLengthField->getFieldValue().c_str());
			if (m_ResponseStats.numOfMessagesWithContentLength != 0)
				m_ResponseStats.averageContentLengthSize = (double)m_ResponseStats.totalConentLengthSize / (double)m_ResponseStats.numOfMessagesWithContentLength;
		}

		// extract content-type and add to content-type map
		pcpp::HeaderField* contentTypeField = res->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
		if (contentTypeField != NULL)
		{
			std::string contentType = contentTypeField->getFieldValue();

			// sometimes content-type contains also the charset it uses.
			// for example: "application/javascript; charset=UTF-8"
			// remove charset as it's not relevant for these stats
			size_t charsetPos = contentType.find(";");
			if (charsetPos != std::string::npos)
				contentType = contentType.substr(0, charsetPos);

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

	    gettimeofday(&tv, NULL);

	    return (((double) tv.tv_sec) + (double) (tv.tv_usec / 1000000.0));
	}

	HttpGeneralStats m_GeneralStats;
	HttpGeneralStats m_PrevGeneralStats;
	HttpRequestStats m_RequestStats;
	HttpRequestStats m_PrevRequestStats;
	HttpResponseStats m_ResponseStats;
	HttpResponseStats m_PrevResponseStats;

	std::map<uint32_t, HttpFlowData> m_FlowTable;

	double m_LastCalcRateTime;
	double m_StartTime;
};
