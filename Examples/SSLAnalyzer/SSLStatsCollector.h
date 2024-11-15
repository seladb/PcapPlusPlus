#pragma once

#include <unordered_map>
#include <sstream>
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "SSLLayer.h"
#include "SystemUtils.h"

/**
 * An auxiliary struct for encapsulating rate stats
 */
struct Rate
{
	// periodic rate
	double currentRate;
	// overall rate
	double totalRate;
};

/**
 * A struct for collecting general SSL/TLS stats
 */
struct SSLGeneralStats
{
	// total number of SSL flows
	int numOfSSLFlows;
	// rate of SSL flows
	Rate sslFlowRate;
	// total number of SSL packets
	int numOfSSLPackets;
	// rate of SSL packets
	Rate sslPacketRate;
	// average number of SSL packets per flow
	double averageNumOfPacketsPerFlow;
	// total SSL traffic in bytes
	int amountOfSSLTraffic;
	// average number of SSL traffic per flow
	double averageAmountOfDataPerFlow;
	// rate of SSL traffic
	Rate sslTrafficRate;
	// total stats collection time
	double sampleTime;
	// number of flows which handshake was complete
	int numOfHandshakeCompleteFlows;
	// number of flows that were terminated because of SSL/TLS alert
	int numOfFlowsWithAlerts;
	// number of flows per SSL/TLS version
	std::unordered_map<uint16_t, int> sslVersionCount;
	// number of flows per TCP port
	std::unordered_map<uint16_t, int> sslPortCount;

	void clear()
	{
		numOfSSLFlows = 0;
		sslFlowRate.currentRate = 0;
		sslFlowRate.totalRate = 0;
		numOfSSLPackets = 0;
		sslPacketRate.currentRate = 0;
		sslPacketRate.totalRate = 0;
		averageNumOfPacketsPerFlow = 0;
		amountOfSSLTraffic = 0;
		averageAmountOfDataPerFlow = 0;
		sslTrafficRate.currentRate = 0;
		sslTrafficRate.totalRate = 0;
		sampleTime = 0;
		numOfHandshakeCompleteFlows = 0;
		numOfFlowsWithAlerts = 0;
		sslVersionCount.clear();
		sslPortCount.clear();
	}
};

/**
 * A base struct for collecting stats on client-hello messages
 */
struct ClientHelloStats
{
	// total number of client-hello messages
	int numOfMessages;
	// rate of client-hello messages
	Rate messageRate;
	// a map for counting the server names seen in traffic
	std::unordered_map<std::string, int> serverNameCount;

	virtual ~ClientHelloStats()
	{}

	virtual void clear()
	{
		numOfMessages = 0;
		messageRate.currentRate = 0;
		messageRate.totalRate = 0;
		serverNameCount.clear();
	}
};

/**
 * A base struct for collecting stats on server-hello messages
 */
struct ServerHelloStats
{
	// total number of server-hello messages
	int numOfMessages;
	// rate of server-hello messages
	Rate messageRate;
	// count of the different chosen cipher-suites
	std::unordered_map<std::string, int> cipherSuiteCount;

	virtual ~ServerHelloStats()
	{}

	virtual void clear()
	{
		numOfMessages = 0;
		messageRate.currentRate = 0;
		messageRate.totalRate = 0;
		cipherSuiteCount.clear();
	}
};

/**
 * The SSL stats collector. Should be called for every packet arriving and also periodically to calculate rates
 */
class SSLStatsCollector
{
public:
	/**
	 * C'tor - clear all structures
	 */
	SSLStatsCollector()
	{
		clear();
	}

	/**
	 * Collect stats for a single packet
	 */
	void collectStats(pcpp::Packet* sslPacket)
	{
		// verify packet is TCP and SSL/TLS
		if (!sslPacket->isPacketOfType(pcpp::TCP) || !sslPacket->isPacketOfType(pcpp::SSL))
			return;

		// collect general SSL traffic stats on this packet
		uint32_t hashVal = collectSSLTrafficStats(sslPacket);

		// if packet contains one or more SSL messages, collect stats on them
		if (sslPacket->isPacketOfType(pcpp::SSL))
		{
			collectSSLStats(sslPacket, hashVal);
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
			m_GeneralStats.sslTrafficRate.currentRate =
			    (m_GeneralStats.amountOfSSLTraffic - m_PrevGeneralStats.amountOfSSLTraffic) / diffSec;
			m_GeneralStats.sslPacketRate.currentRate =
			    (m_GeneralStats.numOfSSLPackets - m_PrevGeneralStats.numOfSSLPackets) / diffSec;
			m_GeneralStats.sslFlowRate.currentRate =
			    (m_GeneralStats.numOfSSLFlows - m_PrevGeneralStats.numOfSSLFlows) / diffSec;
			m_ClientHelloStats.messageRate.currentRate =
			    (m_ClientHelloStats.numOfMessages - m_PrevClientHelloStats.numOfMessages) / diffSec;
			m_ServerHelloStats.messageRate.currentRate =
			    (m_ServerHelloStats.numOfMessages - m_PrevServerHelloStats.numOfMessages) / diffSec;
		}

		// getting the time from the beginning of stats collection until now
		double diffSecTotal = curTime - m_StartTime;

		// calculating total rate which is the change from beginning of stats collection until now divided by time
		// passed from beginning of stats collection until now
		if (diffSecTotal != 0)
		{
			m_GeneralStats.sslTrafficRate.totalRate = m_GeneralStats.amountOfSSLTraffic / diffSecTotal;
			m_GeneralStats.sslPacketRate.totalRate = m_GeneralStats.numOfSSLPackets / diffSecTotal;
			m_GeneralStats.sslFlowRate.totalRate = m_GeneralStats.numOfSSLFlows / diffSecTotal;
			m_ClientHelloStats.messageRate.totalRate = m_ClientHelloStats.numOfMessages / diffSecTotal;
			m_ServerHelloStats.messageRate.totalRate = m_ServerHelloStats.numOfMessages / diffSecTotal;
		}

		// saving current numbers for using them in the next rate calculation
		m_PrevGeneralStats = m_GeneralStats;
		m_PrevClientHelloStats = m_ClientHelloStats;
		m_PrevServerHelloStats = m_ServerHelloStats;

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
		m_ClientHelloStats.clear();
		m_PrevClientHelloStats.clear();
		m_ServerHelloStats.clear();
		m_PrevServerHelloStats.clear();
		m_LastCalcRateTime = getCurTime();
		m_StartTime = m_LastCalcRateTime;
	}

	/**
	 * Get SSL general stats
	 */
	SSLGeneralStats& getGeneralStats()
	{
		return m_GeneralStats;
	}

	/**
	 * Get client-hello stats
	 */
	ClientHelloStats& getClientHelloStats()
	{
		return m_ClientHelloStats;
	}

	/**
	 * Get server-hello stats
	 */
	ServerHelloStats& getServerHelloStats()
	{
		return m_ServerHelloStats;
	}

private:
	/**
	 * Auxiliary data collected for each flow for help calculating stats on this flow
	 */
	struct SSLFlowData
	{
		// was SSL application data seen in this flow
		bool seenAppDataPacket;
		// was SSL alert packet seen in this flow
		bool seenAlertPacket;

		void clear()
		{
			seenAppDataPacket = false;
			seenAlertPacket = false;
		}
	};

	/**
	 * Collect stats relevant for every SSL packet (any SSL message)
	 * This method calculates and returns the flow key for this packet
	 */
	uint32_t collectSSLTrafficStats(pcpp::Packet* sslpPacket)
	{
		pcpp::TcpLayer* tcpLayer = sslpPacket->getLayerOfType<pcpp::TcpLayer>();

		// count traffic
		m_GeneralStats.amountOfSSLTraffic += tcpLayer->getLayerPayloadSize();

		// count packet num
		m_GeneralStats.numOfSSLPackets++;

		// calculate a hash key for this flow to be used in the flow table
		uint32_t hashVal = hash5Tuple(sslpPacket);

		// if flow is a new flow (meaning it's not already in the flow table)
		if (m_FlowTable.find(hashVal) == m_FlowTable.end())
		{
			// count this new flow
			m_GeneralStats.numOfSSLFlows++;

			// find the SSL/TLS port and add it to the port count
			uint16_t srcPort = tcpLayer->getSrcPort();
			uint16_t dstPort = tcpLayer->getDstPort();
			if (pcpp::SSLLayer::isSSLPort(srcPort))
				m_GeneralStats.sslPortCount[srcPort]++;
			else
				m_GeneralStats.sslPortCount[dstPort]++;

			m_FlowTable[hashVal].clear();
		}

		// calculate averages
		if (m_FlowTable.size() != 0)
		{
			m_GeneralStats.averageAmountOfDataPerFlow =
			    static_cast<double>(m_GeneralStats.amountOfSSLTraffic) / static_cast<double>(m_FlowTable.size());
			m_GeneralStats.averageNumOfPacketsPerFlow =
			    static_cast<double>(m_GeneralStats.numOfSSLPackets) / static_cast<double>(m_FlowTable.size());
		}

		return hashVal;
	}

	/**
	 * Collect stats relevant for several kinds SSL messages
	 */
	void collectSSLStats(pcpp::Packet* sslPacket, uint32_t flowKey)
	{
		// go over all SSL messages in this packet
		pcpp::SSLLayer* sslLayer = sslPacket->getLayerOfType<pcpp::SSLLayer>();
		while (sslLayer != nullptr)
		{
			// check if the layer is an alert message
			pcpp::SSLRecordType recType = sslLayer->getRecordType();
			if (recType == pcpp::SSL_ALERT)
			{
				// if it's the first alert seen in this flow
				if (m_FlowTable[flowKey].seenAlertPacket == false)
				{
					m_GeneralStats.numOfFlowsWithAlerts++;
					m_FlowTable[flowKey].seenAlertPacket = true;
				}
			}

			// check if the layer is an app data message
			else if (recType == pcpp::SSL_APPLICATION_DATA)
			{
				// if it's the first app data message seen on this flow it means handshake was completed
				if (m_FlowTable[flowKey].seenAppDataPacket == false)
				{
					m_GeneralStats.numOfHandshakeCompleteFlows++;
					m_FlowTable[flowKey].seenAppDataPacket = true;
				}
			}

			// check if the layer is an handshake message
			else if (recType == pcpp::SSL_HANDSHAKE)
			{
				pcpp::SSLHandshakeLayer* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(sslLayer);
				if (handshakeLayer == nullptr)
					continue;

				// try to find client-hello message
				pcpp::SSLClientHelloMessage* clientHelloMessage =
				    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();

				// collect client-hello stats
				if (clientHelloMessage != nullptr)
				{
					collecClientHelloStats(clientHelloMessage);
				}

				// try to find server-hello message
				pcpp::SSLServerHelloMessage* serverHelloMessage =
				    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();

				// collect server-hello stats
				if (serverHelloMessage != nullptr)
				{
					m_GeneralStats.sslVersionCount[serverHelloMessage->getHandshakeVersion().asUInt()]++;
					collecServerHelloStats(serverHelloMessage);
				}
			}

			sslLayer = sslPacket->getNextLayerOfType<pcpp::SSLLayer>(sslLayer);
		}
	}

	/**
	 * Collect stats relevant only to client-hello messages
	 */
	void collecClientHelloStats(pcpp::SSLClientHelloMessage* clientHelloMessage)
	{
		m_ClientHelloStats.numOfMessages++;

		pcpp::SSLServerNameIndicationExtension* sniExt =
		    clientHelloMessage->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
		if (sniExt != nullptr)
			m_ClientHelloStats.serverNameCount[sniExt->getHostName()]++;
	}

	/**
	 * Collect stats relevant only to server-hello messages
	 */
	void collecServerHelloStats(pcpp::SSLServerHelloMessage* serverHelloMessage)
	{
		m_ServerHelloStats.numOfMessages++;

		pcpp::SSLCipherSuite* cipherSuite = serverHelloMessage->getCipherSuite();
		if (cipherSuite != nullptr)
			m_ServerHelloStats.cipherSuiteCount[cipherSuite->asString()]++;
	}

	double getCurTime(void)
	{
		struct timeval tv;

		gettimeofday(&tv, nullptr);

		return ((static_cast<double>(tv.tv_sec)) + static_cast<double>(tv.tv_usec / 1000000.0));
	}

	SSLGeneralStats m_GeneralStats;
	SSLGeneralStats m_PrevGeneralStats;
	ClientHelloStats m_ClientHelloStats;
	ClientHelloStats m_PrevClientHelloStats;
	ServerHelloStats m_ServerHelloStats;
	ServerHelloStats m_PrevServerHelloStats;

	std::unordered_map<uint32_t, SSLFlowData> m_FlowTable;

	double m_LastCalcRateTime;
	double m_StartTime;
};
