#pragma once

#include "PcapFileDevice.h"
#include "SSLLayer.h"
#include "TcpReassembly.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include <iostream>
#include <vector>
#include <unordered_map>

#if defined(_WIN32)
#	define DIR_SEPARATOR '\\'
#else
#	define DIR_SEPARATOR '/'
#endif

class PcapExtract
{
public:
	PcapExtract(const std::string& pcapFileName, const std::string& outputDirectory, const std::string& format,
	            bool showStats)
	    : m_PcapFileName(pcapFileName), m_OutputDirectory(outputDirectory), m_Format(format), m_ShowStats(showStats)
	{
		if (format != "PEM" && format != "DER")
		{
			throw std::invalid_argument("Unsupported format: " + format);
		}

		if (!outputDirectory.empty() && !pcpp::directoryExists(outputDirectory))
		{
			throw std::invalid_argument("Output directory '" + outputDirectory + "' does not exist");
		}
	}

	void run()
	{
		if (m_RanOnce)
		{
			throw std::runtime_error("Task already ran");
		}

		std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(m_PcapFileName));

		if (!reader->open())
		{
			throw std::runtime_error("Error opening pcap file");
		}

		pcpp::TcpReassembly tcpReassembly(onMessageReady, this, nullptr, onConnectionEnd);

		m_RanOnce = true;
		pcpp::RawPacketVector rawPackets;
		while (reader->getNextPackets(rawPackets, 20) > 0)
		{
			for (auto& rawPacket : rawPackets)
			{
				tcpReassembly.reassemblePacket(rawPacket);
			}
			rawPackets.clear();
		}

		if (m_ShowStats)
		{
			std::cout << "Packet count:                " << m_Stats.packets << std::endl
			          << "TLS packets:                 " << m_Stats.sslPackets << std::endl
			          << "TLS Flows:                   " << m_Stats.sslFlows << std::endl
			          << "TLS handshake messages:      " << m_Stats.sslHandshakeMessages << std::endl
			          << "Certificates parsed:         " << m_Stats.parsedCertificates << std::endl
			          << "Certificates failed parsing: " << m_Stats.failedParsingCertificates << std::endl
			          << "Incomplete Certificates:     " << m_Stats.failedIncompleteCertificates << std::endl;
		}
	}

private:
	struct SSLConnectionData
	{
		int8_t curSide = -1;
		std::vector<uint8_t> data;
		bool canIgnoreFlow = false;

		explicit SSLConnectionData(int8_t side) : curSide(side)
		{}
	};

	using SSLConnectionManager = std::unordered_map<uint32_t, SSLConnectionData>;

	struct SSLPcapStats
	{
		uint64_t packets = 0;
		uint64_t sslPackets = 0;
		uint64_t sslHandshakeMessages = 0;
		uint64_t sslFlows = 0;
		uint64_t parsedCertificates = 0;
		uint64_t failedIncompleteCertificates = 0;
		uint64_t failedParsingCertificates = 0;
	};

	std::string m_PcapFileName;
	std::string m_OutputDirectory;
	std::string m_Format;
	bool m_ShowStats;
	SSLConnectionManager m_ConnectionManager;
	SSLPcapStats m_Stats;
	bool m_RanOnce = false;

	static void onMessageReady(int8_t side, const pcpp::TcpStreamData& tcpData, void* userCookie)
	{
		auto* thisInstance = static_cast<PcapExtract*>(userCookie);
		thisInstance->m_Stats.packets++;

		if (!(pcpp::SSLLayer::isSSLPort(tcpData.getConnectionData().srcPort) ||
		      pcpp::SSLLayer::isSSLPort(tcpData.getConnectionData().dstPort)))
		{
			return;
		}

		thisInstance->m_Stats.sslPackets++;
		auto flow = thisInstance->m_ConnectionManager.find(tcpData.getConnectionData().flowKey);
		if (flow == thisInstance->m_ConnectionManager.end())
		{
			thisInstance->m_Stats.sslFlows++;
			thisInstance->m_ConnectionManager.insert(
			    std::make_pair(tcpData.getConnectionData().flowKey, SSLConnectionData(side)));
			flow = thisInstance->m_ConnectionManager.find(tcpData.getConnectionData().flowKey);
		}

		if (flow->second.canIgnoreFlow)
		{
			return;
		}

		if (flow->second.curSide == side)
		{
			flow->second.data.insert(flow->second.data.end(), tcpData.getData(),
			                         tcpData.getData() + tcpData.getDataLength());
			return;
		}

		if (flow->second.data.empty())
		{
			return;
		}

		size_t const dataSize = flow->second.data.size();
		auto* data = new uint8_t[dataSize];
		std::memcpy(data, flow->second.data.data(), dataSize);

		flow->second.curSide = side;
		flow->second.data.clear();
		flow->second.data.insert(flow->second.data.end(), tcpData.getData(),
		                         tcpData.getData() + tcpData.getDataLength());

		auto sslMessage =
		    std::unique_ptr<pcpp::SSLLayer>(pcpp::SSLLayer::createSSLMessage(data, dataSize, nullptr, nullptr));
		if (sslMessage != nullptr)
		{
			thisInstance->handleSSLMessage(sslMessage.get(), &flow->second);
		}
	};

	static void onConnectionEnd(const pcpp::ConnectionData& connectionData,
	                            pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
	{
		auto* thisInstance = static_cast<PcapExtract*>(userCookie);
		auto flow = thisInstance->m_ConnectionManager.find(connectionData.flowKey);
		if (flow != thisInstance->m_ConnectionManager.end())
		{
			thisInstance->m_ConnectionManager.erase(flow);
		}
	}

	void handleSSLMessage(pcpp::SSLLayer* sslMessage, SSLConnectionData* sslConnectionData)
	{
		while (sslMessage != nullptr)
		{
			auto* applicationDataLayer = dynamic_cast<pcpp::SSLApplicationDataLayer*>(sslMessage);
			if (applicationDataLayer != nullptr)
			{
				sslConnectionData->data.clear();
				sslConnectionData->canIgnoreFlow = true;
				return;
			}

			auto* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(sslMessage);
			if (handshakeLayer == nullptr)
			{
				sslMessage->parseNextLayer();
				sslMessage = dynamic_cast<pcpp::SSLLayer*>(sslMessage->getNextLayer());
				continue;
			}

			m_Stats.sslHandshakeMessages++;

			auto* certMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLCertificateMessage>();
			while (certMessage != nullptr)
			{
				handleSSLCertificateMessage(certMessage);
				certMessage = handshakeLayer->getNextHandshakeMessageOfType<pcpp::SSLCertificateMessage>(certMessage);
			}

			sslMessage->parseNextLayer();
			sslMessage = dynamic_cast<pcpp::SSLLayer*>(sslMessage->getNextLayer());
		}
	}

	void handleSSLCertificateMessage(const pcpp::SSLCertificateMessage* sslCertificateMessage)
	{
		for (int i = 0; i < sslCertificateMessage->getNumOfCertificates(); i++)
		{
			try
			{
				auto x509Cert = sslCertificateMessage->getCertificate(i)->getX509Certificate();
				if (x509Cert != nullptr)
				{
					handleX509Certificate(x509Cert);
				}
				else
				{
					m_Stats.failedIncompleteCertificates++;
				}
			}
			catch (...)
			{
				m_Stats.failedParsingCertificates++;
			}
		}
	}

	void handleX509Certificate(const std::unique_ptr<pcpp::X509Certificate>& x509Cert)
	{
		if (m_Format == "PEM")
		{
			handlePEM(x509Cert);
		}
		else if (m_Format == "DER")
		{
			handleDER(x509Cert);
		}
		else
		{
			throw std::invalid_argument("Unsupported format: " + m_Format);
		}

		m_Stats.parsedCertificates++;
	}

	void handlePEM(const std::unique_ptr<pcpp::X509Certificate>& x509Cert)
	{
		auto pem = x509Cert->toPEM();
		if (m_OutputDirectory.empty())
		{
			std::cout << pem << std::endl;
		}
		else
		{
			std::string const outputFileName =
			    m_OutputDirectory + DIR_SEPARATOR + std::to_string(m_Stats.parsedCertificates + 1) + ".pem";
			std::ofstream pemFile(outputFileName);
			if (!pemFile.is_open())
			{
				throw std::runtime_error("Unable to open file " + outputFileName);
			}
			pemFile << pem;
			pemFile.close();
		}
	}

	void handleDER(const std::unique_ptr<pcpp::X509Certificate>& x509Cert)
	{
		auto der = x509Cert->toDER();
		if (m_OutputDirectory.empty())
		{
			std::cout << pcpp::Base64::encode(der) << std::endl;
		}
		else
		{
			std::string const outputFileName =
			    m_OutputDirectory + DIR_SEPARATOR + std::to_string(m_Stats.parsedCertificates + 1) + ".der";
			std::ofstream derFile(outputFileName);
			if (!derFile.is_open())
			{
				throw std::runtime_error("Unable to open file " + outputFileName);
			}
			derFile.write(reinterpret_cast<const char*>(der.data()), der.size());
			derFile.close();
		}
	}
};
