#pragma once

#include "PcapFileDevice.h"
#include "SSLLayer.h"
#include "TcpReassembly.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include "Logger.h"
#include <iostream>
#include <vector>
#include <unordered_map>

constexpr char getOsPathSeparator()
{
#ifdef _WIN32
	return '\\';
#else
	return '/';
#endif
}

/// Extracts X.509 certificates from PCAP/PCAPNG files by analyzing SSL/TLS traffic.
class PcapExtract
{
public:
	/// Creates a new extractor for the given PCAP file and output configuration.
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

	/// Processes the PCAP file, extracts certificates, and writes them to the output.
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
		pcpp::Logger::getInstance().suppressLogs();
		while (reader->getNextPackets(rawPackets, 20) > 0)
		{
			m_Stats.packets += rawPackets.size();
			for (auto& rawPacket : rawPackets)
			{
				tcpReassembly.reassemblePacket(rawPacket);
			}
			rawPackets.clear();
		}
		pcpp::Logger::getInstance().enableLogs();

		if (m_ShowStats)
		{
			std::cout << "Packet count:                " << m_Stats.packets << std::endl
			          << "TLS messages:                " << m_Stats.sslMessages << std::endl
			          << "TLS Flows:                   " << m_Stats.sslFlows << std::endl
			          << "TLS handshake messages:      " << m_Stats.sslHandshakeMessages << std::endl
			          << "Certificates parsed:         " << m_Stats.parsedCertificates << std::endl
			          << "Certificates failed parsing: " << m_Stats.failedParsingCertificates << std::endl
			          << "Incomplete Certificates:     " << m_Stats.failedIncompleteCertificates << std::endl;
		}
	}

private:
	/// Data associated with a single SSL/TLS connection
	struct SSLConnectionData
	{
		int8_t curSide = -1;
		std::vector<uint8_t> data;
		bool canIgnoreFlow = false;

		explicit SSLConnectionData(int8_t side) : curSide(side)
		{}
	};

	using SSLConnectionManager = std::unordered_map<uint32_t, SSLConnectionData>;

	/// Tracks statistics about the PCAP processing
	struct SSLPcapStats
	{
		uint64_t packets = 0;
		uint64_t sslMessages = 0;
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

	/// Callback for when a complete TCP message is ready for processing
	static void onMessageReady(int8_t side, const pcpp::TcpStreamData& tcpData, void* userCookie)
	{
		auto* thisInstance = static_cast<PcapExtract*>(userCookie);

		// Skip non-SSL traffic
		if (!(pcpp::SSLLayer::isSSLPort(tcpData.getConnectionData().srcPort) ||
		      pcpp::SSLLayer::isSSLPort(tcpData.getConnectionData().dstPort)))
		{
			return;
		}

		thisInstance->m_Stats.sslMessages++;

		// Find or create connection state for this flow
		auto flow = thisInstance->m_ConnectionManager.find(tcpData.getConnectionData().flowKey);
		if (flow == thisInstance->m_ConnectionManager.end())
		{
			thisInstance->m_Stats.sslFlows++;
			thisInstance->m_ConnectionManager.insert(
			    std::make_pair(tcpData.getConnectionData().flowKey, SSLConnectionData(side)));
			flow = thisInstance->m_ConnectionManager.find(tcpData.getConnectionData().flowKey);
		}

		// Skip if we're already ignoring this flow
		if (flow->second.canIgnoreFlow)
		{
			return;
		}

		// If this is a continuation from the same side, accumulate the data
		if (flow->second.curSide == side && !tcpData.isBytesMissing())
		{
			flow->second.data.insert(flow->second.data.end(), tcpData.getData(),
			                         tcpData.getData() + tcpData.getDataLength());
			return;
		}

		// If we have no accumulated data, return
		if (flow->second.data.empty())
		{
			return;
		}

		// Process the accumulated data as a complete SSL message
		size_t const dataSize = flow->second.data.size();
		auto* data = new uint8_t[dataSize];
		std::memcpy(data, flow->second.data.data(), dataSize);

		// Update connection state with new data
		flow->second.curSide = side;
		flow->second.data.clear();
		flow->second.data.insert(flow->second.data.end(), tcpData.getData(),
		                         tcpData.getData() + tcpData.getDataLength());

		// We have all the data for this SSL message. Parse and handle the message
		auto sslMessage =
		    std::unique_ptr<pcpp::SSLLayer>(pcpp::SSLLayer::createSSLMessage(data, dataSize, nullptr, nullptr));
		if (sslMessage != nullptr)
		{
			thisInstance->handleSSLMessage(sslMessage.get(), &flow->second);
		}
	};

	/// Callback for when a TCP connection ends
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

	/// Handles an SSL/TLS message and extracts certificates if present
	void handleSSLMessage(pcpp::SSLLayer* sslMessage, SSLConnectionData* sslConnectionData)
	{
		// Iterate over all the SSL/TLS layers in the message
		while (sslMessage != nullptr)
		{
			auto* applicationDataLayer = dynamic_cast<pcpp::SSLApplicationDataLayer*>(sslMessage);
			if (applicationDataLayer != nullptr)
			{
				sslConnectionData->data.clear();
				sslConnectionData->canIgnoreFlow = true;
				return;
			}

			// Ignore non-handshake messages
			auto* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(sslMessage);
			if (handshakeLayer == nullptr)
			{
				sslMessage->parseNextLayer();
				sslMessage = dynamic_cast<pcpp::SSLLayer*>(sslMessage->getNextLayer());
				continue;
			}

			m_Stats.sslHandshakeMessages++;

			// Iterate over all certificate messages
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

	/// Handles an SSL/TLS certificate message
	void handleSSLCertificateMessage(const pcpp::SSLCertificateMessage* sslCertificateMessage)
	{
		// Iterate over all certificates in this message
		for (int i = 0; i < sslCertificateMessage->getNumOfCertificates(); i++)
		{
			try
			{
				// Parse the certificate
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

	/// Handles an X.509 certificate
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

	/// Stores the certificate in PEM format, either to stdout or to a file
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
			    m_OutputDirectory + getOsPathSeparator() + std::to_string(m_Stats.parsedCertificates + 1) + ".pem";
			std::ofstream pemFile(outputFileName);
			if (!pemFile.is_open())
			{
				throw std::runtime_error("Unable to open file " + outputFileName);
			}
			pemFile << pem;
			pemFile.close();
		}
	}

	/// Stores the certificate in DER format, either to stdout or to a file
	void handleDER(const std::unique_ptr<pcpp::X509Certificate>& x509Cert)
	{
		auto der = x509Cert->toDER();
		if (m_OutputDirectory.empty())
		{
			std::cout << pcpp::Base64::encode(der) << std::endl << "==============" << std::endl;
		}
		else
		{
			std::string const outputFileName =
			    m_OutputDirectory + getOsPathSeparator() + std::to_string(m_Stats.parsedCertificates + 1) + ".der";
			std::ofstream derFile(outputFileName, std::ios::binary);
			if (!derFile.is_open())
			{
				throw std::runtime_error("Unable to open file " + outputFileName);
			}
			derFile.write(reinterpret_cast<const char*>(der.data()), der.size());
			derFile.close();
		}
	}
};
