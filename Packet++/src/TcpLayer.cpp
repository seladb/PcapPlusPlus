#define LOG_MODULE PacketLogModuleTcpLayer

#include "EndianPortable.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "SipLayer.h"
#include "BgpLayer.h"
#include "SSHLayer.h"
#include "DnsLayer.h"
#include "TelnetLayer.h"
#include "TpktLayer.h"
#include "FtpLayer.h"
#include "SomeIpLayer.h"
#include "SmtpLayer.h"
#include "LdapLayer.h"
#include "GtpLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include "DeprecationUtils.h"
#include <sstream>

namespace pcpp
{

#define TCPOPT_DUMMY 0xff

	/// ~~~~~~~~~~~~~~~~
	/// TcpOptionBuilder
	/// ~~~~~~~~~~~~~~~~

	TcpOptionBuilder::TcpOptionBuilder(NopEolOptionTypes optionType)
	{
		switch (optionType)
		{
		case EOL:
			init(static_cast<uint8_t>(PCPP_TCPOPT_EOL), nullptr, 0);
			break;
		case NOP:
		default:
			init(static_cast<uint8_t>(PCPP_TCPOPT_NOP), nullptr, 0);
			break;
		}
	}

	TcpOptionBuilder::TcpOptionBuilder(const NopEolOptionEnumType optionType)
	{
		switch (optionType)
		{
		case NopEolOptionEnumType::Eol:
			init(static_cast<uint8_t>(TcpOptionEnumType::Eol), nullptr, 0);
			break;
		case NopEolOptionEnumType::Nop:
		default:
			init(static_cast<uint8_t>(TcpOptionEnumType::Nop), nullptr, 0);
			break;
		}
	}

	TcpOption TcpOptionBuilder::build() const
	{
		uint8_t recType = static_cast<uint8_t>(m_RecType);
		size_t optionSize = m_RecValueLen + 2 * sizeof(uint8_t);

		if (recType == static_cast<uint8_t>(TcpOptionEnumType::Eol) ||
		    recType == static_cast<uint8_t>(TcpOptionEnumType::Nop))
		{
			if (m_RecValueLen != 0)
			{
				PCPP_LOG_ERROR(
				    "TCP NOP and TCP EOL options are 1-byte long and don't have option value. Tried to set option value of size "
				    << m_RecValueLen);
				return TcpOption(nullptr);
			}

			optionSize = 1;
		}

		uint8_t* recordBuffer = new uint8_t[optionSize];
		memset(recordBuffer, 0, optionSize);
		recordBuffer[0] = recType;
		if (optionSize > 1)
		{
			recordBuffer[1] = static_cast<uint8_t>(optionSize);
			if (optionSize > 2 && m_RecValue != nullptr)
				memcpy(recordBuffer + 2, m_RecValue, m_RecValueLen);
		}

		return TcpOption(recordBuffer);
	}

	/// ~~~~~~~~
	/// TcpLayer
	/// ~~~~~~~~

	uint16_t TcpLayer::getSrcPort() const
	{
		return be16toh(getTcpHeader()->portSrc);
	}

	uint16_t TcpLayer::getDstPort() const
	{
		return be16toh(getTcpHeader()->portDst);
	}

	TcpOption TcpLayer::getTcpOption(const TcpOptionEnumType option) const
	{
		return m_OptionReader.getTLVRecord(static_cast<uint8_t>(option), getOptionsBasePtr(),
		                                   getHeaderLen() - sizeof(tcphdr));
	}

	TcpOption TcpLayer::getFirstTcpOption() const
	{
		return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
	}

	TcpOption TcpLayer::getNextTcpOption(TcpOption& tcpOption) const
	{
		TcpOption nextOpt =
		    m_OptionReader.getNextTLVRecord(tcpOption, getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
		if (nextOpt.isNotNull() && nextOpt.getType() == TCPOPT_DUMMY)
			return TcpOption(nullptr);

		return nextOpt;
	}

	size_t TcpLayer::getTcpOptionCount() const
	{
		return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
	}

	TcpOption TcpLayer::addTcpOption(const TcpOptionBuilder& optionBuilder)
	{
		return addTcpOptionAt(optionBuilder, getHeaderLen() - m_NumOfTrailingBytes);
	}

	TcpOption TcpLayer::insertTcpOptionAfter(const TcpOptionBuilder& optionBuilder,
	                                         const TcpOptionEnumType prevOptionType)
	{
		int offset = 0;

		if (prevOptionType == TcpOptionEnumType::Unknown)
		{
			offset = sizeof(tcphdr);
		}
		else
		{
			const TcpOption prevOpt = getTcpOption(prevOptionType);
			if (prevOpt.isNull())
			{
				PCPP_LOG_ERROR("Previous option of type " << static_cast<int>(prevOptionType)
				                                          << " not found, cannot add a new TCP option");
				return TcpOption(nullptr);
			}

			offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
		}

		return addTcpOptionAt(optionBuilder, offset);
	}

	bool TcpLayer::removeTcpOption(const TcpOptionEnumType optionType)
	{
		const TcpOption opt = getTcpOption(optionType);
		if (opt.isNull())
		{
			return false;
		}

		// calculate total TCP option size
		TcpOption curOpt = getFirstTcpOption();
		size_t totalOptSize = 0;
		while (!curOpt.isNull())
		{
			totalOptSize += curOpt.getTotalSize();
			curOpt = getNextTcpOption(curOpt);
		}
		totalOptSize -= opt.getTotalSize();

		int offset = opt.getRecordBasePtr() - m_Data;

		if (!shortenLayer(offset, opt.getTotalSize()))
		{
			return false;
		}

		adjustTcpOptionTrailer(totalOptSize);

		m_OptionReader.changeTLVRecordCount(-1);

		return true;
	}

	bool TcpLayer::removeAllTcpOptions()
	{
		const int offset = sizeof(tcphdr);

		if (!shortenLayer(offset, getHeaderLen() - offset))
			return false;

		getTcpHeader()->dataOffset = sizeof(tcphdr) / 4;
		m_NumOfTrailingBytes = 0;
		m_OptionReader.changeTLVRecordCount(0 - getTcpOptionCount());
		return true;
	}

	TcpOption TcpLayer::addTcpOptionAt(const TcpOptionBuilder& optionBuilder, const int offset)
	{
		TcpOption newOption = optionBuilder.build();
		if (newOption.isNull())
			return newOption;

		// calculate total TCP option size
		TcpOption curOpt = getFirstTcpOption();
		size_t totalOptSize = 0;
		while (!curOpt.isNull())
		{
			totalOptSize += curOpt.getTotalSize();
			curOpt = getNextTcpOption(curOpt);
		}
		totalOptSize += newOption.getTotalSize();

		size_t sizeToExtend = newOption.getTotalSize();

		if (!extendLayer(offset, sizeToExtend))
		{
			PCPP_LOG_ERROR("Could not extend TcpLayer in [" << sizeToExtend << "] bytes");
			newOption.purgeRecordData();
			return TcpOption(nullptr);
		}

		memcpy(m_Data + offset, newOption.getRecordBasePtr(), newOption.getTotalSize());

		newOption.purgeRecordData();

		adjustTcpOptionTrailer(totalOptSize);

		m_OptionReader.changeTLVRecordCount(1);

		uint8_t* newOptPtr = m_Data + offset;

		return TcpOption(newOptPtr);
	}

	void TcpLayer::adjustTcpOptionTrailer(const size_t totalOptSize)
	{
		int newNumberOfTrailingBytes = 0;
		while ((totalOptSize + newNumberOfTrailingBytes) % 4 != 0)
			newNumberOfTrailingBytes++;

		if (newNumberOfTrailingBytes < m_NumOfTrailingBytes)
			shortenLayer(sizeof(tcphdr) + totalOptSize, m_NumOfTrailingBytes - newNumberOfTrailingBytes - 1);
		else if (newNumberOfTrailingBytes > m_NumOfTrailingBytes)
			extendLayer(sizeof(tcphdr) + totalOptSize, newNumberOfTrailingBytes - m_NumOfTrailingBytes);

		m_NumOfTrailingBytes = newNumberOfTrailingBytes;

		for (int i = 0; i < m_NumOfTrailingBytes; i++)
			m_Data[sizeof(tcphdr) + totalOptSize + i] = TCPOPT_DUMMY;

		getTcpHeader()->dataOffset = (sizeof(tcphdr) + totalOptSize + m_NumOfTrailingBytes) / 4;
	}

	uint16_t TcpLayer::calculateChecksum(const bool writeResultToPacket)
	{
		tcphdr* tcpHdr = getTcpHeader();
		uint16_t checksumRes = 0;
		const uint16_t currChecksumValue = tcpHdr->headerChecksum;

		if (m_PrevLayer != nullptr)
		{
			tcpHdr->headerChecksum = 0;
			PCPP_LOG_DEBUG("TCP data len = " << m_DataLen);

			if (m_PrevLayer->getProtocol() == IPv4)
			{
				const IPv4Address srcIP = static_cast<IPv4Layer*>(m_PrevLayer)->getSrcIPv4Address();
				const IPv4Address dstIP = static_cast<IPv4Layer*>(m_PrevLayer)->getDstIPv4Address();

				checksumRes =
				    pcpp::computePseudoHdrChecksum(reinterpret_cast<uint8_t*>(tcpHdr), getDataLen(),
				                                   IPAddress::IPv4AddressType, PACKETPP_IPPROTO_TCP, srcIP, dstIP);

				PCPP_LOG_DEBUG("calculated IPv4 TCP checksum = 0x" << std::uppercase << std::hex << checksumRes);
			}
			else if (m_PrevLayer->getProtocol() == IPv6)
			{
				const IPv6Address srcIP = static_cast<IPv6Layer*>(m_PrevLayer)->getSrcIPv6Address();
				const IPv6Address dstIP = static_cast<IPv6Layer*>(m_PrevLayer)->getDstIPv6Address();

				checksumRes = computePseudoHdrChecksum(reinterpret_cast<uint8_t*>(tcpHdr), getDataLen(),
				                                       IPAddress::IPv6AddressType, PACKETPP_IPPROTO_TCP, srcIP, dstIP);

				PCPP_LOG_DEBUG("calculated IPv6 TCP checksum = 0xX" << std::uppercase << std::hex << checksumRes);
			}
		}

		if (writeResultToPacket)
			tcpHdr->headerChecksum = htobe16(checksumRes);
		else
			tcpHdr->headerChecksum = currChecksumValue;

		return checksumRes;
	}

	void TcpLayer::initLayer()
	{
		m_DataLen = sizeof(tcphdr);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = TCP;
		m_NumOfTrailingBytes = 0;
		getTcpHeader()->dataOffset = sizeof(tcphdr) / 4;
	}

	TcpLayer::TcpLayer(uint8_t* data, const size_t dataLen, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet, TCP)
	{
		m_NumOfTrailingBytes = 0;
	}

	TcpLayer::TcpLayer()
	{
		initLayer();
	}

	TcpLayer::TcpLayer(const uint16_t portSrc, const uint16_t portDst)
	{
		initLayer();
		getTcpHeader()->portDst = htobe16(portDst);
		getTcpHeader()->portSrc = htobe16(portSrc);
	}

	void TcpLayer::copyLayerData(const TcpLayer& other)
	{
		m_OptionReader = other.m_OptionReader;
		m_NumOfTrailingBytes = other.m_NumOfTrailingBytes;
	}

	TcpLayer::TcpLayer(const TcpLayer& other) : Layer(other)
	{
		copyLayerData(other);
	}

	TcpLayer& TcpLayer::operator=(const TcpLayer& other)
	{
		Layer::operator=(other);

		copyLayerData(other);

		return *this;
	}

	void TcpLayer::parseNextLayer()
	{
		const size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t* payload = m_Data + headerLen;
		const size_t payloadLen = m_DataLen - headerLen;
		const uint16_t portDst = getDstPort();
		const uint16_t portSrc = getSrcPort();
		const char* payloadChar = reinterpret_cast<const char*>(payload);

		if (HttpMessage::isHttpPort(portDst) &&
		    HttpRequestFirstLine::parseMethod(payloadChar, payloadLen) != HttpRequestLayer::HttpMethodUnknown)
		{
			constructNextLayer<HttpRequestLayer>(payload, payloadLen, m_Packet);
		}
		else if (HttpMessage::isHttpPort(portSrc) &&
		         HttpResponseFirstLine::parseVersion(payloadChar, payloadLen) != HttpVersion::HttpVersionUnknown &&
		         !HttpResponseFirstLine::parseStatusCode(payloadChar, payloadLen).isUnsupportedCode())
		{
			constructNextLayer<HttpResponseLayer>(payload, payloadLen, m_Packet);
		}
		else if (SSLLayer::IsSSLMessage(portSrc, portDst, payload, payloadLen))
		{
			setNextLayer(SSLLayer::createSSLMessage(payload, payloadLen, this, m_Packet));
		}
		else if (SipLayer::isSipPort(portDst) || SipLayer::isSipPort(portSrc))
		{
			if (SipRequestFirstLine::parseMethod(payloadChar, payloadLen) != SipRequestLayer::SipMethodUnknown)
			{
				constructNextLayer<SipRequestLayer>(payload, payloadLen, m_Packet);
			}
			else if (SipResponseFirstLine::parseStatusCode(payloadChar, payloadLen) !=
			         SipResponseLayer::SipStatusCodeUnknown)
			{
				constructNextLayer<SipResponseLayer>(payload, payloadLen, m_Packet);
			}
			else
			{
				constructNextLayer<PayloadLayer>(payload, payloadLen, m_Packet);
			}
		}
		else if (BgpLayer::isBgpPort(portSrc, portDst))
		{
			m_NextLayer = BgpLayer::parseBgpLayer(payload, payloadLen, this, m_Packet);
			if (!m_NextLayer)
				constructNextLayer<PayloadLayer>(payload, payloadLen, m_Packet);
		}
		else if (SSHLayer::isSSHPort(portSrc, portDst))
		{
			setNextLayer(SSHLayer::createSSHMessage(payload, payloadLen, this, m_Packet));
		}
		else if (DnsLayer::isDataValid(payload, payloadLen, true) &&
		         (DnsLayer::isDnsPort(portDst) || DnsLayer::isDnsPort(portSrc)))
		{
			constructNextLayer<DnsOverTcpLayer>(payload, payloadLen, m_Packet);
		}
		else if (TelnetLayer::isDataValid(payload, payloadLen) &&
		         (TelnetLayer::isTelnetPort(portDst) || TelnetLayer::isTelnetPort(portSrc)))
		{
			constructNextLayer<TelnetLayer>(payload, payloadLen, m_Packet);
		}
		else if (FtpLayer::isFtpPort(portSrc) && FtpLayer::isDataValid(payload, payloadLen))
		{
			constructNextLayer<FtpResponseLayer>(payload, payloadLen, m_Packet);
		}
		else if (FtpLayer::isFtpPort(portDst) && FtpLayer::isDataValid(payload, payloadLen))
		{
			constructNextLayer<FtpRequestLayer>(payload, payloadLen, m_Packet);
		}
		else if (FtpLayer::isFtpDataPort(portSrc) || FtpLayer::isFtpDataPort(portDst))
		{
			constructNextLayer<FtpDataLayer>(payload, payloadLen, m_Packet);
		}
		else if (SomeIpLayer::isSomeIpPort(portSrc) || SomeIpLayer::isSomeIpPort(portDst))
		{
			setNextLayer(SomeIpLayer::parseSomeIpLayer(payload, payloadLen, this, m_Packet));
		}
		else if (TpktLayer::isDataValid(payload, payloadLen) && TpktLayer::isTpktPort(portSrc, portDst))
		{
			constructNextLayer<TpktLayer>(payload, payloadLen, m_Packet);
		}
		else if (SmtpLayer::isSmtpPort(portSrc) && SmtpLayer::isDataValid(payload, payloadLen))
		{
			constructNextLayer<SmtpResponseLayer>(payload, payloadLen, m_Packet);
		}
		else if (SmtpLayer::isSmtpPort(portDst) && SmtpLayer::isDataValid(payload, payloadLen))
		{
			constructNextLayer<SmtpRequestLayer>(payload, payloadLen, m_Packet);
		}
		else if (LdapLayer::isLdapPort(portDst) || LdapLayer::isLdapPort(portSrc))
		{
			m_NextLayer = LdapLayer::parseLdapMessage(payload, payloadLen, this, m_Packet);
			if (!m_NextLayer)
				constructNextLayer<PayloadLayer>(payload, payloadLen, m_Packet);
		}
		else if ((GtpV2Layer::isGTPv2Port(portDst) || GtpV2Layer::isGTPv2Port(portSrc)) &&
		         GtpV2Layer::isDataValid(payload, payloadLen))
		{
			constructNextLayer<GtpV2Layer>(payload, payloadLen, m_Packet);
		}
		else
		{
			constructNextLayer<PayloadLayer>(payload, payloadLen, m_Packet);
		}
	}

	void TcpLayer::computeCalculateFields()
	{
		tcphdr* tcpHdr = getTcpHeader();

		tcpHdr->dataOffset = getHeaderLen() >> 2;
		calculateChecksum(true);
	}

	std::string TcpLayer::toString() const
	{
		const tcphdr* hdr = getTcpHeader();
		std::string result = "TCP Layer, ";
		if (hdr->synFlag)
		{
			if (hdr->ackFlag)
				result += "[SYN, ACK], ";
			else
				result += "[SYN], ";
		}
		else if (hdr->finFlag)
		{
			if (hdr->ackFlag)
				result += "[FIN, ACK], ";
			else
				result += "[FIN], ";
		}
		else if (hdr->ackFlag)
			result += "[ACK], ";

		std::ostringstream srcPortStream;
		srcPortStream << getSrcPort();
		std::ostringstream dstPortStream;
		dstPortStream << getDstPort();
		result += "Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();

		return result;
	}

	/// ~~~~~~~~
	/// TcpLayer Deprecated Code
	/// ~~~~~~~~

	DISABLE_WARNING_PUSH
	DISABLE_WARNING_DEPRECATED
	TcpOption TcpLayer::addTcpOptionAfter(const TcpOptionBuilder& optionBuilder, TcpOptionType prevOptionType)
	{
		int offset = 0;

		if (prevOptionType == TcpOptionType::TCPOPT_Unknown)
		{
			offset = sizeof(tcphdr);
		}
		else
		{
			TcpOption prevOpt = getTcpOption(prevOptionType);
			if (prevOpt.isNull())
			{
				PCPP_LOG_ERROR("Previous option of type " << static_cast<int>(prevOptionType)
				                                          << " not found, cannot add a new TCP option");
				return TcpOption(nullptr);
			}

			offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
		}

		return addTcpOptionAt(optionBuilder, offset);
	}

	TcpOption TcpLayer::getTcpOption(TcpOptionType option) const
	{
		return m_OptionReader.getTLVRecord(static_cast<uint8_t>(option), getOptionsBasePtr(),
		                                   getHeaderLen() - sizeof(tcphdr));
	}

	bool TcpLayer::removeTcpOption(TcpOptionType optionType)
	{
		TcpOption opt = getTcpOption(optionType);
		if (opt.isNull())
		{
			return false;
		}

		// calculate total TCP option size
		TcpOption curOpt = getFirstTcpOption();
		size_t totalOptSize = 0;
		while (!curOpt.isNull())
		{
			totalOptSize += curOpt.getTotalSize();
			curOpt = getNextTcpOption(curOpt);
		}
		totalOptSize -= opt.getTotalSize();

		int offset = opt.getRecordBasePtr() - m_Data;

		if (!shortenLayer(offset, opt.getTotalSize()))
		{
			return false;
		}

		adjustTcpOptionTrailer(totalOptSize);

		m_OptionReader.changeTLVRecordCount(-1);

		return true;
	}
	DISABLE_WARNING_POP

}  // namespace pcpp
