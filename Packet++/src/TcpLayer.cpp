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
#include "FtpLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <string.h>
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
		init((uint8_t)PCPP_TCPOPT_EOL, NULL, 0);
		break;
	case NOP:
	default:
		init((uint8_t)PCPP_TCPOPT_NOP, NULL, 0);
		break;
	}
}

TcpOption TcpOptionBuilder::build() const
{
	uint8_t recType = static_cast<uint8_t>(m_RecType);
	size_t optionSize = m_RecValueLen + 2*sizeof(uint8_t);

	if (recType == (uint8_t)PCPP_TCPOPT_EOL || recType == (uint8_t)PCPP_TCPOPT_NOP)
	{
		if (m_RecValueLen != 0)
		{
			PCPP_LOG_ERROR("TCP NOP and TCP EOL options are 1-byte long and don't have option value. Tried to set option value of size " << m_RecValueLen);
			return TcpOption(NULL);
		}

		optionSize = 1;
	}

	uint8_t* recordBuffer = new uint8_t[optionSize];
	memset(recordBuffer, 0, optionSize);
	recordBuffer[0] = recType;
	if (optionSize > 1)
	{
		recordBuffer[1] = static_cast<uint8_t>(optionSize);
		if (optionSize > 2 && m_RecValue != NULL)
			memcpy(recordBuffer+2, m_RecValue, m_RecValueLen);
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

TcpOption TcpLayer::getTcpOption(TcpOptionType option) const
{
	return m_OptionReader.getTLVRecord((uint8_t)option, getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

TcpOption TcpLayer::getFirstTcpOption() const
{
	return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

TcpOption TcpLayer::getNextTcpOption(TcpOption& tcpOption) const
{
	TcpOption nextOpt = m_OptionReader.getNextTLVRecord(tcpOption, getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
	if (nextOpt.isNotNull() && nextOpt.getType() == TCPOPT_DUMMY)
		return TcpOption(NULL);

	return nextOpt;
}

size_t TcpLayer::getTcpOptionCount() const
{
	return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

TcpOption TcpLayer::addTcpOption(const TcpOptionBuilder& optionBuilder)
{
	return addTcpOptionAt(optionBuilder, getHeaderLen()-m_NumOfTrailingBytes);
}

TcpOption TcpLayer::addTcpOptionAfter(const TcpOptionBuilder& optionBuilder, TcpOptionType prevOptionType)
{
	int offset = 0;

	if (prevOptionType == TCPOPT_Unknown)
	{
		offset = sizeof(tcphdr);
	}
	else
	{
		TcpOption prevOpt = getTcpOption(prevOptionType);
		if (prevOpt.isNull())
		{
			PCPP_LOG_ERROR("Previous option of type " << (int)prevOptionType << " not found, cannot add a new TCP option");
			return TcpOption(NULL);
		}

		offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
	}

	return addTcpOptionAt(optionBuilder, offset);
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

bool TcpLayer::removeAllTcpOptions()
{
	int offset = sizeof(tcphdr);

	if (!shortenLayer(offset, getHeaderLen()-offset))
		return false;

	getTcpHeader()->dataOffset = sizeof(tcphdr)/4;
	m_NumOfTrailingBytes = 0;
	m_OptionReader.changeTLVRecordCount(0-getTcpOptionCount());
	return true;
}

TcpOption TcpLayer::addTcpOptionAt(const TcpOptionBuilder& optionBuilder, int offset)
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
		return TcpOption(NULL);
	}

	memcpy(m_Data + offset, newOption.getRecordBasePtr(), newOption.getTotalSize());

	newOption.purgeRecordData();

	adjustTcpOptionTrailer(totalOptSize);

	m_OptionReader.changeTLVRecordCount(1);

	uint8_t* newOptPtr = m_Data + offset;

	return TcpOption(newOptPtr);
}

void TcpLayer::adjustTcpOptionTrailer(size_t totalOptSize)
{
	int newNumberOfTrailingBytes = 0;
	while ((totalOptSize + newNumberOfTrailingBytes) % 4 != 0)
		newNumberOfTrailingBytes++;

	if (newNumberOfTrailingBytes < m_NumOfTrailingBytes)
		shortenLayer(sizeof(tcphdr)+totalOptSize, m_NumOfTrailingBytes - newNumberOfTrailingBytes);
	else if (newNumberOfTrailingBytes > m_NumOfTrailingBytes)
		extendLayer(sizeof(tcphdr)+totalOptSize, newNumberOfTrailingBytes - m_NumOfTrailingBytes);

	m_NumOfTrailingBytes = newNumberOfTrailingBytes;

	for (int i = 0; i < m_NumOfTrailingBytes; i++)
		m_Data[sizeof(tcphdr) + totalOptSize + i] = TCPOPT_DUMMY;

	getTcpHeader()->dataOffset = (sizeof(tcphdr) + totalOptSize + m_NumOfTrailingBytes)/4;
}

uint16_t TcpLayer::calculateChecksum(bool writeResultToPacket)
{
	tcphdr* tcpHdr = getTcpHeader();
	uint16_t checksumRes = 0;
	uint16_t currChecksumValue = tcpHdr->headerChecksum;

	if (m_PrevLayer != NULL)
	{
		tcpHdr->headerChecksum = 0;
		ScalarBuffer<uint16_t> vec[2];
		PCPP_LOG_DEBUG("data len = " << m_DataLen);
		vec[0].buffer = (uint16_t*)m_Data;
		vec[0].len = m_DataLen;

		if (m_PrevLayer->getProtocol() == IPv4)
		{
			uint32_t srcIP = ((IPv4Layer*)m_PrevLayer)->getSrcIPv4Address().toInt();
			uint32_t dstIP = ((IPv4Layer*)m_PrevLayer)->getDstIPv4Address().toInt();
			uint16_t pseudoHeader[6];
			pseudoHeader[0] = srcIP >> 16;
			pseudoHeader[1] = srcIP & 0xFFFF;
			pseudoHeader[2] = dstIP >> 16;
			pseudoHeader[3] = dstIP & 0xFFFF;
			pseudoHeader[4] = 0xffff & htobe16(m_DataLen);
			pseudoHeader[5] = htobe16(0x00ff & PACKETPP_IPPROTO_TCP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 12;
			checksumRes = computeChecksum(vec, 2);
			PCPP_LOG_DEBUG("calculated checksum = 0x" << std::uppercase << std::hex << checksumRes);


		}
		else if (m_PrevLayer->getProtocol() == IPv6)
		{
			uint16_t pseudoHeader[18];
			((IPv6Layer*)m_PrevLayer)->getSrcIPv6Address().copyTo((uint8_t*)pseudoHeader);
			((IPv6Layer*)m_PrevLayer)->getDstIPv6Address().copyTo((uint8_t*)(pseudoHeader+8));
			pseudoHeader[16] = 0xffff & htobe16(m_DataLen);
			pseudoHeader[17] = htobe16(0x00ff & PACKETPP_IPPROTO_TCP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = computeChecksum(vec, 2);
			PCPP_LOG_DEBUG("calculated checksum = 0xX" << std::uppercase << std::hex << checksumRes);
		}
	}

	if(writeResultToPacket)
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
	getTcpHeader()->dataOffset = sizeof(tcphdr)/4;
}

TcpLayer::TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = TCP;
	m_NumOfTrailingBytes = 0;
}

TcpLayer::TcpLayer()
{
	initLayer();
}

TcpLayer::TcpLayer(uint16_t portSrc, uint16_t portDst)
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
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	uint8_t* payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;
	uint16_t portDst = getDstPort();
	uint16_t portSrc = getSrcPort();

	if (HttpMessage::isHttpPort(portDst) && HttpRequestFirstLine::parseMethod((char*)payload, payloadLen) != HttpRequestLayer::HttpMethodUnknown)
		m_NextLayer = new HttpRequestLayer(payload, payloadLen, this, m_Packet);
	else if (HttpMessage::isHttpPort(portSrc) && HttpResponseFirstLine::parseStatusCode((char*)payload, payloadLen) != HttpResponseLayer::HttpStatusCodeUnknown)
		m_NextLayer = new HttpResponseLayer(payload, payloadLen, this, m_Packet);
	else if (SSLLayer::IsSSLMessage(portSrc, portDst, payload, payloadLen))
		m_NextLayer = SSLLayer::createSSLMessage(payload, payloadLen, this, m_Packet);
	else if (SipLayer::isSipPort(portDst))
	{
		if (SipRequestFirstLine::parseMethod((char*)payload, payloadLen) != SipRequestLayer::SipMethodUnknown)
			m_NextLayer = new SipRequestLayer(payload, payloadLen, this, m_Packet);
		else if (SipResponseFirstLine::parseStatusCode((char*)payload, payloadLen) != SipResponseLayer::SipStatusCodeUnknown)
			m_NextLayer = new SipResponseLayer(payload, payloadLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
	else if (BgpLayer::isBgpPort(portSrc, portDst))
		m_NextLayer = BgpLayer::parseBgpLayer(payload, payloadLen, this, m_Packet);
	else if (SSHLayer::isSSHPort(portSrc, portDst))
		m_NextLayer = SSHLayer::createSSHMessage(payload, payloadLen, this, m_Packet);
	else if (DnsLayer::isDataValid(payload, payloadLen, true) && (DnsLayer::isDnsPort(portDst) || DnsLayer::isDnsPort(portSrc)))
		m_NextLayer = new DnsOverTcpLayer(payload, payloadLen, this, m_Packet);
	else if (TelnetLayer::isDataValid(payload, payloadLen) && (TelnetLayer::isTelnetPort(portDst) || TelnetLayer::isTelnetPort(portSrc)))
		m_NextLayer = new TelnetLayer(payload, payloadLen, this, m_Packet);
	else if (FtpLayer::isFtpPort(portSrc) && FtpLayer::isDataValid(payload, payloadLen))
		m_NextLayer = new FtpResponseLayer(payload, payloadLen, this, m_Packet);
	else if (FtpLayer::isFtpPort(portDst) && FtpLayer::isDataValid(payload, payloadLen))
		m_NextLayer = new FtpRequestLayer(payload, payloadLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
}

void TcpLayer::computeCalculateFields()
{
	tcphdr* tcpHdr = getTcpHeader();

	tcpHdr->dataOffset = getHeaderLen() >> 2;
	calculateChecksum(true);
}

std::string TcpLayer::toString() const
{
	tcphdr* hdr = getTcpHeader();
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

} // namespace pcpp
