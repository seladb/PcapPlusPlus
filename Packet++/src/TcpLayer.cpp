#define LOG_MODULE PacketLogModuleTcpLayer

#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "SipLayer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

#define TCPOPT_DUMMY 0xff


TcpOptionData* TcpLayer::castPtrToTcpOptionData(uint8_t* ptr)
{
	return (TcpOptionData*)ptr;
}

TcpOptionData* TcpLayer::getTcpOptionData(TcpOption option)
{
	uint16_t dataOffset = ((tcphdr *)m_Data)->dataOffset * 4;

	if (m_DataLen < dataOffset)
		return NULL;

	// check if there are tags at all
	if (dataOffset <= sizeof(tcphdr))
		return NULL;

	uint8_t* curOptPtr = m_Data + sizeof(tcphdr);
	
	while ((curOptPtr - m_Data) < dataOffset)
	{
		TcpOptionData* curOpt = castPtrToTcpOptionData(curOptPtr);
		if ((int)curOpt->option == option)
			return curOpt;

		curOptPtr += curOpt->getTotalSize();
	}

	return NULL;
}

TcpOptionData* TcpLayer::getFirstTcpOptionData()
{
	// check if there are TCP options at all
	if (getHeaderLen() <= sizeof(tcphdr))
		return NULL;

	uint8_t* curOptPtr = m_Data + sizeof(tcphdr);
	return castPtrToTcpOptionData(curOptPtr);
}

TcpOptionData* TcpLayer::getNextTcpOptionData(TcpOptionData* tcpOption)
{
	if (tcpOption == NULL)
		return NULL;

	// prev opt was the last opt
	if ((uint8_t*)tcpOption + tcpOption->getTotalSize() - m_Data >= (int)getHeaderLen())
		return NULL;

	TcpOptionData* nextOption = castPtrToTcpOptionData((uint8_t*)tcpOption + tcpOption->getTotalSize());
	if (nextOption->option == TCPOPT_DUMMY)
		return NULL;

	return nextOption;
}

size_t TcpLayer::getTcpOptionsCount()
{
	if (m_TcpOptionsCount != (size_t)-1)
		return m_TcpOptionsCount;

	m_TcpOptionsCount = 0;
	TcpOptionData* curOpt = getFirstTcpOptionData();
	while (curOpt != NULL)
	{
		m_TcpOptionsCount++;
		curOpt = getNextTcpOptionData(curOpt);
	}

	return m_TcpOptionsCount;
}

TcpOptionData* TcpLayer::addTcpOption(TcpOption optionType, uint8_t optionLength, const uint8_t* optionData)
{
	return addTcpOptionAt(optionType, optionLength, optionData, getHeaderLen()-m_NumOfTrailingBytes);
}

TcpOptionData* TcpLayer::addTcpOptionAfter(TcpOption optionType, uint8_t optionLength, const uint8_t* optionData, TcpOptionData* prevOption)
{
	int offset = 0;
	if (prevOption == NULL)
	{
		offset = sizeof(tcphdr);
	}
	else
	{
		offset = (uint8_t*)prevOption + prevOption->getTotalSize() - m_Data;
	}

	return addTcpOptionAt(optionType, optionLength, optionData, offset);
}

bool TcpLayer::removeTcpOption(TcpOption optionType)
{
	TcpOptionData* opt = getTcpOptionData(optionType);
	if (opt == NULL)
	{
		return false;
	}

	// calculate total TCP option size
	TcpOptionData* curOpt = getFirstTcpOptionData();
	size_t totalOptSize = 0;
	while (curOpt != NULL)
	{
		totalOptSize += curOpt->getTotalSize();
		curOpt = getNextTcpOptionData(curOpt);
	}
	totalOptSize -= opt->getTotalSize();


	int offset = (uint8_t*)opt - m_Data;

	if (!shortenLayer(offset, opt->getTotalSize()))
	{
		return false;
	}

	adjustTcpOptionTrailer(totalOptSize);

	m_TcpOptionsCount--;

	return true;
}

bool TcpLayer::removeAllTcpOptions()
{
	int offset = sizeof(tcphdr);

	if (!shortenLayer(offset, getHeaderLen()-offset))
		return false;

	getTcpHeader()->dataOffset = sizeof(tcphdr)/4;
	m_NumOfTrailingBytes = 0;
	m_TcpOptionsCount = 0;
	return true;
}

TcpOptionData* TcpLayer::addTcpOptionAt(TcpOption optionType, uint8_t optionLength, const uint8_t* optionData, int offset)
{
	if ((optionType == PCPP_TCPOPT_EOL || optionType == PCPP_TCPOPT_NOP) && optionLength != PCPP_TCPOLEN_NOP)
	{
		LOG_ERROR("Can't set TCP NOP option or TCP EOL option with size different than 1, tried to set size %d", optionLength);
		return NULL;
	}

	// calculate total TCP option size
	TcpOptionData* curOpt = getFirstTcpOptionData();
	size_t totalOptSize = 0;
	while (curOpt != NULL)
	{
		totalOptSize += curOpt->getTotalSize();
		curOpt = getNextTcpOptionData(curOpt);
	}
	totalOptSize += optionLength;


	if (!extendLayer(offset, optionLength))
	{
		LOG_ERROR("Could not extend TcpLayer in [%d] bytes", optionLength);
		return NULL;
	}

	uint8_t optionTypeVal = (uint8_t)optionType;
	memcpy(m_Data + offset, &optionTypeVal, sizeof(uint8_t));

	if (optionLength > 1)
	{
		memcpy(m_Data + offset + sizeof(uint8_t), &optionLength, sizeof(uint8_t));
		if (optionLength > 2 && optionData != NULL)
			memcpy(m_Data + offset + 2*sizeof(uint8_t), optionData, optionLength-2*sizeof(uint8_t));
	}

	adjustTcpOptionTrailer(totalOptSize);

	uint8_t* newOptPtr = m_Data + offset;

	m_TcpOptionsCount++;

	return castPtrToTcpOptionData(newOptPtr);
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
		LOG_DEBUG("data len =  %d", (int)m_DataLen);
		vec[0].buffer = (uint16_t*)m_Data;
		vec[0].len = m_DataLen;

		if (m_PrevLayer->getProtocol() == IPv4)
		{
			uint32_t srcIP = ((IPv4Layer*)m_PrevLayer)->getSrcIpAddress().toInt();
			uint32_t dstIP = ((IPv4Layer*)m_PrevLayer)->getDstIpAddress().toInt();
			uint16_t pseudoHeader[6];
			pseudoHeader[0] = srcIP >> 16;
			pseudoHeader[1] = srcIP & 0xFFFF;
			pseudoHeader[2] = dstIP >> 16;
			pseudoHeader[3] = dstIP & 0xFFFF;
			pseudoHeader[4] = 0xffff & htons(m_DataLen);
			pseudoHeader[5] = htons(0x00ff & PACKETPP_IPPROTO_TCP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 12;
			checksumRes = compute_checksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);


		}
		else if (m_PrevLayer->getProtocol() == IPv6)
		{
			uint16_t pseudoHeader[18];
			((IPv6Layer*)m_PrevLayer)->getSrcIpAddress().copyTo((uint8_t*)pseudoHeader);
			((IPv6Layer*)m_PrevLayer)->getDstIpAddress().copyTo((uint8_t*)(pseudoHeader+8));
			pseudoHeader[16] = 0xffff & htons(m_DataLen);
			pseudoHeader[17] = htons(0x00ff & PACKETPP_IPPROTO_TCP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = compute_checksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);
		}
	}

	if(writeResultToPacket)
		tcpHdr->headerChecksum = htons(checksumRes);
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
	m_TcpOptionsCount = 0;
	m_NumOfTrailingBytes = 0;
	getTcpHeader()->dataOffset = sizeof(tcphdr)/4;
}

TcpLayer::TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = TCP;
	m_TcpOptionsCount = -1;
	m_NumOfTrailingBytes = 0;
}

TcpLayer::TcpLayer()
{
	initLayer();
}

TcpLayer::TcpLayer(uint16_t portSrc, uint16_t portDst)
{
	initLayer();
	getTcpHeader()->portDst = htons(portDst);
	getTcpHeader()->portSrc = htons(portSrc);
}

void TcpLayer::copyLayerData(const TcpLayer& other)
{
	m_TcpOptionsCount = other.m_TcpOptionsCount;
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

	tcphdr* tcpHder = getTcpHeader();
	uint16_t portDst = ntohs(tcpHder->portDst);
	uint16_t portSrc = ntohs(tcpHder->portSrc);
	if ((HttpMessage::getHTTPPortMap()->find(portDst) != HttpMessage::getHTTPPortMap()->end()) && HttpRequestFirstLine::parseMethod((char*)(m_Data + headerLen), m_DataLen - headerLen) != HttpRequestLayer::HttpMethodUnknown)
		m_NextLayer = new HttpRequestLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	else if ((HttpMessage::getHTTPPortMap()->find(portSrc) != HttpMessage::getHTTPPortMap()->end()) && HttpResponseFirstLine::parseStatusCode((char*)(m_Data + headerLen), m_DataLen - headerLen) != HttpResponseLayer::HttpStatusCodeUnknown)
		m_NextLayer = new HttpResponseLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	else if (SSLLayer::IsSSLMessage(portSrc, portDst, m_Data + headerLen, m_DataLen - headerLen))
		m_NextLayer = SSLLayer::createSSLMessage(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	else if (((portDst == 5060) || (portDst == 5061)) && (SipRequestFirstLine::parseMethod((char*)(m_Data + headerLen), m_DataLen - headerLen) != SipRequestLayer::SipMethodUnknown))
		m_NextLayer = new SipRequestLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	else if (((portDst == 5060) || (portDst == 5061)) && (SipResponseFirstLine::parseStatusCode((char*)(m_Data + headerLen), m_DataLen - headerLen) != SipResponseLayer::SipStatusCodeUnknown))
		m_NextLayer = new SipResponseLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
}

void TcpLayer::computeCalculateFields()
{
	tcphdr* tcpHdr = getTcpHeader();

	tcpHdr->dataOffset = getHeaderLen() >> 2;
	calculateChecksum(true);
}

std::string TcpLayer::toString()
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
	srcPortStream << ntohs(hdr->portSrc);
	std::ostringstream dstPortStream;
	dstPortStream << ntohs(hdr->portDst);
	result += "Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();

	return result;
}

} // namespace pcpp
