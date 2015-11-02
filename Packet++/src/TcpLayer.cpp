#define LOG_MODULE PacketLogModuleTcpLayer

#include <TcpLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PayloadLayer.h>
#include <HttpLayer.h>
#include <IpUtils.h>
#include <Logger.h>
#include <string.h>
#include <sstream>

const TcpOptionData TcpLayer::TcpOptions[TCP_OPTIONS_COUNT] = {
	{ TCPOPT_NOP,		1						},
	{ TCPOPT_EOL,		1 						},
	{ TCPOPT_MSS,		TCPOLEN_MSS 			},
	{ TCPOPT_WINDOW,	TCPOLEN_WINDOW 			},
	{ TCPOPT_SACK_PERM, TCPOLEN_SACK_PERM 		},
	{ TCPOPT_SACK, 		TCPOLEN_SACK_MIN 		},
	{ TCPOPT_ECHO, 		TCPOLEN_ECHO 			},
	{ TCPOPT_ECHOREPLY, TCPOLEN_ECHOREPLY 		},
	{ TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP 		},
	{ TCPOPT_CC, 		TCPOLEN_CC 				},
	{ TCPOPT_CCNEW, 	TCPOLEN_CCNEW 			},
	{ TCPOPT_CCECHO, 	TCPOLEN_CCECHO	 		},
	{ TCPOPT_MD5, 		TCPOLEN_MD5 			},
	{ TCPOPT_MPTCP, 	TCPOLEN_MPTCP_MIN 		},
	{ TCPOPT_SCPS, 		TCPOLEN_SCPS 			},
	{ TCPOPT_SNACK, 	TCPOLEN_SNACK 			},
	{ TCPOPT_RECBOUND, 	TCPOLEN_RECBOUND 		},
	{ TCPOPT_CORREXP, 	TCPOLEN_CORREXP 		},
	{ TCPOPT_QS, 		TCPOLEN_QS 				},
	{ TCPOPT_USER_TO, 	TCPOLEN_USER_TO 		},
	{ TCPOPT_EXP_FD, 	TCPOLEN_EXP_MIN 		},
	{ TCPOPT_EXP_FE, 	TCPOLEN_EXP_MIN 		},
	{ TCPOPT_RVBD_PROBE,TCPOLEN_RVBD_PROBE_MIN	},
	{ TCPOPT_RVBD_TRPY, TCPOLEN_RVBD_TRPY_MIN 	}
};

const TcpOptionData& TcpLayer::getTcpOptionRawData(TcpOption option)
{
	for (int i = 0; i < TCP_OPTIONS_COUNT; i++)
	{
		if (TcpOptions[i].option == option)
			return TcpOptions[i];
	}

	// Should never get here
	return TcpOptions[1];
}

TcpOptionData* TcpLayer::getTcpOptionData(TcpOption option)
{
	uint8_t* tcpOptionStartPtr = m_Data + sizeof(tcphdr);
	for (size_t i = 0; i < m_TcpOptionsInLayerCount; i++)
	{
		if (m_TcpOptionsInLayer[i].option == option)
			return (TcpOptionData*)(tcpOptionStartPtr + m_TcpOptionsInLayer[i].dataOffset);
	}

	return NULL;
}

uint16_t TcpLayer::calculateChecksum(bool writeResultToPacket)
{
	tcphdr* tcpHdr = getTcpHeader();
	uint16_t checksumRes = 0;
	uint16_t currChecksumValue = tcpHdr->headerChecksum;

	if (m_PrevLayer != NULL)
	{
		tcpHdr->headerChecksum = 0;
		ScalarBuffer vec[2];
		LOG_DEBUG("data len =  %d", m_DataLen);
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

void TcpLayer::initLayer(int tcpOptionsCount, va_list paramsList)
{
	size_t tcpOptionsLen = 0;
	if (tcpOptionsCount != 0)
		m_TcpOptionsInLayer = new TcpOptionPtr[tcpOptionsCount];
	else
		m_TcpOptionsInLayer = NULL;
	m_TcpOptionsInLayerCount = tcpOptionsCount;
	for (int i = 0; i < tcpOptionsCount; i++)
	{
		TcpOption param = (TcpOption)va_arg(paramsList, int);
		const TcpOptionData rawOptionData = getTcpOptionRawData(param);
		tcpOptionsLen += rawOptionData.len;
		m_TcpOptionsInLayer[i].option = param;
	}

	m_DataLen = sizeof(tcphdr) + tcpOptionsLen;
	m_HeaderLen = m_DataLen;
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = TCP;

	int optionOffset = 0;
	uint8_t* optionPtr = m_Data + sizeof(tcphdr);
	for (size_t i = 0; i < m_TcpOptionsInLayerCount; i++)
	{
		m_TcpOptionsInLayer[i].dataOffset = optionOffset;
		const TcpOptionData rawOptionData = getTcpOptionRawData(m_TcpOptionsInLayer[i].option);
		*optionPtr = rawOptionData.option;
		if (rawOptionData.option > 1)
			*(optionPtr+1) = rawOptionData.len;
		optionOffset += rawOptionData.len;
		optionPtr += rawOptionData.len;
	}
}

TcpLayer::TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = TCP;
	m_TcpOptionsInLayerCount = 0;
	m_TcpOptionsInLayer = NULL;

	uint16_t headerLength = ((tcphdr*)m_Data)->dataOffset*4;
	m_HeaderLen = headerLength;
	if (m_HeaderLen > sizeof(tcphdr))
	{
		m_TcpOptionsInLayer = new TcpOptionPtr[MAX_SUPPORTED_TCP_OPTIONS];
		uint8_t* optionsPtr = m_Data + sizeof(tcphdr);
		int optionPtrOffset = 0;
		while (optionsPtr < m_Data + m_HeaderLen)
		{
			m_TcpOptionsInLayer[m_TcpOptionsInLayerCount].option = (TcpOption)*optionsPtr;
			const TcpOptionData rawOptionData = getTcpOptionRawData(m_TcpOptionsInLayer[m_TcpOptionsInLayerCount].option);
			m_TcpOptionsInLayer[m_TcpOptionsInLayerCount].dataOffset = optionPtrOffset;
			optionsPtr += rawOptionData.len;
			optionPtrOffset += rawOptionData.len;
			m_TcpOptionsInLayerCount++;
		}
	}
}

TcpLayer::TcpLayer(int tcpOptionsCount, ...) : m_TcpOptionsInLayer(NULL), m_TcpOptionsInLayerCount(0), m_HeaderLen(0)
{
	va_list paramList;
	va_start(paramList, tcpOptionsCount);
	initLayer(tcpOptionsCount, paramList);
	va_end(paramList);
}

TcpLayer::TcpLayer(uint16_t portSrc, uint16_t portDst, int tcpOptionsCount, ...)
{
	va_list paramList;
	va_start(paramList, tcpOptionsCount);
	initLayer(tcpOptionsCount, paramList);
	va_end(paramList);
	getTcpHeader()->portDst = htons(portDst);
	getTcpHeader()->portSrc = htons(portSrc);
}

void TcpLayer::copyLayerData(const TcpLayer& other)
{
	m_TcpOptionsInLayerCount = other.m_TcpOptionsInLayerCount;
	m_HeaderLen = other.m_HeaderLen;

	if (other.m_TcpOptionsInLayerCount > 0)
		m_TcpOptionsInLayer = new TcpOptionPtr[other.m_TcpOptionsInLayerCount];
	else
		m_TcpOptionsInLayer = NULL;

	for (size_t i = 0; i < other.m_TcpOptionsInLayerCount; i++)
		m_TcpOptionsInLayer[i] = other.m_TcpOptionsInLayer[i];
}

TcpLayer::TcpLayer(const TcpLayer& other) : Layer(other)
{
	copyLayerData(other);
}

TcpLayer& TcpLayer::operator=(const TcpLayer& other)
{
	Layer::operator=(other);

	if (m_TcpOptionsInLayer != NULL)
		delete [] m_TcpOptionsInLayer;

	copyLayerData(other);

	return *this;
}

void TcpLayer::parseNextLayer()
{
	if (m_DataLen <= m_HeaderLen)
		return;

	tcphdr* tcpHder = getTcpHeader();
	uint16_t portDst = ntohs(tcpHder->portDst);
	uint16_t portSrc = ntohs(tcpHder->portSrc);
	if ((portDst == 80 || portDst == 8080) && HttpRequestFirstLine::parseMethod((char*)(m_Data + m_HeaderLen), m_DataLen - m_HeaderLen) != HttpRequestLayer::HttpMethodUnknown)
		m_NextLayer = new HttpRequestLayer(m_Data + m_HeaderLen, m_DataLen - m_HeaderLen, this, m_Packet);
	else if ((portSrc == 80 || portSrc == 8080) && HttpResponseFirstLine::parseStatusCode((char*)(m_Data + m_HeaderLen), m_DataLen - m_HeaderLen) != HttpResponseLayer::HttpStatusCodeUnknown)
		m_NextLayer = new HttpResponseLayer(m_Data + m_HeaderLen, m_DataLen - m_HeaderLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(m_Data + m_HeaderLen, m_DataLen - m_HeaderLen, this, m_Packet);
}

void TcpLayer::computeCalculateFields()
{
	tcphdr* tcpHdr = getTcpHeader();

	tcpHdr->dataOffset = m_HeaderLen >> 2;
	calculateChecksum(true);
}

TcpLayer::~TcpLayer()
{
	if (m_TcpOptionsInLayer != NULL)
		delete[] m_TcpOptionsInLayer;
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
