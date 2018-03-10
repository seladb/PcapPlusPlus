#define LOG_MODULE PacketLogModuleIPv4Layer

#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"
#include "IcmpLayer.h"
#include "GreLayer.h"
#include "IgmpLayer.h"
#include <string.h>
#include <sstream>
#include "IpUtils.h"
#include "Logger.h"

namespace pcpp
{

#define IPV4OPT_DUMMMY 0xff
#define IPV4_MAX_OPT_SIZE 40

void IPv4Layer::initLayer()
{
	m_DataLen = sizeof(iphdr);
	m_Data = new uint8_t[m_DataLen];
	m_Protocol = IPv4;
	memset(m_Data, 0, sizeof(iphdr));
	iphdr* ipHdr = getIPv4Header();
	ipHdr->internetHeaderLength = (5 & 0xf);
	setOptionCount(-1);
	m_NumOfTrailingBytes = 0;
	m_TempHeaderExtension = 0;
}

void IPv4Layer::initLayerInPacket(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, bool setTotalLenAsDataLen)
{
	m_Protocol = IPv4;
	m_OptionCount = -1;
	m_NumOfTrailingBytes = 0;
	m_TempHeaderExtension = 0;
	if (setTotalLenAsDataLen)
	{
		size_t totalLen = ntohs(getIPv4Header()->totalLength);
		if (totalLen < m_DataLen)
			m_DataLen = totalLen;
	}
}

void IPv4Layer::copyLayerData(const IPv4Layer& other)
{
	m_OptionCount = other.m_OptionCount;
	m_NumOfTrailingBytes = other.m_NumOfTrailingBytes;
	m_TempHeaderExtension = other.m_TempHeaderExtension;
}

IPv4OptionData* IPv4Layer::castPtrToOptionData(uint8_t* ptr)
{
	return (IPv4OptionData*)ptr;
}

IPv4Layer::IPv4Layer()
{
	initLayer();
}

IPv4Layer::IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, bool setTotalLenAsDataLen) : Layer(data, dataLen, prevLayer, packet)
{
	initLayerInPacket(data, dataLen, prevLayer, packet, setTotalLenAsDataLen);
}

IPv4Layer::IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	initLayerInPacket(data, dataLen, prevLayer, packet, true);
}

IPv4Layer::IPv4Layer(const IPv4Address& srcIP, const IPv4Address& dstIP)
{
	initLayer();
	iphdr* ipHdr = getIPv4Header();
	ipHdr->ipSrc = srcIP.toInt();
	ipHdr->ipDst = dstIP.toInt();
}

IPv4Layer::IPv4Layer(const IPv4Layer& other) : Layer(other)
{
	copyLayerData(other);
}

IPv4Layer& IPv4Layer::operator=(const IPv4Layer& other)
{
	Layer::operator=(other);

	copyLayerData(other);

	return *this;
}

void IPv4Layer::parseNextLayer()
{
	size_t hdrLen = getHeaderLen();
	if (m_DataLen <= hdrLen)
		return;

	iphdr* ipHdr = getIPv4Header();

	ProtocolType greVer = UnknownProtocol;
	ProtocolType igmpVer = UnknownProtocol;
	bool igmpQuery = false;

	uint8_t ipVersion = 0;

	// If it's a fragment don't parse upper layers, unless if it's the first fragment
	// TODO: assuming first fragment contains at least L4 header, what if it's not true?
	if (isFragment())
	{
		m_NextLayer = new PayloadLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		return;
	}

	switch (ipHdr->protocol)
	{
	case PACKETPP_IPPROTO_UDP:
		if (m_DataLen - hdrLen >= sizeof(udphdr))
			m_NextLayer = new UdpLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_TCP:
		if (m_DataLen - hdrLen >= sizeof(tcphdr))
			m_NextLayer = new TcpLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_ICMP:
		m_NextLayer = new IcmpLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_IPIP:
		ipVersion = *(m_Data + hdrLen);
		if (ipVersion >> 4 == 4)
			m_NextLayer = new IPv4Layer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		else if (ipVersion >> 4 == 6)
			m_NextLayer = new IPv6Layer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_GRE:
		greVer = GreLayer::getGREVersion(m_Data + hdrLen, m_DataLen - hdrLen);
		if (greVer == GREv0)
			m_NextLayer = new GREv0Layer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		else if (greVer == GREv1)
			m_NextLayer = new GREv1Layer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_IGMP:
		igmpVer = IgmpLayer::getIGMPVerFromData(m_Data + hdrLen, ntohs(getIPv4Header()->totalLength) - hdrLen, igmpQuery);
		if (igmpVer == IGMPv1)
			m_NextLayer = new IgmpV1Layer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		else if (igmpVer == IGMPv2)
			m_NextLayer = new IgmpV2Layer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		else if (igmpVer == IGMPv3)
		{
			if (igmpQuery)
				m_NextLayer = new IgmpV3QueryLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
			else
				m_NextLayer = new IgmpV3ReportLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		}
		else
			m_NextLayer = new PayloadLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
		return;
	}
}

void IPv4Layer::computeCalculateFields()
{
	iphdr* ipHdr = getIPv4Header();
	ipHdr->ipVersion = (4 & 0x0f);
	ipHdr->totalLength = htons(m_DataLen);
	ipHdr->headerChecksum = 0;

	if (m_NextLayer != NULL)
	{
		switch (m_NextLayer->getProtocol())
		{
		case TCP:
			ipHdr->protocol = PACKETPP_IPPROTO_TCP;
			break;
		case UDP:
			ipHdr->protocol = PACKETPP_IPPROTO_UDP;
			break;
		case ICMP:
			ipHdr->protocol = PACKETPP_IPPROTO_ICMP;
			break;
		case GREv0:
		case GREv1:
			ipHdr->protocol = PACKETPP_IPPROTO_GRE;
			break;
		case IGMPv1:
		case IGMPv2:
		case IGMPv3:
			ipHdr->protocol = PACKETPP_IPPROTO_IGMP;
			break;
		default:
			break;
		}
	}

	ScalarBuffer<uint16_t> scalar = { (uint16_t*)ipHdr, (size_t)(ipHdr->internetHeaderLength*4) } ;
	ipHdr->headerChecksum = htons(compute_checksum(&scalar, 1));
}

bool IPv4Layer::isFragment()
{
	return ((getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS) != 0 || getFragmentOffset() != 0);
}

bool IPv4Layer::isFirstFragment()
{
	return isFragment() && (getFragmentOffset() == 0);
}

bool IPv4Layer::isLastFragment()
{
	return isFragment() && ((getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS) == 0);
}

uint8_t IPv4Layer::getFragmentFlags()
{
	return getIPv4Header()->fragmentOffset & 0xE0;
}

uint16_t IPv4Layer::getFragmentOffset()
{
	return ntohs(getIPv4Header()->fragmentOffset & (uint16_t)0xFF1F) * 8;
}

std::string IPv4Layer::toString()
{
	std::string fragmet = "";
	if (isFragment())
	{
		if (isFirstFragment())
			fragmet = "First fragment";
		else if (isLastFragment())
			fragmet = "Last fragment";
		else
			fragmet = "Fragment";

		std::stringstream sstm;
		sstm << fragmet << " [offset= " << getFragmentOffset() << "], ";
		fragmet = sstm.str();
	}


	return "IPv4 Layer, " + fragmet + "Src: " + getSrcIpAddress().toString() + ", Dst: " + getDstIpAddress().toString();
}

IPv4OptionData* IPv4Layer::getOptionData(IPv4OptionTypes option)
{
	// check if there are options at all
	if (m_DataLen <= sizeof(iphdr))
		return NULL;

	IPv4OptionData* curOpt = getFirstOptionData();
	while (curOpt != NULL)
	{
		if ((int)curOpt->opCode == option)
			return curOpt;

		curOpt = getNextOptionData(curOpt);
	}

	return NULL;
}

IPv4OptionData* IPv4Layer::getFirstOptionData()
{
	// check if there are IPv4 options at all
	if (getHeaderLen() <= sizeof(iphdr))
		return NULL;

	uint8_t* curOptPtr = m_Data + sizeof(iphdr);
	return castPtrToOptionData(curOptPtr);
}

IPv4OptionData* IPv4Layer::getNextOptionData(IPv4OptionData* option)
{
	if (option == NULL)
		return NULL;

	// prev opt was the last opt
	if ((uint8_t*)option + option->getTotalSize() - m_Data >= (int)getHeaderLen())
		return NULL;

	IPv4OptionData* nextOption = castPtrToOptionData((uint8_t*)option + option->getTotalSize());

	if (nextOption->opCode == IPV4OPT_DUMMMY)
		return NULL;

	return nextOption;
}

size_t IPv4Layer::getOptionsCount()
{
	if (m_OptionCount != (size_t)-1)
		return m_OptionCount;

	m_OptionCount = 0;
	IPv4OptionData* curOpt = getFirstOptionData();
	while (curOpt != NULL)
	{
		m_OptionCount++;
		curOpt = getNextOptionData(curOpt);
	}

	return m_OptionCount;
}

void IPv4Layer::incOptionCount(int val)
{
	if (m_OptionCount == (size_t)-1)
		getOptionsCount(); // this method already calculates the current number of options, no need to increment/decrement m_OptionCount again
	else
		m_OptionCount += val;
}

void IPv4Layer::setOptionCount(int val)
{
	m_OptionCount = val;
}

void IPv4Layer::adjustOptionsTrailer(size_t totalOptSize)
{
	size_t ipHdrSize = sizeof(iphdr);

	int newNumberOfTrailingBytes = 0;
	while ((totalOptSize + newNumberOfTrailingBytes) % 4 != 0)
		newNumberOfTrailingBytes++;

	if (newNumberOfTrailingBytes < m_NumOfTrailingBytes)
		shortenLayer(ipHdrSize+totalOptSize, m_NumOfTrailingBytes - newNumberOfTrailingBytes);
	else if (newNumberOfTrailingBytes > m_NumOfTrailingBytes)
		extendLayer(ipHdrSize+totalOptSize, newNumberOfTrailingBytes - m_NumOfTrailingBytes);

	m_NumOfTrailingBytes = newNumberOfTrailingBytes;

	for (int i = 0; i < m_NumOfTrailingBytes; i++)
		m_Data[ipHdrSize + totalOptSize + i] = IPV4OPT_DUMMMY;

	m_TempHeaderExtension = 0;
	getIPv4Header()->internetHeaderLength = ((ipHdrSize + totalOptSize + m_NumOfTrailingBytes)/4 & 0x0f);
}

IPv4OptionData* IPv4Layer::addOptionAt(IPv4OptionTypes optionType, uint8_t optionDataLength, const uint8_t* optionData, int offset)
{
	size_t sizeToExtend = optionDataLength + 2*sizeof(uint8_t);

	if ((optionType == IPV4OPT_NOP || optionType == IPV4OPT_EndOfOtionsList))
	{
		if (optionDataLength != 0)
		{
			LOG_ERROR("Can't set IPv4 NOP option or IPv4 End-of-options option with size different than 0, tried to set size %d", optionDataLength);
			return NULL;
		}

		sizeToExtend = sizeof(uint8_t);
	}

	size_t totalOptSize = getHeaderLen() - sizeof(iphdr) - m_NumOfTrailingBytes + sizeToExtend;

	if (totalOptSize > IPV4_MAX_OPT_SIZE)
	{
		LOG_ERROR("Cannot add option - adding this option will exceed IPv4 total option size which is %d", IPV4_MAX_OPT_SIZE);
		return NULL;
	}

	if (!extendLayer(offset, sizeToExtend))
	{
		LOG_ERROR("Could not extend IPv4Layer in [%d] bytes", (int)sizeToExtend);
		return NULL;
	}

	uint8_t optionTypeVal = (uint8_t)optionType;
	memcpy(m_Data + offset, &optionTypeVal, sizeof(uint8_t));

	if (sizeToExtend > 1)
	{
		memcpy(m_Data + offset + sizeof(uint8_t), &sizeToExtend, sizeof(uint8_t));
		if (sizeToExtend > 2 && optionData != NULL)
			memcpy(m_Data + offset + 2*sizeof(uint8_t), optionData, optionDataLength);
	}

	// setting this m_TempHeaderExtension because adjustOptionsTrailer() may extend or shorten the layer and the extend or shorten methods need to know the accurate
	// current size of the header. m_TempHeaderExtension will be added to the length extracted from getIPv4Header()->internetHeaderLength as the temp new size
	m_TempHeaderExtension = sizeToExtend;
	adjustOptionsTrailer(totalOptSize);
	// the adjustOptionsTrailer() adds or removed the trailing bytes and sets getIPv4Header()->internetHeaderLength to the correct size, so the m_TempHeaderExtension
	// isn't needed anymore
	m_TempHeaderExtension = 0;

	uint8_t* newOptPtr = m_Data + offset;

	incOptionCount(1);

	return castPtrToOptionData(newOptPtr);
}

void IPv4Layer::buildIPListOptionData(const std::vector<IPv4Address>& ipList, uint8_t** optionData, int& optionDataLength)
{
	optionDataLength = ipList.size()*sizeof(uint32_t) + sizeof(uint8_t);
	(*optionData) = new uint8_t[optionDataLength];

	size_t curOffset = 0;
	(*optionData)[curOffset++] = 0; // init pointer value

	bool firstZero = false;
	for (std::vector<IPv4Address>::const_iterator iter = ipList.begin(); iter != ipList.end(); iter++)
	{
		uint32_t ipAddrAsInt = iter->toInt();

		if (!firstZero)
			(*optionData)[0] += (uint8_t)4;

		if (!firstZero && ipAddrAsInt == 0)
			firstZero = true;

		memcpy((*optionData) + curOffset , &ipAddrAsInt, sizeof(uint32_t));
		curOffset += sizeof(uint32_t);
	}
}

void IPv4Layer::buildTimestampOptionData(const IPv4TimestampOptionValue& timestampVal, uint8_t** optionData, int& optionDataLength)
{
	optionDataLength = 0;
	*optionData = NULL;

	if (timestampVal.type == IPv4TimestampOptionValue::Unknown)
	{
		LOG_ERROR("Cannot build timestamp option of type IPv4TimestampOptionValue::Unknown");
		return;
	}

	if (timestampVal.type == IPv4TimestampOptionValue::TimestampsForPrespecifiedIPs)
	{
		LOG_ERROR("Cannot build timestamp option of type IPv4TimestampOptionValue::TimestampsForPrespecifiedIPs - this type is not supported");
		return;
	}

	if (timestampVal.type == IPv4TimestampOptionValue::TimestampAndIP && timestampVal.timestamps.size() != timestampVal.ipAddresses.size())
	{
		LOG_ERROR("Cannot build timestamp option of type IPv4TimestampOptionValue::TimestampAndIP because number of timestamps and IP addresses is not equal");
		return;
	}

	optionDataLength = timestampVal.timestamps.size()*sizeof(uint32_t) + 2*sizeof(uint8_t);

	if (timestampVal.type == IPv4TimestampOptionValue::TimestampAndIP)
	{
		optionDataLength += timestampVal.timestamps.size()*sizeof(uint32_t);
	}

	(*optionData) = new uint8_t[optionDataLength];

	size_t curOffset = 0;
	(*optionData)[curOffset++] = 1; //pointer default value is 1 - means there are no empty timestamps
	(*optionData)[curOffset++] = (uint8_t)timestampVal.type; // timestamp type

	int firstZero = -1;
	for (int i = 0; i < (int)timestampVal.timestamps.size(); i++)
	{
		uint32_t timestamp = htonl(timestampVal.timestamps.at(i));

		// for pointer calculation - find the first timestamp equals to 0
		if (timestamp == 0 && firstZero == -1)
			firstZero = i;

		if (timestampVal.type == IPv4TimestampOptionValue::TimestampAndIP)
		{
			uint32_t ipAddrAsInt = timestampVal.ipAddresses.at(i).toInt();
			memcpy((*optionData) + curOffset , &ipAddrAsInt, sizeof(uint32_t));
			curOffset += sizeof(uint32_t);
		}

		memcpy((*optionData) + curOffset , &timestamp, sizeof(uint32_t));
		curOffset += sizeof(uint32_t);
	}

	// calculate pointer field
	if (firstZero > -1)
	{
		uint8_t pointerVal = (uint8_t)(4*sizeof(uint8_t) + firstZero*sizeof(uint32_t) + 1);
		if (timestampVal.type == IPv4TimestampOptionValue::TimestampAndIP)
			pointerVal += (uint8_t)(firstZero*sizeof(uint32_t));

		(*optionData)[0] = pointerVal;
	}
}

IPv4OptionData* IPv4Layer::addOption(IPv4OptionTypes optionType, uint8_t optionDataLength, const uint8_t* optionData)
{
	return addOptionAt(optionType, optionDataLength, optionData, getHeaderLen()-m_NumOfTrailingBytes);
}

IPv4OptionData* IPv4Layer::addOption(IPv4OptionTypes optionType, const std::vector<IPv4Address>& ipList)
{
	uint8_t* optionData = NULL;
	int optionDataLength = 0;
	buildIPListOptionData(ipList, &optionData, optionDataLength);

	IPv4OptionData* res = addOption(optionType, optionDataLength, optionData);

	delete [] optionData;

	return res;
}

IPv4OptionData* IPv4Layer::addTimestampOption(const IPv4TimestampOptionValue& timestampValue)
{
	uint8_t* optionData = NULL;
	int optionDataLength = 0;
	buildTimestampOptionData(timestampValue, &optionData, optionDataLength);

	if (optionData == NULL)
		return NULL;

	IPv4OptionData* res = addOption(IPV4OPT_Timestamp, optionDataLength, optionData);

	delete [] optionData;

	return res;
}

IPv4OptionData* IPv4Layer::addOptionAfter(IPv4OptionTypes optionType, uint8_t optionDataLength, const uint8_t* optionData, IPv4OptionTypes prevOption)
{
	int offset = 0;

	IPv4OptionData* prevOpt = getOptionData(prevOption);

	if (prevOpt == NULL)
	{
		offset = sizeof(iphdr);
	}
	else
	{
		offset = (uint8_t*)prevOpt + prevOpt->getTotalSize() - m_Data;
	}

	return addOptionAt(optionType, optionDataLength, optionData, offset);
}

IPv4OptionData* IPv4Layer::addOptionAfter(IPv4OptionTypes optionType, const std::vector<IPv4Address>& ipList, IPv4OptionTypes prevOption)
{
	uint8_t* optionData = NULL;
	int optionDataLength = 0;
	buildIPListOptionData(ipList, &optionData, optionDataLength);

	IPv4OptionData* res = addOptionAfter(optionType, (uint8_t)optionDataLength, optionData, prevOption);

	delete [] optionData;

	return res;
}

IPv4OptionData* IPv4Layer::addTimestampOptionAfter(const IPv4TimestampOptionValue& timestampValue, IPv4OptionTypes prevOption)
{
	uint8_t* optionData = NULL;
	int optionDataLength = 0;
	buildTimestampOptionData(timestampValue, &optionData, optionDataLength);

	if (optionData == NULL)
		return NULL;

	IPv4OptionData* res = addOptionAfter(IPV4OPT_Timestamp, (uint8_t)optionDataLength, optionData, prevOption);

	delete [] optionData;

	return res;
}

bool IPv4Layer::removeOption(IPv4OptionTypes option)
{
	IPv4OptionData* opt = getOptionData(option);
	if (opt == NULL)
	{
		return false;
	}

	// calculate total option size
	IPv4OptionData* curOpt = getFirstOptionData();
	size_t totalOptSize = 0;
	while (curOpt != NULL)
	{
		totalOptSize += curOpt->getTotalSize();
		curOpt = getNextOptionData(curOpt);
	}
	totalOptSize -= opt->getTotalSize();


	int offset = (uint8_t*)opt - m_Data;

	size_t sizeToShorten = opt->getTotalSize();
	if (!shortenLayer(offset, sizeToShorten))
	{
		LOG_ERROR("Failed to remove IPv4 option: cannot shorten layer");
		return false;
	}

	// setting this m_TempHeaderExtension because adjustOptionsTrailer() may extend or shorten the layer and the extend or shorten methods need to know the accurate
	// current size of the header. m_TempHeaderExtension will be added to the length extracted from getIPv4Header()->internetHeaderLength as the temp new size
	m_TempHeaderExtension = 0-sizeToShorten;
	adjustOptionsTrailer(totalOptSize);
	// the adjustOptionsTrailer() adds or removed the trailing bytes and sets getIPv4Header()->internetHeaderLength to the correct size, so the m_TempHeaderExtension
	// isn't needed anymore
	m_TempHeaderExtension = 0;

	incOptionCount(-1);

	return true;
}

bool IPv4Layer::removeAllOptions()
{
	int offset = sizeof(iphdr);

	if (!shortenLayer(offset, getHeaderLen()-offset))
		return false;

	getIPv4Header()->internetHeaderLength = (5 & 0xf);
	m_NumOfTrailingBytes = 0;
	setOptionCount(0);
	return true;
}

} // namespace pcpp
