#define LOG_MODULE PacketLogModuleGreLayer

#include "GreLayer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PPPoELayer.h"
#include "VlanLayer.h"
#include "MplsLayer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include "IpUtils.h"
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

// ==============
// GreLayer class
// ==============

namespace pcpp
{

ProtocolType GreLayer::getGREVersion(uint8_t* greData, size_t greDataLen)
{
	if (greDataLen < sizeof(gre_basic_header))
		return UnknownProtocol;

	uint8_t version = *(greData+1);
	version &= 0x07;
	if (version == 0)
		return GREv0;
	else if (version == 1)
		return GREv1;
	else
		return UnknownProtocol;
}

uint8_t* GreLayer::getFieldValue(GreField field, bool returnOffsetEvenIfFieldMissing)
{
	uint8_t* ptr = m_Data + sizeof(gre_basic_header);

	gre_basic_header* header = (gre_basic_header*)m_Data;

	GreField curField = GreChecksumOrRouting;

	while (curField < 4)
	{
		bool curFieldExists = false;

		uint8_t* origPtr = ptr;

		switch (curField)
		{
		case GreChecksumOrRouting:
			if (header->checksumBit == 1 || header->routingBit == 1)
			{
				curFieldExists = true;
				ptr += sizeof(uint32_t);
			}
			break;
		case GreKey:
			if (header->keyBit == 1)
			{
				curFieldExists = true;
				ptr += sizeof(uint32_t);
			}
			break;
		case GreSeq:
			if (header->sequenceNumBit == 1)
			{
				curFieldExists = true;
				ptr += sizeof(uint32_t);
			}
			break;
		case GreAck:
			if (header->ackSequenceNumBit == 1)
			{
				curFieldExists = true;
				ptr += sizeof(uint32_t);
			}
			break;
		default: // shouldn't get there
			return NULL;
		}

		if (field == curField)
		{
			if (curFieldExists || returnOffsetEvenIfFieldMissing)
				return origPtr;
			else
				return NULL;
		}

		int curFieldAsInt = (int)curField;
		curFieldAsInt++;
		curField = static_cast<GreField>(curFieldAsInt);
	}

	return NULL;
}

void GreLayer::computeCalculateFieldsInner()
{
	gre_basic_header* header = (gre_basic_header*)m_Data;
	if (m_NextLayer != NULL)
	{
		switch (m_NextLayer->getProtocol())
		{
		case IPv4:
			header->protocol = htons(PCPP_ETHERTYPE_IP);
			break;
		case IPv6:
			header->protocol = htons(PCPP_ETHERTYPE_IPV6);
			break;
		case VLAN:
			header->protocol = htons(PCPP_ETHERTYPE_VLAN);
			break;
		case MPLS:
			header->protocol = htons(PCPP_ETHERTYPE_MPLS);
			break;
		case PPP_PPTP:
			header->protocol = htons(PCPP_ETHERTYPE_PPP);
			break;

		default:
			break;
		}
	}
}

bool GreLayer::getSequenceNumber(uint32_t& seqNumber)
{
	gre_basic_header* header = (gre_basic_header*)m_Data;

	if (header->sequenceNumBit == 0)
		return false;

	uint32_t* val = (uint32_t*)getFieldValue(GreSeq, false);
	if (val == NULL)
		return false;

	seqNumber = ntohl(*val);
	return true;
}

bool GreLayer::setSequenceNumber(uint32_t seqNumber)
{
	gre_basic_header* header = (gre_basic_header*)m_Data;

	bool needToExtendLayer = false;

	if (header->sequenceNumBit == 0)
		needToExtendLayer = true;

	uint8_t* offsetPtr = getFieldValue(GreSeq, true);

	int offset = offsetPtr - m_Data;
	if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
	{
		header->sequenceNumBit = 0;
		LOG_ERROR("Couldn't extend layer to set sequence number");
		return false;
	}

	header = (gre_basic_header*)m_Data;
	header->sequenceNumBit = 1;
	uint32_t* seqPtr = (uint32_t*)(m_Data + offset);
	*seqPtr = htonl(seqNumber);

	return true;
}

bool GreLayer::unsetSequenceNumber()
{
	gre_basic_header* header = (gre_basic_header*)m_Data;

	if (header->sequenceNumBit == 0)
	{
		LOG_ERROR("Couldn't unset sequence number as it's already unset");
		return false;
	}

	uint8_t* offsetPtr = getFieldValue(GreSeq, true);

	int offset = offsetPtr - m_Data;
	if (!shortenLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Couldn't shorted layer to unset sequence number");
		return false;
	}

	header = (gre_basic_header*)m_Data;
	header->sequenceNumBit = 0;
	return true;
}

void GreLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	gre_basic_header* header = (gre_basic_header*)m_Data;
	switch (ntohs(header->protocol))
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPP:
		m_NextLayer = new PPP_PPTPLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	}
}

size_t GreLayer::getHeaderLen()
{
	size_t result = sizeof(gre_basic_header);

	gre_basic_header* header = (gre_basic_header*)m_Data;

	if (header->checksumBit == 1 || header->routingBit == 1 )
		result += 4;
	if (header->keyBit == 1)
		result += 4;
	if (header->sequenceNumBit == 1)
		result += 4;
	if (header->ackSequenceNumBit == 1)
		result += 4;

	return result;
}



// ================
// GREv0Layer class
// ================


GREv0Layer::GREv0Layer()
{
	m_DataLen = sizeof(gre_basic_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = GREv0;
}

bool GREv0Layer::getChecksum(uint16_t& checksum)
{
	if (getGreHeader()->checksumBit == 0)
		return false;

	uint16_t* val = (uint16_t*)getFieldValue(GreChecksumOrRouting, false);
	if (val == NULL)
		return false;

	checksum = ntohs(*val);
	return true;
}

bool GREv0Layer::setChecksum(uint16_t checksum)
{
	gre_basic_header* header = getGreHeader();

	bool needToExtendLayer = false;

	if (header->routingBit == 0 && header->checksumBit == 0)
		needToExtendLayer = true;

	uint8_t* offsetPtr = getFieldValue(GreChecksumOrRouting, true);
	int offset = offsetPtr - m_Data;
	// extend layer in 4 bytes to keep 4-byte alignment
	if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Couldn't extend layer to set checksum");
		return false;
	}

	uint16_t* checksumPtr = (uint16_t*)(m_Data + offset);
	*checksumPtr = htons(checksum);

	// if layer was extended in 4 bytes, make sure the offset field stays 0
	if (needToExtendLayer)
	{
		checksumPtr++;
		*checksumPtr = 0;
	}

	header = getGreHeader();
	header->checksumBit = 1;

	return true;
}

bool GREv0Layer::unsetChecksum()
{
	gre_basic_header* header = getGreHeader();

	if (header->checksumBit == 0)
	{
		LOG_ERROR("Couldn't unset checksum as it's already unset");
		return false;
	}

	// if both routing and checksum are unset we need to shorted the layer
	bool needToShortenLayer = (header->routingBit == 0);

	uint8_t* offsetPtr = getFieldValue(GreChecksumOrRouting, true);
	int offset = offsetPtr - m_Data;
	if (needToShortenLayer && !shortenLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Couldn't extend layer to unset checksum");
		return false;
	}

	if (!needToShortenLayer) // meaning routing bit is set - only zero the checksum field
	{
		uint16_t* checksumPtr = (uint16_t*)(m_Data + offset);
		*checksumPtr = 0;
	}

	header = getGreHeader();
	header->checksumBit = 0;

	return true;
}

bool GREv0Layer::getOffset(uint16_t& offset)
{
	if (getGreHeader()->routingBit == 0)
		return false;

	uint8_t* val = (uint8_t*)getFieldValue(GreChecksumOrRouting, false);
	if (val == NULL)
		return false;

	offset = ntohs(*(val+2));
	return true;
}

bool GREv0Layer::getKey(uint32_t& key)
{
	if (getGreHeader()->keyBit == 0)
		return false;

	uint32_t* val = (uint32_t*)getFieldValue(GreKey, false);
	if (val == NULL)
		return false;

	key = ntohl(*val);
	return true;
}

bool GREv0Layer::setKey(uint32_t key)
{
	gre_basic_header* header = getGreHeader();

	bool needToExtendLayer = false;

	if (header->keyBit == 0)
		needToExtendLayer = true;

	uint8_t* offsetPtr = getFieldValue(GreKey, true);

	int offset = offsetPtr - m_Data;
	if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
	{
		header->keyBit = 0;
		LOG_ERROR("Couldn't extend layer to set key");
		return false;
	}

	header = getGreHeader();
	header->keyBit = 1;
	uint32_t* keyPtr = (uint32_t*)(m_Data + offset);
	*keyPtr = htonl(key);

	return true;
}

bool GREv0Layer::unsetKey()
{
	gre_basic_header* header = getGreHeader();

	if (header->keyBit == 0)
	{
		LOG_ERROR("Couldn't unset key as it's already unset");
		return false;
	}

	uint8_t* offsetPtr = getFieldValue(GreKey, true);

	int offset = offsetPtr - m_Data;
	if (!shortenLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Couldn't shorted layer to unset key");
		return false;
	}

	header = (gre_basic_header*)m_Data;
	header->keyBit = 0;
	return true;
}

void GREv0Layer::computeCalculateFields()
{
	computeCalculateFieldsInner();

	if (getGreHeader()->checksumBit == 0)
		return;

	// calculate checksum
	setChecksum(0);

	ScalarBuffer<uint16_t> buffer;
	buffer.buffer = (uint16_t*)m_Data;
	buffer.len = m_DataLen;
	size_t checksum = compute_checksum(&buffer, 1);

	setChecksum(checksum);
}

std::string GREv0Layer::toString()
{
	return "GRE Layer, version 0";
}


// ================
// GREv1Layer class
// ================

GREv1Layer::GREv1Layer(uint16_t callID)
{
	m_DataLen = sizeof(gre1_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = GREv1;

	gre1_header* header = getGreHeader();
	header->keyBit = 1;
	header->version = 1;
	header->callID = htons(callID);
}

bool GREv1Layer::getAcknowledgmentNum(uint32_t& ackNum)
{
	if (getGreHeader()->ackSequenceNumBit == 0)
		return false;

	uint32_t* val = (uint32_t*)getFieldValue(GreAck, false);
	if (val == NULL)
		return false;

	ackNum = ntohl(*val);
	return true;
}

bool GREv1Layer::setAcknowledgmentNum(uint32_t ackNum)
{
	bool needToExtendLayer = false;

	gre1_header* header = getGreHeader();

	if (header->ackSequenceNumBit == 0)
		needToExtendLayer = true;

	uint8_t* offsetPtr = getFieldValue(GreAck, true);
	int offset = offsetPtr - m_Data;
	if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Couldn't extend layer to set ack number");
		return false;
	}

	header = getGreHeader();
	header->ackSequenceNumBit = 1;
	uint32_t* ackPtr = (uint32_t*)(m_Data + offset);
	*ackPtr = htonl(ackNum);
	return true;
}

bool GREv1Layer::unsetAcknowledgmentNum()
{
	gre1_header* header = getGreHeader();

	if (header->ackSequenceNumBit == 0)
	{
		LOG_ERROR("Couldn't unset ack number as it's already unset");
		return false;
	}

	uint8_t* offsetPtr = getFieldValue(GreAck, true);

	int offset = offsetPtr - m_Data;
	if (!shortenLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Couldn't shorted layer to unset ack number");
		return false;
	}

	header = getGreHeader();
	header->ackSequenceNumBit = 0;
	return true;
}

void GREv1Layer::computeCalculateFields()
{
	computeCalculateFieldsInner();

	getGreHeader()->payloadLength = htons(m_DataLen - getHeaderLen());
}

std::string GREv1Layer::toString()
{
	return "GRE Layer, version 1";
}



// ===================
// PPP_PPTPLayer class
// ===================

PPP_PPTPLayer::PPP_PPTPLayer(uint8_t address, uint8_t control)
{
	m_DataLen = sizeof(ppp_pptp_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = PPP_PPTP;

	ppp_pptp_header* header = getPPP_PPTPHeader();
	header->address = address;
	header->control = control;
}


void PPP_PPTPLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	switch (ntohs(getPPP_PPTPHeader()->protocol))
	{
	case PCPP_PPP_IP:
		m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PCPP_PPP_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	}
}

void PPP_PPTPLayer::computeCalculateFields()
{
	ppp_pptp_header* header = getPPP_PPTPHeader();
	if (m_NextLayer != NULL)
	{
		switch (m_NextLayer->getProtocol())
		{
		case IPv4:
			header->protocol = htons(PCPP_PPP_IP);
			break;
		case IPv6:
			header->protocol = htons(PCPP_PPP_IPV6);
			break;
		default:
			break;
		}
	}
	else
		header->protocol = 0;
}

} // namespace pcpp
