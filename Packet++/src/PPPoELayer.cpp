#define LOG_MODULE PacketLogModulePPPoELayer

#include <PPPoELayer.h>
#include <PayloadLayer.h>
#include <Logger.h>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

/// PPPoELayer
/// ~~~~~~~~~~

PPPoELayer::PPPoELayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId)
{
	m_DataLen = sizeof(pppoe_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, sizeof(m_DataLen));

	pppoe_header* pppoeHdr = getPPPoEHeader();
	pppoeHdr->version = (version & 0xf);
	pppoeHdr->type = (type & 0x0f);
	pppoeHdr->code = code;
	pppoeHdr->sessionId = htons(sessionId);
	pppoeHdr->payloadLength = 0;
}

void PPPoELayer::computeCalculateFields()
{
	pppoe_header* pppoeHdr = (pppoe_header*)m_Data;
	pppoeHdr->payloadLength = htons(m_DataLen - sizeof(pppoe_header));
}



/// PPPoESessionLayer
/// ~~~~~~~~~~~~~~~~~


void PPPoESessionLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(pppoe_header))
		return;

	m_NextLayer = new PayloadLayer(m_Data + sizeof(pppoe_header), m_DataLen - sizeof(pppoe_header), this);
}



/// PPPoEDiscoveryLayer
/// ~~~~~~~~~~~~~~~~~~~


PPPoEDiscoveryLayer::PPPoETagTypes PPPoEDiscoveryLayer::PPPoETag::getType()
{
	return (PPPoEDiscoveryLayer::PPPoETagTypes)ntohs(tagType);
}

size_t PPPoEDiscoveryLayer::PPPoETag::getTagTotalSize() const
{
	return 2*sizeof(uint16_t) + ntohs(tagDataLength);
}

PPPoEDiscoveryLayer::PPPoETag* PPPoEDiscoveryLayer::getTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType)
{
	// check if there are tags at all
	if (m_DataLen <= sizeof(pppoe_header))
		return NULL;

	uint8_t* curTagPtr = m_Data + sizeof(pppoe_header);
	while ((curTagPtr - m_Data) < m_DataLen)
	{
		PPPoEDiscoveryLayer::PPPoETag* curTag = castPtrToPPPoETag(curTagPtr);
		if (curTag->tagType == htons(tagType))
			return curTag;

		curTagPtr += curTag->getTagTotalSize();
	}

	return NULL;
}

PPPoEDiscoveryLayer::PPPoETag* PPPoEDiscoveryLayer::getFirstTag()
{
	// check if there are tags at all
	if (m_DataLen <= sizeof(pppoe_header))
		return NULL;

	uint8_t* curTagPtr = m_Data + sizeof(pppoe_header);
	return castPtrToPPPoETag(curTagPtr);
}

PPPoEDiscoveryLayer::PPPoETag* PPPoEDiscoveryLayer::getNextTag(PPPoEDiscoveryLayer::PPPoETag* tag)
{
	if (tag == NULL)
		return NULL;

	// prev tag was the last tag
	if ((uint8_t*)tag + tag->getTagTotalSize() - m_Data >= (int)m_DataLen)
		return NULL;

	return castPtrToPPPoETag((uint8_t*)tag + tag->getTagTotalSize());
}

int PPPoEDiscoveryLayer::getTagCount()
{
	if (m_TagCount != -1)
		return m_TagCount;

	m_TagCount = 0;
	PPPoEDiscoveryLayer::PPPoETag* curTag = getFirstTag();
	while (curTag != NULL)
	{
		m_TagCount++;
		curTag = getNextTag(curTag);
	}

	return m_TagCount;
}

PPPoEDiscoveryLayer::PPPoETag* PPPoEDiscoveryLayer::addTagAt(PPPoETagTypes tagType, uint16_t tagLength, const uint8_t* tagData, int offset)
{
	size_t tagTotalLength = 2*sizeof(uint16_t) + tagLength;
	if (!extendLayer(offset, tagTotalLength))
	{
		LOG_ERROR("Could not extend PPPoEDiscoveryLayer in [%d] bytes", tagTotalLength);
		return NULL;
	}

	uint16_t tagTypeVal = htons((uint16_t)tagType);
	tagLength = htons(tagLength);
	memcpy(m_Data + offset, &tagTypeVal, sizeof(uint16_t));
	memcpy(m_Data + offset + sizeof(uint16_t), &tagLength, sizeof(uint16_t));
	if (tagLength > 0 && tagData != NULL)
		memcpy(m_Data + offset + 2*sizeof(uint16_t), tagData, ntohs(tagLength));

	uint8_t* newTagPtr = m_Data + offset;

	getPPPoEHeader()->payloadLength += htons(tagTotalLength);
	m_TagCount++;

	return castPtrToPPPoETag(newTagPtr);
}

PPPoEDiscoveryLayer::PPPoETag* PPPoEDiscoveryLayer::addTagAfter(PPPoETagTypes tagType, uint16_t tagLength, const uint8_t* tagData, PPPoEDiscoveryLayer::PPPoETag* prevTag)
{
	if (prevTag == NULL)
	{
		LOG_ERROR("prevTag is NULL");
		return NULL;
	}

	int offset = (uint8_t*)prevTag + prevTag->getTagTotalSize() - m_Data;

	return addTagAt(tagType, tagLength, tagData, offset);
}

PPPoEDiscoveryLayer::PPPoETag* PPPoEDiscoveryLayer::addTag(PPPoETagTypes tagType, uint16_t tagLength, const uint8_t* tagData)
{
	return addTagAt(tagType, tagLength, tagData, getHeaderLen());
}

size_t PPPoEDiscoveryLayer::getHeaderLen()
{
	return sizeof(pppoe_header) + ntohs(getPPPoEHeader()->payloadLength);
}

PPPoEDiscoveryLayer::PPPoETag* PPPoEDiscoveryLayer::castPtrToPPPoETag(uint8_t* ptr)
{
	return (PPPoEDiscoveryLayer::PPPoETag*)ptr;
}

bool PPPoEDiscoveryLayer::removeTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType)
{
	PPPoEDiscoveryLayer::PPPoETag* tag = getTag(tagType);
	if (tag == NULL)
	{
		LOG_ERROR("Couldn't find tag");
		return false;
	}

	int offset = (uint8_t*)tag - m_Data;

	return shortenLayer(offset, tag->getTagTotalSize());
}

bool PPPoEDiscoveryLayer::removeAllTags()
{
	int offset = sizeof(pppoe_header);
	return shortenLayer(offset, m_DataLen-offset);
}

std::string PPPoEDiscoveryLayer::codeToString(PPPoECode code)
{
	switch (code)
	{
	case PPPoELayer::PPPOE_CODE_SESSION:return string("PPPoE Session");
	case PPPoELayer::PPPOE_CODE_PADO:	return string("PADO");
	case PPPoELayer::PPPOE_CODE_PADI:	return string("PADI");
	case PPPoELayer::PPPOE_CODE_PADG:	return string("PADG");
	case PPPoELayer::PPPOE_CODE_PADC:	return string("PADC");
	case PPPoELayer::PPPOE_CODE_PADQ:	return string("PADQ");
	case PPPoELayer::PPPOE_CODE_PADR:	return string("PADR");
	case PPPoELayer::PPPOE_CODE_PADS:	return string("PADS");
	case PPPoELayer::PPPOE_CODE_PADT:	return string("PADT");
	case PPPoELayer::PPPOE_CODE_PADM:	return string("PADM");
	case PPPoELayer::PPPOE_CODE_PADN:	return string("PADN");
	default:							return string("Unknown PPPoE code");
	}
}


