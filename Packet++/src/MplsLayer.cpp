#define LOG_MODULE PacketLogModuleMplsLayer

#include "MplsLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include <string.h>
#include <sstream>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

namespace pcpp
{

MplsLayer::MplsLayer(uint32_t mplsLabel, uint8_t ttl, uint8_t expermentalUseValue, bool bottomOfStack)
{
	m_DataLen = sizeof(mpls_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = MPLS;

	setMplsLabel(mplsLabel);
	setTTL(ttl);
	setExperimentalUseValue(expermentalUseValue);
	setBottomOfStack(bottomOfStack);
}

bool MplsLayer::isBottomOfStack()
{
	return (getMplsHeader()->misc & 0x01);
}

void MplsLayer::setBottomOfStack(bool val)
{
	if (!val)
		getMplsHeader()->misc &= 0xFE;
	else
		getMplsHeader()->misc |= 0xFF;
}

uint8_t MplsLayer::getExperimentalUseValue()
{
	return ((getMplsHeader()->misc & 0x0E) >> 1);
}

bool MplsLayer::setExperimentalUseValue(uint8_t val)
{
	// exp value is only 3 bits
	if (val > 7)
	{
		LOG_ERROR("Set ExperimentalUse value got an illegal value: %d. Value must be lower than 8", val);
		return false;
	}

	mpls_header* hdr = getMplsHeader();

	// clear the 3 exp bits
	hdr->misc &= 0xF1;

	// move the 3 bits to their place
	val = val << 1;

	hdr->misc |= val;

	return true;
}

uint32_t MplsLayer::getMplsLabel()
{
	return (htons(getMplsHeader()->hiLabel) << 4) | ((getMplsHeader()->misc & 0xF0) >> 4);
}

bool MplsLayer::setMplsLabel(uint32_t label)
{
	if (label > 0xFFFFF)
	{
		LOG_ERROR("MPLS label mustn't exceed 20 bits which is the value %d. Got a parameter with the value %d", 0xFFFFF, label);
		return false;
	}

	mpls_header* hdr = getMplsHeader();

	// clear the 4 label bits in misc field
	hdr->misc &= 0x0F;

	// take the last nibble of the label value and move this nibble to its place in misc
	uint8_t miscVal = (label & 0x0F) << 4;

	// update misc field
	hdr->misc |= miscVal;

	// get rid of the nibble that went to misc
	label = label >> 4;

	// set the high 2 bytes of the label
	hdr->hiLabel = (uint16_t)htons(label);

	return true;
}


void MplsLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen < headerLen + 1)
		return;

	if (!isBottomOfStack())
	{
		m_NextLayer = new MplsLayer(m_Data + sizeof(mpls_header), m_DataLen - sizeof(mpls_header), this, m_Packet);
		return;
	}

	uint8_t nextNibble = (*((uint8_t*)(m_Data + headerLen)) & 0xF0) >> 4;

	if (nextNibble == 4)
		m_NextLayer = new IPv4Layer(m_Data + sizeof(mpls_header), m_DataLen - sizeof(mpls_header), this, m_Packet);
	else if (nextNibble == 6)
		m_NextLayer = new IPv6Layer(m_Data + sizeof(mpls_header), m_DataLen - sizeof(mpls_header), this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(m_Data + sizeof(mpls_header), m_DataLen - sizeof(mpls_header), this, m_Packet);
}

void MplsLayer::computeCalculateFields()
{
	Layer* nextLayer = getNextLayer();
	if (nextLayer != NULL)
	{
		setBottomOfStack((nextLayer->getProtocol() == MPLS));
	}
}

std::string MplsLayer::toString()
{
	std::ostringstream labelStream;
	labelStream << getMplsLabel();
	std::ostringstream expStream;
	expStream << (int)getExperimentalUseValue();
	std::ostringstream ttlStream;
	ttlStream << (int)getTTL();
	std::string bottomOfStack = isBottomOfStack() ? "true" : "false";

	return "MPLS Layer, Label: " + labelStream.str() + ", Exp: " + expStream.str() + ", TTL: " + ttlStream.str() +
			", Bottom of stack: " + bottomOfStack;
}

} // namespace pcpp
