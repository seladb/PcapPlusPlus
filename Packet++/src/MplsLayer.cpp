#define LOG_MODULE PacketLogModuleMplsLayer

#include "MplsLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include <sstream>
#include "EndianPortable.h"

namespace pcpp
{

	MplsLayer::MplsLayer(uint32_t mplsLabel, uint8_t ttl, uint8_t experimentalUseValue, bool bottomOfStack)
	{
		const size_t headerLen = sizeof(mpls_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		m_Protocol = MPLS;

		setMplsLabel(mplsLabel);
		setTTL(ttl);
		setExperimentalUseValue(experimentalUseValue);
		setBottomOfStack(bottomOfStack);
	}

	bool MplsLayer::isBottomOfStack() const
	{
		return (getMplsHeader()->misc & 0x01);
	}

	void MplsLayer::setBottomOfStack(bool val)
	{
		if (!val)
			getMplsHeader()->misc &= 0xFE;
		else
			getMplsHeader()->misc |= 0x1;
	}

	uint8_t MplsLayer::getExperimentalUseValue() const
	{
		return ((getMplsHeader()->misc & 0x0E) >> 1);
	}

	bool MplsLayer::setExperimentalUseValue(uint8_t val)
	{
		// exp value is only 3 bits
		if (val > 7)
		{
			PCPP_LOG_ERROR("Set ExperimentalUse value got an illegal value: " << (int)val
			                                                                  << ". Value must be lower than 8");
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

	uint32_t MplsLayer::getMplsLabel() const
	{
		return (htobe16(getMplsHeader()->hiLabel) << 4) | ((getMplsHeader()->misc & 0xF0) >> 4);
	}

	bool MplsLayer::setMplsLabel(uint32_t label)
	{
		if (label > 0xFFFFF)
		{
			PCPP_LOG_ERROR(
			    "MPLS label mustn't exceed 20 bits which is the value 0xffff. Got a parameter with the value 0x"
			    << std::hex << label);
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
		hdr->hiLabel = (uint16_t)htobe16(label);

		return true;
	}

	void MplsLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen < headerLen + 1)
			return;

		uint8_t* payload = m_Data + sizeof(mpls_header);
		size_t payloadLen = m_DataLen - sizeof(mpls_header);

		if (!isBottomOfStack())
		{
			m_NextLayer = new MplsLayer(payload, payloadLen, this, m_Packet);
			return;
		}

		uint8_t nextNibble = (*((uint8_t*)(m_Data + headerLen)) & 0xF0) >> 4;
		switch (nextNibble)
		{
		case 4:
			m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
			break;
		case 6:
			m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
			break;
		default:
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		}
	}

	void MplsLayer::computeCalculateFields()
	{
		Layer* nextLayer = getNextLayer();
		if (nextLayer != nullptr)
		{
			setBottomOfStack((nextLayer->getProtocol() != MPLS));
		}
	}

	std::string MplsLayer::toString() const
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

}  // namespace pcpp
