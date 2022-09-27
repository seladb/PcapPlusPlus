#define LOG_MODULE PacketLogModuleL2tpLayer

#include "L2tpLayer.h"
#include "EndianPortable.h"
#include "EthDot3Layer.h"
#include "EthLayer.h"
#include "GreLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Logger.h"
#include "MplsLayer.h"
#include "PPPoELayer.h"
#include "PacketUtils.h"
#include "PayloadLayer.h"
#include "VlanLayer.h"

// ==============
// L2tpLayer class
// ==============

namespace pcpp
{
void L2tpLayer::ToStructuredOutput(std::ostream &os) const
{
	bool control = isControlMessage();

	os << "l2tp Header:" << '\n';
	os << "\t"
	   << "control bytes: \t" << (std::bitset<8>)(uint16_t)*m_Data << '\n';
	os << "\t"
	   << "tunnel id: \t\t" << getTunnelID() << '\n';
	os << "\t"
	   << "session id: \t" << getSessionID() << '\n';
	if (control)
	{
		os << "\t"
		   << "type: \t\t\tcontrol message" << '\n'
		   << "\t"
		   << "length: \t\t" << getLength() << '\n'
		   << "\t"
		   << "Ns: \t\t\t" << getNs() << '\n'
		   << "\t"
		   << "Nr: \t\t\t" << getNr() << '\n';
	}
	else
	{
		os << "\t"
		   << "type: \t\t\tdata message\n"
		   << "\t"
		   << "offset: \t\t" << getOffset() << '\n'
		   << "\t"
		   << "priority: \t";
		if (isPriority())
		{
			os << "yes";
		}
		else
		{
			os << "no";
		}
		os << '\n';
	}
}

bool L2tpLayer::isFieldTrue(L2tpField field) const
{
	uint8_t *ptr = m_Data;

	bool curFieldExists = false;

	switch (field)
	{
	case L2tpTypeBit:
		curFieldExists = true;
		break;
	case L2tpLengthBit:
		curFieldExists = true;
		ptr += 1;
		break;
	case L2tpSequenceBit:
		curFieldExists = true;
		ptr += 4;
		break;
	case L2tpOffsetBit:
		curFieldExists = true;
		ptr += 6;
		break;
	case L2tpPriorityBit:
		curFieldExists = true;
		ptr += 7;
		break;
	default: // shouldn't get there
		return false;
	}

	if (curFieldExists)
		return (bool *)ptr;

	return false;
}

uint16_t L2tpLayer::getLength() const
{
	if (isControlMessage() && isFieldTrue(L2tpLengthBit))
	{
		l2tphdr_control *h = (l2tphdr_control *)m_Data;
		return h->length;
	}
	return -1;
}
uint16_t L2tpLayer::getTunnelID() const
{
	if (isControlMessage())
	{
		l2tphdr_control *h = (l2tphdr_control *)m_Data;
		return h->tunnelID;
	}
	l2tphdr_data *h = (l2tphdr_data *)m_Data;
	return h->tunnelID;
}
uint16_t L2tpLayer::getSessionID() const
{
	if (isControlMessage())
	{
		l2tphdr_control *h = (l2tphdr_control *)m_Data;
		return h->sessionID;
	}
	l2tphdr_data *h = (l2tphdr_data *)m_Data;
	return h->sessionID;
}
uint16_t L2tpLayer::getNs() const
{
	if (isControlMessage() && isFieldTrue(L2tpSequenceBit))
	{
		l2tphdr_control *h = (l2tphdr_control *)m_Data;
		return h->ns;
	}
	return -1;
}
uint16_t L2tpLayer::getNr() const
{
	if (isControlMessage() && isFieldTrue(L2tpSequenceBit))
	{
		l2tphdr_control *h = (l2tphdr_control *)m_Data;
		return h->nr;
	}
	return -1;
}

uint32_t L2tpLayer::getOffset() const
{
	if (isDataMessage() && isFieldTrue(L2tpOffsetBit))
	{
		l2tphdr_data *h = (l2tphdr_data *)m_Data;
		return uint16_t((h->offset) << 16 | h->offsetPadding);
	}
	return -1;
}
bool L2tpLayer::isPriority() const
{
	if (isDataMessage() && isFieldTrue(L2tpPriorityBit))
		return true;
	return false;
}

void L2tpLayer::computeCalculateFields()
{
}

void L2tpLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	uint8_t *payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;

	// TODO: is there any difference between control and data messages?
	m_NextLayer = new PPP_PPTPLayer(payload, payloadLen, this, m_Packet);
}

size_t L2tpLayer::getHeaderLen() const
{
	return sizeof(*m_header);
}

std::string L2tpLayer::toString() const
{
	std::stringstream stream;
	ToStructuredOutput(stream);
	return stream.str();
}

} // namespace pcpp