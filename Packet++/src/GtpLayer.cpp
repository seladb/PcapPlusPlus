#define LOG_MODULE PacketLogModuleGtpLayer

#include <map>
#include <sstream>
#include "Logger.h"
#include "GtpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"

namespace pcpp
{

#define PCPP_GTP_V1_GPDU_MESSAGE_TYPE 0xff

/// ==================
/// GtpExtension class
/// ==================


GtpV1Layer::GtpExtension::GtpExtension()
{
	m_Data = NULL;
	m_DataLen = 0;
	m_ExtType = 0;
}

GtpV1Layer::GtpExtension::GtpExtension(uint8_t* data, size_t dataLen, uint8_t type)
{
	m_Data = data;
	m_DataLen = dataLen;
	m_ExtType = type;
}

GtpV1Layer::GtpExtension::GtpExtension(const GtpExtension& other)
{
	m_Data = other.m_Data;
	m_DataLen = other.m_DataLen;
	m_ExtType = other.m_ExtType;
}

GtpV1Layer::GtpExtension& GtpV1Layer::GtpExtension::operator=(const GtpV1Layer::GtpExtension& other)
{
	m_Data = other.m_Data;
	m_DataLen = other.m_DataLen;
	m_ExtType = other.m_ExtType;
	return *this;
}

bool GtpV1Layer::GtpExtension::isNull() const
{
	return m_Data == NULL;
}

uint8_t GtpV1Layer::GtpExtension::getExtensionType() const
{
	return m_ExtType;
}

size_t GtpV1Layer::GtpExtension::getTotalLength() const
{
	if (m_Data == NULL)
	{
		return 0;
	}

	size_t len = (size_t)(m_Data[0]*4);
	if (len <= m_DataLen)
	{
		return len;
	}

	return m_DataLen;
}

size_t GtpV1Layer::GtpExtension::getContentLength() const
{
	size_t res = getTotalLength();

	if (res >= 2*sizeof(uint8_t))
	{
		return (size_t)(res - 2*sizeof(uint8_t));
	}

	return 0;
}

uint8_t* GtpV1Layer::GtpExtension::getContent() const
{
	if (m_Data == NULL || getContentLength() == 0)
	{
		return NULL;
	}

	return m_Data + sizeof(uint8_t);
}

uint8_t GtpV1Layer::GtpExtension::getNextExtensionHeaderType() const
{
	if (m_Data == NULL || getTotalLength() < 4)
	{
		return 0;
	}

	uint8_t res = *(uint8_t*)(m_Data + sizeof(uint8_t) + getContentLength());

	return res;
}

GtpV1Layer::GtpExtension GtpV1Layer::GtpExtension::getNextExtension() const
{
	size_t totalLength = getTotalLength();
	uint8_t nextExtType = getNextExtensionHeaderType();
	if (nextExtType > 0 && m_DataLen > totalLength + sizeof(uint8_t))
	{
		return GtpV1Layer::GtpExtension(m_Data + totalLength, m_DataLen - totalLength, nextExtType);
	}
	else
	{
		return GtpV1Layer::GtpExtension();
	}
}

void GtpV1Layer::GtpExtension::setNextHeaderType(uint8_t nextHeaderType)
{
	if (m_Data != NULL && m_DataLen > 1)
	{
		m_Data[getTotalLength() - 1] = nextHeaderType;
	}
}

GtpV1Layer::GtpExtension GtpV1Layer::GtpExtension::createGtpExtension(uint8_t* data, size_t dataLen, uint8_t extType, uint16_t content)
{
	if (dataLen < 4*sizeof(uint8_t))
	{
		return GtpExtension();
	}

	data[0] = 1;
	data[1] = (content >> 8);
	data[2] = content & 0xff;
	data[3] = 0;

	return GtpV1Layer::GtpExtension(data, dataLen, extType);
}




/// ================
/// GtpV1Layer class
/// ================


GtpV1Layer::GtpV1Layer(GtpV1MessageType messageType, uint32_t teid)
{
	init(messageType, teid, false, 0, false, 0);
}

GtpV1Layer::GtpV1Layer(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum, uint8_t npduNum)
{
	init(messageType, teid, setSeqNum, seqNum, setNpduNum, npduNum);
}

void GtpV1Layer::init(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum, uint8_t npduNum)
{
	size_t dataLen = sizeof(gtpv1_header);
	if (setSeqNum || setNpduNum)
	{
		dataLen += sizeof(gtpv1_header_extra);
	}

	m_DataLen = dataLen;
	m_Data = new uint8_t[dataLen];
	memset(m_Data, 0, dataLen);
	m_Protocol = GTPv1;

	gtpv1_header* hdr = getHeader();
	hdr->version = 1;
	hdr->protocolType = 1;
	hdr->messageType = (uint8_t)messageType;
	hdr->teid = htobe32(teid);

	if (setSeqNum || setNpduNum)
	{
		hdr->messageLength = htobe16(sizeof(gtpv1_header_extra));
		gtpv1_header_extra* extraHdr = getHeaderExtra();
		if (setSeqNum)
		{
			hdr->sequenceNumberFlag = 1;
			extraHdr->sequenceNumber = htobe16(seqNum);
		}

		if (setNpduNum)
		{
			hdr->npduNumberFlag = 1;
			extraHdr->npduNumber = npduNum;
		}
	}
}


bool GtpV1Layer::isGTPv1(const uint8_t* data, size_t dataSize)
{
	if(data != NULL && dataSize >= sizeof(gtpv1_header) && (data[0] & 0xE0) == 0x20)
	{
		return true;
	}

	return false;
}

GtpV1Layer::gtpv1_header_extra* GtpV1Layer::getHeaderExtra() const
{
	if (m_Data != NULL && m_DataLen >= sizeof(gtpv1_header) + sizeof(gtpv1_header_extra))
	{
		return (gtpv1_header_extra*)(m_Data + sizeof(gtpv1_header));
	}

	return NULL;
}

bool GtpV1Layer::getSequenceNumber(uint16_t& seqNumber) const
{
	gtpv1_header* header = getHeader();
	gtpv1_header_extra* headerExtra = getHeaderExtra();
	if (header != NULL && headerExtra != NULL && header->sequenceNumberFlag == 1)
	{
		seqNumber = be16toh(headerExtra->sequenceNumber);
		return true;
	}

	return false;
}

bool GtpV1Layer::setSequenceNumber(const uint16_t seqNumber)
{
	// get GTP header
	gtpv1_header* header = getHeader();
	if (header == NULL)
	{
		PCPP_LOG_ERROR("Set sequence failed: GTP header is NULL");
		return false;
	}

	// if all flags are unset then create the GTP extra header
	if (header->npduNumberFlag == 0 && header->sequenceNumberFlag == 0 && header->extensionHeaderFlag == 0)
	{
		if (!extendLayer(sizeof(gtpv1_header), sizeof(gtpv1_header_extra)))
		{
			PCPP_LOG_ERROR("Set sequence failed: cannot extend layer");
			return false;
		}
		header = getHeader();
	}

	// get the extra header
	gtpv1_header_extra* headerExtra = getHeaderExtra();
	if (headerExtra == NULL)
	{
		PCPP_LOG_ERROR("Set sequence failed: extra header is NULL");
		return false;
	}

	// set seq number
	header->sequenceNumberFlag = 1;
	headerExtra->sequenceNumber = htobe16(seqNumber);

	// extend GTP length
	header->messageLength = htobe16(be16toh(header->messageLength) + sizeof(gtpv1_header_extra));

	return true;
}

bool GtpV1Layer::getNpduNumber(uint8_t& npduNum) const
{
	gtpv1_header* header = getHeader();
	gtpv1_header_extra* headerExtra = getHeaderExtra();
	if (header != NULL && headerExtra != NULL && header->npduNumberFlag == 1)
	{
		npduNum = headerExtra->npduNumber;
		return true;
	}

	return false;
}

bool GtpV1Layer::setNpduNumber(const uint8_t npduNum)
{
	// get GTP header
	gtpv1_header* header = getHeader();
	if (header == NULL)
	{
		PCPP_LOG_ERROR("Set N-PDU failed: GTP header is NULL");
		return false;
	}

	// if all flags are unset then create the GTP extra header
	if (header->npduNumberFlag == 0 && header->sequenceNumberFlag == 0 && header->extensionHeaderFlag == 0)
	{
		if (!extendLayer(sizeof(gtpv1_header), sizeof(gtpv1_header_extra)))
		{
			PCPP_LOG_ERROR("Set N-PDU failed: cannot extend layer");
			return false;
		}
		header = getHeader();
	}

	// get the extra header
	gtpv1_header_extra* headerExtra = getHeaderExtra();
	if (headerExtra == NULL)
	{
		PCPP_LOG_ERROR("Set N-PDU failed: extra header is NULL");
		return false;
	}

	// set N-PDU value
	header->npduNumberFlag = 1;
	headerExtra->npduNumber = npduNum;

	// extend GTP length
	header->messageLength = htobe16(be16toh(header->messageLength) + sizeof(gtpv1_header_extra));

	return true;
}

bool GtpV1Layer::getNextExtensionHeaderType(uint8_t& nextExtType) const
{
	gtpv1_header* header = getHeader();
	gtpv1_header_extra* headerExtra = getHeaderExtra();
	if (header != NULL && headerExtra != NULL && header->extensionHeaderFlag == 1)
	{
		nextExtType = headerExtra->nextExtensionHeader;
		return true;
	}

	return false;
}

GtpV1Layer::GtpExtension GtpV1Layer::getNextExtension() const
{
	uint8_t nextExtType = 0;
	bool nextExtExists = getNextExtensionHeaderType(nextExtType);
	if (!nextExtExists || nextExtType == 0 || m_DataLen <= sizeof(gtpv1_header) + sizeof(gtpv1_header_extra))
	{
		return GtpV1Layer::GtpExtension();
	}

	return GtpV1Layer::GtpExtension(m_Data + sizeof(gtpv1_header) + sizeof(gtpv1_header_extra), m_DataLen - sizeof(gtpv1_header) - sizeof(gtpv1_header_extra), nextExtType);
}

GtpV1Layer::GtpExtension GtpV1Layer::addExtension(uint8_t extensionType, uint16_t extensionContent)
{
	// get GTP header
	gtpv1_header* header = getHeader();
	if (header == NULL)
	{
		PCPP_LOG_ERROR("Add extension failed: GTP header is NULL");
		return GtpExtension();
	}

	size_t offsetForNewExtension = sizeof(gtpv1_header);

	// if all flags are unset then create the GTP extra header
	if (header->npduNumberFlag == 0 && header->sequenceNumberFlag == 0 && header->extensionHeaderFlag == 0)
	{
		if (!extendLayer(offsetForNewExtension, sizeof(gtpv1_header_extra)))
		{
			PCPP_LOG_ERROR("Add extension failed: cannot extend layer");
			return GtpExtension();
		}
		header = getHeader();
	}

	// get the extra header
	gtpv1_header_extra* headerExtra = getHeaderExtra();
	if (headerExtra == NULL)
	{
		PCPP_LOG_ERROR("Add extension failed: extra header is NULL");
		return GtpExtension();
	}

	offsetForNewExtension += sizeof(gtpv1_header_extra);

	// find the last GTP header extension
	GtpV1Layer::GtpExtension lastExt = getNextExtension();

	// go over the GTP header extensions
	while (!lastExt.getNextExtension().isNull())
	{
		// add ext total length to offset
		offsetForNewExtension += lastExt.getTotalLength();
		lastExt = lastExt.getNextExtension();
	}

	// lastExt != null means layer contains 1 or more extensions
	if (!lastExt.isNull())
	{
		// add ext total length to offset
		offsetForNewExtension += lastExt.getTotalLength();
	}

	// allocate extension space in layer (assuming extension length can only be 4 bytes)
	if (!extendLayer(offsetForNewExtension, 4*sizeof(uint8_t)))
	{
		PCPP_LOG_ERROR("Add extension failed: cannot extend layer");
		return GtpExtension();
	}

	// lastExt != null means layer contains 1 or more extensions
	if (!lastExt.isNull())
	{
		// set the next header type in the last extension
		lastExt.setNextHeaderType(extensionType);
	}
	else
	{
		// mark extension flags in the layer
		header->extensionHeaderFlag = 1;
		headerExtra->nextExtensionHeader = extensionType;
	}

	// create the extension data and return the extension object to the user
	return GtpV1Layer::GtpExtension::createGtpExtension(
		m_Data + offsetForNewExtension,
		m_DataLen - offsetForNewExtension,
		extensionType,
		extensionContent);
}

GtpV1MessageType GtpV1Layer::getMessageType() const
{
	gtpv1_header* header = getHeader();

	if (header == NULL)
	{
		return GtpV1_MessageTypeUnknown;
	}

	return (GtpV1MessageType)header->messageType;
}

std::map<uint8_t, std::string> createGtpV1MessageTypeToStringMap()
{
	std::map<uint8_t, std::string> tempMap;

	tempMap[0] = "GTPv1 Message Type Unknown";
	tempMap[1] = "Echo Request";
	tempMap[2] = "Echo Response";
	tempMap[3] = "Version Not Supported";
	tempMap[4] = "Node Alive Request";
	tempMap[5] = "Node Alive Response";
	tempMap[6] = "Redirection Request";
	tempMap[7] = "Create PDP Context Request";
	tempMap[16] = "Create PDP Context Response";
	tempMap[17] = "Update PDP Context Request";
	tempMap[18] = "Update PDP Context Response";
	tempMap[19] = "Delete PDP Context Request";
	tempMap[20] = "Delete PDP Context Response";
	tempMap[22] = "Initiate PDP Context Activation Request";
	tempMap[23] = "Initiate PDP Context Activation Response";
	tempMap[26] = "Error Indication";
	tempMap[27] = "PDU Notification Request";
	tempMap[28] = "PDU Notification Response";
	tempMap[29] = "PDU Notification Reject Request";
	tempMap[30] = "PDU Notification Reject Response";
	tempMap[31] = "Supported Extensions Header Notification";
	tempMap[32] = "Send Routing for GPRS Request";
	tempMap[33] = "Send Routing for GPRS Response";
	tempMap[34] = "Failure Report Request";
	tempMap[35] = "Failure Report Response";
	tempMap[36] = "Note MS Present Request";
	tempMap[37] = "Note MS Present Response";
	tempMap[38] = "Identification Request";
	tempMap[39] = "Identification Response";
	tempMap[50] = "SGSN Context Request";
	tempMap[51] = "SGSN Context Response";
	tempMap[52] = "SGSN Context Acknowledge";
	tempMap[53] = "Forward Relocation Request";
	tempMap[54] = "Forward Relocation Response";
	tempMap[55] = "Forward Relocation Complete";
	tempMap[56] = "Relocation Cancel Request";
	tempMap[57] = "Relocation Cancel Response";
	tempMap[58] = "Forward SRNS Context";
	tempMap[59] = "Forward Relocation Complete Acknowledge";
	tempMap[60] = "Forward SRNS Context Acknowledge";
	tempMap[61] = "UE Registration Request";
	tempMap[62] = "UE Registration Response";
	tempMap[70] = "RAN Information Relay";
	tempMap[96] = "MBMS Notification Request";
	tempMap[97] = "MBMS Notification Response";
	tempMap[98] = "MBMS Notification Reject Request";
	tempMap[99] = "MBMS Notification Reject Response";
	tempMap[100] = "Create MBMS Notification Request";
	tempMap[101] = "Create MBMS Notification Response";
	tempMap[102] = "Update MBMS Notification Request";
	tempMap[103] = "Update MBMS Notification Response";
	tempMap[104] = "Delete MBMS Notification Request";
	tempMap[105] = "Delete MBMS Notification Response";
	tempMap[112] = "MBMS Registration Request";
	tempMap[113] = "MBMS Registration Response";
	tempMap[114] = "MBMS De-Registration Request";
	tempMap[115] = "MBMS De-Registration Response";
	tempMap[116] = "MBMS Session Start Request";
	tempMap[117] = "MBMS Session Start Response";
	tempMap[118] = "MBMS Session Stop Request";
	tempMap[119] = "MBMS Session Stop Response";
	tempMap[120] = "MBMS Session Update Request";
	tempMap[121] = "MBMS Session Update Response";
	tempMap[128] = "MS Info Change Request";
	tempMap[129] = "MS Info Change Response";
	tempMap[240] = "Data Record Transfer Request";
	tempMap[241] = "Data Record Transfer Response";
	tempMap[254] = "End Marker";
	tempMap[255] = "G-PDU";

	return tempMap;
}

const std::map<uint8_t, std::string> GTPv1MsgTypeToStringMap = createGtpV1MessageTypeToStringMap();

std::string GtpV1Layer::getMessageTypeAsString() const
{
	gtpv1_header* header = getHeader();

	if (header == NULL)
	{
		return GTPv1MsgTypeToStringMap.find(0)->second;
	}

	std::map<uint8_t, std::string>::const_iterator iter = GTPv1MsgTypeToStringMap.find(header->messageType);
	if (iter != GTPv1MsgTypeToStringMap.end())
	{
		return iter->second;
	}
	else
	{
		return GTPv1MsgTypeToStringMap.find(0)->second;
	}
}

bool GtpV1Layer::isGTPUMessage() const
{
	gtpv1_header* header = getHeader();
	if (header == NULL)
	{
		return false;
	}

	return header->messageType == PCPP_GTP_V1_GPDU_MESSAGE_TYPE;
}

bool GtpV1Layer::isGTPCMessage() const
{
	gtpv1_header* header = getHeader();
	if (header == NULL)
	{
		return false;
	}

	return header->messageType != PCPP_GTP_V1_GPDU_MESSAGE_TYPE;
}


void GtpV1Layer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (headerLen < sizeof(gtpv1_header))
	{
		// do nothing
		return;
	}

	gtpv1_header* header = getHeader();
	if (header->messageType != PCPP_GTP_V1_GPDU_MESSAGE_TYPE)
	{
		// this is a GTP-C message, hence it is the last layer
		return;
	}

	if (m_DataLen <= headerLen)
	{
		// no data beyond headerLen, nothing to parse further
		return;
	}

	// GTP-U message, try to parse the next layer

	uint8_t* payload = (uint8_t*)(m_Data + headerLen);
	size_t payloadLen = m_DataLen - headerLen;

	uint8_t subProto = *payload;
	if (subProto >= 0x45 && subProto <= 0x4e)
	{
		m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
	}
	else if ((subProto & 0xf0) == 0x60)
	{
		m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
	}
	else
	{
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
}

size_t GtpV1Layer::getHeaderLen() const
{
	gtpv1_header* header = getHeader();
	if (header == NULL)
	{
		return 0;
	}

	size_t res = sizeof(gtpv1_header);

	if (header->messageType != PCPP_GTP_V1_GPDU_MESSAGE_TYPE)
	{
		size_t msgLen = be16toh(header->messageLength);
		res += (msgLen > m_DataLen - sizeof(gtpv1_header) ? m_DataLen - sizeof(gtpv1_header) : msgLen);
	}
	else
	{
		gtpv1_header_extra* headerExtra = getHeaderExtra();
		if (headerExtra != NULL && (header->extensionHeaderFlag == 1 || header->sequenceNumberFlag == 1 || header->npduNumberFlag == 1))
		{
			res += sizeof(gtpv1_header_extra);
			GtpExtension nextExt = getNextExtension();
			while (!nextExt.isNull())
			{
				res += nextExt.getTotalLength();
				nextExt = nextExt.getNextExtension();
			}
		}
	}

	return res;
}

std::string GtpV1Layer::toString() const
{
	std::string res = "GTP v1 Layer";

	gtpv1_header* header = getHeader();
	if (header != NULL)
	{
		std::stringstream teidStream;
		teidStream << be32toh(header->teid);

		std::string gtpu_gtpc;
		if (header->messageType == PCPP_GTP_V1_GPDU_MESSAGE_TYPE)
		{
			gtpu_gtpc = "GTP-U message";
		}
		else
		{
			gtpu_gtpc = "GTP-C message: " + getMessageTypeAsString();
		}

		res += ", " + gtpu_gtpc + ", TEID: " + teidStream.str();
	}

	return res;
}

void GtpV1Layer::computeCalculateFields()
{
	gtpv1_header* hdr = getHeader();
	if (hdr == NULL)
	{
		return;
	}

	hdr->messageLength = htobe16(m_DataLen - sizeof(gtpv1_header));
}

}
