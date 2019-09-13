#include <map>
#include <sstream>
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

bool GtpV1Layer::GtpExtension::isNull()
{
    return m_Data == NULL;
}

uint8_t GtpV1Layer::GtpExtension::getExtensionType()
{
    return m_ExtType;
}

size_t GtpV1Layer::GtpExtension::getTotalLength()
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

size_t GtpV1Layer::GtpExtension::getContentLength()
{
    size_t res = getTotalLength();

    if (res >= 2*sizeof(uint8_t))
    {
        return (size_t)(res - 2*sizeof(uint8_t));
    }

    return 0;
}

uint8_t* GtpV1Layer::GtpExtension::getContent()
{
    if (m_Data == NULL || getContentLength() == 0)
    {
        return NULL;
    }

    return m_Data + sizeof(uint8_t);
}

uint8_t GtpV1Layer::GtpExtension::getNextExtensionHeaderType()
{
    if (m_Data == NULL || getTotalLength() < 4)
    {
        return 0;
    }

    uint8_t res = *(uint8_t*)(m_Data + sizeof(uint8_t) + getContentLength());

    return res;
}

GtpV1Layer::GtpExtension GtpV1Layer::GtpExtension::getNextExtension()
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



/// ================
/// GtpV1Layer class
/// ================


bool GtpV1Layer::isGTPv1(const uint8_t* data, size_t dataSize)
{
    if (data != NULL && dataSize > 1 && (data[0] & 0xE0) == 0x20)
    {
        return true;
    }

    return false;
}

GtpV1Layer::gtpv1_header_extra* GtpV1Layer::getHeaderExtra()
{
    if (m_Data != NULL && m_DataLen >= sizeof(gtpv1_header) + sizeof(gtpv1_header_extra))
    {
        return (gtpv1_header_extra*)(m_Data + sizeof(gtpv1_header));
    }

    return NULL;
}

bool GtpV1Layer::getSequenceNumber(uint16_t& seqNumber)
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

bool GtpV1Layer::getNpduNumber(uint8_t& npduNum)
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

bool GtpV1Layer::getNextExtensionHeaderType(uint8_t& nextExtType)
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

GtpV1Layer::GtpExtension GtpV1Layer::getNextExtension()
{
    uint8_t nextExtType = 0;
    bool nextExtExists = getNextExtensionHeaderType(nextExtType);
    if (!nextExtExists || nextExtType == 0 || m_DataLen < sizeof(gtpv1_header) + sizeof(uint8_t))
    {
        return GtpV1Layer::GtpExtension();
    }

    return GtpV1Layer::GtpExtension(m_Data + sizeof(gtpv1_header) + sizeof(gtpv1_header_extra), m_DataLen - sizeof(gtpv1_header) - sizeof(gtpv1_header_extra), nextExtType);
}

GtpV1MessageType GtpV1Layer::getMessageType()
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

    tempMap[0] =   "GTPv1 Message Type Unknown";
    tempMap[1] =   "Echo Request";
    tempMap[2] =   "Echo Response";
    tempMap[3] =   "Version Not Supported";
    tempMap[4] =   "Node Alive Request";
    tempMap[5] =   "Node Alive Response";
    tempMap[6] =   "Redirection Request";
    tempMap[7] =   "Create PDP Context Request";
    tempMap[16] =  "Create PDP Context Response";
    tempMap[17] =  "Update PDP Context Request";
    tempMap[18] =  "Update PDP Context Response";
    tempMap[19] =  "Delete PDP Context Request";
    tempMap[20] =  "Delete PDP Context Response";
    tempMap[22] =  "Initiate PDP Context Activation Request";
    tempMap[23] =  "Initiate PDP Context Activation Response";
    tempMap[26] =  "Error Indication";
    tempMap[27] =  "PDU Notification Request";
    tempMap[28] =  "PDU Notification Response";
    tempMap[29] =  "PDU Notification Reject Request";
    tempMap[30] =  "PDU Notification Reject Response";
    tempMap[31] =  "Supported Extensions Header Notification";
    tempMap[32] =  "Send Routing for GPRS Request";
    tempMap[33] =  "Send Routing for GPRS Response";
    tempMap[34] =  "Failure Report Request";
    tempMap[35] =  "Failure Report Response";
    tempMap[36] =  "Note MS Present Request";
    tempMap[37] =  "Note MS Present Response";
    tempMap[38] =  "Identification Request";
    tempMap[39] =  "Identification Response";
    tempMap[50] =  "SGSN Context Request";
    tempMap[51] =  "SGSN Context Response";
    tempMap[52] =  "SGSN Context Acknowledge";
    tempMap[53] =  "Forward Relocation Request";
    tempMap[54] =  "Forward Relocation Response";
    tempMap[55] =  "Forward Relocation Complete";
    tempMap[56] =  "Relocation Cancel Request";
    tempMap[57] =  "Relocation Cancel Response";
    tempMap[58] =  "Forward SRNS Context";
    tempMap[59] =  "Forward Relocation Complete Acknowledge";
    tempMap[60] =  "Forward SRNS Context Acknowledge";
    tempMap[61] =  "UE Registration Request";
    tempMap[62] =  "UE Registration Response";
    tempMap[70] =  "RAN Information Relay";
    tempMap[96] =  "MBMS Notification Request";
    tempMap[97] =  "MBMS Notification Response";
    tempMap[98] =  "MBMS Notification Reject Request";
    tempMap[99] =  "MBMS Notification Reject Response";
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

std::string GtpV1Layer::getMessageTypeAsString()
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

bool GtpV1Layer::isGTPUMessage()
{
    gtpv1_header* header = getHeader();
    if (header == NULL)
    {
        return false;
    }

    return header->messageType == PCPP_GTP_V1_GPDU_MESSAGE_TYPE;
}

bool GtpV1Layer::isGTPCMessage()
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

    uint8_t subProto = *(uint8_t*)(m_Data + headerLen);
    if (subProto >= 0x45 && subProto <= 0x4e)
    {
        m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
    }
    else if ((subProto & 0xf0) == 0x60)
    {
        m_NextLayer = new IPv6Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
    }
    else
    {
        m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
    }
}

size_t GtpV1Layer::getHeaderLen()
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

std::string GtpV1Layer::toString()
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

}