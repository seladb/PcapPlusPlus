#define LOG_MODULE PacketLogModulePPPoELayer

#include "PPPoELayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include <map>
#include <sstream>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

namespace pcpp
{

/// PPPoELayer
/// ~~~~~~~~~~

PPPoELayer::PPPoELayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId, size_t additionalBytesToAllocate)
{
	m_DataLen = sizeof(pppoe_header) + additionalBytesToAllocate;
	m_Data = new uint8_t[m_DataLen + additionalBytesToAllocate];
	memset(m_Data, 0, m_DataLen + additionalBytesToAllocate);

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
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	switch (getPPPNextProtocol())
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

uint16_t PPPoESessionLayer::getPPPNextProtocol()
{
	if (m_DataLen < getHeaderLen())
	{
		LOG_ERROR("ERROR: size of layer is smaller then PPPoE session header");
		return 0;
	}

	uint16_t pppNextProto = *(uint16_t*)(m_Data + sizeof(pppoe_header));
	return ntohs(pppNextProto);
}

void PPPoESessionLayer::setPPPNextProtocol(uint16_t nextProtocol)
{
	if (m_DataLen < getHeaderLen())
	{
		LOG_ERROR("ERROR: size of layer is smaller then PPPoE session header");
		return;
	}

	uint16_t* pppProto = (uint16_t*)(m_Data + sizeof(pppoe_header));
	*pppProto = htons(nextProtocol);
}

std::map<uint16_t, std::string> createPPPNextProtoToStringMap()
{
	std::map<uint16_t, std::string> tempMap;
	tempMap[PCPP_PPP_PADDING] =     "Padding Protocol";
	tempMap[PCPP_PPP_ROHC_SCID] =   "ROHC small-CID";
	tempMap[PCPP_PPP_ROHC_LCID] =   "ROHC large-CID";
	tempMap[PCPP_PPP_IP] =          "Internet Protocol version 4";
	tempMap[PCPP_PPP_OSI] =         "OSI Network Layer";
	tempMap[PCPP_PPP_XNSIDP] =      "Xerox NS IDP";
	tempMap[PCPP_PPP_DEC4] =        "DECnet Phase IV";
	tempMap[PCPP_PPP_AT] =          "Appletalk";
	tempMap[PCPP_PPP_IPX] =         "Novell IPX";
	tempMap[PCPP_PPP_VJC_COMP] =    "Van Jacobson Compressed TCP/IP";
	tempMap[PCPP_PPP_VJC_UNCOMP] =  "Van Jacobson Uncompressed TCP/IP";
	tempMap[PCPP_PPP_BCP] =         "Bridging PDU";
	tempMap[PCPP_PPP_ST] =          "Stream Protocol (ST-II)";
	tempMap[PCPP_PPP_VINES] =       "Banyan Vines";
	tempMap[PCPP_PPP_AT_EDDP] =     "AppleTalk EDDP";
	tempMap[PCPP_PPP_AT_SB] =       "AppleTalk SmartBuffered";
	tempMap[PCPP_PPP_MP] =          "Multi-Link";
	tempMap[PCPP_PPP_NB] =          "NETBIOS Framing";
	tempMap[PCPP_PPP_CISCO] =       "Cisco Systems";
	tempMap[PCPP_PPP_ASCOM] =       "Ascom Timeplex";
	tempMap[PCPP_PPP_LBLB] =        "Fujitsu Link Backup and Load Balancing (LBLB)";
	tempMap[PCPP_PPP_RL] =          "DCA Remote Lan";
	tempMap[PCPP_PPP_SDTP] =        "Serial Data Transport Protocol (PPP-SDTP)";
	tempMap[PCPP_PPP_LLC] =         "SNA over 802.2";
	tempMap[PCPP_PPP_SNA] =         "SNA";
	tempMap[PCPP_PPP_IPV6HC] =      "IPv6 Header Compression ";
    tempMap[PCPP_PPP_KNX] =         "KNX Bridging Data";
    tempMap[PCPP_PPP_ENCRYPT] =     "Encryption";
    tempMap[PCPP_PPP_ILE] =         "Individual Link Encryption";
    tempMap[PCPP_PPP_IPV6] =        "Internet Protocol version 6";
    tempMap[PCPP_PPP_MUX] =         "PPP Muxing";
    tempMap[PCPP_PPP_VSNP] =        "Vendor-Specific Network Protocol (VSNP)";
    tempMap[PCPP_PPP_TNP] =         "TRILL Network Protocol (TNP)";
    tempMap[PCPP_PPP_RTP_FH] =      "RTP IPHC Full Header";
    tempMap[PCPP_PPP_RTP_CTCP] =    "RTP IPHC Compressed TCP";
    tempMap[PCPP_PPP_RTP_CNTCP] =   "RTP IPHC Compressed Non TCP";
    tempMap[PCPP_PPP_RTP_CUDP8] =   "RTP IPHC Compressed UDP 8";
    tempMap[PCPP_PPP_RTP_CRTP8] =   "RTP IPHC Compressed RTP 8";
    tempMap[PCPP_PPP_STAMPEDE] =    "Stampede Bridging";
    tempMap[PCPP_PPP_MPPLUS] =      "MP+ Protocol";
    tempMap[PCPP_PPP_NTCITS_IPI] =  "NTCITS IPI";
    tempMap[PCPP_PPP_ML_SLCOMP] =   "Single link compression in multilink";
    tempMap[PCPP_PPP_COMP] =        "Compressed datagram";
    tempMap[PCPP_PPP_STP_HELLO] =   "802.1d Hello Packets";
    tempMap[PCPP_PPP_IBM_SR] =      "IBM Source Routing BPDU";
    tempMap[PCPP_PPP_DEC_LB] =      "DEC LANBridge100 Spanning Tree";
    tempMap[PCPP_PPP_CDP] =         "Cisco Discovery Protocol";
    tempMap[PCPP_PPP_NETCS] =       "Netcs Twin Routing";
    tempMap[PCPP_PPP_STP] =         "STP - Scheduled Transfer Protocol";
    tempMap[PCPP_PPP_EDP] =         "EDP - Extreme Discovery Protocol";
    tempMap[PCPP_PPP_OSCP] =        "Optical Supervisory Channel Protocol (OSCP)";
    tempMap[PCPP_PPP_OSCP2] =       "Optical Supervisory Channel Protocol (OSCP)";
    tempMap[PCPP_PPP_LUXCOM] =      "Luxcom";
    tempMap[PCPP_PPP_SIGMA] =       "Sigma Network Systems";
    tempMap[PCPP_PPP_ACSP] =        "Apple Client Server Protocol";
    tempMap[PCPP_PPP_MPLS_UNI] =    "MPLS Unicast";
    tempMap[PCPP_PPP_MPLS_MULTI] =  "MPLS Multicast";
    tempMap[PCPP_PPP_P12844] =      "IEEE p1284.4 standard - data packets";
    tempMap[PCPP_PPP_TETRA] =       "ETSI TETRA Network Protocol Type 1";
    tempMap[PCPP_PPP_MFTP] =        "Multichannel Flow Treatment Protocol";
    tempMap[PCPP_PPP_RTP_CTCPND] =  "RTP IPHC Compressed TCP No Delta";
    tempMap[PCPP_PPP_RTP_CS] =      "RTP IPHC Context State";
    tempMap[PCPP_PPP_RTP_CUDP16] =  "RTP IPHC Compressed UDP 16";
    tempMap[PCPP_PPP_RTP_CRDP16] =  "RTP IPHC Compressed RTP 16";
    tempMap[PCPP_PPP_CCCP] =        "Cray Communications Control Protocol";
    tempMap[PCPP_PPP_CDPD_MNRP] =   "CDPD Mobile Network Registration Protocol";
    tempMap[PCPP_PPP_EXPANDAP] =    "Expand accelerator protocol";
    tempMap[PCPP_PPP_ODSICP] =      "ODSICP NCP";
    tempMap[PCPP_PPP_DOCSIS] =      "DOCSIS DLL";
    tempMap[PCPP_PPP_CETACEANNDP] = "Cetacean Network Detection Protocol";
    tempMap[PCPP_PPP_LZS] =         "Stacker LZS";
    tempMap[PCPP_PPP_REFTEK] =      "RefTek Protocol";
    tempMap[PCPP_PPP_FC] =          "Fibre Channel";
    tempMap[PCPP_PPP_EMIT] =        "EMIT Protocols";
    tempMap[PCPP_PPP_VSP] =         "Vendor-Specific Protocol (VSP)";
    tempMap[PCPP_PPP_TLSP] =        "TRILL Link State Protocol (TLSP)";
    tempMap[PCPP_PPP_IPCP] =        "Internet Protocol Control Protocol";
    tempMap[PCPP_PPP_OSINLCP] =     "OSI Network Layer Control Protocol";
    tempMap[PCPP_PPP_XNSIDPCP] =    "Xerox NS IDP Control Protocol";
    tempMap[PCPP_PPP_DECNETCP] =    "DECnet Phase IV Control Protocol";
    tempMap[PCPP_PPP_ATCP] =        "AppleTalk Control Protocol";
    tempMap[PCPP_PPP_IPXCP] =       "Novell IPX Control Protocol";
    tempMap[PCPP_PPP_BRIDGENCP] =   "Bridging NCP";
    tempMap[PCPP_PPP_SPCP] =        "Stream Protocol Control Protocol";
    tempMap[PCPP_PPP_BVCP] =        "Banyan Vines Control Protocol";
    tempMap[PCPP_PPP_MLCP] =        "Multi-Link Control Protocol";
    tempMap[PCPP_PPP_NBCP] =        "NETBIOS Framing Control Protocol";
    tempMap[PCPP_PPP_CISCOCP] =     "Cisco Systems Control Protocol";
    tempMap[PCPP_PPP_ASCOMCP] =     "Ascom Timeplex";
    tempMap[PCPP_PPP_LBLBCP] =      "Fujitsu LBLB Control Protocol";
    tempMap[PCPP_PPP_RLNCP] =       "DCA Remote Lan Network Control Protocol (RLNCP)";
    tempMap[PCPP_PPP_SDCP] =        "Serial Data Control Protocol (PPP-SDCP)";
    tempMap[PCPP_PPP_LLCCP] =       "SNA over 802.2 Control Protocol";
    tempMap[PCPP_PPP_SNACP] =       "SNA Control Protocol";
    tempMap[PCPP_PPP_IP6HCCP] =     "IP6 Header Compression Control Protocol";
    tempMap[PCPP_PPP_KNXCP] =       "KNX Bridging Control Protocol";
    tempMap[PCPP_PPP_ECP] =         "Encryption Control Protocol";
    tempMap[PCPP_PPP_ILECP] =       "Individual Link Encryption Control Protocol";
    tempMap[PCPP_PPP_IPV6CP] =      "IPv6 Control Protocol";
    tempMap[PCPP_PPP_MUXCP] =       "PPP Muxing Control Protocol";
    tempMap[PCPP_PPP_VSNCP] =       "Vendor-Specific Network Control Protocol (VSNCP)";
    tempMap[PCPP_PPP_TNCP] =        "TRILL Network Control Protocol";
    tempMap[PCPP_PPP_STAMPEDECP] =  "Stampede Bridging Control Protocol";
    tempMap[PCPP_PPP_MPPCP] =       "MP+ Control Protocol";
    tempMap[PCPP_PPP_IPICP] =       "NTCITS IPI Control Protocol";
    tempMap[PCPP_PPP_SLCC] =        "Single link compression in multilink control";
    tempMap[PCPP_PPP_CCP] =         "Compression Control Protocol";
    tempMap[PCPP_PPP_CDPCP] =       "Cisco Discovery Protocol Control Protocol";
    tempMap[PCPP_PPP_NETCSCP] =     "Netcs Twin Routing";
    tempMap[PCPP_PPP_STPCP] =       "STP - Control Protocol";
    tempMap[PCPP_PPP_EDPCP] =       "EDPCP - Extreme Discovery Protocol Control Protocol";
    tempMap[PCPP_PPP_ACSPC] =       "Apple Client Server Protocol Control";
    tempMap[PCPP_PPP_MPLSCP] =      "MPLS Control Protocol";
    tempMap[PCPP_PPP_P12844CP] =    "IEEE p1284.4 standard - Protocol Control";
    tempMap[PCPP_PPP_TETRACP] =     "ETSI TETRA TNP1 Control Protocol";
    tempMap[PCPP_PPP_MFTPCP] =      "Multichannel Flow Treatment Protocol";
    tempMap[PCPP_PPP_LCP] =         "Link Control Protocol";
    tempMap[PCPP_PPP_PAP] =         "Password Authentication Protocol";
    tempMap[PCPP_PPP_LQR] =         "Link Quality Report";
    tempMap[PCPP_PPP_SPAP] =        "Shiva Password Authentication Protocol";
    tempMap[PCPP_PPP_CBCP] =        "Callback Control Protocol (CBCP)";
    tempMap[PCPP_PPP_BACP] =        "BACP Bandwidth Allocation Control Protocol";
    tempMap[PCPP_PPP_BAP] =         "BAP Bandwidth Allocation Protocol";
    tempMap[PCPP_PPP_VSAP] =        "Vendor-Specific Authentication Protocol (VSAP)";
    tempMap[PCPP_PPP_CONTCP] =      "Container Control Protocol";
    tempMap[PCPP_PPP_CHAP] =        "Challenge Handshake Authentication Protocol";
    tempMap[PCPP_PPP_RSAAP] =       "RSA Authentication Protocol";
    tempMap[PCPP_PPP_EAP] =         "Extensible Authentication Protocol";
    tempMap[PCPP_PPP_SIEP] =        "Mitsubishi Security Information Exchange Protocol (SIEP)";
    tempMap[PCPP_PPP_SBAP] =        "Stampede Bridging Authorization Protocol";
    tempMap[PCPP_PPP_PRPAP] =       "Proprietary Authentication Protocol";
    tempMap[PCPP_PPP_PRPAP2] =      "Proprietary Authentication Protocol";
    tempMap[PCPP_PPP_PRPNIAP] =     "Proprietary Node ID Authentication Protocol";
	return tempMap;
}

const std::map<uint16_t, std::string> PPPNextProtoToString = createPPPNextProtoToStringMap();

std::string PPPoESessionLayer::toString()
{
	std::map<uint16_t, std::string>::const_iterator iter = PPPNextProtoToString.find(getPPPNextProtocol());
	std::string nextProtocol;
	if (iter != PPPNextProtoToString.end())
		nextProtocol = iter->second;
	else
	{
		std::ostringstream stream;
		stream << "Unknown (0x" << std::hex << getPPPNextProtocol() << ")";
		nextProtocol = stream.str();
	}

	return "PPP-over-Ethernet Session (followed by '" + nextProtocol +  "')";
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
	while ((curTagPtr - m_Data) < (int)m_DataLen)
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
		LOG_ERROR("Could not extend PPPoEDiscoveryLayer in [%d] bytes", (int)tagTotalLength);
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
	case PPPoELayer::PPPOE_CODE_SESSION:return std::string("PPPoE Session");
	case PPPoELayer::PPPOE_CODE_PADO:	return std::string("PADO");
	case PPPoELayer::PPPOE_CODE_PADI:	return std::string("PADI");
	case PPPoELayer::PPPOE_CODE_PADG:	return std::string("PADG");
	case PPPoELayer::PPPOE_CODE_PADC:	return std::string("PADC");
	case PPPoELayer::PPPOE_CODE_PADQ:	return std::string("PADQ");
	case PPPoELayer::PPPOE_CODE_PADR:	return std::string("PADR");
	case PPPoELayer::PPPOE_CODE_PADS:	return std::string("PADS");
	case PPPoELayer::PPPOE_CODE_PADT:	return std::string("PADT");
	case PPPoELayer::PPPOE_CODE_PADM:	return std::string("PADM");
	case PPPoELayer::PPPOE_CODE_PADN:	return std::string("PADN");
	default:							return std::string("Unknown PPPoE code");
	}
}

} // namespace pcpp
