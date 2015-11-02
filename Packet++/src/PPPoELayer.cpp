#define LOG_MODULE PacketLogModulePPPoELayer

#include <PPPoELayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PayloadLayer.h>
#include <Logger.h>
#include <map>
#include <sstream>
#ifdef WIN32
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

/// PPPoELayer
/// ~~~~~~~~~~

PPPoELayer::PPPoELayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId, size_t additionalBytesToAllocate)
{
	m_DataLen = sizeof(pppoe_header) + additionalBytesToAllocate;
	m_Data = new uint8_t[m_DataLen + + additionalBytesToAllocate];
	memset(m_Data, 0, sizeof(m_DataLen) + additionalBytesToAllocate);

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
	case PPP_IP:
		m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PPP_IPV6:
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
	tempMap[PPP_PADDING] =     "Padding Protocol";
	tempMap[PPP_ROHC_SCID] =   "ROHC small-CID";
	tempMap[PPP_ROHC_LCID] =   "ROHC large-CID";
	tempMap[PPP_IP] =          "Internet Protocol version 4";
	tempMap[PPP_OSI] =         "OSI Network Layer";
	tempMap[PPP_XNSIDP] =      "Xerox NS IDP";
	tempMap[PPP_DEC4] =        "DECnet Phase IV";
	tempMap[PPP_AT] =          "Appletalk";
	tempMap[PPP_IPX] =         "Novell IPX";
	tempMap[PPP_VJC_COMP] =    "Van Jacobson Compressed TCP/IP";
	tempMap[PPP_VJC_UNCOMP] =  "Van Jacobson Uncompressed TCP/IP";
	tempMap[PPP_BCP] =         "Bridging PDU";
	tempMap[PPP_ST] =          "Stream Protocol (ST-II)";
	tempMap[PPP_VINES] =       "Banyan Vines";
	tempMap[PPP_AT_EDDP] =     "AppleTalk EDDP";
	tempMap[PPP_AT_SB] =       "AppleTalk SmartBuffered";
	tempMap[PPP_MP] =          "Multi-Link";
	tempMap[PPP_NB] =          "NETBIOS Framing";
	tempMap[PPP_CISCO] =       "Cisco Systems";
	tempMap[PPP_ASCOM] =       "Ascom Timeplex";
	tempMap[PPP_LBLB] =        "Fujitsu Link Backup and Load Balancing (LBLB)";
	tempMap[PPP_RL] =          "DCA Remote Lan";
	tempMap[PPP_SDTP] =        "Serial Data Transport Protocol (PPP-SDTP)";
	tempMap[PPP_LLC] =         "SNA over 802.2";
	tempMap[PPP_SNA] =         "SNA";
	tempMap[PPP_IPV6HC] =      "IPv6 Header Compression ";
    tempMap[PPP_KNX] =         "KNX Bridging Data";
    tempMap[PPP_ENCRYPT] =     "Encryption";
    tempMap[PPP_ILE] =         "Individual Link Encryption";
    tempMap[PPP_IPV6] =        "Internet Protocol version 6";
    tempMap[PPP_MUX] =         "PPP Muxing";
    tempMap[PPP_VSNP] =        "Vendor-Specific Network Protocol (VSNP)";
    tempMap[PPP_TNP] =         "TRILL Network Protocol (TNP)";
    tempMap[PPP_RTP_FH] =      "RTP IPHC Full Header";
    tempMap[PPP_RTP_CTCP] =    "RTP IPHC Compressed TCP";
    tempMap[PPP_RTP_CNTCP] =   "RTP IPHC Compressed Non TCP";
    tempMap[PPP_RTP_CUDP8] =   "RTP IPHC Compressed UDP 8";
    tempMap[PPP_RTP_CRTP8] =   "RTP IPHC Compressed RTP 8";
    tempMap[PPP_STAMPEDE] =    "Stampede Bridging";
    tempMap[PPP_MPPLUS] =      "MP+ Protocol";
    tempMap[PPP_NTCITS_IPI] =  "NTCITS IPI";
    tempMap[PPP_ML_SLCOMP] =   "Single link compression in multilink";
    tempMap[PPP_COMP] =        "Compressed datagram";
    tempMap[PPP_STP_HELLO] =   "802.1d Hello Packets";
    tempMap[PPP_IBM_SR] =      "IBM Source Routing BPDU";
    tempMap[PPP_DEC_LB] =      "DEC LANBridge100 Spanning Tree";
    tempMap[PPP_CDP] =         "Cisco Discovery Protocol";
    tempMap[PPP_NETCS] =       "Netcs Twin Routing";
    tempMap[PPP_STP] =         "STP - Scheduled Transfer Protocol";
    tempMap[PPP_EDP] =         "EDP - Extreme Discovery Protocol";
    tempMap[PPP_OSCP] =        "Optical Supervisory Channel Protocol (OSCP)";
    tempMap[PPP_OSCP2] =       "Optical Supervisory Channel Protocol (OSCP)";
    tempMap[PPP_LUXCOM] =      "Luxcom";
    tempMap[PPP_SIGMA] =       "Sigma Network Systems";
    tempMap[PPP_ACSP] =        "Apple Client Server Protocol";
    tempMap[PPP_MPLS_UNI] =    "MPLS Unicast";
    tempMap[PPP_MPLS_MULTI] =  "MPLS Multicast";
    tempMap[PPP_P12844] =      "IEEE p1284.4 standard - data packets";
    tempMap[PPP_TETRA] =       "ETSI TETRA Network Protocol Type 1";
    tempMap[PPP_MFTP] =        "Multichannel Flow Treatment Protocol";
    tempMap[PPP_RTP_CTCPND] =  "RTP IPHC Compressed TCP No Delta";
    tempMap[PPP_RTP_CS] =      "RTP IPHC Context State";
    tempMap[PPP_RTP_CUDP16] =  "RTP IPHC Compressed UDP 16";
    tempMap[PPP_RTP_CRDP16] =  "RTP IPHC Compressed RTP 16";
    tempMap[PPP_CCCP] =        "Cray Communications Control Protocol";
    tempMap[PPP_CDPD_MNRP] =   "CDPD Mobile Network Registration Protocol";
    tempMap[PPP_EXPANDAP] =    "Expand accelerator protocol";
    tempMap[PPP_ODSICP] =      "ODSICP NCP";
    tempMap[PPP_DOCSIS] =      "DOCSIS DLL";
    tempMap[PPP_CETACEANNDP] = "Cetacean Network Detection Protocol";
    tempMap[PPP_LZS] =         "Stacker LZS";
    tempMap[PPP_REFTEK] =      "RefTek Protocol";
    tempMap[PPP_FC] =          "Fibre Channel";
    tempMap[PPP_EMIT] =        "EMIT Protocols";
    tempMap[PPP_VSP] =         "Vendor-Specific Protocol (VSP)";
    tempMap[PPP_TLSP] =        "TRILL Link State Protocol (TLSP)";
    tempMap[PPP_IPCP] =        "Internet Protocol Control Protocol";
    tempMap[PPP_OSINLCP] =     "OSI Network Layer Control Protocol";
    tempMap[PPP_XNSIDPCP] =    "Xerox NS IDP Control Protocol";
    tempMap[PPP_DECNETCP] =    "DECnet Phase IV Control Protocol";
    tempMap[PPP_ATCP] =        "AppleTalk Control Protocol";
    tempMap[PPP_IPXCP] =       "Novell IPX Control Protocol";
    tempMap[PPP_BRIDGENCP] =   "Bridging NCP";
    tempMap[PPP_SPCP] =        "Stream Protocol Control Protocol";
    tempMap[PPP_BVCP] =        "Banyan Vines Control Protocol";
    tempMap[PPP_MLCP] =        "Multi-Link Control Protocol";
    tempMap[PPP_NBCP] =        "NETBIOS Framing Control Protocol";
    tempMap[PPP_CISCOCP] =     "Cisco Systems Control Protocol";
    tempMap[PPP_ASCOMCP] =     "Ascom Timeplex";
    tempMap[PPP_LBLBCP] =      "Fujitsu LBLB Control Protocol";
    tempMap[PPP_RLNCP] =       "DCA Remote Lan Network Control Protocol (RLNCP)";
    tempMap[PPP_SDCP] =        "Serial Data Control Protocol (PPP-SDCP)";
    tempMap[PPP_LLCCP] =       "SNA over 802.2 Control Protocol";
    tempMap[PPP_SNACP] =       "SNA Control Protocol";
    tempMap[PPP_IP6HCCP] =     "IP6 Header Compression Control Protocol";
    tempMap[PPP_KNXCP] =       "KNX Bridging Control Protocol";
    tempMap[PPP_ECP] =         "Encryption Control Protocol";
    tempMap[PPP_ILECP] =       "Individual Link Encryption Control Protocol";
    tempMap[PPP_IPV6CP] =      "IPv6 Control Protocol";
    tempMap[PPP_MUXCP] =       "PPP Muxing Control Protocol";
    tempMap[PPP_VSNCP] =       "Vendor-Specific Network Control Protocol (VSNCP)";
    tempMap[PPP_TNCP] =        "TRILL Network Control Protocol";
    tempMap[PPP_STAMPEDECP] =  "Stampede Bridging Control Protocol";
    tempMap[PPP_MPPCP] =       "MP+ Control Protocol";
    tempMap[PPP_IPICP] =       "NTCITS IPI Control Protocol";
    tempMap[PPP_SLCC] =        "Single link compression in multilink control";
    tempMap[PPP_CCP] =         "Compression Control Protocol";
    tempMap[PPP_CDPCP] =       "Cisco Discovery Protocol Control Protocol";
    tempMap[PPP_NETCSCP] =     "Netcs Twin Routing";
    tempMap[PPP_STPCP] =       "STP - Control Protocol";
    tempMap[PPP_EDPCP] =       "EDPCP - Extreme Discovery Protocol Control Protocol";
    tempMap[PPP_ACSPC] =       "Apple Client Server Protocol Control";
    tempMap[PPP_MPLSCP] =      "MPLS Control Protocol";
    tempMap[PPP_P12844CP] =    "IEEE p1284.4 standard - Protocol Control";
    tempMap[PPP_TETRACP] =     "ETSI TETRA TNP1 Control Protocol";
    tempMap[PPP_MFTPCP] =      "Multichannel Flow Treatment Protocol";
    tempMap[PPP_LCP] =         "Link Control Protocol";
    tempMap[PPP_PAP] =         "Password Authentication Protocol";
    tempMap[PPP_LQR] =         "Link Quality Report";
    tempMap[PPP_SPAP] =        "Shiva Password Authentication Protocol";
    tempMap[PPP_CBCP] =        "Callback Control Protocol (CBCP)";
    tempMap[PPP_BACP] =        "BACP Bandwidth Allocation Control Protocol";
    tempMap[PPP_BAP] =         "BAP Bandwidth Allocation Protocol";
    tempMap[PPP_VSAP] =        "Vendor-Specific Authentication Protocol (VSAP)";
    tempMap[PPP_CONTCP] =      "Container Control Protocol";
    tempMap[PPP_CHAP] =        "Challenge Handshake Authentication Protocol";
    tempMap[PPP_RSAAP] =       "RSA Authentication Protocol";
    tempMap[PPP_EAP] =         "Extensible Authentication Protocol";
    tempMap[PPP_SIEP] =        "Mitsubishi Security Information Exchange Protocol (SIEP)";
    tempMap[PPP_SBAP] =        "Stampede Bridging Authorization Protocol";
    tempMap[PPP_PRPAP] =       "Proprietary Authentication Protocol";
    tempMap[PPP_PRPAP2] =      "Proprietary Authentication Protocol";
    tempMap[PPP_PRPNIAP] =     "Proprietary Node ID Authentication Protocol";
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


