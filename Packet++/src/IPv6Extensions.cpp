#define LOG_MODULE PacketLogModuleIPv6ExtensionLayer

#include <sstream>
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif
#include "Logger.h"
#include "IPv6Extensions.h"
#include "IPv6Layer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"
#include "GreLayer.h"

namespace pcpp
{

// =============
// IPv6Extension
// =============

IPv6Extension& IPv6Extension::operator=(const IPv6Extension& other)
{
	// notice this is not necessarily safe - it assumes the current extension has enough memory allocated to consume
	// the other extension. That's why the assignment operator isn't public (it's currently used only inside IPv6Layer)
	memcpy(getDataPtr(), other.getDataPtr(), other.getExtensionLen());
	m_NextHeader = NULL;
	m_ExtType = other.m_ExtType;

	return *this;
}

uint8_t* IPv6Extension::getDataPtr() const
{
	if (m_DataContainer != NULL)
		return m_DataContainer->getDataPtr(m_Offset);

	return m_ShadowData;
}

void IPv6Extension::initShadowPtr(size_t size)
{
	m_ShadowData = new uint8_t[size];
}

IPv6Extension::~IPv6Extension()
{
	if (m_ShadowData != NULL)
		delete [] m_ShadowData;
}

// =======================
// IPv6FragmentationHeader
// =======================

IPv6FragmentationHeader::IPv6FragmentationHeader(uint32_t fragId, uint16_t fragOffset, bool lastFragment)
{
	initShadowPtr(sizeof(ipv6_frag_header));
	m_ExtType = IPv6Fragmentation;
	memset(getDataPtr(), 0, sizeof(ipv6_frag_header));

	ipv6_frag_header* fragHdr = getFragHeader();
	fragHdr->nextHeader = 0;
	fragHdr->headerLen = 0;
	fragHdr->id = htonl(fragId);

	fragOffset /= 8;
	fragOffset = htons(fragOffset << 3) & (uint16_t)0xf8ff;
	if (!lastFragment)
		fragOffset = fragOffset | 0x0100;

	fragHdr->fragOffsetAndFlags = fragOffset;
}

bool IPv6FragmentationHeader::isFirstFragment()
{
	return (getFragmentOffset() == 0);
}

bool IPv6FragmentationHeader::isLastFragment()
{
	return (!isMoreFragments());
}

bool IPv6FragmentationHeader::isMoreFragments()
{
	uint8_t isMoreFragsBit = (getFragHeader()->fragOffsetAndFlags & (uint16_t)0x0100) >> 8;
	return (isMoreFragsBit == 1);
}

uint16_t IPv6FragmentationHeader::getFragmentOffset()
{
	uint16_t fragOffset = (ntohs(getFragHeader()->fragOffsetAndFlags & (uint16_t)0xf8ff) >> 3) * 8;
	return fragOffset;
}

// ================
// TLVOptionBuilder
// ================

IPv6TLVOptionHeader::TLVOptionBuilder::TLVOptionBuilder(uint8_t optType, uint8_t optDataLen, const uint8_t* optValue)
{
	init(optType, optDataLen, optValue);
}

IPv6TLVOptionHeader::TLVOptionBuilder::TLVOptionBuilder(uint8_t optType, uint8_t optValue)
{
	init(optType, sizeof(uint8_t), &optValue);
}

IPv6TLVOptionHeader::TLVOptionBuilder::TLVOptionBuilder(uint8_t optType, uint16_t optValue)
{
	init(optType, sizeof(uint16_t), (uint8_t*)&optValue);
}

IPv6TLVOptionHeader::TLVOptionBuilder::TLVOptionBuilder(const TLVOptionBuilder& other )
{
	size_t totalSize = other.build()->getTotalSize();
	m_OptionBuffer = new uint8_t[totalSize];
	memcpy(m_OptionBuffer, other.m_OptionBuffer, totalSize);
}

void IPv6TLVOptionHeader::TLVOptionBuilder::init(uint8_t optType, uint8_t optDataLen, const uint8_t* optValue)
{
	size_t optionTotalSize = sizeof(uint8_t);
	if (optType != IPv6TLVOptionHeader::TLVOption::Pad0OptionType)
		optionTotalSize += sizeof(uint8_t) + optDataLen;

	m_OptionBuffer = new uint8_t[optionTotalSize];
	memset(m_OptionBuffer, 0, optionTotalSize);

	if (optType != IPv6TLVOptionHeader::TLVOption::Pad0OptionType)
	{
		m_OptionBuffer[0] = optType;
		m_OptionBuffer[1] = optDataLen;
		if (optDataLen > 0)
			memcpy(m_OptionBuffer+2, optValue, optDataLen);
	}
}


// ===================
// IPv6TLVOptionHeader
// ===================

IPv6TLVOptionHeader::TLVOption* IPv6TLVOptionHeader::getOption(uint8_t optionType)
{
	// check if there are options at all
	if (getExtensionLen() <= sizeof(ipv6_ext_base_header))
		return NULL;

	IPv6TLVOptionHeader::TLVOption* curOpt = getFirstOption();
	while (curOpt != NULL)
	{
		if (curOpt->optionType == optionType)
			return curOpt;

		curOpt = getNextOption(curOpt);
	}

	return NULL;
}

IPv6TLVOptionHeader::TLVOption* IPv6TLVOptionHeader::getFirstOption()
{
	// check if there are options at all
	if (getExtensionLen() <= sizeof(ipv6_ext_base_header))
		return NULL;

	uint8_t* curOptPtr = getDataPtr() + sizeof(ipv6_ext_base_header);
	return (IPv6TLVOptionHeader::TLVOption*)(curOptPtr);
}

IPv6TLVOptionHeader::TLVOption* IPv6TLVOptionHeader::getNextOption(IPv6TLVOptionHeader::TLVOption* option)
{
	if (option == NULL)
		return NULL;

	// option pointer is out-bounds of the extension memory
	if (((uint8_t*)option - getDataPtr()) < 0)
		return NULL;

	// option pointer is out-bounds of the extension memory
	if ((uint8_t*)option + option->getTotalSize() - getDataPtr() >= (int)getExtensionLen())
		return NULL;

	IPv6TLVOptionHeader::TLVOption* nextOption = (IPv6TLVOptionHeader::TLVOption*)((uint8_t*)option + option->getTotalSize());

	return nextOption;
}

size_t IPv6TLVOptionHeader::getOptionCount()
{
	if (m_OptionCount != (size_t)-1)
		return m_OptionCount;

	m_OptionCount = 0;
	IPv6TLVOptionHeader::TLVOption* curOpt = getFirstOption();
	while (curOpt != NULL)
	{
		m_OptionCount++;
		curOpt = getNextOption(curOpt);
	}

	return m_OptionCount;
}

IPv6TLVOptionHeader::IPv6TLVOptionHeader(const std::vector<TLVOptionBuilder>& options)
{
	m_ExtType = IPv6ExtensionUnknown;
	m_OptionCount = options.size();

	size_t totalSize = sizeof(uint16_t); // nextHeader + headerLen

	for (std::vector<TLVOptionBuilder>::const_iterator iter = options.begin(); iter != options.end(); iter++)
		totalSize += iter->build()->getTotalSize();

	while (totalSize % 8 != 0)
		totalSize++;

	initShadowPtr(totalSize);
	memset(getDataPtr(), 0, totalSize);

	getBaseHeader()->headerLen = ((totalSize / 8) - 1);

	size_t offset = sizeof(uint16_t);

	for (std::vector<TLVOptionBuilder>::const_iterator iter = options.begin(); iter != options.end(); iter++)
	{
		TLVOption* option = iter->build();
		memcpy((uint8_t*)(getDataPtr() + offset), iter->getRawBuffer(), option->getTotalSize());
		offset += option->getTotalSize();
	}
}

IPv6TLVOptionHeader::IPv6TLVOptionHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset)
{
	m_OptionCount = (size_t)-1;
}


// =================
// IPv6RoutingHeader
// =================

IPv6RoutingHeader::IPv6RoutingHeader(uint8_t routingType, uint8_t segmentsLeft, const uint8_t* additionalRoutingData, size_t additionalRoutingDataLen)
{
	size_t totalSize = sizeof(ipv6_routing_header) + additionalRoutingDataLen;
	while (totalSize % 8 != 0)
		totalSize++;

	initShadowPtr(totalSize);
	memset(getDataPtr(), 0, totalSize);

	m_ExtType = IPv6Routing;

	ipv6_routing_header* routingHeader = getRoutingHeader();
	routingHeader->nextHeader = 0;
	routingHeader->headerLen = ((totalSize / 8) - 1);
	routingHeader->routingType = routingType;
	routingHeader->segmentsLeft = segmentsLeft;

	if (additionalRoutingDataLen > 0 && additionalRoutingData != NULL)
	{
		uint8_t* additionalDataPtr = (uint8_t*)(getDataPtr() + sizeof(ipv6_routing_header));
		memcpy(additionalDataPtr, additionalRoutingData, additionalRoutingDataLen);
	}
}

uint8_t* IPv6RoutingHeader::getRoutingAdditionalData()
{
	if (getExtensionLen() > sizeof(ipv6_routing_header))
		return (uint8_t*)(getDataPtr() + sizeof(ipv6_routing_header));

	return NULL;
}

size_t IPv6RoutingHeader::getRoutingAdditionalDataLength()
{
	int result = getExtensionLen() - sizeof(ipv6_routing_header);
	if (result < 0)
		return (size_t)0;

	return (size_t)result;
}

IPv6Address IPv6RoutingHeader::getRoutingAdditionalDataAsIPv6Address(size_t offset)
{

	size_t routingAddDataLen = getRoutingAdditionalDataLength();
	if (routingAddDataLen - offset >= 16)
		return IPv6Address((uint8_t*)(getRoutingAdditionalData() + offset));

	return IPv6Address::Zero;
}


// ========================
// IPv6AuthenticationHeader
// ========================

IPv6AuthenticationHeader::IPv6AuthenticationHeader(uint32_t securityParametersIndex, uint32_t sequenceNumber, const uint8_t* integrityCheckValue, size_t integrityCheckValueLen)
{
	size_t totalSize = sizeof(ipv6_authentication_header) + integrityCheckValueLen;
	while (totalSize % 8 != 0)
		totalSize++;

	initShadowPtr(totalSize);
	memset(getDataPtr(), 0, totalSize);

	m_ExtType = IPv6AuthenticationHdr;

	ipv6_authentication_header* authHeader = getAuthHeader();
	authHeader->nextHeader = 0;
	authHeader->headerLen = ((totalSize / 4) - 2);
	authHeader->securityParametersIndex = htonl(securityParametersIndex);
	authHeader->sequenceNumber = htonl(sequenceNumber);

	if (integrityCheckValueLen > 0 && integrityCheckValue != NULL)
	{
		uint8_t* icvPtr = (uint8_t*)(getDataPtr() + sizeof(ipv6_authentication_header));
		memcpy(icvPtr, integrityCheckValue, integrityCheckValueLen);
	}
}

uint8_t* IPv6AuthenticationHeader::getIntegrityCheckValue()
{
	if (getExtensionLen() > sizeof(ipv6_authentication_header))
		return (uint8_t*)(getDataPtr() + sizeof(ipv6_authentication_header));

	return NULL;
}

size_t IPv6AuthenticationHeader::getIntegrityCheckValueLength()
{
	int result = getExtensionLen() - sizeof(ipv6_authentication_header);
	if (result < 0)
		return (size_t)0;

	return (size_t)result;
}

}
