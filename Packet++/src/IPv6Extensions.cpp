#define LOG_MODULE PacketLogModuleIPv6ExtensionLayer

#include "EndianPortable.h"
#include "IPv6Extensions.h"
#include "IPv6Layer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"

namespace pcpp
{

	// =============
	// IPv6Extension
	// =============

	IPv6Extension& IPv6Extension::operator=(const IPv6Extension& other)
	{
		// notice this is not necessarily safe - it assumes the current extension has enough memory allocated to consume
		// the other extension. That's why the assignment operator isn't public (it's currently used only inside
		// IPv6Layer)
		memcpy(getDataPtr(), other.getDataPtr(), other.getExtensionLen());
		m_NextHeader = nullptr;
		m_ExtType = other.m_ExtType;

		return *this;
	}

	uint8_t* IPv6Extension::getDataPtr() const
	{
		if (m_DataContainer != nullptr)
			return m_DataContainer->getDataPtr(m_Offset);

		return m_ShadowData;
	}

	void IPv6Extension::initShadowPtr(size_t size)
	{
		m_ShadowData = new uint8_t[size];
	}

	IPv6Extension::~IPv6Extension()
	{
		if (m_ShadowData != nullptr)
			delete[] m_ShadowData;
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
		fragHdr->id = htobe32(fragId);

		fragOffset /= 8;
		fragOffset = htobe16(fragOffset << 3) & (uint16_t)0xf8ff;
		if (!lastFragment)
			fragOffset = fragOffset | 0x0100;

		fragHdr->fragOffsetAndFlags = fragOffset;
	}

	bool IPv6FragmentationHeader::isFirstFragment() const
	{
		return (getFragmentOffset() == 0);
	}

	bool IPv6FragmentationHeader::isLastFragment() const
	{
		return (!isMoreFragments());
	}

	bool IPv6FragmentationHeader::isMoreFragments() const
	{
		uint8_t isMoreFragsBit = (getFragHeader()->fragOffsetAndFlags & (uint16_t)0x0100) >> 8;
		return (isMoreFragsBit == 1);
	}

	uint16_t IPv6FragmentationHeader::getFragmentOffset() const
	{
		uint16_t fragOffset = (be16toh(getFragHeader()->fragOffsetAndFlags & (uint16_t)0xf8ff) >> 3) * 8;
		return fragOffset;
	}

	// ====================
	// IPv6TLVOptionBuilder
	// ====================

	IPv6TLVOptionHeader::IPv6Option IPv6TLVOptionHeader::IPv6TLVOptionBuilder::build() const
	{
		size_t optionTotalSize = sizeof(uint8_t);
		uint8_t recType = static_cast<uint8_t>(m_RecType);
		if (recType != IPv6TLVOptionHeader::IPv6Option::Pad0OptionType)
			optionTotalSize += sizeof(uint8_t) + m_RecValueLen;

		uint8_t* recordBuffer = new uint8_t[optionTotalSize];
		memset(recordBuffer, 0, optionTotalSize);

		if (m_RecType != IPv6TLVOptionHeader::IPv6Option::Pad0OptionType)
		{
			recordBuffer[0] = recType;
			recordBuffer[1] = static_cast<uint8_t>(m_RecValueLen);
			if (m_RecValueLen > 0)
				memcpy(recordBuffer + 2, m_RecValue, m_RecValueLen);
		}

		return IPv6Option(recordBuffer);
	}

	// ===================
	// IPv6TLVOptionHeader
	// ===================

	IPv6TLVOptionHeader::IPv6Option IPv6TLVOptionHeader::getOption(uint8_t optionType) const
	{
		return m_OptionReader.getTLVRecord(optionType, getDataPtr() + sizeof(ipv6_ext_base_header),
		                                   getExtensionLen() - sizeof(ipv6_ext_base_header));
	}

	IPv6TLVOptionHeader::IPv6Option IPv6TLVOptionHeader::getFirstOption() const
	{
		return m_OptionReader.getFirstTLVRecord(getDataPtr() + sizeof(ipv6_ext_base_header),
		                                        getExtensionLen() - sizeof(ipv6_ext_base_header));
	}

	IPv6TLVOptionHeader::IPv6Option IPv6TLVOptionHeader::getNextOption(IPv6TLVOptionHeader::IPv6Option& option) const
	{
		return m_OptionReader.getNextTLVRecord(option, getDataPtr() + sizeof(ipv6_ext_base_header),
		                                       getExtensionLen() - sizeof(ipv6_ext_base_header));
	}

	size_t IPv6TLVOptionHeader::getOptionCount() const
	{
		return m_OptionReader.getTLVRecordCount(getDataPtr() + sizeof(ipv6_ext_base_header),
		                                        getExtensionLen() - sizeof(ipv6_ext_base_header));
	}

	IPv6TLVOptionHeader::IPv6TLVOptionHeader(const std::vector<IPv6TLVOptionBuilder>& options)
	{
		m_ExtType = IPv6ExtensionUnknown;
		m_OptionReader.changeTLVRecordCount(options.size());

		size_t totalSize = sizeof(uint16_t);  // nextHeader + headerLen

		for (const auto& iter : options)
		{
			IPv6Option option = iter.build();
			totalSize += option.getTotalSize();
			option.purgeRecordData();
		}

		while (totalSize % 8 != 0)
			totalSize++;

		initShadowPtr(totalSize);
		memset(getDataPtr(), 0, totalSize);

		getBaseHeader()->headerLen = ((totalSize / 8) - 1);

		size_t offset = sizeof(uint16_t);

		for (const auto& iter : options)
		{
			IPv6Option option = iter.build();
			memcpy(getDataPtr() + offset, option.getRecordBasePtr(), option.getTotalSize());
			offset += option.getTotalSize();
			option.purgeRecordData();
		}
	}

	IPv6TLVOptionHeader::IPv6TLVOptionHeader(IDataContainer* dataContainer, size_t offset)
	    : IPv6Extension(dataContainer, offset)
	{}

	// =================
	// IPv6RoutingHeader
	// =================

	IPv6RoutingHeader::IPv6RoutingHeader(uint8_t routingType, uint8_t segmentsLeft,
	                                     const uint8_t* additionalRoutingData, size_t additionalRoutingDataLen)
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

		if (additionalRoutingDataLen > 0 && additionalRoutingData != nullptr)
		{
			uint8_t* additionalDataPtr = getDataPtr() + sizeof(ipv6_routing_header);
			memcpy(additionalDataPtr, additionalRoutingData, additionalRoutingDataLen);
		}
	}

	uint8_t* IPv6RoutingHeader::getRoutingAdditionalData() const
	{
		if (getExtensionLen() > sizeof(ipv6_routing_header))
			return getDataPtr() + sizeof(ipv6_routing_header);

		return nullptr;
	}

	size_t IPv6RoutingHeader::getRoutingAdditionalDataLength() const
	{
		int result = getExtensionLen() - sizeof(ipv6_routing_header);
		if (result < 0)
			return (size_t)0;

		return (size_t)result;
	}

	IPv6Address IPv6RoutingHeader::getRoutingAdditionalDataAsIPv6Address(size_t offset) const
	{

		size_t routingAddDataLen = getRoutingAdditionalDataLength();
		if (routingAddDataLen - offset >= 16)
			return IPv6Address(getRoutingAdditionalData() + offset);

		return IPv6Address();
	}

	// ========================
	// IPv6AuthenticationHeader
	// ========================

	IPv6AuthenticationHeader::IPv6AuthenticationHeader(uint32_t securityParametersIndex, uint32_t sequenceNumber,
	                                                   const uint8_t* integrityCheckValue,
	                                                   size_t integrityCheckValueLen)
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
		authHeader->securityParametersIndex = htobe32(securityParametersIndex);
		authHeader->sequenceNumber = htobe32(sequenceNumber);

		if (integrityCheckValueLen > 0 && integrityCheckValue != nullptr)
		{
			uint8_t* icvPtr = getDataPtr() + sizeof(ipv6_authentication_header);
			memcpy(icvPtr, integrityCheckValue, integrityCheckValueLen);
		}
	}

	uint8_t* IPv6AuthenticationHeader::getIntegrityCheckValue() const
	{
		if (getExtensionLen() > sizeof(ipv6_authentication_header))
			return getDataPtr() + sizeof(ipv6_authentication_header);

		return nullptr;
	}

	size_t IPv6AuthenticationHeader::getIntegrityCheckValueLength() const
	{
		int result = getExtensionLen() - sizeof(ipv6_authentication_header);
		if (result < 0)
			return (size_t)0;

		return (size_t)result;
	}

}  // namespace pcpp
