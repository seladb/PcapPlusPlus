#define LOG_MODULE PacketLogModuleSomeIpSdLayer

#include "SomeIpSdLayer.h"
#include "EndianPortable.h"
#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace pcpp
{
	// -------- Class SomeIpSdOption -----------------

	SomeIpSdOption::~SomeIpSdOption()
	{
		if (m_ShadowData != nullptr)
			delete[] m_ShadowData;
	}

	SomeIpSdOption::OptionType SomeIpSdOption::getType() const
	{
		return static_cast<OptionType>(getSomeIpSdOptionHeader()->type);
	}

	uint8_t* SomeIpSdOption::getDataPtr() const
	{
		if (m_DataContainer != nullptr)
			return m_DataContainer->getDataPtr(m_Offset);

		return m_ShadowData;
	}

	SomeIpSdOption::someipsdhdroptionsbase* SomeIpSdOption::getSomeIpSdOptionHeader() const
	{
		return (someipsdhdroptionsbase*)getDataPtr();
	}

	void SomeIpSdOption::initStdFields(OptionType type)
	{
		someipsdhdroptionsbase* optionHdr = getSomeIpSdOptionHeader();

		optionHdr->type = static_cast<uint8_t>(type);
		// Length field is excluding length field itself and uint8_t type field
		optionHdr->length = htobe16((uint16_t)(m_DataLen - sizeof(optionHdr->length) - sizeof(optionHdr->type)));
	}

	// -------- Class SomeIpSdIPv4Option -----------------

	SomeIpSdIPv4Option::SomeIpSdIPv4Option(IPv4OptionType type, IPv4Address ipAddress, uint16_t port,
	                                       SomeIpSdProtocolType l4Protocol)
	{
		m_DataLen = sizeof(someipsdhdroptionsipv4);
		m_ShadowData = new uint8_t[m_DataLen];
		memset(m_ShadowData, 0, m_DataLen);

		switch (type)
		{
		case IPv4OptionType::IPv4Endpoint:
			initStdFields(OptionType::IPv4Endpoint);
			break;
		case IPv4OptionType::IPv4Multicast:
			initStdFields(OptionType::IPv4Multicast);
			break;
		case IPv4OptionType::IPv4SdEndpoint:
			initStdFields(OptionType::IPv4SdEndpoint);
			break;
		}

		someipsdhdroptionsipv4* hdr = (someipsdhdroptionsipv4*)getDataPtr();
		hdr->ipv4Address = ipAddress.toInt();
		hdr->portNumber = htobe16(port);
		hdr->l4Protocol = l4Protocol;
	}

	SomeIpSdIPv4Option::SomeIpSdIPv4Option(const IDataContainer* dataContainer, size_t offset)
	    : SomeIpSdOption(dataContainer, offset)
	{
		m_DataLen = sizeof(someipsdhdroptionsipv4);
	}

	IPv4Address SomeIpSdIPv4Option::getIpAddress() const
	{
		someipsdhdroptionsipv4* hdr = (someipsdhdroptionsipv4*)getDataPtr();
		IPv4Address ipAddr(hdr->ipv4Address);

		return ipAddr;
	}

	uint16_t SomeIpSdIPv4Option::getPort() const
	{
		someipsdhdroptionsipv4* hdr = (someipsdhdroptionsipv4*)getDataPtr();
		return be16toh(hdr->portNumber);
	}

	SomeIpSdProtocolType SomeIpSdIPv4Option::getProtocol() const
	{
		someipsdhdroptionsipv4* hdr = (someipsdhdroptionsipv4*)getDataPtr();
		return hdr->l4Protocol;
	}

	// -------- Class SomeIpSdIPv6Option -----------------

	SomeIpSdIPv6Option::SomeIpSdIPv6Option(IPv6OptionType type, IPv6Address ipAddress, uint16_t port,
	                                       SomeIpSdProtocolType l4Protocol)
	{
		m_DataLen = sizeof(someipsdhdroptionsipv6);
		m_ShadowData = new uint8_t[m_DataLen];
		memset(m_ShadowData, 0, m_DataLen);

		switch (type)
		{
		case IPv6OptionType::IPv6Endpoint:
			initStdFields(OptionType::IPv6Endpoint);
			break;
		case IPv6OptionType::IPv6Multicast:
			initStdFields(OptionType::IPv6Multicast);
			break;
		case IPv6OptionType::IPv6SdEndpoint:
			initStdFields(OptionType::IPv6SdEndpoint);
			break;
		}

		someipsdhdroptionsipv6* hdr = (someipsdhdroptionsipv6*)getDataPtr();
		std::memcpy(hdr->ipv6Address, ipAddress.toBytes(), 16);
		hdr->portNumber = htobe16(port);
		hdr->l4Protocol = l4Protocol;
	}

	SomeIpSdIPv6Option::SomeIpSdIPv6Option(const IDataContainer* dataContainer, size_t offset)
	    : SomeIpSdOption(dataContainer, offset)
	{
		m_DataLen = sizeof(someipsdhdroptionsipv6);
	}

	IPv6Address SomeIpSdIPv6Option::getIpAddress() const
	{
		someipsdhdroptionsipv6* hdr = (someipsdhdroptionsipv6*)getDataPtr();
		IPv6Address ipAddr(hdr->ipv6Address);

		return ipAddr;
	}

	uint16_t SomeIpSdIPv6Option::getPort() const
	{
		someipsdhdroptionsipv6* hdr = (someipsdhdroptionsipv6*)getDataPtr();
		return be16toh(hdr->portNumber);
	}

	SomeIpSdProtocolType SomeIpSdIPv6Option::getProtocol() const
	{
		someipsdhdroptionsipv6* hdr = (someipsdhdroptionsipv6*)getDataPtr();
		return hdr->l4Protocol;
	}

	// -------- Class SomeIpSdConfigurationOption -----------------

	SomeIpSdConfigurationOption::SomeIpSdConfigurationOption(const std::string& configurationString)
	{
		m_DataLen = configurationString.length() + sizeof(someipsdhdroptionsbase);
		m_ShadowData = new uint8_t[m_DataLen];
		memset(m_ShadowData, 0, m_DataLen);

		initStdFields(OptionType::ConfigurationString);
		std::memcpy(getDataPtr() + sizeof(someipsdhdroptionsbase), configurationString.c_str(),
		            configurationString.length());
	}

	SomeIpSdConfigurationOption::SomeIpSdConfigurationOption(const IDataContainer* dataContainer, size_t offset)
	    : SomeIpSdOption(dataContainer, offset)
	{
		m_DataLen = sizeof(someipsdhdroptionsbase) - 1 + be16toh(getSomeIpSdOptionHeader()->length);
	}

	std::string SomeIpSdConfigurationOption::getConfigurationString() const
	{
		return std::string((char*)getDataPtr() + sizeof(someipsdhdroptionsbase),
		                   be16toh(getSomeIpSdOptionHeader()->length) - 1);
	}

	// -------- Class SomeIpSdLoadBalancingOption -----------------

	SomeIpSdLoadBalancingOption::SomeIpSdLoadBalancingOption(uint16_t priority, uint16_t weight)
	{
		m_DataLen = sizeof(someipsdhdroptionsload);
		m_ShadowData = new uint8_t[m_DataLen];
		memset(m_ShadowData, 0, m_DataLen);

		initStdFields(OptionType::LoadBalancing);

		someipsdhdroptionsload* hdr = (someipsdhdroptionsload*)getDataPtr();
		hdr->priority = htobe16(priority);
		hdr->weight = htobe16(weight);
	}

	SomeIpSdLoadBalancingOption::SomeIpSdLoadBalancingOption(const IDataContainer* dataContainer, size_t offset)
	    : SomeIpSdOption(dataContainer, offset)
	{
		m_DataLen = sizeof(someipsdhdroptionsload);
	}

	uint16_t SomeIpSdLoadBalancingOption::getPriority() const
	{
		someipsdhdroptionsload* hdr = (someipsdhdroptionsload*)getDataPtr();
		return be16toh(hdr->priority);
	}

	uint16_t SomeIpSdLoadBalancingOption::getWeight() const
	{
		someipsdhdroptionsload* hdr = (someipsdhdroptionsload*)getDataPtr();
		return be16toh(hdr->weight);
	}

	// -------- Class SomeIpSdEntry -----------------

	SomeIpSdEntry::SomeIpSdEntry(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion,
	                             uint32_t TTL, uint32_t minorVersion)
	{
		initStdFields(type, serviceID, instanceID, majorVersion, TTL);
		setMinorVersion(minorVersion);
	}

	SomeIpSdEntry::SomeIpSdEntry(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion,
	                             uint32_t TTL, uint8_t counter, uint16_t eventGroupID)
	{
		initStdFields(type, serviceID, instanceID, majorVersion, TTL);
		setCounter(counter);
		setEventgroupId(eventGroupID);
	}

	SomeIpSdEntry::SomeIpSdEntry(const SomeIpSdLayer* pSomeIpSdLayer, size_t offset)
	    : m_Layer(pSomeIpSdLayer), m_Offset(offset), m_ShadowData(nullptr)
	{
		EntryType entryType;

		someipsdhdrentry* hdr = getSomeIpSdEntryHeader();
		TypeInternal internalType = static_cast<TypeInternal>(hdr->type);
		auto ttl = getTtl();

		switch (internalType)
		{
		case SomeIpSdEntry::TypeInternal::FindService_Internal:
			entryType = SomeIpSdEntry::EntryType::FindService;
			break;
		case SomeIpSdEntry::TypeInternal::OfferService_Internal:
			if (ttl == 0)
			{
				entryType = EntryType::StopOfferService;
			}
			else
			{
				entryType = EntryType::OfferService;
			}
			break;
		case SomeIpSdEntry::TypeInternal::SubscribeEventgroup_Internal:
			if (ttl == 0)
			{
				entryType = EntryType::StopSubscribeEventgroup;
			}
			else
			{
				entryType = EntryType::SubscribeEventgroup;
			}
			break;
		case SomeIpSdEntry::TypeInternal::SubscribeEventgroupAck_Internal:
			if (ttl == 0)
			{
				entryType = EntryType::SubscribeEventgroupNack;
			}
			else
			{
				entryType = EntryType::SubscribeEventgroupAck;
			}
			break;
		default:
			entryType = EntryType::UnknownEntryType;
			break;
		}

		m_EntryType = entryType;
	}

	SomeIpSdEntry::~SomeIpSdEntry()
	{
		if (m_ShadowData != nullptr)
			delete[] m_ShadowData;
	}

	uint8_t* SomeIpSdEntry::getDataPtr() const
	{
		if (m_Layer != nullptr)
			return m_Layer->getDataPtr(m_Offset);

		return m_ShadowData;
	}

	SomeIpSdEntry::someipsdhdrentry* SomeIpSdEntry::getSomeIpSdEntryHeader() const
	{
		return (someipsdhdrentry*)getDataPtr();
	}

	uint32_t SomeIpSdEntry::getNumOptions() const
	{
		auto* hdr = getSomeIpSdEntryHeader();
		return hdr->nrOpt1 + hdr->nrOpt2;
	}

	uint16_t SomeIpSdEntry::getServiceId() const
	{
		return be16toh(getSomeIpSdEntryHeader()->serviceID);
	}

	void SomeIpSdEntry::setServiceId(uint16_t serviceId)
	{
		getSomeIpSdEntryHeader()->serviceID = htobe16(serviceId);
	}

	uint16_t SomeIpSdEntry::getInstanceId() const
	{
		return be16toh(getSomeIpSdEntryHeader()->instanceID);
	}

	void SomeIpSdEntry::setInstanceId(uint16_t instanceId)
	{
		getSomeIpSdEntryHeader()->instanceID = htobe16(instanceId);
	}

	uint8_t SomeIpSdEntry::getMajorVersion() const
	{
		return (be32toh(getSomeIpSdEntryHeader()->majorVersion_ttl) & ~SOMEIPSD_HDR_ENTRY_MASK_TTL) >> 24;
	}

	void SomeIpSdEntry::setMajorVersion(uint8_t majorVersion)
	{
		someipsdhdrentry* hdr = getSomeIpSdEntryHeader();
		uint32_t val = (majorVersion << 24) | (be32toh(hdr->majorVersion_ttl) & SOMEIPSD_HDR_ENTRY_MASK_TTL);
		hdr->majorVersion_ttl = htobe32(val);
	}

	uint32_t SomeIpSdEntry::getTtl() const
	{
		return be32toh(getSomeIpSdEntryHeader()->majorVersion_ttl) & SOMEIPSD_HDR_ENTRY_MASK_TTL;
	}

	void SomeIpSdEntry::setTtl(uint32_t ttl)
	{
		someipsdhdrentry* hdr = getSomeIpSdEntryHeader();
		uint32_t val =
		    (ttl & SOMEIPSD_HDR_ENTRY_MASK_TTL) | (be32toh(hdr->majorVersion_ttl) & ~SOMEIPSD_HDR_ENTRY_MASK_TTL);
		hdr->majorVersion_ttl = htobe32(val);
	}

	uint32_t SomeIpSdEntry::getMinorVersion() const
	{
		return be32toh(getSomeIpSdEntryHeader()->data);
	}

	void SomeIpSdEntry::setMinorVersion(uint32_t minorVersion)
	{
		getSomeIpSdEntryHeader()->data = htobe32(minorVersion);
	}

	uint8_t SomeIpSdEntry::getCounter() const
	{
		return (uint8_t)((be32toh(getSomeIpSdEntryHeader()->data) >> 16) & 0x0F);
	}

	void SomeIpSdEntry::setCounter(uint8_t counter)
	{
		someipsdhdrentry* hdr = getSomeIpSdEntryHeader();
		hdr->data = htobe32((be32toh(hdr->data) & 0xFFF0FFFF) | ((counter & 0x0F) << 16));
	}

	uint16_t SomeIpSdEntry::getEventgroupId() const
	{
		return (uint16_t)(be32toh(getSomeIpSdEntryHeader()->data) & 0x0000FFFF);
	}

	void SomeIpSdEntry::setEventgroupId(uint16_t eventgroupID)
	{
		someipsdhdrentry* hdr = getSomeIpSdEntryHeader();
		hdr->data = htobe32((be32toh(hdr->data) & 0xFFFF0000) | eventgroupID);
	}

	void SomeIpSdEntry::initStdFields(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion,
	                                  uint32_t TTL)
	{
		m_EntryType = type;
		m_Layer = nullptr;
		m_Offset = 0;

		size_t dataLen = sizeof(someipsdhdrentry);
		m_ShadowData = new uint8_t[dataLen];
		memset(m_ShadowData, 0, dataLen);

		someipsdhdrentry* hdr = getSomeIpSdEntryHeader();
		setServiceId(serviceID);
		setInstanceId(instanceID);
		setMajorVersion(majorVersion);
		setTtl(TTL);

		switch (type)
		{
		case EntryType::FindService:
		{
			hdr->type = static_cast<uint8_t>(TypeInternal::FindService_Internal);
			break;
		}
		case EntryType::OfferService:
		case EntryType::StopOfferService:
		{
			hdr->type = static_cast<uint8_t>(TypeInternal::OfferService_Internal);
			break;
		}
		case EntryType::SubscribeEventgroup:
		case EntryType::StopSubscribeEventgroup:
		{
			hdr->type = static_cast<uint8_t>(TypeInternal::SubscribeEventgroup_Internal);
			break;
		}
		case EntryType::SubscribeEventgroupAck:
		case EntryType::SubscribeEventgroupNack:
		{
			hdr->type = static_cast<uint8_t>(TypeInternal::SubscribeEventgroupAck_Internal);
			break;
		}
		default:
			break;
		}
	}

	// -------- Class SomeIpSdLayer -----------------

	SomeIpSdLayer::SomeIpSdLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : SomeIpLayer(data, dataLen, prevLayer, packet)
	{
		countOptions(m_NumOptions, data);
	}

	SomeIpSdLayer::SomeIpSdLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
	                             uint8_t interfaceVersion, MsgType type, uint8_t returnCode, uint8_t flags)
	{
		m_Protocol = SomeIP;
		m_DataLen = sizeof(someipsdhdr) + 2 * sizeof(uint32_t);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);

		m_NumOptions = 0;

		setServiceID(serviceID);
		setMethodID(methodID);
		setPayloadLength(sizeof(uint32_t) * 3);  // Flags+Reserved, Length Entries, Length Options
		setClientID(clientID);
		setSessionID(sessionID);
		setProtocolVersion(0x01);
		setInterfaceVersion(interfaceVersion);
		setMessageType(type);
		setReturnCode(returnCode);
		setFlags(flags);
	}

	uint8_t SomeIpSdLayer::getFlags() const
	{
		someipsdhdr* hdr = (someipsdhdr*)m_Data;
		return hdr->flags;
	}

	void SomeIpSdLayer::setFlags(uint8_t flags)
	{
		someipsdhdr* hdr = (someipsdhdr*)m_Data;
		hdr->flags = flags;
	}

	uint32_t SomeIpSdLayer::getNumEntries() const
	{
		return (uint32_t)(getLenEntries() / sizeof(SomeIpSdEntry::someipsdhdrentry));
	}

	uint32_t SomeIpSdLayer::getNumOptions() const
	{
		return m_NumOptions;
	}

	const SomeIpSdLayer::EntriesVec SomeIpSdLayer::getEntries() const
	{
		size_t remainingLen = getLenEntries();
		size_t offset = sizeof(someipsdhdr) + sizeof(uint32_t);

		EntriesVec vecEntries;
		EntryPtr entry;

		while (remainingLen > 0)
		{
			// Ensure there is enough remaining length for a new entry
			if (remainingLen < sizeof(SomeIpSdEntry::someipsdhdrentry))
			{
				break;
			}
			entry = new SomeIpSdEntry(this, offset);

			size_t entryLen = entry->getLength();
			remainingLen -= entryLen;
			offset += entryLen;

			vecEntries.push_back(entry);
		}

		return vecEntries;
	};

	const SomeIpSdLayer::OptionsVec SomeIpSdLayer::getOptions() const
	{
		OptionsVec vecOptions;
		OptionPtr option;

		size_t remainingLen = getLenOptions();
		size_t offset = sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries() + sizeof(uint32_t);

		while (remainingLen > 0)
		{
			SomeIpSdOption::someipsdhdroptionsbase* hdr = (SomeIpSdOption::someipsdhdroptionsbase*)(m_Data + offset);
			SomeIpSdOption::OptionType optionType = static_cast<SomeIpSdOption::OptionType>(hdr->type);

			option = parseOption(optionType, offset);

			if (option != nullptr)
			{
				vecOptions.push_back(std::move(option));
			}

			size_t optionLen = be16toh(hdr->length) + 3;
			remainingLen -= optionLen;
			offset += optionLen;
		}

		return vecOptions;
	}

	const SomeIpSdLayer::OptionsVec SomeIpSdLayer::getOptionsFromEntry(uint32_t index) const
	{
		OptionsVec vecOptions;
		OptionPtr option;

		if (index >= getNumEntries())
			return vecOptions;

		size_t remainingLen = getLenOptions();
		size_t offset = sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries() + sizeof(uint32_t);

		size_t offsetToEntry = sizeof(someipsdhdr) + sizeof(uint32_t) + index * sizeof(SomeIpSdEntry::someipsdhdrentry);
		SomeIpSdEntry::someipsdhdrentry* hdrEntry = (SomeIpSdEntry::someipsdhdrentry*)(m_Data + offsetToEntry);
		uint8_t startIdxRun1 = hdrEntry->indexFirstOption;
		uint8_t lenRun1 = hdrEntry->nrOpt1;
		uint8_t startIdxRun2 = hdrEntry->indexSecondOption;
		uint8_t lenRun2 = hdrEntry->nrOpt2;

		int idx = 0;

		while (remainingLen > 0)
		{
			SomeIpSdOption::someipsdhdroptionsbase* hdrOption =
			    (SomeIpSdOption::someipsdhdroptionsbase*)(m_Data + offset);

			if (((idx >= startIdxRun1) && (idx < (startIdxRun1 + lenRun1))) ||
			    ((idx >= startIdxRun2) && (idx < (startIdxRun2 + lenRun2))))
			{
				SomeIpSdOption::OptionType optionType = static_cast<SomeIpSdOption::OptionType>(hdrOption->type);

				option = parseOption(optionType, offset);

				if (option != nullptr)
				{
					vecOptions.push_back(std::move(option));
				}
			}

			size_t optionLen = be16toh(hdrOption->length) + 3;
			remainingLen -= optionLen;
			offset += optionLen;
			++idx;
		}

		return vecOptions;
	}

	bool SomeIpSdLayer::addOptionTo(uint32_t indexEntry, const SomeIpSdOption& option)
	{
		if (indexEntry >= getNumEntries())
		{
			return false;
		}

		uint32_t indexOption = findOption(option);
		bool success = addOptionIndex(indexEntry, indexOption);

		if (!success)
		{
			return false;
		}

		if (indexOption == m_NumOptions)
		{
			addOption(option);
		}

		return true;
	}

	std::string SomeIpSdLayer::toString() const
	{
		std::stringstream dataStream;

		dataStream << "SOME/IP-SD Layer, " << getNumEntries() << " entries, " << getNumOptions() << " options";

		return dataStream.str();
	}

	uint32_t SomeIpSdLayer::addEntry(const SomeIpSdEntry& entry)
	{
		size_t lenEntries = getLenEntries();
		int offsetToAddAt = sizeof(someipsdhdr) + sizeof(uint32_t) + lenEntries;

		extendLayer(offsetToAddAt, entry.getLength());

		setLenEntries(lenEntries + entry.getLength());

		memcpy(m_Data + offsetToAddAt, entry.getDataPtr(), entry.getLength());

		auto hdr = getSomeIpHeader();
		hdr->length = htobe32(be32toh(hdr->length) + (uint32_t)entry.getLength());

		return getNumEntries() - 1;
	}

	bool SomeIpSdLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		uint32_t count;
		if (!data || dataLen < sizeof(someipsdhdr) + sizeof(uint32_t) ||
		    dataLen < sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries(data) + sizeof(uint32_t) ||
		    dataLen <
		        sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries(data) + sizeof(uint32_t) + getLenOptions(data) ||
		    !countOptions(count, data))
		{
			return false;
		}

		return true;
	}

	bool SomeIpSdLayer::countOptions(uint32_t& count, const uint8_t* data)
	{
		size_t offsetOption = sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries(data) + sizeof(uint32_t);
		size_t lenOptions = getLenOptions(data);
		uint32_t len = 0;

		count = 0;
		while (len < lenOptions)
		{
			if (len + sizeof(uint16_t) + 3 * sizeof(uint8_t) > lenOptions)
				return false;

			uint32_t lenOption = be16toh(*((uint16_t*)(data + offsetOption + len))) + 3 * sizeof(uint8_t);
			len += lenOption;
			if (len > lenOptions)  // the last one must be equal to lenOptions
				return false;

			++(count);
		}
		return true;
	}

	uint32_t SomeIpSdLayer::findOption(const SomeIpSdOption& option)
	{
		size_t offsetOption = sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries() + sizeof(uint32_t);

		uint32_t i = 0;
		while (i < m_NumOptions)
		{
			uint32_t lenOption = be16toh(*((uint16_t*)(m_Data + offsetOption))) + 3 * sizeof(uint8_t);

			if (option.getLength() == lenOption)
			{
				if (memcmp(m_Data + offsetOption, option.getDataPtr(), option.getLength()) == 0)
				{
					return i;
				}
			}

			offsetOption += lenOption;
			++i;
		}
		return i;
	}

	void SomeIpSdLayer::addOption(const SomeIpSdOption& option)
	{
		int offsetToAddAt = (int)getHeaderLen();

		extendLayer(offsetToAddAt, option.getLength());
		memcpy(m_Data + offsetToAddAt, option.getDataPtr(), option.getLength());

		setLenOptions(uint32_t(getLenOptions() + option.getLength()));

		auto hdr = getSomeIpHeader();
		hdr->length = htobe32(be32toh(hdr->length) + (uint32_t)option.getLength());

		++m_NumOptions;
	}

	bool SomeIpSdLayer::addOptionIndex(uint32_t indexEntry, uint32_t indexOffset)
	{
		//    The SOME/IP-SD protocol supports two option runs. Runs meaning that two different starting indices with
		//    differing length can be provided. Of course, this only works if the indices in both runs are consecutive.
		//
		//    So, indices like this would work:
		//        1 2 3 ; 7 8
		//
		//    What wouldn't work is this:
		//        1 2 3 ; 7 9
		//        1 3 ; 7 8

		const size_t someipsdhdrentrySize = sizeof(SomeIpSdEntry::someipsdhdrentry);
		size_t offsetToAddAt = sizeof(someipsdhdr) + sizeof(uint32_t) + indexEntry * someipsdhdrentrySize;
		auto hdrEntry = (SomeIpSdEntry::someipsdhdrentry*)(m_Data + offsetToAddAt);

		uint8_t indexFirstOption = hdrEntry->indexFirstOption;
		uint8_t lenFirstOption = hdrEntry->nrOpt1;

		if (lenFirstOption == 0)
		{
			hdrEntry->indexFirstOption = indexOffset;
			++hdrEntry->nrOpt1;
			return true;
		}

		if (static_cast<uint32_t>(indexFirstOption + lenFirstOption + 1) == indexOffset)
		{
			++hdrEntry->nrOpt1;
			return true;
		}

		uint8_t indexSecondOption = hdrEntry->indexSecondOption;
		uint8_t lenSecondOption = hdrEntry->nrOpt2;

		if (lenSecondOption == 0)
		{
			hdrEntry->indexFirstOption = indexOffset;
			++hdrEntry->nrOpt1;
			return true;
		}

		if (static_cast<uint32_t>(indexSecondOption + lenSecondOption + 1) == indexOffset)
		{
			++hdrEntry->nrOpt2;
			return true;
		}

		return false;
	}

	SomeIpSdLayer::OptionPtr SomeIpSdLayer::parseOption(SomeIpSdOption::OptionType type, size_t offset) const
	{
		switch (type)
		{
		case SomeIpSdOption::OptionType::IPv4Endpoint:
		case SomeIpSdOption::OptionType::IPv4Multicast:
		case SomeIpSdOption::OptionType::IPv4SdEndpoint:
		{
			return new SomeIpSdIPv4Option(this, offset);
		}
		case SomeIpSdOption::OptionType::IPv6Endpoint:
		case SomeIpSdOption::OptionType::IPv6Multicast:
		case SomeIpSdOption::OptionType::IPv6SdEndpoint:
		{
			return new SomeIpSdIPv6Option(this, offset);
		}
		case SomeIpSdOption::OptionType::ConfigurationString:
		{
			return new SomeIpSdConfigurationOption(this, offset);
		}
		case SomeIpSdOption::OptionType::LoadBalancing:
		{
			return new SomeIpSdLoadBalancingOption(this, offset);
		}
		default:
			break;
		}
		return nullptr;
	}

	size_t SomeIpSdLayer::getLenEntries() const
	{
		return getLenEntries(m_Data);
	}

	size_t SomeIpSdLayer::getLenEntries(const uint8_t* data)
	{
		return be32toh(*((uint32_t*)(data + sizeof(someipsdhdr))));
	}

	size_t SomeIpSdLayer::getLenOptions() const
	{
		return getLenOptions(m_Data);
	}

	size_t SomeIpSdLayer::getLenOptions(const uint8_t* data)
	{
		return be32toh(*((uint32_t*)(data + sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries(data))));
	}

	void SomeIpSdLayer::setLenEntries(uint32_t length)
	{
		*((uint32_t*)(m_Data + sizeof(someipsdhdr))) = htobe32(length);
	}

	void SomeIpSdLayer::setLenOptions(uint32_t length)
	{
		*((uint32_t*)(m_Data + sizeof(someipsdhdr) + sizeof(uint32_t) + getLenEntries())) = htobe32(length);
	}
}  // namespace pcpp
