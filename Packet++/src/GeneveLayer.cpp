#define LOG_MODULE PacketLogModuleGeneveLayer

#include "GeneveLayer.h"
#include "ArpLayer.h"
#include "EndianPortable.h"
#include "EthDot3Layer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Logger.h"
#include "MplsLayer.h"
#include "PayloadLayer.h"
#include "VlanLayer.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace pcpp
{
	uint16_t geneve_option_header::getOptionClass() const
	{
		return be16toh(optionClass);
	}

	void geneve_option_header::setOptionClass(uint16_t value)
	{
		optionClass = htobe16(value);
	}

	bool GeneveOption::canAssign(const uint8_t* optionRawData, size_t optionDataLen)
	{
		if (optionRawData == nullptr || optionDataLen < sizeof(geneve_option_header))
			return false;

		return reinterpret_cast<const geneve_option_header*>(optionRawData)->getTotalSize() <= optionDataLen;
	}

	uint16_t GeneveOption::getOptionClass() const
	{
		return m_Data->getOptionClass();
	}

	uint8_t GeneveOption::getType() const
	{
		return m_Data->getType();
	}

	bool GeneveOption::isCritical() const
	{
		return m_Data->isCritical();
	}

	size_t GeneveOption::getDataSize() const
	{
		return m_Data->getDataSize();
	}

	size_t GeneveOption::getTotalSize() const
	{
		return m_Data->getTotalSize();
	}

	uint8_t* GeneveOption::getData() const
	{
		return reinterpret_cast<uint8_t*>(m_Data) + sizeof(geneve_option_header);
	}

	GeneveOption GeneveOptionIterator::operator*() const
	{
		return GeneveOption(*reinterpret_cast<geneve_option_header*>(m_Current));
	}

	GeneveOptionIterator& GeneveOptionIterator::operator++()
	{
		if (m_Current == m_End)
			return *this;

		size_t remaining = static_cast<size_t>(m_End - m_Current);
		if (!GeneveOption::canAssign(m_Current, remaining))
		{
			m_Current = m_End;
			return *this;
		}

		m_Current += (**this).getTotalSize();
		if (m_Current != m_End && !GeneveOption::canAssign(m_Current, static_cast<size_t>(m_End - m_Current)))
		{
			m_Current = m_End;
		}

		return *this;
	}

	GeneveOptionIterator GeneveOptionIterator::operator++(int)
	{
		GeneveOptionIterator previous = *this;
		++(*this);
		return previous;
	}

	GeneveOptionRange::GeneveOptionRange(uint8_t* begin, uint8_t* end) : m_Begin(begin), m_End(end)
	{
		if (m_Begin == nullptr || m_Begin == m_End ||
		    !GeneveOption::canAssign(m_Begin, static_cast<size_t>(m_End - m_Begin)))
		{
			m_Begin = m_End;
		}
	}

	GeneveOptionIterator GeneveOptionRange::find(uint16_t optionClass, uint8_t optionType) const
	{
		for (auto iterator = begin(); iterator != end(); ++iterator)
		{
			GeneveOption option = *iterator;
			if (option.getOptionClass() == optionClass &&
			    option.getType() == geneve_option_header::extractType(optionType))
				return iterator;
		}

		return end();
	}

	size_t GeneveOptionRange::size() const
	{
		size_t count = 0;
		for (auto iterator = begin(); iterator != end(); ++iterator)
			++count;
		return count;
	}

	std::vector<uint8_t> GeneveOptionBuilder::build() const
	{
		if (m_RecValueLen > geneve_option_header::MaxDataLength)
			return {};

		size_t paddedDataLength = geneve_option_header::alignDataSize(m_RecValueLen);

		size_t totalLength = sizeof(geneve_option_header) + paddedDataLength;
		std::vector<uint8_t> optionData(totalLength, 0);

		geneve_option_header header = {};
		header.setOptionClass(m_OptionClass);
		header.setType(m_RecType, m_Critical);
		header.setDataSize(paddedDataLength);
		memcpy(optionData.data(), &header, sizeof(header));
		if (m_RecValueLen > 0)
			memcpy(optionData.data() + sizeof(geneve_option_header), m_RecValue, m_RecValueLen);

		return optionData;
	}

	GeneveLayer::GeneveLayer(uint32_t vni, uint16_t protocolType, bool oamFlag)
	{
		allocData(sizeof(geneve_header));
		m_Protocol = Geneve;
		setVNI(vni);
		setProtocolType(protocolType);
		getGeneveHeader()->oamFlag = oamFlag ? 1 : 0;
	}

	bool GeneveLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		if (!canReinterpretAs<geneve_header>(data, dataLen))
			return false;

		auto* header = reinterpret_cast<const geneve_header*>(data);
		// RFC 8926 defines GENEVE version 0; this implementation supports that version only.
		if (header->version != 0)
			return false;
		// RFC 8926 Section 3.4 requires Protocol Type to follow the EtherType convention,
		// whose valid encodings start at 0x0600.
		if (be16toh(header->protocolType) < 0x0600)
			return false;

		auto optionsLength = header->getOptionsLength();
		if (optionsLength > dataLen - sizeof(geneve_header))
			return false;

		const uint8_t* option = data + sizeof(geneve_header);
		size_t remaining = optionsLength;
		while (remaining > 0)
		{
			if (!GeneveOption::canAssign(option, remaining))
				return false;
			if (reinterpret_cast<const geneve_option_header*>(option)->isCritical() && header->criticalFlag == 0)
				return false;

			size_t optionLength = reinterpret_cast<const geneve_option_header*>(option)->getTotalSize();
			option += optionLength;
			remaining -= optionLength;
		}

		return true;
	}

	uint32_t GeneveLayer::getVNI() const
	{
		return getGeneveHeader()->getVNI();
	}

	void GeneveLayer::setVNI(uint32_t vni)
	{
		getGeneveHeader()->setVNI(vni);
	}

	uint16_t GeneveLayer::getProtocolType() const
	{
		return be16toh(getGeneveHeader()->protocolType);
	}

	void GeneveLayer::setProtocolType(uint16_t protocolType)
	{
		getGeneveHeader()->protocolType = htobe16(protocolType);
	}

	size_t GeneveLayer::getOptionsLength() const
	{
		if (m_Data == nullptr || m_DataLen < sizeof(geneve_header))
			return 0;
		return getGeneveHeader()->getOptionsLength();
	}

	size_t GeneveLayer::getHeaderLen() const
	{
		if (m_Data == nullptr)
			return 0;
		if (m_DataLen < sizeof(geneve_header))
			return m_DataLen;

		return (std::min)(m_DataLen, sizeof(geneve_header) + getOptionsLength());
	}

	GeneveOptionRange GeneveLayer::getOptions() const
	{
		if (m_Data == nullptr || m_DataLen <= sizeof(geneve_header))
			return {};

		size_t optionsLength = getHeaderLen() - sizeof(geneve_header);
		uint8_t* options = m_Data + sizeof(geneve_header);
		return GeneveOptionRange(options, options + optionsLength);
	}

	size_t GeneveLayer::getOptionCount() const
	{
		return getOptions().size();
	}

	bool GeneveLayer::addOption(const GeneveOptionBuilder& optionBuilder)
	{
		std::vector<uint8_t> optionData = optionBuilder.build();
		if (optionData.empty())
		{
			PCPP_LOG_ERROR("Cannot build GENEVE option");
			return false;
		}

		size_t oldOptionsLength = getOptionsLength();
		if (oldOptionsLength + optionData.size() > geneve_header::MaxOptionsLength)
		{
			PCPP_LOG_ERROR("GENEVE options exceed the maximum length of 252 bytes");
			return false;
		}

		int offset = static_cast<int>(sizeof(geneve_header) + oldOptionsLength);
		size_t optionSize = optionData.size();
		if (!extendLayer(offset, optionSize))
		{
			PCPP_LOG_ERROR("Could not extend GeneveLayer by " << optionSize << " bytes");
			return false;
		}

		memcpy(m_Data + offset, optionData.data(), optionSize);
		getGeneveHeader()->setOptionsLength(oldOptionsLength + optionSize);
		updateCriticalFlag();
		return true;
	}

	bool GeneveLayer::removeOption(uint16_t optionClass, uint8_t optionType)
	{
		GeneveOptionRange options = getOptions();
		GeneveOptionIterator optionIterator = options.find(optionClass, optionType);
		if (optionIterator == options.end())
			return false;
		GeneveOption option = *optionIterator;

		size_t oldOptionsLength = getOptionsLength();
		size_t optionSize = option.getTotalSize();
		int offset = static_cast<int>(option.getRecordBasePtr() - m_Data);
		if (!shortenLayer(offset, optionSize))
			return false;

		getGeneveHeader()->setOptionsLength(oldOptionsLength - optionSize);
		updateCriticalFlag();
		return true;
	}

	bool GeneveLayer::removeAllOptions()
	{
		size_t optionsLength = getOptionsLength();
		if (optionsLength == 0)
		{
			getGeneveHeader()->criticalFlag = 0;
			return true;
		}

		if (!shortenLayer(sizeof(geneve_header), optionsLength))
			return false;

		getGeneveHeader()->optionsLength = 0;
		getGeneveHeader()->criticalFlag = 0;
		return true;
	}

	void GeneveLayer::updateCriticalFlag()
	{
		getGeneveHeader()->criticalFlag = 0;
		for (GeneveOption option : getOptions())
		{
			if (option.isCritical())
			{
				getGeneveHeader()->criticalFlag = 1;
				return;
			}
		}
	}

	void GeneveLayer::parseNextLayer()
	{
		size_t headerLength = getHeaderLen();
		if (m_DataLen <= headerLength)
			return;

		uint8_t* payload = m_Data + headerLength;
		size_t payloadLength = m_DataLen - headerLength;
		switch (getProtocolType())
		{
		case PCPP_ETHERTYPE_IP:
			tryConstructNextLayerWithFallback<IPv4Layer, PayloadLayer>(payload, payloadLength);
			break;
		case PCPP_ETHERTYPE_ARP:
			tryConstructNextLayerWithFallback<ArpLayer, PayloadLayer>(payload, payloadLength);
			break;
		case PCPP_ETHERTYPE_IPV6:
			tryConstructNextLayerWithFallback<IPv6Layer, PayloadLayer>(payload, payloadLength);
			break;
		case PCPP_ETHERTYPE_VLAN:
		case PCPP_ETHERTYPE_IEEE_802_1AD:
			tryConstructNextLayerWithFallback<VlanLayer, PayloadLayer>(payload, payloadLength);
			break;
		case PCPP_ETHERTYPE_MPLS:
			tryConstructNextLayerWithFallback<MplsLayer, PayloadLayer>(payload, payloadLength);
			break;
		case PCPP_ETHERTYPE_ETHBRIDGE:
			if (tryConstructNextLayer<EthLayer>(payload, payloadLength) == nullptr)
				tryConstructNextLayerWithFallback<EthDot3Layer, PayloadLayer>(payload, payloadLength);
			break;
		default:
			constructNextLayer<PayloadLayer>(payload, payloadLength);
			break;
		}
	}

	void GeneveLayer::computeCalculateFields()
	{
		updateCriticalFlag();
		if (m_NextLayer == nullptr)
			return;

		switch (m_NextLayer->getProtocol())
		{
		case IPv4:
			setProtocolType(PCPP_ETHERTYPE_IP);
			break;
		case ARP:
			setProtocolType(PCPP_ETHERTYPE_ARP);
			break;
		case IPv6:
			setProtocolType(PCPP_ETHERTYPE_IPV6);
			break;
		case VLAN:
			setProtocolType(PCPP_ETHERTYPE_VLAN);
			break;
		case MPLS:
			setProtocolType(PCPP_ETHERTYPE_MPLS);
			break;
		case Ethernet:
		case EthernetDot3:
			setProtocolType(PCPP_ETHERTYPE_ETHBRIDGE);
			break;
		default:
			break;
		}
	}

	std::string GeneveLayer::toString() const
	{
		std::ostringstream result;
		result << "GENEVE Layer, VNI: " << getVNI() << ", Protocol type: 0x" << std::hex << getProtocolType();
		return result.str();
	}
}  // namespace pcpp
