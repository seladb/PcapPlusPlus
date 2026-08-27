#define LOG_MODULE PacketLogModuleGeneveLayer

#include "GeneveLayer.h"
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
	namespace
	{
		constexpr uint8_t GeneveSupportedVersion = 0;
		constexpr size_t GeneveOptionAlignment = 4;
		constexpr uint8_t GeneveOptionLengthMask = 0x1f;
		constexpr uint8_t GeneveOptionTypeMask = 0x7f;
		constexpr uint8_t GeneveOptionCriticalBitMask = 0x80;
		constexpr uint8_t GeneveOptionsLengthMask = 0x3f;
		constexpr size_t GeneveMaxOptionDataLength = GeneveOptionLengthMask * GeneveOptionAlignment;
		constexpr size_t GeneveMaxOptionsLength = GeneveOptionsLengthMask * GeneveOptionAlignment;
		constexpr uint8_t BitsPerByte = 8;
		constexpr uint32_t ByteMask = 0xff;

		size_t getGeneveOptionTotalSize(const uint8_t* optionData)
		{
			constexpr size_t OptionLengthFieldOffset = sizeof(geneve_option_header) - 1;
			auto optionDataLength = static_cast<size_t>(optionData[OptionLengthFieldOffset] & GeneveOptionLengthMask) *
			                        GeneveOptionAlignment;
			return sizeof(geneve_option_header) + optionDataLength;
		}
	}  // namespace

	bool GeneveOption::canAssign(const uint8_t* optionRawData, size_t optionDataLen)
	{
		if (optionRawData == nullptr || optionDataLen < sizeof(geneve_option_header))
			return false;

		return getGeneveOptionTotalSize(optionRawData) <= optionDataLen;
	}

	uint16_t GeneveOption::getOptionClass() const
	{
		return be16toh(m_Data->optionClass);
	}

	uint8_t GeneveOption::getType() const
	{
		return static_cast<uint8_t>(m_Data->type & GeneveOptionTypeMask);
	}

	bool GeneveOption::isCritical() const
	{
		return (m_Data->type & GeneveOptionCriticalBitMask) != 0;
	}

	size_t GeneveOption::getDataSize() const
	{
		return static_cast<size_t>(m_Data->length) * GeneveOptionAlignment;
	}

	size_t GeneveOption::getTotalSize() const
	{
		return sizeof(geneve_option_header) + getDataSize();
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
			if (option.getOptionClass() == optionClass && option.getType() == (optionType & GeneveOptionTypeMask))
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
		if (m_RecValueLen > GeneveMaxOptionDataLength)
			return {};

		constexpr size_t AlignmentMask = GeneveOptionAlignment - 1;
		size_t paddedDataLength = (m_RecValueLen + AlignmentMask) & ~AlignmentMask;

		size_t totalLength = sizeof(geneve_option_header) + paddedDataLength;
		std::vector<uint8_t> optionData(totalLength, 0);

		geneve_option_header header = {};
		header.optionClass = htobe16(m_OptionClass);
		header.type = static_cast<uint8_t>(m_RecType & GeneveOptionTypeMask);
		if (m_Critical)
			header.type |= GeneveOptionCriticalBitMask;
		header.length = static_cast<uint8_t>(paddedDataLength / GeneveOptionAlignment);
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
		if (header->version != GeneveSupportedVersion)
			return false;

		size_t optionsLength = static_cast<size_t>(header->optionsLength) * GeneveOptionAlignment;
		if (optionsLength > dataLen - sizeof(geneve_header))
			return false;

		const uint8_t* option = data + sizeof(geneve_header);
		size_t remaining = optionsLength;
		while (remaining > 0)
		{
			if (!GeneveOption::canAssign(option, remaining))
				return false;

			size_t optionLength = getGeneveOptionTotalSize(option);
			option += optionLength;
			remaining -= optionLength;
		}

		return true;
	}

	uint32_t GeneveLayer::getVNI() const
	{
		const uint8_t* vni = getGeneveHeader()->vni;
		return (static_cast<uint32_t>(vni[0]) << (2 * BitsPerByte)) | (static_cast<uint32_t>(vni[1]) << BitsPerByte) |
		       vni[2];
	}

	void GeneveLayer::setVNI(uint32_t vni)
	{
		uint8_t* vniData = getGeneveHeader()->vni;
		vniData[0] = static_cast<uint8_t>((vni >> (2 * BitsPerByte)) & ByteMask);
		vniData[1] = static_cast<uint8_t>((vni >> BitsPerByte) & ByteMask);
		vniData[2] = static_cast<uint8_t>(vni & ByteMask);
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
		return static_cast<size_t>(getGeneveHeader()->optionsLength) * GeneveOptionAlignment;
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
		if (oldOptionsLength + optionData.size() > GeneveMaxOptionsLength)
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
		getGeneveHeader()->optionsLength =
		    static_cast<uint8_t>((oldOptionsLength + optionSize) / GeneveOptionAlignment);
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

		getGeneveHeader()->optionsLength =
		    static_cast<uint8_t>((oldOptionsLength - optionSize) / GeneveOptionAlignment);
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
