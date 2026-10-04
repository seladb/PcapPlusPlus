#define LOG_MODULE PacketLogModuleGeneveLayer

#include "GeneveLayer.h"
#include "ArpLayer.h"
#include "EthDot3Layer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Logger.h"
#include "MplsLayer.h"
#include "PayloadLayer.h"
#include "VlanLayer.h"
#include "SystemUtils.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <vector>

namespace pcpp
{
	void GeneveOption::setOptionClass(uint16_t value)
	{
		m_Data->optionClass = hostToNet16(value);
	}

	void GeneveOption::setType(uint8_t value, bool critical)
	{
		m_Data->type = static_cast<uint8_t>(extractType(value) | (critical ? CriticalBitMask : 0));
	}

	void GeneveOption::setDataSize(size_t value)
	{
		m_Data->length = static_cast<uint8_t>(value / DataLengthUnit);
	}

	bool GeneveOption::canAssign(const uint8_t* optionRawData, size_t optionDataLen)
	{
		if (optionRawData == nullptr || optionDataLen < HeaderLength)
			return false;

		const auto* header = reinterpret_cast<const geneve_option_header*>(optionRawData);
		const auto totalSize = HeaderLength + static_cast<size_t>(header->length) * DataLengthUnit;
		return totalSize <= optionDataLen;
	}

	uint16_t GeneveOption::getOptionClass() const
	{
		if (isNull())
			return 0;
		return netToHost16(m_Data->optionClass);
	}

	uint8_t GeneveOption::getType() const
	{
		if (isNull())
			return 0;
		return extractType(m_Data->type);
	}

	bool GeneveOption::isCritical() const
	{
		if (isNull())
			return false;
		return (m_Data->type & CriticalBitMask) != 0;
	}

	size_t GeneveOption::getDataSize() const
	{
		if (isNull())
			return 0;
		return static_cast<size_t>(m_Data->length) * DataLengthUnit;
	}

	size_t GeneveOption::getTotalSize() const
	{
		if (isNull())
			return 0;
		return HeaderLength + getDataSize();
	}

	uint8_t* GeneveOption::getData() const
	{
		if (isNull())
			return nullptr;
		return reinterpret_cast<uint8_t*>(m_Data) + HeaderLength;
	}

	GeneveLayer::GeneveLayer(uint32_t vni, uint16_t protocolType, bool oamFlag)
	{
		allocData(HeaderLength);
		m_Protocol = Geneve;
		setVNI(vni);
		setProtocolType(protocolType);
		setOamFlag(oamFlag);
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
		if (netToHost16(header->protocolType) < 0x0600)
			return false;

		auto optionsLength = static_cast<size_t>(header->optionsLength) * OptionsLengthUnit;
		if (optionsLength > dataLen - HeaderLength)
			return false;

		return true;
	}

	uint32_t GeneveLayer::getVNI() const
	{
		const geneve_header* header = getGeneveHeader();
		return (static_cast<uint32_t>(header->vni[0]) << 16) | (static_cast<uint32_t>(header->vni[1]) << 8) |
		       header->vni[2];
	}

	void GeneveLayer::setVNI(uint32_t vni)
	{
		geneve_header* header = getGeneveHeader();
		header->vni[0] = static_cast<uint8_t>((vni >> 16) & 0xff);
		header->vni[1] = static_cast<uint8_t>((vni >> 8) & 0xff);
		header->vni[2] = static_cast<uint8_t>(vni & 0xff);
	}

	uint16_t GeneveLayer::getProtocolType() const
	{
		return netToHost16(getGeneveHeader()->protocolType);
	}

	void GeneveLayer::setProtocolType(uint16_t protocolType)
	{
		getGeneveHeader()->protocolType = hostToNet16(protocolType);
	}

	bool GeneveLayer::getOamFlag() const
	{
		return getGeneveHeader()->oamFlag != 0;
	}

	void GeneveLayer::setOamFlag(bool value)
	{
		getGeneveHeader()->oamFlag = value ? 1 : 0;
	}

	bool GeneveLayer::getCriticalFlag() const
	{
		return getGeneveHeader()->criticalFlag != 0;
	}

	size_t GeneveLayer::getOptionsLength() const
	{
		return static_cast<size_t>(getGeneveHeader()->optionsLength) * OptionsLengthUnit;
	}

	void GeneveLayer::setOptionsLength(size_t value)
	{
		getGeneveHeader()->optionsLength = static_cast<uint8_t>(value / OptionsLengthUnit);
	}

	size_t GeneveLayer::getHeaderLen() const
	{
		return (std::min)(m_DataLen, HeaderLength + getOptionsLength());
	}

	GeneveOption GeneveLayer::getFirstOption() const
	{
		if (m_Data == nullptr || m_DataLen < HeaderLength || getOptionsLength() > m_DataLen - HeaderLength)
			return GeneveOption();

		uint8_t* options = m_Data + HeaderLength;
		return GeneveOption::canAssign(options, getOptionsLength()) ? GeneveOption(options) : GeneveOption();
	}

	GeneveOption GeneveLayer::getNextOption(const GeneveOption& option) const
	{
		if (m_Data == nullptr || m_DataLen < HeaderLength || option.isNull() ||
		    getOptionsLength() > m_DataLen - HeaderLength)
			return GeneveOption();

		uint8_t* optionsBegin = m_Data + HeaderLength;
		uint8_t* current = option.getRecordBasePtr();
		const auto optionsBeginAddress = reinterpret_cast<std::uintptr_t>(optionsBegin);
		const auto currentAddress = reinterpret_cast<std::uintptr_t>(current);
		if (currentAddress < optionsBeginAddress)
			return GeneveOption();

		const auto currentOffsetAddress = currentAddress - optionsBeginAddress;
		const size_t optionsLength = getOptionsLength();
		if (currentOffsetAddress >= optionsLength)
			return GeneveOption();

		const auto currentOffset = static_cast<size_t>(currentOffsetAddress);
		const size_t currentBytesAvailable = optionsLength - currentOffset;
		if (!GeneveOption::canAssign(current, currentBytesAvailable))
			return GeneveOption();

		const size_t nextOffset = currentOffset + option.getTotalSize();
		if (nextOffset >= optionsLength)
			return GeneveOption();

		uint8_t* next = optionsBegin + nextOffset;
		if (!GeneveOption::canAssign(next, optionsLength - nextOffset))
			return GeneveOption();

		return GeneveOption(next);
	}

	GeneveOption GeneveLayer::getOption(uint16_t optionClass, uint8_t optionType) const
	{
		for (GeneveOption option = getFirstOption(); !option.isNull(); option = getNextOption(option))
		{
			if (option.getOptionClass() == optionClass && option.getType() == GeneveOption::extractType(optionType))
				return option;
		}

		return GeneveOption();
	}

	size_t GeneveLayer::getOptionCount() const
	{
		size_t count = 0;
		for (GeneveOption option = getFirstOption(); !option.isNull(); option = getNextOption(option))
			++count;
		return count;
	}

	bool GeneveLayer::addOption(uint16_t optionClass, uint8_t optionType, const uint8_t* optionData,
	                            size_t optionDataLen, bool critical)
	{
		if (optionDataLen > GeneveOption::MaxDataLength || (optionData == nullptr && optionDataLen > 0))
		{
			PCPP_LOG_ERROR("Cannot add GENEVE option with invalid data length");
			return false;
		}

		size_t paddedDataLength = GeneveOption::alignDataSize(optionDataLen);
		size_t optionSize = GeneveOption::HeaderLength + paddedDataLength;
		size_t oldOptionsLength = getOptionsLength();
		if (oldOptionsLength + optionSize > MaxOptionsLength)
		{
			PCPP_LOG_ERROR("GENEVE options exceed the maximum length of 252 bytes");
			return false;
		}

		// extendLayer() can reallocate the layer data, so preserve the input before extending it. This also handles
		// callers passing data that aliases this layer or another layer in the same packet.
		std::vector<uint8_t> optionDataCopy(optionDataLen);
		if (optionDataLen > 0)
			memcpy(optionDataCopy.data(), optionData, optionDataLen);

		auto offset = static_cast<int>(HeaderLength + oldOptionsLength);
		if (!extendLayer(offset, optionSize))
		{
			PCPP_LOG_ERROR("Could not extend GeneveLayer by " << optionSize << " bytes");
			return false;
		}

		memset(m_Data + offset, 0, optionSize);
		GeneveOption option(m_Data + offset);
		option.setOptionClass(optionClass);
		option.setType(optionType, critical);
		option.setDataSize(paddedDataLength);
		if (optionDataLen > 0)
			memcpy(option.getData(), optionDataCopy.data(), optionDataLen);
		setOptionsLength(oldOptionsLength + optionSize);
		updateCriticalFlag();
		return true;
	}

	bool GeneveLayer::removeOption(uint16_t optionClass, uint8_t optionType)
	{
		GeneveOption option = getOption(optionClass, optionType);
		if (option.isNull())
			return false;

		size_t oldOptionsLength = getOptionsLength();
		size_t optionSize = option.getTotalSize();
		auto offset = static_cast<int>(option.getRecordBasePtr() - m_Data);
		if (!shortenLayer(offset, optionSize))
			return false;

		setOptionsLength(oldOptionsLength - optionSize);
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

		if (!shortenLayer(HeaderLength, optionsLength))
			return false;

		setOptionsLength(0);
		getGeneveHeader()->criticalFlag = 0;
		return true;
	}

	void GeneveLayer::updateCriticalFlag()
	{
		getGeneveHeader()->criticalFlag = 0;
		for (GeneveOption option = getFirstOption(); !option.isNull(); option = getNextOption(option))
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
