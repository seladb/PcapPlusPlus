#define LOG_MODULE PacketLogModuleNdpLayer

#include "NdpLayer.h"
#include "Logger.h"

namespace pcpp
{

	// -------- Class NdpOptionBuilder -----------------

	NdpOption NdpOptionBuilder::build() const
	{
		size_t optionSize = m_RecValueLen + 2 * sizeof(uint8_t);
		size_t padding = (8 - (optionSize % 8)) % 8;  // Padding bytes for a option with 8 byte boundary
		size_t optionSizeWithPadding = optionSize + padding;

		uint8_t* recordBuffer = new uint8_t[optionSizeWithPadding];
		memset(recordBuffer, 0, optionSizeWithPadding);
		recordBuffer[0] = static_cast<uint8_t>(m_RecType);
		// length value is stored in units of 8 octets
		recordBuffer[1] = static_cast<uint8_t>(optionSizeWithPadding / 8);
		memcpy(recordBuffer + 2, m_RecValue, m_RecValueLen);

		return NdpOption(recordBuffer);
	}

	// -------- Class NDPLayerBase -----------------

	size_t NDPLayerBase::getNdpOptionCount() const
	{
		return m_OptionReader.getTLVRecordCount(getNdpOptionsBasePtr(), getHeaderLen() - getNdpHeaderLen());
	}

	NdpOption NDPLayerBase::getFirstNdpOption() const
	{
		return m_OptionReader.getFirstTLVRecord(getNdpOptionsBasePtr(), getHeaderLen() - getNdpHeaderLen());
	}

	NdpOption NDPLayerBase::getNextNdpOption(NdpOption& option) const
	{
		return m_OptionReader.getNextTLVRecord(option, getNdpOptionsBasePtr(), getHeaderLen() - getNdpHeaderLen());
	}

	NdpOption NDPLayerBase::getNdpOption(NDPNeighborOptionTypes option) const
	{
		return m_OptionReader.getTLVRecord((uint8_t)option, getNdpOptionsBasePtr(), getHeaderLen() - getNdpHeaderLen());
	}

	NdpOption NDPLayerBase::addNdpOption(const NdpOptionBuilder& optionBuilder)
	{
		return addNdpOptionAt(optionBuilder, getHeaderLen());
	}

	NdpOption NDPLayerBase::addNdpOptionAt(const NdpOptionBuilder& optionBuilder, int offset)
	{
		NdpOption newOption = optionBuilder.build();

		if (newOption.isNull())
		{
			PCPP_LOG_ERROR("Cannot build new option of type " << (int)newOption.getType());
			return newOption;
		}

		size_t sizeToExtend = newOption.getTotalSize();

		if (!extendLayer(offset, sizeToExtend))
		{
			PCPP_LOG_ERROR("Could not extend NdpLayer in [" << sizeToExtend << "] bytes");
			newOption.purgeRecordData();
			return NdpOption(nullptr);
		}

		memcpy(m_Data + offset, newOption.getRecordBasePtr(), newOption.getTotalSize());

		newOption.purgeRecordData();

		m_OptionReader.changeTLVRecordCount(1);

		uint8_t* newOptPtr = m_Data + offset;

		return NdpOption(newOptPtr);
	}

	bool NDPLayerBase::removeAllNdpOptions()
	{
		int offset = getNdpHeaderLen();
		if (!shortenLayer(offset, getHeaderLen() - offset))
			return false;

		m_OptionReader.changeTLVRecordCount(0 - getNdpOptionCount());
		return true;
	}

	// -------- Class NDPNeighborSolicitationLayer -----------------

	NDPNeighborSolicitationLayer::NDPNeighborSolicitationLayer(uint8_t code, const IPv6Address& targetIP)
	{
		initLayer(code, targetIP);
	}

	NDPNeighborSolicitationLayer::NDPNeighborSolicitationLayer(uint8_t code, const IPv6Address& targetIP,
	                                                           const MacAddress& srcMac)
	{
		initLayer(code, targetIP);
		this->addNdpOption(
		    pcpp::NdpOptionBuilder(pcpp::NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER, srcMac.getRawData(), 6));
	}

	void NDPNeighborSolicitationLayer::initLayer(uint8_t code, const IPv6Address& targetIP)
	{
		m_DataLen = sizeof(ndpneighborsolicitationhdr);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = ICMPv6;

		ndpneighborsolicitationhdr* pHdr = getNdpHeader();
		pHdr->type = static_cast<uint8_t>(ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION);
		pHdr->code = code;
		memcpy(pHdr->targetIP, targetIP.toBytes(), 16);
	}

	bool NDPNeighborSolicitationLayer::hasLinkLayerAddress() const
	{
		NdpOption option = this->getNdpOption(NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER);
		return option.isNull() ? false : true;
	}

	MacAddress NDPNeighborSolicitationLayer::getLinkLayerAddress() const
	{
		NdpOption option = this->getNdpOption(NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER);

		if (option.isNull())
		{
			return MacAddress::Zero;
		}

		return MacAddress(option.getValue());
	}

	std::string NDPNeighborSolicitationLayer::toString() const
	{
		std::ostringstream typeStream;
		typeStream << "ICMPv6 Layer, Neighbor Solicitation Message, TargetIP: " + getTargetIP().toString();
		hasLinkLayerAddress() ? typeStream << ", SourceMAC: " + getLinkLayerAddress().toString()
		                      : typeStream << ", no Option";

		return typeStream.str();
	}

	// -------- Class NDPNeighborAdvertisementLayer -----------------

	NDPNeighborAdvertisementLayer::NDPNeighborAdvertisementLayer(uint8_t code, const IPv6Address& targetIP,
	                                                             const MacAddress& targetMac, bool routerFlag,
	                                                             bool unicastFlag, bool overrideFlag)
	{
		initLayer(code, targetIP, routerFlag, unicastFlag, overrideFlag);
		this->addNdpOption(pcpp::NdpOptionBuilder(pcpp::NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER,
		                                          targetMac.getRawData(), 6));
	}

	NDPNeighborAdvertisementLayer::NDPNeighborAdvertisementLayer(uint8_t code, const IPv6Address& targetIP,
	                                                             bool routerFlag, bool unicastFlag, bool overrideFlag)
	{
		initLayer(code, targetIP, routerFlag, unicastFlag, overrideFlag);
	}

	void NDPNeighborAdvertisementLayer::initLayer(uint8_t code, const IPv6Address& targetIP, bool routerFlag,
	                                              bool unicastFlag, bool overrideFlag)
	{
		m_DataLen = sizeof(ndpneighboradvertisementhdr);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = ICMPv6;

		ndpneighboradvertisementhdr* pHdr = getNdpHeader();
		pHdr->type = static_cast<uint8_t>(ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT);
		pHdr->code = code;
		pHdr->router = routerFlag;
		pHdr->solicited = unicastFlag;
		pHdr->override = overrideFlag;

		memcpy(pHdr->targetIP, targetIP.toBytes(), 16);
	}

	bool NDPNeighborAdvertisementLayer::hasTargetMacInfo() const
	{
		NdpOption option = this->getNdpOption(NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER);
		return option.isNull() ? false : true;
	}

	MacAddress NDPNeighborAdvertisementLayer::getTargetMac() const
	{
		NdpOption option = this->getNdpOption(NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER);

		if (option.isNull())
		{
			return MacAddress::Zero;
		}

		return MacAddress(option.getValue());
	}

	std::string NDPNeighborAdvertisementLayer::toString() const
	{
		std::ostringstream typeStream;
		typeStream << "ICMPv6 Layer, Neighbor Advertisement Message, TargetIP: " << getTargetIP().toString();
		hasTargetMacInfo() ? typeStream << ", TargetMAC: " + getTargetMac().toString() : typeStream << ", no Option";

		return typeStream.str();
	}

}  // namespace pcpp
