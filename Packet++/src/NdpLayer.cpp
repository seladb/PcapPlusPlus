#define LOG_MODULE PacketLogModuleNdpLayer

#include <NdpLayer.h>
#include "Logger.h"

namespace pcpp
{

/*
 *	NdpOptionBuilder
 */

NdpOption NdpOptionBuilder::build() const
{
	size_t optionSize = m_RecValueLen + 2*sizeof(uint8_t);
	size_t padding = 0;

	while((optionSize+padding) % 8){
		++padding;
	}
	size_t optionSizePadding = optionSize + padding;

	uint8_t* recordBuffer = new uint8_t[optionSizePadding];
	memset(recordBuffer, 0, optionSizePadding);
	recordBuffer[0] = static_cast<uint8_t>(m_RecType);
	recordBuffer[1] = static_cast<uint8_t>(optionSizePadding / 8);
	memcpy(recordBuffer+2, m_RecValue, m_RecValueLen);

	return NdpOption(recordBuffer);
}

/*
 *	NDPLayerBase
 */

size_t NDPLayerBase::getNdpOptionCount() const
{
	return m_OptionReader.getTLVRecordCount(getNdpOptionsBasePtr(), getHeaderLen() - getNdpHeaderLen());
}

NdpOption NDPLayerBase::getFirstNdpOption() const
{
	return m_OptionReader.getFirstTLVRecord(getNdpOptionsBasePtr(), getHeaderLen() - getNdpHeaderLen());
}

NdpOption NDPLayerBase::getNextNdpOption(NdpOption& ndpOption) const
{
	NdpOption nextOpt = m_OptionReader.getNextTLVRecord(ndpOption, getNdpOptionsBasePtr(), getHeaderLen() - getNdpHeaderLen());
	if (nextOpt.isNotNull())
		return NdpOption(NULL);

	return nextOpt;
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
		return NdpOption(NULL);
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
	if (!shortenLayer(offset, getHeaderLen()-getNdpHeaderLen()))
		return false;

	m_OptionReader.changeTLVRecordCount(0-getNdpOptionCount());
	return true;
}

/*
 *	NDPNeighborAdvertisementLayer
 */

NDPNeighborAdvertisementLayer::NDPNeighborAdvertisementLayer(const IPv6Address &targetIP, const MacAddress &targetMac,
															 bool byRouter, bool unicastResponse, bool override)
{
	m_DataLen = sizeof(ndpneighboradvertisementhdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = NDPNeighborAdvertisement;

	setNeighborAdvertisementHeaderFields(targetIP, byRouter, unicastResponse, override);

	this->addNdpOption(pcpp::NdpOptionBuilder(pcpp::NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER, targetMac.getRawData(), 6));
}

NDPNeighborAdvertisementLayer::NDPNeighborAdvertisementLayer(const IPv6Address &targetIP, bool byRouter,
															 bool unicastResponse, bool override)
{
	m_DataLen = sizeof(ndpneighboradvertisementhdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = NDPNeighborAdvertisement;

	setNeighborAdvertisementHeaderFields(targetIP, byRouter, unicastResponse, override);
}

void NDPNeighborAdvertisementLayer::setNeighborAdvertisementHeaderFields(const IPv6Address &targetIP, bool byRouter,
																		 bool unicastResponse, bool override)
{
	ndpneighboradvertisementhdr *pHdr = getNdpHeader();
	pHdr->type =ICMPv6_NEIGHBOR_ADVERTISEMENT;
	pHdr->router = byRouter;
	pHdr->solicited = unicastResponse;
	pHdr->override = override;

	memcpy(pHdr->targetIP, targetIP.toBytes(), 16);
}

std::string NDPNeighborAdvertisementLayer::toString() const
{
	return "NDP Neighbor Advertisement Layer, TargetIP: " + getTargetIP().toString() + ", TargetMAC: " + getTargetMac().toString();
}

bool NDPNeighborAdvertisementLayer::hasTargetMacInfo() const
{
	NdpOption option = this->getNdpOption(NDP_OPTION_TARGET_LINK_LAYER);
	return option.isNull() ? false : true;
}

MacAddress NDPNeighborAdvertisementLayer::getTargetMac() const
{
	NdpOption option = this->getNdpOption(NDP_OPTION_TARGET_LINK_LAYER);

	if(option.isNull())
	{
		return MacAddress::Zero;
	}

	return MacAddress(option.getValue());
}

/*
 *	NDPNeighborSolicitationLayer
 */

NDPNeighborSolicitationLayer::NDPNeighborSolicitationLayer(const IPv6Address &targetIP)
{
	m_DataLen = sizeof(ndpneighborsolicitationhdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = NDPNeighborSolicitation;

	ndpneighborsolicitationhdr *pHdr = getNdpHeader();
	pHdr->type =ICMPv6_NEIGHBOR_SOLICITATION;
	memcpy(pHdr->targetIP, targetIP.toBytes(), 16);
}

NDPNeighborSolicitationLayer::NDPNeighborSolicitationLayer(const IPv6Address &targetIP, const MacAddress &srcMac)
{
	m_DataLen = sizeof(ndpneighborsolicitationhdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = NDPNeighborSolicitation;

	ndpneighborsolicitationhdr *pHdr = getNdpHeader();
	pHdr->type =ICMPv6_NEIGHBOR_SOLICITATION;
	memcpy(pHdr->targetIP, targetIP.toBytes(), 16);

	this->addNdpOption(pcpp::NdpOptionBuilder(pcpp::NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER, srcMac.getRawData(), 6));
}

std::string NDPNeighborSolicitationLayer::toString() const
{
	return "NDP Neighbor Solicitation Layer, TargetIP: " + getTargetIP().toString();
}

bool NDPNeighborSolicitationLayer::hasLinkLayerAddress() const
{
	NdpOption option = this->getNdpOption(NDP_OPTION_SOURCE_LINK_LAYER);
	return option.isNull() ? false : true;
}

MacAddress NDPNeighborSolicitationLayer::getLinkLayerAddress() const
{
	NdpOption option = this->getNdpOption(NDP_OPTION_SOURCE_LINK_LAYER);

	if(option.isNull())
	{
		return MacAddress::Zero;
	}

	return MacAddress(option.getValue());
}

} // namespace pcpp
