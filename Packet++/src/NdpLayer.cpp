#define LOG_MODULE PacketLogModuleNdpLayer

#include <NdpLayer.h>

namespace pcpp
{

ndpoptionbase *NDPLayerBase::GetOptionOfType(size_t headerLen, NDPNeighborOptionTypes type) const
{
	uint8_t *ptr = m_Data + headerLen;

	/** Parse options as long as there is data available */
	while (ptr < (m_Data + m_DataLen))
	{
		ndpoptionbase *option = (ndpoptionbase *)ptr;

		switch (option->type)
		{
		/** Advance pointer by size of option. The pointer is therefore pointing to the beginning of the next option */

		/** Currently only the link layer options are implemented */
		case NDP_OPTION_TARGET_LINK_LAYER:
		case NDP_OPTION_SOURCE_LINK_LAYER: {
			if (type == option->type)
			{
				return option;
			}

			ptr += sizeof(ndpoptionlinklayer);
		}
		}
	}

	return nullptr;
}

void NDPLayerBase::CreateLinkLayerOption(ndpoptionlinklayer *pOption, NDPNeighborOptionTypes optionType,
										 const MacAddress &linkLayerAddr)
{
	pOption->type = optionType;
	pOption->length = sizeof(ndpoptionlinklayer) / 8;
	memcpy(pOption->linklayerAddress, linkLayerAddr.getRawData(), 6);
}

/*
 *	NDPNeighborAdvertisementLayer
 */

NDPNeighborAdvertisementLayer::NDPNeighborAdvertisementLayer(const IPv6Address &targetIP, const MacAddress &targetMac,
															 bool byRouter, bool unicastResponse, bool override)
{
	m_DataLen = sizeof(ndpneighboradvertisementhdr) + sizeof(ndpoptionlinklayer);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = NDPNeighborAdvertisement;

	setNeighborAdvertisementHeaderFields(targetIP, byRouter, unicastResponse, override);

	ndpoptionlinklayer *ptrToOption = (ndpoptionlinklayer *)(m_Data + sizeof(ndpneighboradvertisementhdr));
	CreateLinkLayerOption(ptrToOption, NDP_OPTION_TARGET_LINK_LAYER, targetMac);
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
	return m_DataLen > sizeof(ndpneighboradvertisementhdr);
}

MacAddress NDPNeighborAdvertisementLayer::getTargetMac() const
{
	if (!hasTargetMacInfo())
	{
		return MacAddress::Zero;
	}

	ndpoptionlinklayer *option =
		(ndpoptionlinklayer *)GetOptionOfType(sizeof(ndpneighboradvertisementhdr), NDP_OPTION_TARGET_LINK_LAYER);

	return MacAddress(option->linklayerAddress);
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
	memcpy(pHdr->targetIP, targetIP.toBytes(), 16);
}

NDPNeighborSolicitationLayer::NDPNeighborSolicitationLayer(const IPv6Address &targetIP, const MacAddress &srcMac)
{
	m_DataLen = sizeof(ndpneighborsolicitationhdr) + sizeof(ndpoptionlinklayer);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = NDPNeighborSolicitation;

	ndpneighborsolicitationhdr *pHdr = getNdpHeader();
	memcpy(pHdr->targetIP, targetIP.toBytes(), 16);

	ndpoptionlinklayer *ptrToOption = (ndpoptionlinklayer *)(m_Data + sizeof(ndpneighborsolicitationhdr));
	CreateLinkLayerOption(ptrToOption, NDP_OPTION_SOURCE_LINK_LAYER, srcMac);
}

std::string NDPNeighborSolicitationLayer::toString() const
{
	return "NDP Neighbor Solicitation Layer, TargetIP: " + getTargetIP().toString();
}

bool NDPNeighborSolicitationLayer::hasLinkLayerAddress() const
{
	return m_DataLen > sizeof(ndpneighborsolicitationhdr);
}

MacAddress NDPNeighborSolicitationLayer::getLinkLayerAddress() const
{
	if (!hasLinkLayerAddress())
	{
		return MacAddress::Zero;
	}

	ndpoptionlinklayer *option =
		(ndpoptionlinklayer *)GetOptionOfType(sizeof(ndpneighborsolicitationhdr), NDP_OPTION_SOURCE_LINK_LAYER);

	return MacAddress(option->linklayerAddress);
}

} // namespace pcpp
