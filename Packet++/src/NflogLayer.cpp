#define LOG_MODULE PacketLogModuleNflogLayer

#include "NflogLayer.h"
#include "Logger.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "ArpLayer.h"
#include "VlanLayer.h"
#include "PPPoELayer.h"
#include "MplsLayer.h"
#include <string.h>
#include "EndianPortable.h"

namespace pcpp
{

void NflogLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(nflog_header))
		return;

	uint8_t* payload = m_Data + sizeof(nflog_header);
	size_t payloadLen = m_DataLen - sizeof(nflog_header);

	m_NextLayer = static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet));


}

void NflogLayer::computeCalculateFields()
{
	if (m_NextLayer == NULL)
		return;

	nflog_header* hdr = getNflogHeader();
	switch (m_NextLayer->getProtocol())
	{
		case IPv4:
			hdr->address_family = PCPP_ETHERTYPE_IP;
			break;
		default:
			return;
	}
}

std::string NflogLayer::toString() const
{
	return "Linux Netfilter NFLOG";
}

} // namespace pcpp
