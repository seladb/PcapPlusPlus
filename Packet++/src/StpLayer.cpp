#define LOG_MODULE PacketLogModuleStpLayer

#include "StpLayer.h"
#include "Logger.h"

namespace pcpp
{

// ---------------------- Class STP Layer ----------------------
MacAddress StpLayer::StpMulticastDstMAC("01:80:C2:00:00:00");
MacAddress StpLayer::StpUplinkFastMulticastDstMAC("01:00:0C:CD:CD:CD");

MacAddress StpLayer::IDtoMacAddress(uint64_t id)
{
	return MacAddress((id >> 40) & 0xFF, (id >> 32) & 0xFF, (id >> 24) & 0xFF, (id >> 16) & 0xFF,
							(id >> 8) & 0xFF, id & 0xFF);
}

bool StpLayer::isDataValid(const uint8_t *data, size_t dataLen) { return data && dataLen; }

StpLayer* StpLayer::parseStpLayer(uint8_t *data, size_t dataLen, Layer* prevLayer, Packet* packet)
{
	if (dataLen >= sizeof(stp_tcn_bpdu))
	{
		stp_tcn_bpdu *ptr = (stp_tcn_bpdu *)data;
		switch (ptr->type)
		{
		case 0x00:
			return StpConfigurationBPDULayer::isDataValid(data, dataLen)
				? new StpConfigurationBPDULayer(data, dataLen, prevLayer, packet)
				: nullptr;
		case 0x80:
			return StpTopologyChangeBPDULayer::isDataValid(data, dataLen)
				? new StpTopologyChangeBPDULayer(data, dataLen, prevLayer, packet)
				: nullptr;
		case 0x02:
			if (ptr->version == 0x2)
				return RapidStpLayer::isDataValid(data, dataLen)
					? new RapidStpLayer(data, dataLen, prevLayer, packet)
					: nullptr;
			if (ptr->version == 0x3)
				return MultipleStpLayer::isDataValid(data, dataLen)
					? new MultipleStpLayer(data, dataLen, prevLayer, packet)
					: nullptr;
			PCPP_LOG_DEBUG("Unknown Spanning Tree Version");
			return nullptr;
		// TODO: Per VLAN Spanning Tree+ (PVST+)
		// TODO: Rapid Per VLAN Spanning Tree+ (RPVST+)
		// TODO: Cisco Uplink Fast
		default:
			PCPP_LOG_DEBUG("Unknown Spanning Tree Protocol type");
			return nullptr;
		}
	}

	PCPP_LOG_DEBUG("Data length is less than any STP header");
	return nullptr;
}

// ---------------------- Class MultipleStp Layer ----------------------

msti_conf_msg *MultipleStpLayer::getMstiConfMessages() const
{
	if (getNumberOfMSTIConfMessages())
		return (msti_conf_msg *)(m_Data + sizeof(mstp_conf_bpdu));
	return nullptr;
}

std::string MultipleStpLayer::getMstConfigurationName() const
{
	std::string str = std::string((char *)(getMstpHeader()->mstConfigName), 32);
	str.erase(std::find(str.begin(), str.end(), '\0'), str.end());
	return str;
}

} // namespace pcpp
