#define LOG_MODULE PacketLogModuleStpLayer

#include "StpLayer.h"
#include "EndianPortable.h"
#include "Logger.h"

namespace pcpp
{

// ---------------------- Class STPLayer ----------------------
MacAddress StpLayer::StpMulticastDstMAC("01:80:C2:00:00:00");
MacAddress StpLayer::StpUplinkFastMulticastDstMAC("01:00:0C:CD:CD:CD");

MacAddress StpLayer::IDtoMacAddress(uint64_t id)
{
	return MacAddress((id >> 40) & 0xFF, (id >> 32) & 0xFF, (id >> 24) & 0xFF, (id >> 16) & 0xFF, (id >> 8) & 0xFF,
						id & 0xFF);
}

bool StpLayer::isDataValid(const uint8_t *data, size_t dataLen) { return data && dataLen; }

StpLayer *StpLayer::parseStpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
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

// ---------------------- Class StpConfigurationBPDULayer ----------------------
uint64_t StpConfigurationBPDULayer::getRootId() const { return be64toh(getStpConfHeader()->rootId); }

uint16_t StpConfigurationBPDULayer::getRootPriority() const { return be16toh(getStpConfHeader()->rootId) & 0xf000; }

uint16_t StpConfigurationBPDULayer::getRootSystemIDExtension() const
{
	return be16toh(getStpConfHeader()->rootId) & 0x0fff;
}

uint32_t StpConfigurationBPDULayer::getPathCost() const { return be32toh(getStpConfHeader()->pathCost); }

uint64_t StpConfigurationBPDULayer::getBridgeId() const { return be64toh(getStpConfHeader()->bridgeId); }

uint16_t StpConfigurationBPDULayer::getBridgePriority() const
{
	return be16toh(getStpConfHeader()->bridgeId) & 0xf000;
}

uint16_t StpConfigurationBPDULayer::getBridgeSystemIDExtension() const
{
	return be16toh(getStpConfHeader()->bridgeId) & 0x0fff;
}

uint16_t StpConfigurationBPDULayer::getPortId() const { return be16toh(getStpConfHeader()->portId); }

double StpConfigurationBPDULayer::getMessageAge() const { return be16toh(getStpConfHeader()->msgAge) / 256.0; }

double StpConfigurationBPDULayer::getMaximumAge() const { return be16toh(getStpConfHeader()->maxAge) / 256.0; }

double StpConfigurationBPDULayer::getTransmissionInterval() const
{
	return be16toh(getStpConfHeader()->helloTime) / 256.0;
}

double StpConfigurationBPDULayer::getForwardDelay() const
{
	return be16toh(getStpConfHeader()->forwardDelay) / 256.0;
}

// ---------------------- Class MultipleStpLayer ----------------------

uint16_t MultipleStpLayer::getVersion3Len() const { return be16toh(getMstpHeader()->version3Len); }

uint32_t MultipleStpLayer::getCISTIrpc() const { return be32toh(getMstpHeader()->irpc); }

uint64_t MultipleStpLayer::getCISTBridgeId() const { return be64toh(getMstpHeader()->cistBridgeId); }

uint16_t MultipleStpLayer::getCISTBridgePriority() const { return be16toh(getMstpHeader()->cistBridgeId) & 0xf000; }

uint16_t MultipleStpLayer::getCISTBridgeSystemIDExtension() const
{
	return be16toh(getMstpHeader()->cistBridgeId) & 0x0fff;
}

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
