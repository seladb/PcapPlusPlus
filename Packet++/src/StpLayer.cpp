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

uint64_t StpLayer::MacAddresstoID(const pcpp::MacAddress &addr)
{
	uint8_t value[6];
	addr.copyTo(value);
	return ((uint64_t(value[0]) << 40) | (uint64_t(value[1]) << 32) | (uint64_t(value[2]) << 24) |
			(uint64_t(value[3]) << 16) | (uint64_t(value[4]) << 8) | (uint64_t(value[5])));
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

void StpConfigurationBPDULayer::setRootId(uint64_t value) { getStpConfHeader()->rootId = htobe64(value); }

uint16_t StpConfigurationBPDULayer::getRootPriority() const { return be16toh(getStpConfHeader()->rootId) & 0xf000; }

void StpConfigurationBPDULayer::setRootPriority(uint16_t value)
{
	getStpConfHeader()->rootId = (getStpConfHeader()->rootId & ~htobe16(0xf000)) | htobe16(value & 0xf000);
}

uint16_t StpConfigurationBPDULayer::getRootSystemIDExtension() const
{
	return be16toh(getStpConfHeader()->rootId) & 0x0fff;
}

void StpConfigurationBPDULayer::setRootSystemIDExtension(uint16_t value)
{
	getStpConfHeader()->rootId = (getStpConfHeader()->rootId & ~htobe16(0x0fff)) | htobe16(value & 0x0fff);
}

void StpConfigurationBPDULayer::setRootSystemID(const pcpp::MacAddress &value) 
{
	setRootId((getRootId() & (uint64_t(0xffff) << 48)) | MacAddresstoID(value));
};

uint32_t StpConfigurationBPDULayer::getPathCost() const { return be32toh(getStpConfHeader()->pathCost); }

void StpConfigurationBPDULayer::setPathCost(uint32_t value) { getStpConfHeader()->pathCost = htobe32(value); }

uint64_t StpConfigurationBPDULayer::getBridgeId() const { return be64toh(getStpConfHeader()->bridgeId); }

void StpConfigurationBPDULayer::setBridgeId(uint64_t value) { getStpConfHeader()->bridgeId = htobe64(value); }

uint16_t StpConfigurationBPDULayer::getBridgePriority() const
{
	return be16toh(getStpConfHeader()->bridgeId) & 0xf000;
}

void StpConfigurationBPDULayer::setBridgePriority(uint16_t value)
{
	getStpConfHeader()->bridgeId = (getStpConfHeader()->bridgeId & ~htobe16(0xf000)) | htobe16(value & 0xf000);
}

uint16_t StpConfigurationBPDULayer::getBridgeSystemIDExtension() const
{
	return be16toh(getStpConfHeader()->bridgeId) & 0x0fff;
}

void StpConfigurationBPDULayer::setBridgeSystemIDExtension(uint16_t value)
{
	getStpConfHeader()->bridgeId = (getStpConfHeader()->bridgeId & ~htobe16(0x0fff)) | htobe16(value & 0x0fff);
}

void StpConfigurationBPDULayer::setBridgeSystemID(const pcpp::MacAddress &value)
{
	setBridgeId((getBridgeId() & (uint64_t(0xffff) << 48)) | MacAddresstoID(value));
}

uint16_t StpConfigurationBPDULayer::getPortId() const { return be16toh(getStpConfHeader()->portId); }

void StpConfigurationBPDULayer::setPortId(uint16_t value) { getStpConfHeader()->portId = htobe16(value); }

double StpConfigurationBPDULayer::getMessageAge() const { return getStpConfHeader()->msgAge; }

void StpConfigurationBPDULayer::setMessageAge(double value) { getStpConfHeader()->msgAge = value; }

double StpConfigurationBPDULayer::getMaximumAge() const { return getStpConfHeader()->maxAge; }

void StpConfigurationBPDULayer::setMaximumAge(double value) { getStpConfHeader()->maxAge = value; }

double StpConfigurationBPDULayer::getTransmissionInterval() const { return getStpConfHeader()->helloTime; }

void StpConfigurationBPDULayer::setTransmissionInterval(double value) { getStpConfHeader()->helloTime = value; }

double StpConfigurationBPDULayer::getForwardDelay() const { return getStpConfHeader()->forwardDelay; }

void StpConfigurationBPDULayer::setForwardDelay(double value) { getStpConfHeader()->forwardDelay = value; }

// ---------------------- Class MultipleStpLayer ----------------------

uint16_t MultipleStpLayer::getVersion3Len() const { return be16toh(getMstpHeader()->version3Len); }

void MultipleStpLayer::setVersion3Len(uint16_t value)
{
	getMstpHeader()->version3Len = htobe16(getMstpHeader()->version3Len);
}

uint32_t MultipleStpLayer::getCISTIrpc() const { return be32toh(getMstpHeader()->irpc); }

void MultipleStpLayer::setCISTIrpc(uint32_t value) { getMstpHeader()->irpc = htobe32(value); }

uint64_t MultipleStpLayer::getCISTBridgeId() const { return be64toh(getMstpHeader()->cistBridgeId); }

void MultipleStpLayer::setCISTBridgeId(uint64_t value) { getMstpHeader()->cistBridgeId = htobe64(value); }

uint16_t MultipleStpLayer::getCISTBridgePriority() const { return be16toh(getMstpHeader()->cistBridgeId) & 0xf000; }

void MultipleStpLayer::setCISTBridgePriority(uint16_t value)
{
	getMstpHeader()->cistBridgeId =
		htobe16((be16toh(getMstpHeader()->cistBridgeId) & ~(0xf000)) | (value & 0xf000));
}

uint16_t MultipleStpLayer::getCISTBridgeSystemIDExtension() const
{
	return be16toh(getMstpHeader()->cistBridgeId) & 0x0fff;
}

void MultipleStpLayer::setCISTBridgeSystemIDExtension(uint16_t value)
{
	getMstpHeader()->cistBridgeId =
		htobe16((be16toh(getMstpHeader()->cistBridgeId) & ~(0x0fff)) | (value & 0x0fff));
}

void MultipleStpLayer::setCISTBridgeSystemID(const pcpp::MacAddress &value)
{
	setCISTBridgeId((getCISTBridgeId() & (uint64_t(0x0fff) << 48)) | MacAddresstoID(value));
}

void setNumberOfMSTIConfMessages(uint8_t value)
{
	// <-------------------------------------------------------
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
