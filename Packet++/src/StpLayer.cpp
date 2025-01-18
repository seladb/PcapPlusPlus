#define LOG_MODULE PacketLogModuleStpLayer

#include "StpLayer.h"
#include "PayloadLayer.h"
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

	uint64_t StpLayer::macAddressToID(const pcpp::MacAddress& addr)
	{
		uint8_t value[6];
		addr.copyTo(value);
		return ((uint64_t(value[0]) << 40) | (uint64_t(value[1]) << 32) | (uint64_t(value[2]) << 24) |
		        (uint64_t(value[3]) << 16) | (uint64_t(value[4]) << 8) | (uint64_t(value[5])));
	}

	bool StpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen;
	}

	StpLayer* StpLayer::parseStpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (dataLen >= sizeof(stp_tcn_bpdu))
		{
			stp_tcn_bpdu* ptr = (stp_tcn_bpdu*)data;
			switch (ptr->type)
			{
			case 0x00:
				return StpConfigurationBPDULayer::isDataValid(data, dataLen)
				           ? new StpConfigurationBPDULayer(data, dataLen, prevLayer, packet)
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
			case 0x80:
				return StpTopologyChangeBPDULayer::isDataValid(data, dataLen)
				           ? new StpTopologyChangeBPDULayer(data, dataLen, prevLayer, packet)
				           : nullptr;
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

	// ---------------------- Class StpTopologyChangeBPDULayer ----------------------
	StpTopologyChangeBPDULayer::StpTopologyChangeBPDULayer() : StpLayer(sizeof(stp_tcn_bpdu))
	{
		// Set initial values for TCN
		setProtoId(0x0);
		setVersion(0x0);
		setType(0x80);
	}

	void StpTopologyChangeBPDULayer::parseNextLayer()
	{
		if (m_DataLen > sizeof(stp_tcn_bpdu))
			m_NextLayer = new PayloadLayer(m_Data, m_DataLen - sizeof(stp_tcn_bpdu), this, m_Packet);
	}

	// ---------------------- Class StpConfigurationBPDULayer ----------------------
	StpConfigurationBPDULayer::StpConfigurationBPDULayer() : StpTopologyChangeBPDULayer(sizeof(stp_conf_bpdu))
	{
		// Set initial value for configuration BPDU
		setProtoId(0x0);
		setVersion(0x0);
		setType(0x0);
	}

	uint64_t StpConfigurationBPDULayer::getRootId() const
	{
		return be64toh(getStpConfHeader()->rootId);
	}

	void StpConfigurationBPDULayer::setRootId(uint64_t value)
	{
		getStpConfHeader()->rootId = htobe64(value);
	}

	uint16_t StpConfigurationBPDULayer::getRootPriority() const
	{
		return be16toh(getStpConfHeader()->rootId) & 0xf000;
	}

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

	void StpConfigurationBPDULayer::setRootSystemID(const pcpp::MacAddress& value)
	{
		setRootId((getRootId() & (uint64_t(0xffff) << 48)) | macAddressToID(value));
	};

	uint32_t StpConfigurationBPDULayer::getPathCost() const
	{
		return be32toh(getStpConfHeader()->pathCost);
	}

	void StpConfigurationBPDULayer::setPathCost(uint32_t value)
	{
		getStpConfHeader()->pathCost = htobe32(value);
	}

	uint64_t StpConfigurationBPDULayer::getBridgeId() const
	{
		return be64toh(getStpConfHeader()->bridgeId);
	}

	void StpConfigurationBPDULayer::setBridgeId(uint64_t value)
	{
		getStpConfHeader()->bridgeId = htobe64(value);
	}

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

	void StpConfigurationBPDULayer::setBridgeSystemID(const pcpp::MacAddress& value)
	{
		setBridgeId((getBridgeId() & (uint64_t(0xffff) << 48)) | macAddressToID(value));
	}

	uint16_t StpConfigurationBPDULayer::getPortId() const
	{
		return be16toh(getStpConfHeader()->portId);
	}

	void StpConfigurationBPDULayer::setPortId(uint16_t value)
	{
		getStpConfHeader()->portId = htobe16(value);
	}

	double StpConfigurationBPDULayer::getMessageAge() const
	{
		return getStpConfHeader()->msgAge;
	}

	void StpConfigurationBPDULayer::setMessageAge(double value)
	{
		getStpConfHeader()->msgAge = value;
	}

	double StpConfigurationBPDULayer::getMaximumAge() const
	{
		return getStpConfHeader()->maxAge;
	}

	void StpConfigurationBPDULayer::setMaximumAge(double value)
	{
		getStpConfHeader()->maxAge = value;
	}

	double StpConfigurationBPDULayer::getTransmissionInterval() const
	{
		return getStpConfHeader()->helloTime;
	}

	void StpConfigurationBPDULayer::setTransmissionInterval(double value)
	{
		getStpConfHeader()->helloTime = value;
	}

	double StpConfigurationBPDULayer::getForwardDelay() const
	{
		return getStpConfHeader()->forwardDelay;
	}

	void StpConfigurationBPDULayer::setForwardDelay(double value)
	{
		getStpConfHeader()->forwardDelay = value;
	}

	void StpConfigurationBPDULayer::parseNextLayer()
	{
		if (m_DataLen > sizeof(stp_conf_bpdu))
			m_NextLayer = new PayloadLayer(m_Data, m_DataLen - sizeof(stp_conf_bpdu), this, m_Packet);
	}

	// ---------------------- Class RapidStpLayer ----------------------
	RapidStpLayer::RapidStpLayer() : StpConfigurationBPDULayer(sizeof(rstp_conf_bpdu))
	{
		// Set initial value for Rapid STP
		setProtoId(0x0);
		setVersion(0x2);
		setType(0x2);
	}

	void RapidStpLayer::parseNextLayer()
	{
		if (m_DataLen > sizeof(rstp_conf_bpdu))
			m_NextLayer = new PayloadLayer(m_Data, m_DataLen - sizeof(rstp_conf_bpdu), this, m_Packet);
	}

	// ---------------------- Class MultipleStpLayer ----------------------
	MultipleStpLayer::MultipleStpLayer() : RapidStpLayer(sizeof(mstp_conf_bpdu))
	{
		// Set initial value for Multiple STP
		setProtoId(0x0);
		setVersion(0x3);
		setType(0x2);
	}

	uint16_t MultipleStpLayer::getVersion3Len() const
	{
		return be16toh(getMstpHeader()->version3Len);
	}

	void MultipleStpLayer::setVersion3Len(uint16_t value)
	{
		getMstpHeader()->version3Len = htobe16(value);
	}

	uint32_t MultipleStpLayer::getCISTIrpc() const
	{
		return be32toh(getMstpHeader()->irpc);
	}

	void MultipleStpLayer::setCISTIrpc(uint32_t value)
	{
		getMstpHeader()->irpc = htobe32(value);
	}

	uint64_t MultipleStpLayer::getCISTBridgeId() const
	{
		return be64toh(getMstpHeader()->cistBridgeId);
	}

	void MultipleStpLayer::setCISTBridgeId(uint64_t value)
	{
		getMstpHeader()->cistBridgeId = htobe64(value);
	}

	uint16_t MultipleStpLayer::getCISTBridgePriority() const
	{
		return be16toh(getMstpHeader()->cistBridgeId) & 0xf000;
	}

	void MultipleStpLayer::setCISTBridgePriority(uint16_t value)
	{
		getMstpHeader()->cistBridgeId = (getMstpHeader()->cistBridgeId & ~htobe16(0xf000)) | htobe16(value & 0xf000);
	}

	uint16_t MultipleStpLayer::getCISTBridgeSystemIDExtension() const
	{
		return be16toh(getMstpHeader()->cistBridgeId) & 0x0fff;
	}

	void MultipleStpLayer::setCISTBridgeSystemIDExtension(uint16_t value)
	{
		getMstpHeader()->cistBridgeId = (getMstpHeader()->cistBridgeId & ~htobe16(0x0fff)) | htobe16(value & 0x0fff);
	}

	void MultipleStpLayer::setCISTBridgeSystemID(const pcpp::MacAddress& value)
	{
		setCISTBridgeId((getCISTBridgeId() & (uint64_t(0xffff) << 48)) | macAddressToID(value));
	}

	std::string MultipleStpLayer::getMstConfigurationName() const
	{
		std::string str = std::string((char*)(getMstpHeader()->mstConfigName), 32);
		str.erase(std::find(str.begin(), str.end(), '\0'), str.end());
		return str;
	}

	uint16_t MultipleStpLayer::getMstConfigRevision() const
	{
		return be16toh(getMstpHeader()->mstConfigRevision);
	}

	void MultipleStpLayer::setMstConfigRevision(uint16_t value)
	{
		getMstpHeader()->mstConfigRevision = htobe16(value);
	}

	void MultipleStpLayer::setMstConfigDigest(const uint8_t* value, uint8_t len)
	{
		memset(getMstpHeader()->mstConfigDigest, 0, 16);
		memcpy(getMstpHeader()->mstConfigDigest, value, std::min<size_t>(len, 16));
	}

	void MultipleStpLayer::setMstConfigurationName(const std::string& value)
	{
		memset(getMstpHeader()->mstConfigName, 0, 32);
		memcpy(getMstpHeader()->mstConfigName, value.c_str(), std::min<size_t>(value.size(), 32));
	}

	msti_conf_msg* MultipleStpLayer::getMstiConfMessages() const
	{
		if (getNumberOfMSTIConfMessages())
			return (msti_conf_msg*)(m_Data + sizeof(mstp_conf_bpdu));
		return nullptr;
	}

}  // namespace pcpp
