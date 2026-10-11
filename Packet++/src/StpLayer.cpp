#define LOG_MODULE PacketLogModuleStpLayer

#include "StpLayer.h"
#include "GeneralUtils.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"
#include "Logger.h"

namespace pcpp
{
	const FieldDescriptor StpLayer::SerializedFields::ProtoId{ Layer::SerializedFields::MaxID + 1, "protoId" };
	const FieldDescriptor StpLayer::SerializedFields::Version{ Layer::SerializedFields::MaxID + 2, "version" };
	const FieldDescriptor StpLayer::SerializedFields::Type{ Layer::SerializedFields::MaxID + 3, "type" };

	void StpLayer::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SerializedFields::ProtoId, be16toh(getProtoId()));
		serializer.writeField(SerializedFields::Version, getVersion());
		serializer.writeField(SerializedFields::Type, getType());
	}

	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::Flags{
		StpLayer::SerializedFields::MaxStpFieldID + 1, "flags"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::RootId{
		StpLayer::SerializedFields::MaxStpFieldID + 2, "rootId"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::PathCost{
		StpLayer::SerializedFields::MaxStpFieldID + 3, "pathCost"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::BridgeId{
		StpLayer::SerializedFields::MaxStpFieldID + 4, "bridgeId"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::PortId{
		StpLayer::SerializedFields::MaxStpFieldID + 5, "portId"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::MessageAge{
		StpLayer::SerializedFields::MaxStpFieldID + 6, "messageAge"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::MaximumAge{
		StpLayer::SerializedFields::MaxStpFieldID + 7, "maximumAge"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::HelloTime{
		StpLayer::SerializedFields::MaxStpFieldID + 8, "helloTime"
	};
	const FieldDescriptor StpConfigurationBPDULayer::SerializedFields::ForwardDelay{
		StpLayer::SerializedFields::MaxStpFieldID + 9, "forwardDelay"
	};

	void StpConfigurationBPDULayer::serializeLayer(ObjectScope& serializer) const
	{
		StpLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Flags, getFlag());
		serializer.writeField(SerializedFields::RootId, getRootId());
		serializer.writeField(SerializedFields::PathCost, getPathCost());
		serializer.writeField(SerializedFields::BridgeId, getBridgeId());
		serializer.writeField(SerializedFields::PortId, getPortId());
		serializer.writeField(SerializedFields::MessageAge, be16toh(getStpConfHeader()->msgAge));
		serializer.writeField(SerializedFields::MaximumAge, be16toh(getStpConfHeader()->maxAge));
		serializer.writeField(SerializedFields::HelloTime, be16toh(getStpConfHeader()->helloTime));
		serializer.writeField(SerializedFields::ForwardDelay, be16toh(getStpConfHeader()->forwardDelay));
	}

	const FieldDescriptor RapidStpLayer::SerializedFields::Version1Length{
		StpConfigurationBPDULayer::SerializedFields::MaxConfigurationFieldID + 1, "version1Length"
	};

	void RapidStpLayer::serializeLayer(ObjectScope& serializer) const
	{
		StpConfigurationBPDULayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Version1Length, getVersion1Len());
	}

	const FieldDescriptor MultipleStpLayer::SerializedFields::Version3Length{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 1, "version3Length"
	};
	const FieldDescriptor MultipleStpLayer::SerializedFields::ConfigFormatSelector{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 2, "configFormatSelector"
	};
	const FieldDescriptor MultipleStpLayer::SerializedFields::ConfigName{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 3, "configName"
	};
	const FieldDescriptor MultipleStpLayer::SerializedFields::ConfigRevision{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 4, "configRevision"
	};
	const FieldDescriptor MultipleStpLayer::SerializedFields::ConfigDigest{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 5, "configDigest"
	};
	const FieldDescriptor MultipleStpLayer::SerializedFields::CistInternalRootPathCost{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 6, "cistInternalRootPathCost"
	};
	const FieldDescriptor MultipleStpLayer::SerializedFields::CistBridgeId{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 7, "cistBridgeId"
	};
	const FieldDescriptor MultipleStpLayer::SerializedFields::RemainingHopCount{
		RapidStpLayer::SerializedFields::MaxStpFieldID + 8, "remainingHopCount"
	};
	const ObjectFieldDescriptor<MultipleStpLayer::MstiSerializedFields>
	    MultipleStpLayer::SerializedFields::MstiMessages{ RapidStpLayer::SerializedFields::MaxStpFieldID + 9,
		                                                  "mstiMessages" };

	void MultipleStpLayer::serializeLayer(ObjectScope& serializer) const
	{
		RapidStpLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Version3Length, getVersion3Len());
		serializer.writeField(SerializedFields::ConfigFormatSelector, getMstConfigurationFormatSelector());
		serializer.writeField(SerializedFields::ConfigName, getMstConfigurationName());
		serializer.writeField(SerializedFields::ConfigRevision, getMstConfigRevision());
		serializer.writeField(SerializedFields::ConfigDigest, byteArrayToHexString(getMstConfigDigest(), 16));
		serializer.writeField(SerializedFields::CistInternalRootPathCost, getCISTIrpc());
		serializer.writeField(SerializedFields::CistBridgeId, getCISTBridgeId());
		serializer.writeField(SerializedFields::RemainingHopCount, getRemainingHopCount());
		auto messages = serializer.writeArray(SerializedFields::MstiMessages);
		constexpr size_t fixedVersion3Length = sizeof(mstp_conf_bpdu) - sizeof(rstp_conf_bpdu) - sizeof(uint16_t);
		const size_t declaredLength = getVersion3Len();
		if (declaredLength < fixedVersion3Length || m_DataLen < sizeof(mstp_conf_bpdu))
			return;
		const size_t declaredCount = (declaredLength - fixedVersion3Length) / sizeof(msti_conf_msg);
		const size_t availableCount = (m_DataLen - sizeof(mstp_conf_bpdu)) / sizeof(msti_conf_msg);
		const size_t count = std::min<size_t>(64, std::min(declaredCount, availableCount));
		for (size_t i = 0; i < count; ++i)
		{
			const auto* message =
			    reinterpret_cast<const msti_conf_msg*>(m_Data + sizeof(mstp_conf_bpdu) + i * sizeof(msti_conf_msg));
			auto object = messages.writeObject(SerializedFields::MstiMessages);
			object.writeField(MstiSerializedFields::Flags, message->flags);
			object.writeField(MstiSerializedFields::RegionalRootId, be64toh(message->regionalRootId));
			object.writeField(MstiSerializedFields::PathCost, be32toh(message->pathCost));
			object.writeField(MstiSerializedFields::BridgePriority, message->bridgePriority);
			object.writeField(MstiSerializedFields::PortPriority, message->portPriority);
			object.writeField(MstiSerializedFields::RemainingHops, message->remainingHops);
		}
	}

	const FieldDescriptor MultipleStpLayer::MstiSerializedFields::Flags{ 1, "flags" };
	const FieldDescriptor MultipleStpLayer::MstiSerializedFields::RegionalRootId{ 2, "regionalRootId" };
	const FieldDescriptor MultipleStpLayer::MstiSerializedFields::PathCost{ 3, "pathCost" };
	const FieldDescriptor MultipleStpLayer::MstiSerializedFields::BridgePriority{ 4, "bridgePriority" };
	const FieldDescriptor MultipleStpLayer::MstiSerializedFields::PortPriority{ 5, "portPriority" };
	const FieldDescriptor MultipleStpLayer::MstiSerializedFields::RemainingHops{ 6, "remainingHops" };

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
		uint8_t value[6] = { 0 };
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
			stp_tcn_bpdu* ptr = reinterpret_cast<stp_tcn_bpdu*>(data);
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
		{
			constructNextLayer<PayloadLayer>(m_Data, m_DataLen - sizeof(stp_tcn_bpdu));
		}
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
		{
			constructNextLayer<PayloadLayer>(m_Data, m_DataLen - sizeof(stp_conf_bpdu));
		}
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
		{
			constructNextLayer<PayloadLayer>(m_Data, m_DataLen - sizeof(rstp_conf_bpdu));
		}
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
		std::string str = std::string(reinterpret_cast<char*>(getMstpHeader()->mstConfigName), 32);
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
			return reinterpret_cast<msti_conf_msg*>(m_Data + sizeof(mstp_conf_bpdu));
		return nullptr;
	}

}  // namespace pcpp
