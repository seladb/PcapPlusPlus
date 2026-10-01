#include "GvcpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <sstream>

namespace pcpp
{
	namespace
	{
		using GvcpCommand = GvcpLayer::GvcpCommand;
		using GvcpResponseStatus = GvcpAcknowledgeLayer::GvcpResponseStatus;
		using GvcpVersion = GvcpDiscoveryAcknowledgeLayer::GvcpVersion;

		constexpr uint8_t gvcpMagicNumber = 0x42;
		constexpr GvcpFlag gvcpAcknowledgeFlag = 0x01;
		constexpr GvcpFlag gvcpAllowBroadcastAckFlag = 0x10;

		/// @return True if the value is an acknowledge value. Command values are even and each acknowledge value is
		/// the matching command value + 1
		bool isAcknowledgeValue(GvcpCommand command)
		{
			return (static_cast<uint16_t>(command) & 0x01) != 0;
		}

		/// @return The name of a command defined by the spec, or nullptr if the value isn't defined
		const char* getGvcpCommandName(GvcpCommand command)
		{
			switch (command)
			{
			case GvcpCommand::DiscoveredCmd:
				return "DiscoveredCmd";
			case GvcpCommand::DiscoveredAck:
				return "DiscoveredAck";
			case GvcpCommand::ForceIpCmd:
				return "ForceIpCmd";
			case GvcpCommand::ForceIpAck:
				return "ForceIpAck";
			case GvcpCommand::PacketResendCmd:
				return "PacketResendCmd";
			case GvcpCommand::PacketResendAck:
				return "PacketResendAck";
			case GvcpCommand::ReadRegCmd:
				return "ReadRegCmd";
			case GvcpCommand::ReadRegAck:
				return "ReadRegAck";
			case GvcpCommand::WriteRegCmd:
				return "WriteRegCmd";
			case GvcpCommand::WriteRegAck:
				return "WriteRegAck";
			case GvcpCommand::ReadMemCmd:
				return "ReadMemCmd";
			case GvcpCommand::ReadMemAck:
				return "ReadMemAck";
			case GvcpCommand::WriteMemCmd:
				return "WriteMemCmd";
			case GvcpCommand::WriteMemAck:
				return "WriteMemAck";
			case GvcpCommand::PendingAck:
				return "PendingAck";
			case GvcpCommand::EventCmd:
				return "EventCmd";
			case GvcpCommand::EventAck:
				return "EventAck";
			case GvcpCommand::EventDataCmd:
				return "EventDataCmd";
			case GvcpCommand::EventDataAck:
				return "EventDataAck";
			case GvcpCommand::ActionCmd:
				return "ActionCmd";
			case GvcpCommand::ActionAck:
				return "ActionAck";
			default:
				return nullptr;
			}
		}

		/// @return The name of a status defined by the spec, or nullptr if the value isn't defined
		const char* getGvcpResponseStatusName(GvcpResponseStatus status)
		{
			switch (status)
			{
			case GvcpResponseStatus::Success:
				return "Success";
			case GvcpResponseStatus::PacketResend:
				return "PacketResend";
			case GvcpResponseStatus::NotImplemented:
				return "NotImplemented";
			case GvcpResponseStatus::InvalidParameter:
				return "InvalidParameter";
			case GvcpResponseStatus::InvalidAddress:
				return "InvalidAddress";
			case GvcpResponseStatus::WriteProtect:
				return "WriteProtect";
			case GvcpResponseStatus::BadAlignment:
				return "BadAlignment";
			case GvcpResponseStatus::AccessDenied:
				return "AccessDenied";
			case GvcpResponseStatus::Busy:
				return "Busy";
			case GvcpResponseStatus::LocalProblem:
				return "LocalProblem";
			case GvcpResponseStatus::MsgMismatch:
				return "MsgMismatch";
			case GvcpResponseStatus::InvalidProtocol:
				return "InvalidProtocol";
			case GvcpResponseStatus::NoMsg:
				return "NoMsg";
			case GvcpResponseStatus::PacketUnavailable:
				return "PacketUnavailable";
			case GvcpResponseStatus::DataOverrun:
				return "DataOverrun";
			case GvcpResponseStatus::InvalidHeader:
				return "InvalidHeader";
			case GvcpResponseStatus::WrongConfig:
				return "WrongConfig";
			case GvcpResponseStatus::PacketNotYetAvailable:
				return "PacketNotYetAvailable";
			case GvcpResponseStatus::PacketAndPrevRemovedFromMemory:
				return "PacketAndPrevRemovedFromMemory";
			case GvcpResponseStatus::PacketRemovedFromMemory:
				return "PacketRemovedFromMemory";
			case GvcpResponseStatus::NoRefTime:
				return "NoRefTime";
			case GvcpResponseStatus::PacketTemporarilyUnavailable:
				return "PacketTemporarilyUnavailable";
			case GvcpResponseStatus::Overflow:
				return "Overflow";
			case GvcpResponseStatus::ActionLate:
				return "ActionLate";
			case GvcpResponseStatus::LeaderTrailerOverflow:
				return "LeaderTrailerOverflow";
			case GvcpResponseStatus::Error:
				return "Error";
			default:
				return nullptr;
			}
		}

		GvcpCommand toGvcpCommand(uint16_t value)
		{
			const auto command = static_cast<GvcpCommand>(value);
			return getGvcpCommandName(command) != nullptr ? command : GvcpCommand::Unknown;
		}

		GvcpResponseStatus toGvcpResponseStatus(uint16_t value)
		{
			const auto status = static_cast<GvcpResponseStatus>(value);
			return getGvcpResponseStatusName(status) != nullptr ? status : GvcpResponseStatus::Unknown;
		}

		const char* commandToString(GvcpCommand command)
		{
			const char* name = getGvcpCommandName(command);
			return name != nullptr ? name : "Unknown";
		}

		const char* statusToString(GvcpResponseStatus status)
		{
			const char* name = getGvcpResponseStatusName(status);
			return name != nullptr ? name : "Unknown";
		}

		/// Read a fixed size char field which isn't necessarily null-terminated
		template <size_t N> std::string fieldToString(const char (&field)[N])
		{
			return std::string(field, std::find(field, field + N, '\0'));
		}

		/// Write a string to a fixed size char field, always leaving room for the null terminator
		template <size_t N> void stringToField(const std::string& value, char (&field)[N])
		{
			memset(field, 0, N);
			memcpy(field, value.data(), std::min(value.size(), N - 1));
		}
	}  // namespace

	std::ostream& operator<<(std::ostream& os, GvcpCommand command)
	{
		return os << commandToString(command);
	}

	std::ostream& operator<<(std::ostream& os, GvcpResponseStatus status)
	{
		return os << statusToString(status);
	}

	// -------- Class GvcpLayer -----------------

	GvcpLayer* GvcpLayer::parseGvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		const bool isRequest = GvcpRequestLayer::isDataValid(data, dataLen);
		if (!isRequest && !GvcpAcknowledgeLayer::isDataValid(data, dataLen))
			return nullptr;

		const GvcpCommand command =
		    toGvcpCommand(netToHost16(reinterpret_cast<const GvcpRequestLayer::gvcp_request_header*>(data)->command));

		if (isRequest)
		{
			if (command == GvcpCommand::DiscoveredCmd)
				return new GvcpDiscoveryRequestLayer(data, dataLen, prevLayer, packet);
			if (command == GvcpCommand::ForceIpCmd && GvcpForceIpRequestLayer::isDataValid(data, dataLen))
				return new GvcpForceIpRequestLayer(data, dataLen, prevLayer, packet);
			return new GvcpRequestLayer(data, dataLen, prevLayer, packet);
		}

		if (command == GvcpCommand::DiscoveredAck && GvcpDiscoveryAcknowledgeLayer::isDataValid(data, dataLen))
			return new GvcpDiscoveryAcknowledgeLayer(data, dataLen, prevLayer, packet);
		if (command == GvcpCommand::ForceIpAck)
			return new GvcpForceIpAcknowledgeLayer(data, dataLen, prevLayer, packet);
		return new GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet);
	}

	void GvcpLayer::initLayer(size_t dataLen)
	{
		allocData(dataLen);
		m_Protocol = GVCP;
	}

	void GvcpLayer::parseNextLayer()
	{
		const size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		constructNextLayer<PayloadLayer>(m_Data + headerLen, m_DataLen - headerLen);
	}

	const FieldDescriptor GvcpLayer::SerializedFields::Command{ Layer::SerializedFields::MaxID + 1, "command" };
	const FieldDescriptor GvcpLayer::SerializedFields::CommandName{ Layer::SerializedFields::MaxID + 2, "commandName" };
	const FieldDescriptor GvcpLayer::SerializedFields::DataSize{ Layer::SerializedFields::MaxID + 3, "dataSize" };

	void GvcpLayer::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SerializedFields::Command, static_cast<uint16_t>(getCommand()));
		serializer.writeField(SerializedFields::CommandName, commandToString(getCommand()));
		serializer.writeField(SerializedFields::DataSize, getDataSize());
	}

	// -------- Class GvcpRequestLayer -----------------

	GvcpRequestLayer::GvcpRequestLayer(GvcpCommand command, GvcpFlag flag, uint16_t requestId, size_t bodyLen)
	{
		if (isAcknowledgeValue(command))
			throw std::invalid_argument("A GVCP request can't be created with an acknowledge value");

		initLayer(sizeof(gvcp_request_header) + bodyLen);

		auto* header = getGvcpHeader();
		header->magicNumber = gvcpMagicNumber;
		header->flag = flag;
		header->command = hostToNet16(static_cast<uint16_t>(command));
		header->dataSize = hostToNet16(static_cast<uint16_t>(bodyLen));
		header->requestId = hostToNet16(requestId);
	}

	bool GvcpRequestLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return canReinterpretAs<gvcp_request_header>(data, dataLen) && data[0] == gvcpMagicNumber;
	}

	GvcpFlag GvcpRequestLayer::getFlag() const
	{
		return getGvcpHeader()->flag;
	}

	void GvcpRequestLayer::setFlag(GvcpFlag flag)
	{
		getGvcpHeader()->flag = flag;
	}

	bool GvcpRequestLayer::hasAcknowledgeFlag() const
	{
		return (getGvcpHeader()->flag & gvcpAcknowledgeFlag) != 0;
	}

	uint16_t GvcpRequestLayer::getRequestId() const
	{
		return netToHost16(getGvcpHeader()->requestId);
	}

	void GvcpRequestLayer::setRequestId(uint16_t requestId)
	{
		getGvcpHeader()->requestId = hostToNet16(requestId);
	}

	GvcpCommand GvcpRequestLayer::getCommand() const
	{
		return toGvcpCommand(netToHost16(getGvcpHeader()->command));
	}

	uint16_t GvcpRequestLayer::getDataSize() const
	{
		return netToHost16(getGvcpHeader()->dataSize);
	}

	void GvcpRequestLayer::computeCalculateFields()
	{
		getGvcpHeader()->dataSize = hostToNet16(static_cast<uint16_t>(m_DataLen - sizeof(gvcp_request_header)));
	}

	std::string GvcpRequestLayer::toString() const
	{
		std::ostringstream ss;
		ss << "GVCP Request Layer, Command: " << getCommand() << ", Request ID: " << getRequestId();
		return ss.str();
	}

	const FieldDescriptor GvcpRequestLayer::SerializedFields::Flag{ GvcpLayer::SerializedFields::MaxID + 1, "flag" };
	const FieldDescriptor GvcpRequestLayer::SerializedFields::AcknowledgeRequired{
		GvcpLayer::SerializedFields::MaxID + 2, "acknowledgeRequired"
	};
	const FieldDescriptor GvcpRequestLayer::SerializedFields::RequestId{ GvcpLayer::SerializedFields::MaxID + 3,
		                                                                 "requestId" };

	void GvcpRequestLayer::serializeLayer(ObjectScope& serializer) const
	{
		GvcpLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Flag, getFlag());
		serializer.writeField(SerializedFields::AcknowledgeRequired, hasAcknowledgeFlag());
		serializer.writeField(SerializedFields::RequestId, getRequestId());
	}

	// -------- Class GvcpAcknowledgeLayer -----------------

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command, uint16_t ackId,
	                                           size_t bodyLen)
	{
		if (!isAcknowledgeValue(command))
			throw std::invalid_argument("A GVCP acknowledge can't be created with a command value");

		initLayer(sizeof(gvcp_ack_header) + bodyLen);

		auto* header = getGvcpHeader();
		header->status = hostToNet16(static_cast<uint16_t>(status));
		header->command = hostToNet16(static_cast<uint16_t>(command));
		header->dataSize = hostToNet16(static_cast<uint16_t>(bodyLen));
		header->ackId = hostToNet16(ackId);
	}

	bool GvcpAcknowledgeLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return canReinterpretAs<gvcp_ack_header>(data, dataLen);
	}

	GvcpResponseStatus GvcpAcknowledgeLayer::getStatus() const
	{
		return toGvcpResponseStatus(netToHost16(getGvcpHeader()->status));
	}

	void GvcpAcknowledgeLayer::setStatus(GvcpResponseStatus status)
	{
		getGvcpHeader()->status = hostToNet16(static_cast<uint16_t>(status));
	}

	uint16_t GvcpAcknowledgeLayer::getAckId() const
	{
		return netToHost16(getGvcpHeader()->ackId);
	}

	void GvcpAcknowledgeLayer::setAckId(uint16_t ackId)
	{
		getGvcpHeader()->ackId = hostToNet16(ackId);
	}

	GvcpCommand GvcpAcknowledgeLayer::getCommand() const
	{
		return toGvcpCommand(netToHost16(getGvcpHeader()->command));
	}

	uint16_t GvcpAcknowledgeLayer::getDataSize() const
	{
		return netToHost16(getGvcpHeader()->dataSize);
	}

	void GvcpAcknowledgeLayer::computeCalculateFields()
	{
		getGvcpHeader()->dataSize = hostToNet16(static_cast<uint16_t>(m_DataLen - sizeof(gvcp_ack_header)));
	}

	std::string GvcpAcknowledgeLayer::toString() const
	{
		std::ostringstream ss;
		ss << "GVCP Acknowledge Layer, Command: " << getCommand() << ", Acknowledge ID: " << getAckId()
		   << ", Status: " << getStatus();
		return ss.str();
	}

	const FieldDescriptor GvcpAcknowledgeLayer::SerializedFields::Status{ GvcpLayer::SerializedFields::MaxID + 1,
		                                                                  "status" };
	const FieldDescriptor GvcpAcknowledgeLayer::SerializedFields::StatusName{ GvcpLayer::SerializedFields::MaxID + 2,
		                                                                      "statusName" };
	const FieldDescriptor GvcpAcknowledgeLayer::SerializedFields::AckId{ GvcpLayer::SerializedFields::MaxID + 3,
		                                                                 "ackId" };

	void GvcpAcknowledgeLayer::serializeLayer(ObjectScope& serializer) const
	{
		GvcpLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Status, static_cast<uint16_t>(getStatus()));
		serializer.writeField(SerializedFields::StatusName, statusToString(getStatus()));
		serializer.writeField(SerializedFields::AckId, getAckId());
	}

	// -------- Class GvcpDiscoveryRequestLayer -----------------

	GvcpDiscoveryRequestLayer::GvcpDiscoveryRequestLayer(bool allowBroadcastAck, bool acknowledgeRequired,
	                                                     uint16_t requestId)
	    : GvcpRequestLayer(GvcpCommand::DiscoveredCmd,
	                       static_cast<GvcpFlag>((allowBroadcastAck ? gvcpAllowBroadcastAckFlag : 0) |
	                                             (acknowledgeRequired ? gvcpAcknowledgeFlag : 0)),
	                       requestId)
	{}

	bool GvcpDiscoveryRequestLayer::hasAllowBroadcastAckFlag() const
	{
		return (getFlag() & gvcpAllowBroadcastAckFlag) != 0;
	}

	void GvcpDiscoveryRequestLayer::setAllowBroadcastAckFlag(bool allowBroadcastAck)
	{
		setFlag(static_cast<GvcpFlag>(allowBroadcastAck ? getFlag() | gvcpAllowBroadcastAckFlag
		                                                : getFlag() & ~gvcpAllowBroadcastAckFlag));
	}

	const FieldDescriptor GvcpDiscoveryRequestLayer::SerializedFields::AllowBroadcastAck{
		GvcpRequestLayer::SerializedFields::MaxID + 1, "allowBroadcastAck"
	};

	void GvcpDiscoveryRequestLayer::serializeLayer(ObjectScope& serializer) const
	{
		GvcpRequestLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::AllowBroadcastAck, hasAllowBroadcastAckFlag());
	}

	// -------- Class GvcpDiscoveryAcknowledgeLayer -----------------

	GvcpDiscoveryAcknowledgeLayer::GvcpDiscoveryAcknowledgeLayer(GvcpResponseStatus status, uint16_t ackId)
	    : GvcpAcknowledgeLayer(status, GvcpCommand::DiscoveredAck, ackId, sizeof(gvcp_discovery_body))
	{}

	bool GvcpDiscoveryAcknowledgeLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return GvcpAcknowledgeLayer::isDataValid(data, dataLen) &&
		       dataLen >= sizeof(gvcp_ack_header) + sizeof(gvcp_discovery_body);
	}

	GvcpVersion GvcpDiscoveryAcknowledgeLayer::getVersion() const
	{
		auto* body = getGvcpDiscoveryBody();
		return { netToHost16(body->versionMajor), netToHost16(body->versionMinor) };
	}

	void GvcpDiscoveryAcknowledgeLayer::setVersion(const GvcpVersion& version)
	{
		auto* body = getGvcpDiscoveryBody();
		body->versionMajor = hostToNet16(version.major);
		body->versionMinor = hostToNet16(version.minor);
	}

	MacAddress GvcpDiscoveryAcknowledgeLayer::getMacAddress() const
	{
		return MacAddress(getGvcpDiscoveryBody()->macAddress);
	}

	void GvcpDiscoveryAcknowledgeLayer::setMacAddress(const MacAddress& macAddress)
	{
		macAddress.copyTo(getGvcpDiscoveryBody()->macAddress, sizeof(gvcp_discovery_body::macAddress));
	}

	IPv4Address GvcpDiscoveryAcknowledgeLayer::getIpAddress() const
	{
		return { getGvcpDiscoveryBody()->ipAddress };
	}

	void GvcpDiscoveryAcknowledgeLayer::setIpAddress(const IPv4Address& ipAddress)
	{
		getGvcpDiscoveryBody()->ipAddress = ipAddress.toInt();
	}

	IPv4Address GvcpDiscoveryAcknowledgeLayer::getSubnetMask() const
	{
		return { getGvcpDiscoveryBody()->subnetMask };
	}

	void GvcpDiscoveryAcknowledgeLayer::setSubnetMask(const IPv4Address& subnetMask)
	{
		getGvcpDiscoveryBody()->subnetMask = subnetMask.toInt();
	}

	IPv4Address GvcpDiscoveryAcknowledgeLayer::getGatewayIpAddress() const
	{
		return { getGvcpDiscoveryBody()->defaultGateway };
	}

	void GvcpDiscoveryAcknowledgeLayer::setGatewayIpAddress(const IPv4Address& gatewayIpAddress)
	{
		getGvcpDiscoveryBody()->defaultGateway = gatewayIpAddress.toInt();
	}

	std::string GvcpDiscoveryAcknowledgeLayer::getManufacturerName() const
	{
		return fieldToString(getGvcpDiscoveryBody()->manufacturerName);
	}

	void GvcpDiscoveryAcknowledgeLayer::setManufacturerName(const std::string& manufacturerName)
	{
		stringToField(manufacturerName, getGvcpDiscoveryBody()->manufacturerName);
	}

	std::string GvcpDiscoveryAcknowledgeLayer::getModelName() const
	{
		return fieldToString(getGvcpDiscoveryBody()->modelName);
	}

	void GvcpDiscoveryAcknowledgeLayer::setModelName(const std::string& modelName)
	{
		stringToField(modelName, getGvcpDiscoveryBody()->modelName);
	}

	std::string GvcpDiscoveryAcknowledgeLayer::getDeviceVersion() const
	{
		return fieldToString(getGvcpDiscoveryBody()->deviceVersion);
	}

	void GvcpDiscoveryAcknowledgeLayer::setDeviceVersion(const std::string& deviceVersion)
	{
		stringToField(deviceVersion, getGvcpDiscoveryBody()->deviceVersion);
	}

	std::string GvcpDiscoveryAcknowledgeLayer::getManufacturerSpecificInformation() const
	{
		return fieldToString(getGvcpDiscoveryBody()->manufacturerSpecificInformation);
	}

	void GvcpDiscoveryAcknowledgeLayer::setManufacturerSpecificInformation(const std::string& info)
	{
		stringToField(info, getGvcpDiscoveryBody()->manufacturerSpecificInformation);
	}

	std::string GvcpDiscoveryAcknowledgeLayer::getSerialNumber() const
	{
		return fieldToString(getGvcpDiscoveryBody()->serialNumber);
	}

	void GvcpDiscoveryAcknowledgeLayer::setSerialNumber(const std::string& serialNumber)
	{
		stringToField(serialNumber, getGvcpDiscoveryBody()->serialNumber);
	}

	std::string GvcpDiscoveryAcknowledgeLayer::getUserDefinedName() const
	{
		return fieldToString(getGvcpDiscoveryBody()->userDefinedName);
	}

	void GvcpDiscoveryAcknowledgeLayer::setUserDefinedName(const std::string& userDefinedName)
	{
		stringToField(userDefinedName, getGvcpDiscoveryBody()->userDefinedName);
	}

	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::VersionMajor{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 1, "versionMajor"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::VersionMinor{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 2, "versionMinor"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::MacAddress{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 3, "macAddress"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::IpAddress{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 4, "ipAddress"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::SubnetMask{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 5, "subnetMask"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::GatewayIpAddress{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 6, "gatewayIpAddress"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::ManufacturerName{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 7, "manufacturerName"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::ModelName{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 8, "modelName"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::DeviceVersion{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 9, "deviceVersion"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::ManufacturerSpecificInformation{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 10, "manufacturerSpecificInformation"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::SerialNumber{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 11, "serialNumber"
	};
	const FieldDescriptor GvcpDiscoveryAcknowledgeLayer::SerializedFields::UserDefinedName{
		GvcpAcknowledgeLayer::SerializedFields::MaxID + 12, "userDefinedName"
	};

	void GvcpDiscoveryAcknowledgeLayer::serializeLayer(ObjectScope& serializer) const
	{
		GvcpAcknowledgeLayer::serializeLayer(serializer);
		const GvcpVersion version = getVersion();
		serializer.writeField(SerializedFields::VersionMajor, version.major);
		serializer.writeField(SerializedFields::VersionMinor, version.minor);
		serializer.writeField(SerializedFields::MacAddress, getMacAddress().toString());
		serializer.writeField(SerializedFields::IpAddress, getIpAddress().toString());
		serializer.writeField(SerializedFields::SubnetMask, getSubnetMask().toString());
		serializer.writeField(SerializedFields::GatewayIpAddress, getGatewayIpAddress().toString());
		serializer.writeField(SerializedFields::ManufacturerName, getManufacturerName());
		serializer.writeField(SerializedFields::ModelName, getModelName());
		serializer.writeField(SerializedFields::DeviceVersion, getDeviceVersion());
		serializer.writeField(SerializedFields::ManufacturerSpecificInformation, getManufacturerSpecificInformation());
		serializer.writeField(SerializedFields::SerialNumber, getSerialNumber());
		serializer.writeField(SerializedFields::UserDefinedName, getUserDefinedName());
	}

	// -------- Class GvcpForceIpRequestLayer -----------------

	GvcpForceIpRequestLayer::GvcpForceIpRequestLayer(const MacAddress& macAddress, const IPv4Address& ipAddress,
	                                                 const IPv4Address& subnetMask, const IPv4Address& gatewayIpAddress,
	                                                 GvcpFlag flag, uint16_t requestId)
	    : GvcpRequestLayer(GvcpCommand::ForceIpCmd, flag, requestId, sizeof(gvcp_forceip_body))
	{
		setMacAddress(macAddress);
		setIpAddress(ipAddress);
		setSubnetMask(subnetMask);
		setGatewayIpAddress(gatewayIpAddress);
	}

	bool GvcpForceIpRequestLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return GvcpRequestLayer::isDataValid(data, dataLen) &&
		       dataLen >= sizeof(gvcp_request_header) + sizeof(gvcp_forceip_body);
	}

	MacAddress GvcpForceIpRequestLayer::getMacAddress() const
	{
		return MacAddress(getGvcpForceIpBody()->macAddress);
	}

	void GvcpForceIpRequestLayer::setMacAddress(const MacAddress& macAddress)
	{
		macAddress.copyTo(getGvcpForceIpBody()->macAddress, sizeof(gvcp_forceip_body::macAddress));
	}

	IPv4Address GvcpForceIpRequestLayer::getIpAddress() const
	{
		return { getGvcpForceIpBody()->ipAddress };
	}

	void GvcpForceIpRequestLayer::setIpAddress(const IPv4Address& ipAddress)
	{
		getGvcpForceIpBody()->ipAddress = ipAddress.toInt();
	}

	IPv4Address GvcpForceIpRequestLayer::getSubnetMask() const
	{
		return { getGvcpForceIpBody()->subnetMask };
	}

	void GvcpForceIpRequestLayer::setSubnetMask(const IPv4Address& subnetMask)
	{
		getGvcpForceIpBody()->subnetMask = subnetMask.toInt();
	}

	IPv4Address GvcpForceIpRequestLayer::getGatewayIpAddress() const
	{
		return { getGvcpForceIpBody()->gateway };
	}

	void GvcpForceIpRequestLayer::setGatewayIpAddress(const IPv4Address& gatewayIpAddress)
	{
		getGvcpForceIpBody()->gateway = gatewayIpAddress.toInt();
	}
	const FieldDescriptor GvcpForceIpRequestLayer::SerializedFields::MacAddress{
		GvcpRequestLayer::SerializedFields::MaxID + 1, "macAddress"
	};
	const FieldDescriptor GvcpForceIpRequestLayer::SerializedFields::IpAddress{
		GvcpRequestLayer::SerializedFields::MaxID + 2, "ipAddress"
	};
	const FieldDescriptor GvcpForceIpRequestLayer::SerializedFields::SubnetMask{
		GvcpRequestLayer::SerializedFields::MaxID + 3, "subnetMask"
	};
	const FieldDescriptor GvcpForceIpRequestLayer::SerializedFields::GatewayIpAddress{
		GvcpRequestLayer::SerializedFields::MaxID + 4, "gatewayIpAddress"
	};

	void GvcpForceIpRequestLayer::serializeLayer(ObjectScope& serializer) const
	{
		GvcpRequestLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::MacAddress, getMacAddress().toString());
		serializer.writeField(SerializedFields::IpAddress, getIpAddress().toString());
		serializer.writeField(SerializedFields::SubnetMask, getSubnetMask().toString());
		serializer.writeField(SerializedFields::GatewayIpAddress, getGatewayIpAddress().toString());
	}

}  // namespace pcpp
