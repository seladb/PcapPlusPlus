#include "GvcpLayer.h"
#include "EndianPortable.h"
#include <algorithm>
#include <cstring>
#include <sstream>

namespace pcpp
{
	namespace
	{
		constexpr uint8_t gvcpMagicNumber = 0x42;
		constexpr GvcpFlag gvcpAcknowledgeFlag = 0x01;

		GvcpCommand toGvcpCommand(uint16_t command)
		{
			switch (static_cast<GvcpCommand>(command))
			{
			case GvcpCommand::DiscoveredCmd:
			case GvcpCommand::DiscoveredAck:
			case GvcpCommand::ForceIpCmd:
			case GvcpCommand::ForceIpAck:
			case GvcpCommand::PacketResendCmd:
			case GvcpCommand::PacketResendAck:
			case GvcpCommand::ReadRegCmd:
			case GvcpCommand::ReadRegAck:
			case GvcpCommand::WriteRegCmd:
			case GvcpCommand::WriteRegAck:
			case GvcpCommand::ReadMemCmd:
			case GvcpCommand::ReadMemAck:
			case GvcpCommand::WriteMemCmd:
			case GvcpCommand::WriteMemAck:
			case GvcpCommand::PendingAck:
			case GvcpCommand::EventCmd:
			case GvcpCommand::EventAck:
			case GvcpCommand::EventDataCmd:
			case GvcpCommand::EventDataAck:
			case GvcpCommand::ActionCmd:
			case GvcpCommand::ActionAck:
				return static_cast<GvcpCommand>(command);
			default:
				return GvcpCommand::Unknown;
			}
		}

		GvcpResponseStatus toGvcpResponseStatus(uint16_t status)
		{
			switch (static_cast<GvcpResponseStatus>(status))
			{
			case GvcpResponseStatus::Success:
			case GvcpResponseStatus::PacketResend:
			case GvcpResponseStatus::NotImplemented:
			case GvcpResponseStatus::InvalidParameter:
			case GvcpResponseStatus::InvalidAddress:
			case GvcpResponseStatus::WriteProtect:
			case GvcpResponseStatus::BadAlignment:
			case GvcpResponseStatus::AccessDenied:
			case GvcpResponseStatus::Busy:
			case GvcpResponseStatus::LocalProblem:
			case GvcpResponseStatus::MsgMismatch:
			case GvcpResponseStatus::InvalidProtocol:
			case GvcpResponseStatus::NoMsg:
			case GvcpResponseStatus::PacketUnavailable:
			case GvcpResponseStatus::DataOverrun:
			case GvcpResponseStatus::InvalidHeader:
			case GvcpResponseStatus::WrongConfig:
			case GvcpResponseStatus::PacketNotYetAvailable:
			case GvcpResponseStatus::PacketAndPrevRemovedFromMemory:
			case GvcpResponseStatus::PacketRemovedFromMemory:
			case GvcpResponseStatus::NoRefTime:
			case GvcpResponseStatus::PacketTemporarilyUnavailable:
			case GvcpResponseStatus::Overflow:
			case GvcpResponseStatus::ActionLate:
			case GvcpResponseStatus::LeaderTrailerOverflow:
			case GvcpResponseStatus::Error:
				return static_cast<GvcpResponseStatus>(status);
			default:
				return GvcpResponseStatus::Unknown;
			}
		}

		/// Write a value in hex without changing the formatting flags of the stream
		std::ostream& writeHex(std::ostream& os, uint16_t value)
		{
			const auto flags = os.flags();
			os << "0x" << std::hex << value;
			os.flags(flags);
			return os;
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
		return writeHex(os, static_cast<uint16_t>(command));
	}

	std::ostream& operator<<(std::ostream& os, GvcpResponseStatus status)
	{
		return writeHex(os, static_cast<uint16_t>(status));
	}

	// -------- Class GvcpLayer -----------------

	GvcpLayer* GvcpLayer::parseGvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (GvcpRequestLayer::isDataValid(data, dataLen))
		{
			auto* header = reinterpret_cast<internal::gvcp_request_header*>(data);
			switch (toGvcpCommand(be16toh(header->command)))
			{
			case GvcpCommand::DiscoveredCmd:
				return new GvcpDiscoveryRequestLayer(data, dataLen, prevLayer, packet);
			case GvcpCommand::ForceIpCmd:
				if (dataLen >= sizeof(internal::gvcp_request_header) + sizeof(internal::gvcp_forceip_body))
					return new GvcpForceIpRequestLayer(data, dataLen, prevLayer, packet);
				return new GvcpRequestLayer(data, dataLen, prevLayer, packet);
			default:
				return new GvcpRequestLayer(data, dataLen, prevLayer, packet);
			}
		}

		if (GvcpAcknowledgeLayer::isDataValid(data, dataLen))
		{
			auto* header = reinterpret_cast<internal::gvcp_ack_header*>(data);
			switch (toGvcpCommand(be16toh(header->command)))
			{
			case GvcpCommand::DiscoveredAck:
				if (dataLen >= sizeof(internal::gvcp_ack_header) + sizeof(internal::gvcp_discovery_body))
					return new GvcpDiscoveryAcknowledgeLayer(data, dataLen, prevLayer, packet);
				return new GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet);
			case GvcpCommand::ForceIpAck:
				return new GvcpForceIpAcknowledgeLayer(data, dataLen, prevLayer, packet);
			default:
				return new GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet);
			}
		}

		return nullptr;
	}

	// the payload accessors rely on the request header and the acknowledge header having the same size
	static_assert(sizeof(internal::gvcp_request_header) == sizeof(internal::gvcp_ack_header),
	              "GVCP request and acknowledge headers should have the same size");

	uint8_t* GvcpLayer::getPayloadData() const
	{
		return m_DataLen > sizeof(internal::gvcp_request_header) ? m_Data + sizeof(internal::gvcp_request_header)
		                                                         : nullptr;
	}

	size_t GvcpLayer::getPayloadDataLen() const
	{
		return m_DataLen > sizeof(internal::gvcp_request_header) ? m_DataLen - sizeof(internal::gvcp_request_header)
		                                                         : 0;
	}

	// -------- Class GvcpRequestLayer -----------------

	GvcpRequestLayer::GvcpRequestLayer(GvcpCommand command, const uint8_t* payloadData, uint16_t payloadDataSize,
	                                   GvcpFlag flag, uint16_t requestId)
	{
		if (payloadData == nullptr)
			payloadDataSize = 0;

		initLayer(command, payloadDataSize, flag, requestId);
		if (payloadDataSize > 0)
			memcpy(getPayloadData(), payloadData, payloadDataSize);
	}

	void GvcpRequestLayer::initLayer(GvcpCommand command, uint16_t dataSize, GvcpFlag flag, uint16_t requestId)
	{
		allocData(sizeof(internal::gvcp_request_header) + dataSize);

		auto* header = getGvcpHeader();
		header->magicNumber = gvcpMagicNumber;
		header->flag = flag;
		header->command = htobe16(static_cast<uint16_t>(command));
		header->dataSize = htobe16(dataSize);
		header->requestId = htobe16(requestId);

		m_Protocol = GVCP;
	}

	bool GvcpRequestLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return canReinterpretAs<internal::gvcp_request_header>(data, dataLen) && data[0] == gvcpMagicNumber;
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
		return be16toh(getGvcpHeader()->requestId);
	}

	void GvcpRequestLayer::setRequestId(uint16_t requestId)
	{
		getGvcpHeader()->requestId = htobe16(requestId);
	}

	GvcpCommand GvcpRequestLayer::getCommand() const
	{
		return toGvcpCommand(be16toh(getGvcpHeader()->command));
	}

	uint16_t GvcpRequestLayer::getDataSize() const
	{
		return be16toh(getGvcpHeader()->dataSize);
	}

	void GvcpRequestLayer::computeCalculateFields()
	{
		getGvcpHeader()->dataSize = htobe16(static_cast<uint16_t>(getPayloadDataLen()));
	}

	std::string GvcpRequestLayer::toString() const
	{
		std::ostringstream ss;
		ss << "GVCP Request Layer, Command: " << getCommand() << ", Request ID: " << getRequestId();
		return ss.str();
	}

	// -------- Class GvcpAcknowledgeLayer -----------------

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command,
	                                           const uint8_t* payloadData, uint16_t payloadDataSize, uint16_t ackId)
	{
		if (payloadData == nullptr)
			payloadDataSize = 0;

		initLayer(status, command, payloadDataSize, ackId);
		if (payloadDataSize > 0)
			memcpy(getPayloadData(), payloadData, payloadDataSize);
	}

	void GvcpAcknowledgeLayer::initLayer(GvcpResponseStatus status, GvcpCommand command, uint16_t dataSize,
	                                     uint16_t ackId)
	{
		allocData(sizeof(internal::gvcp_ack_header) + dataSize);

		auto* header = getGvcpHeader();
		header->status = htobe16(static_cast<uint16_t>(status));
		header->command = htobe16(static_cast<uint16_t>(command));
		header->dataSize = htobe16(dataSize);
		header->ackId = htobe16(ackId);

		m_Protocol = GVCP;
	}

	bool GvcpAcknowledgeLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return canReinterpretAs<internal::gvcp_ack_header>(data, dataLen);
	}

	GvcpResponseStatus GvcpAcknowledgeLayer::getStatus() const
	{
		return toGvcpResponseStatus(be16toh(getGvcpHeader()->status));
	}

	void GvcpAcknowledgeLayer::setStatus(GvcpResponseStatus status)
	{
		getGvcpHeader()->status = htobe16(static_cast<uint16_t>(status));
	}

	uint16_t GvcpAcknowledgeLayer::getAckId() const
	{
		return be16toh(getGvcpHeader()->ackId);
	}

	void GvcpAcknowledgeLayer::setAckId(uint16_t ackId)
	{
		getGvcpHeader()->ackId = htobe16(ackId);
	}

	GvcpCommand GvcpAcknowledgeLayer::getCommand() const
	{
		return toGvcpCommand(be16toh(getGvcpHeader()->command));
	}

	uint16_t GvcpAcknowledgeLayer::getDataSize() const
	{
		return be16toh(getGvcpHeader()->dataSize);
	}

	void GvcpAcknowledgeLayer::computeCalculateFields()
	{
		getGvcpHeader()->dataSize = htobe16(static_cast<uint16_t>(getPayloadDataLen()));
	}

	std::string GvcpAcknowledgeLayer::toString() const
	{
		std::ostringstream ss;
		ss << "GVCP Acknowledge Layer, Command: " << getCommand() << ", Acknowledge ID: " << getAckId()
		   << ", Status: " << getStatus();
		return ss.str();
	}

	// -------- Class GvcpDiscoveryAcknowledgeLayer -----------------

	GvcpDiscoveryAcknowledgeLayer::GvcpDiscoveryAcknowledgeLayer(GvcpResponseStatus status, uint16_t ackId)
	{
		initLayer(status, GvcpCommand::DiscoveredAck, sizeof(internal::gvcp_discovery_body), ackId);
	}

	std::pair<uint16_t, uint16_t> GvcpDiscoveryAcknowledgeLayer::getVersion() const
	{
		auto* body = getGvcpDiscoveryBody();
		return { be16toh(body->versionMajor), be16toh(body->versionMinor) };
	}

	void GvcpDiscoveryAcknowledgeLayer::setVersion(uint16_t major, uint16_t minor)
	{
		auto* body = getGvcpDiscoveryBody();
		body->versionMajor = htobe16(major);
		body->versionMinor = htobe16(minor);
	}

	MacAddress GvcpDiscoveryAcknowledgeLayer::getMacAddress() const
	{
		return MacAddress(getGvcpDiscoveryBody()->macAddress);
	}

	void GvcpDiscoveryAcknowledgeLayer::setMacAddress(const MacAddress& macAddress)
	{
		macAddress.copyTo(getGvcpDiscoveryBody()->macAddress, 6);
	}

	IPv4Address GvcpDiscoveryAcknowledgeLayer::getIpAddress() const
	{
		return IPv4Address(getGvcpDiscoveryBody()->ipAddress);
	}

	void GvcpDiscoveryAcknowledgeLayer::setIpAddress(const IPv4Address& ipAddress)
	{
		getGvcpDiscoveryBody()->ipAddress = ipAddress.toInt();
	}

	IPv4Address GvcpDiscoveryAcknowledgeLayer::getSubnetMask() const
	{
		return IPv4Address(getGvcpDiscoveryBody()->subnetMask);
	}

	void GvcpDiscoveryAcknowledgeLayer::setSubnetMask(const IPv4Address& subnetMask)
	{
		getGvcpDiscoveryBody()->subnetMask = subnetMask.toInt();
	}

	IPv4Address GvcpDiscoveryAcknowledgeLayer::getGatewayIpAddress() const
	{
		return IPv4Address(getGvcpDiscoveryBody()->defaultGateway);
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

	// -------- Class GvcpForceIpRequestLayer -----------------

	GvcpForceIpRequestLayer::GvcpForceIpRequestLayer(const MacAddress& macAddress, const IPv4Address& ipAddress,
	                                                 const IPv4Address& subnetMask, const IPv4Address& gatewayIpAddress,
	                                                 GvcpFlag flag, uint16_t requestId)
	{
		initLayer(GvcpCommand::ForceIpCmd, sizeof(internal::gvcp_forceip_body), flag, requestId);

		setMacAddress(macAddress);
		setIpAddress(ipAddress);
		setSubnetMask(subnetMask);
		setGatewayIpAddress(gatewayIpAddress);
	}

	MacAddress GvcpForceIpRequestLayer::getMacAddress() const
	{
		return MacAddress(getGvcpForceIpBody()->macAddress);
	}

	void GvcpForceIpRequestLayer::setMacAddress(const MacAddress& macAddress)
	{
		macAddress.copyTo(getGvcpForceIpBody()->macAddress, 6);
	}

	IPv4Address GvcpForceIpRequestLayer::getIpAddress() const
	{
		return IPv4Address(getGvcpForceIpBody()->ipAddress);
	}

	void GvcpForceIpRequestLayer::setIpAddress(const IPv4Address& ipAddress)
	{
		getGvcpForceIpBody()->ipAddress = ipAddress.toInt();
	}

	IPv4Address GvcpForceIpRequestLayer::getSubnetMask() const
	{
		return IPv4Address(getGvcpForceIpBody()->subnetMask);
	}

	void GvcpForceIpRequestLayer::setSubnetMask(const IPv4Address& subnetMask)
	{
		getGvcpForceIpBody()->subnetMask = subnetMask.toInt();
	}

	IPv4Address GvcpForceIpRequestLayer::getGatewayIpAddress() const
	{
		return IPv4Address(getGvcpForceIpBody()->gateway);
	}

	void GvcpForceIpRequestLayer::setGatewayIpAddress(const IPv4Address& gatewayIpAddress)
	{
		getGvcpForceIpBody()->gateway = gatewayIpAddress.toInt();
	}
}  // namespace pcpp
