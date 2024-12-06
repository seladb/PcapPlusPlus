#define LOG_MODULE PacketLogModuleGvcpLayer

#include "GvcpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"
#include <cstring>
#include <functional>
#include <sstream>
#include <unordered_set>

template <> struct std::hash<pcpp::GvcpCommand>
{
	std::size_t operator()(const pcpp::GvcpCommand& command) const
	{
		return static_cast<uint16_t>(command);
	}
};

namespace pcpp
{
	namespace internal
	{
		std::unordered_set<GvcpCommand> gvcpCommandSet = {
			GvcpCommand::DiscoveredCmd, GvcpCommand::DiscoveredAck,   GvcpCommand::ForceIpCmd,
			GvcpCommand::ForceIpAck,    GvcpCommand::PacketResendCmd, GvcpCommand::PacketResendAck,
			GvcpCommand::ReadRegCmd,    GvcpCommand::ReadRegAck,      GvcpCommand::WriteRegCmd,
			GvcpCommand::WriteRegAck,   GvcpCommand::ReadMemCmd,      GvcpCommand::ReadMemAck,
			GvcpCommand::WriteMemCmd,   GvcpCommand::WriteMemAck,     GvcpCommand::PendingAck,
			GvcpCommand::EventCmd,      GvcpCommand::EventAck,        GvcpCommand::EventDataCmd,
			GvcpCommand::EventDataAck,  GvcpCommand::ActionCmd,       GvcpCommand::ActionAck,
			GvcpCommand::Unknown
		};

		gvcp_request_header::gvcp_request_header(GvcpFlag flag, GvcpCommand command, uint16_t dataSize,
		                                         uint16_t requestId)
		    : flag(flag), command(hostToNet16(static_cast<uint16_t>(command))), dataSize(hostToNet16(dataSize)),
		      requestId(hostToNet16(requestId))
		{}

		GvcpCommand gvcp_request_header::getCommand() const
		{
			GvcpCommand command_ = static_cast<GvcpCommand>(netToHost16(command));
			if (internal::gvcpCommandSet.find(command_) != internal::gvcpCommandSet.end())
			{
				return command_;
			}

			return GvcpCommand::Unknown;
		}

		gvcp_ack_header::gvcp_ack_header(GvcpResponseStatus status, GvcpCommand command, uint16_t dataSize,
		                                 uint16_t ackId)
		    : status(hostToNet16(static_cast<uint16_t>(status))), command(hostToNet16(static_cast<uint16_t>(command))),
		      dataSize(hostToNet16(dataSize)), ackId(hostToNet16(ackId))
		{}

		GvcpCommand gvcp_ack_header::getCommand() const
		{
			GvcpCommand command_ = static_cast<GvcpCommand>(netToHost16(command));
			if (internal::gvcpCommandSet.find(command_) != internal::gvcpCommandSet.end())
			{
				return command_;
			}

			return GvcpCommand::Unknown;
		}

	}  // namespace internal

	std::ostream& operator<<(std::ostream& os, GvcpCommand command)
	{
		os << "0x" << std::hex << static_cast<uint16_t>(command) << std::dec;
		return os;
	}

	std::ostream& operator<<(std::ostream& os, GvcpResponseStatus status)
	{
		os << "0x" << std::hex << static_cast<uint16_t>(status) << std::dec;
		return os;
	}

	/*---------------------- Class GvcpLayer ----------------------------*/

	GvcpLayer::GvcpLayer(uint8_t* data, size_t dataSize, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataSize, prevLayer, packet, GVCP)
	{}

	Layer* GvcpLayer::parseGvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (data == nullptr || dataLen < sizeof(internal::gvcp_request_header) ||
		    dataLen < sizeof(internal::gvcp_ack_header))
		{
			return new PayloadLayer(data, dataLen, prevLayer, packet);
		}

		if (GvcpLayer::verifyRequest(data))
		{
			auto* header = reinterpret_cast<internal::gvcp_request_header*>(data);
			switch (header->getCommand())
			{
			case GvcpCommand::DiscoveredCmd:
				return new GvcpDiscoveryRequestLayer(data, dataLen, prevLayer, packet);
			case GvcpCommand::ForceIpCmd:
				return new GvcpForceIpRequestLayer(data, dataLen, prevLayer, packet);
			default:
				return new GvcpRequestLayer(data, dataLen, prevLayer, packet);
			}
		}
		else
		{
			auto* header = reinterpret_cast<internal::gvcp_ack_header*>(data);
			switch (header->getCommand())
			{
			case GvcpCommand::DiscoveredAck:
				return new GvcpDiscoveryAcknowledgeLayer(data, dataLen);
			case GvcpCommand::ForceIpAck:
				return new GvcpForceIpAcknowledgeLayer(data, dataLen);
			default:
				return new GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet);
			}
		}
	}

	/*---------------------- Class GvcpRequestLayer ----------------------------*/
	GvcpRequestLayer::GvcpRequestLayer(uint8_t* data, size_t dataSize, Layer* prevLayer, Packet* packet)
	    : GvcpLayer(data, dataSize, prevLayer, packet)
	{}

	GvcpRequestLayer::GvcpRequestLayer(GvcpCommand command, const uint8_t* payloadData, uint16_t payloadDataSize,
	                                   GvcpFlag flag, uint16_t requestId)
	{
		m_Protocol = GVCP;

		m_DataLen = getHeaderLen() + payloadDataSize;
		m_Data = new uint8_t[m_DataLen];

		// copy the payload data
		memcpy(m_Data + getHeaderLen(), payloadData, payloadDataSize);

		// set the header fields
		auto header = reinterpret_cast<internal::gvcp_request_header*>(m_Data);
		header->command = hostToNet16(static_cast<uint16_t>(command));
		header->flag = flag;
		header->requestId = hostToNet16(requestId);
		header->dataSize = hostToNet16(payloadDataSize);
	}

	GvcpRequestLayer::GvcpRequestLayer(const uint8_t* data, size_t dataSize)
	{
		m_Protocol = GVCP;

		m_DataLen = dataSize;
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, data, m_DataLen);
	}

	std::string GvcpRequestLayer::toString() const
	{
		std::stringstream ss;
		ss << "GVCP Request Layer, Command: " << getCommand() << ", Request ID: " << getRequestId();
		return ss.str();
	}

	uint16_t GvcpRequestLayer::getDataSize() const
	{
		return netToHost16(getGvcpHeader()->dataSize);
	}

	uint16_t GvcpRequestLayer::getRequestId() const
	{
		return netToHost16(getGvcpHeader()->requestId);
	}

	GvcpCommand GvcpRequestLayer::getCommand() const
	{
		GvcpCommand command = getGvcpHeader()->getCommand();
		if (internal::gvcpCommandSet.find(command) != internal::gvcpCommandSet.end())
		{
			return command;
		}

		return GvcpCommand::Unknown;
	}

	/*---------------------- Class GvcpAcknowledgeLayer ----------------------------*/
	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(uint8_t* data, size_t dataSize, Layer* prevLayer, Packet* packet)
	    : GvcpLayer(data, dataSize, prevLayer, packet)
	{}

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command,
	                                           const uint8_t* payloadData, uint16_t payloadDataSize, uint16_t ackId)
	{
		m_Protocol = GVCP;

		m_DataLen = getHeaderLen() + payloadDataSize;
		m_Data = new uint8_t[m_DataLen];

		// copy the payload data
		memcpy(m_Data + getHeaderLen(), payloadData, payloadDataSize);

		// set the header fields
		auto header = reinterpret_cast<internal::gvcp_ack_header*>(m_Data);
		header->status = hostToNet16(static_cast<uint16_t>(status));
		header->command = hostToNet16(static_cast<uint16_t>(command));
		header->dataSize = hostToNet16(payloadDataSize);
		header->ackId = hostToNet16(ackId);
	}

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(const uint8_t* data, size_t dataSize)
	{
		m_Protocol = GVCP;

		m_DataLen = dataSize;
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, data, m_DataLen);
	}

	std::string GvcpAcknowledgeLayer::toString() const
	{
		std::stringstream ss;
		ss << "GVCP Acknowledge Layer, Command: " << getCommand() << ", Acknowledge ID: " << getAckId()
		   << ", Status: " << getStatus();
		return ss.str();
	}

	GvcpResponseStatus GvcpAcknowledgeLayer::getStatus() const
	{
		return static_cast<GvcpResponseStatus>((netToHost16(getGvcpHeader()->status)));
	}

	GvcpCommand GvcpAcknowledgeLayer::getCommand() const
	{
		GvcpCommand command = getGvcpHeader()->getCommand();
		if (internal::gvcpCommandSet.find(command) != internal::gvcpCommandSet.end())
		{
			return command;
		}

		return GvcpCommand::Unknown;
	}

	uint16_t GvcpAcknowledgeLayer::getDataSize() const
	{
		return netToHost16(getGvcpHeader()->dataSize);
	}

	uint16_t GvcpAcknowledgeLayer::getAckId() const
	{
		return netToHost16(getGvcpHeader()->ackId);
	}
}  // namespace pcpp
