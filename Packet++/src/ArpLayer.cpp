#define LOG_MODULE PacketLogModuleArpLayer

#include "ArpLayer.h"
#include "EthLayer.h"
#include "EndianPortable.h"

namespace pcpp
{
	ArpLayer::ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const IPv4Address& senderIpAddr,
	                   const MacAddress& targetMacAddr, const IPv4Address& targetIpAddr)
	{
		constexpr size_t headerLen = sizeof(arphdr);
		allocData(headerLen);
		m_Protocol = ARP;

		arphdr* arpHeader = getArpHeader();
		arpHeader->opcode = htobe16(static_cast<uint16_t>(opCode));
		senderMacAddr.copyTo(arpHeader->senderMacAddr);
		targetMacAddr.copyTo(arpHeader->targetMacAddr);
		arpHeader->senderIpAddr = senderIpAddr.toInt();
		arpHeader->targetIpAddr = targetIpAddr.toInt();
	}

	// This constructor zeroes the target MAC address for ARP requests to keep backward compatibility.
	ArpLayer::ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr,
	                   const IPv4Address& senderIpAddr, const IPv4Address& targetIpAddr)
	    : ArpLayer(opCode, senderMacAddr, senderIpAddr, opCode == ARP_REQUEST ? MacAddress::Zero : targetMacAddr,
	               targetIpAddr)
	{}

	ArpLayer::ArpLayer(ArpRequest const& arpRequest)
	    : ArpLayer(ARP_REQUEST, arpRequest.senderMacAddr, arpRequest.senderIpAddr, MacAddress::Zero,
	               arpRequest.targetIpAddr)
	{}

	ArpLayer::ArpLayer(ArpReply const& arpReply)
	    : ArpLayer(ARP_REPLY, arpReply.senderMacAddr, arpReply.senderIpAddr, arpReply.targetMacAddr,
	               arpReply.targetIpAddr)
	{}

	ArpLayer::ArpLayer(GratuitousArpRequest const& gratuitousArpRequest)
	    : ArpLayer(ARP_REQUEST, gratuitousArpRequest.senderMacAddr, gratuitousArpRequest.senderIpAddr,
	               MacAddress::Broadcast, gratuitousArpRequest.senderIpAddr)
	{}

	ArpLayer::ArpLayer(GratuitousArpReply const& gratuitousArpReply)
	    : ArpLayer(ARP_REPLY, gratuitousArpReply.senderMacAddr, gratuitousArpReply.senderIpAddr, MacAddress::Broadcast,
	               gratuitousArpReply.senderIpAddr)
	{}

	ArpOpcode ArpLayer::getOpcode() const
	{
		return static_cast<ArpOpcode>(be16toh(getArpHeader()->opcode));
	}

	void ArpLayer::computeCalculateFields()
	{
		arphdr* arpHeader = getArpHeader();
		arpHeader->hardwareType = htobe16(1);  // Ethernet
		arpHeader->hardwareSize = 6;
		arpHeader->protocolType = htobe16(PCPP_ETHERTYPE_IP);  // assume IPv4 over ARP
		arpHeader->protocolSize = 4;                           // assume IPv4 over ARP
	}

	ArpMessageType ArpLayer::getMessageType() const
	{
		switch (getOpcode())
		{
		case ArpOpcode::ARP_REQUEST:
		{
			if (getTargetMacAddress() == MacAddress::Broadcast && getSenderIpAddr() == getTargetIpAddr())
			{
				return ArpMessageType::GratuitousRequest;
			}
			return ArpMessageType::Request;
		}
		case ArpOpcode::ARP_REPLY:
		{
			if (getTargetMacAddress() == MacAddress::Broadcast && getSenderIpAddr() == getTargetIpAddr())
			{
				return ArpMessageType::GratuitousReply;
			}
			return ArpMessageType::Reply;
		}
		default:
			return ArpMessageType::Unknown;
		}
	}

	bool ArpLayer::isRequest() const
	{
		return getOpcode() == pcpp::ArpOpcode::ARP_REQUEST;
	}

	bool ArpLayer::isReply() const
	{
		return getOpcode() == pcpp::ArpOpcode::ARP_REPLY;
	}

	std::string ArpLayer::toString() const
	{
		switch (getOpcode())
		{
		case ArpOpcode::ARP_REQUEST:
			return "ARP Layer, ARP request, who has " + getTargetIpAddr().toString() + " ? Tell " +
			       getSenderIpAddr().toString();
		case ArpOpcode::ARP_REPLY:
			return "ARP Layer, ARP reply, " + getSenderIpAddr().toString() + " is at " +
			       getSenderMacAddress().toString();
		default:
			return "ARP Layer, unknown opcode (" + std::to_string(getOpcode()) + ")";
		}
	}

	const FieldDescriptor ArpLayer::SerializedFields::OpCode{ Layer::SerializedFields::MaxID + 1, "opCode" };
	const FieldDescriptor ArpLayer::SerializedFields::SenderMacAddress{ Layer::SerializedFields::MaxID + 2,
		                                                                "senderMacAddress" };
	const FieldDescriptor ArpLayer::SerializedFields::TargetMacAddress{ Layer::SerializedFields::MaxID + 3,
		                                                                "targetMacAddress" };
	const FieldDescriptor ArpLayer::SerializedFields::SenderIpAddress{ Layer::SerializedFields::MaxID + 4,
		                                                               "senderIpAddress" };
	const FieldDescriptor ArpLayer::SerializedFields::TargetIpAddress{ Layer::SerializedFields::MaxID + 5,
		                                                               "targetIpAddress" };
	const FieldDescriptor ArpLayer::SerializedFields::MessageType{ Layer::SerializedFields::MaxID + 6, "messageType" };
	const FieldDescriptor ArpLayer::SerializedFields::HardwareType{ Layer::SerializedFields::MaxID + 7,
		                                                            "hardwareType" };
	const FieldDescriptor ArpLayer::SerializedFields::HardwareSize{ Layer::SerializedFields::MaxID + 8,
		                                                            "hardwareSize" };
	const FieldDescriptor ArpLayer::SerializedFields::ProtocolType{ Layer::SerializedFields::MaxID + 9,
		                                                            "protocolType" };
	const FieldDescriptor ArpLayer::SerializedFields::ProtocolSize{ Layer::SerializedFields::MaxID + 10,
		                                                            "protocolSize" };

	static constexpr const char* getOpCodeAsString(ArpOpcode opCode)
	{
		switch (opCode)
		{
		case ARP_REQUEST:
			return "Request";
		case ARP_REPLY:
			return "Reply";
		default:
			return "Unknown";
		}
	}

	static constexpr const char* getMessageTypeAsString(ArpMessageType messageType)
	{
		switch (messageType)
		{
		case ArpMessageType::Request:
			return "Request";
		case ArpMessageType::Reply:
			return "Reply";
		case ArpMessageType::GratuitousRequest:
			return "GratuitousRequest";
		case ArpMessageType::GratuitousReply:
			return "GratuitousReply";
		default:
			return "Unknown";
		}
	}

	void ArpLayer::serializeLayer(ObjectScope& serializer) const
	{
		auto* opCode = getOpCodeAsString(getOpcode());
		auto* messageType = getMessageTypeAsString(getMessageType());

		serializer.writeField(SerializedFields::OpCode, opCode);
		serializer.writeField(SerializedFields::SenderMacAddress, getSenderMacAddress().toString());
		serializer.writeField(SerializedFields::TargetMacAddress, getTargetMacAddress().toString());
		serializer.writeField(SerializedFields::SenderIpAddress, getSenderIpAddr().toString());
		serializer.writeField(SerializedFields::TargetIpAddress, getTargetIpAddr().toString());
		serializer.writeField(SerializedFields::MessageType, messageType);
		auto* header = getArpHeader();
		serializer.writeField(SerializedFields::HardwareType, be16toh(header->hardwareType));
		serializer.writeField(SerializedFields::HardwareSize, header->hardwareSize);
		serializer.writeField(SerializedFields::ProtocolType, be16toh(header->protocolType));
		serializer.writeField(SerializedFields::ProtocolSize, header->protocolSize);
	}
}  // namespace pcpp
