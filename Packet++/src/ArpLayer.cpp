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
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen]{};  // zero-initialized
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

}  // namespace pcpp
