#define LOG_MODULE PacketLogModuleIcmpV6Layer

#include "IcmpV6Layer.h"
#include "EndianPortable.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "NdpLayer.h"
#include "PacketUtils.h"
#include "PayloadLayer.h"
#include <sstream>

// IcmpV6Layer

namespace pcpp
{

	Layer* IcmpV6Layer::parseIcmpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (dataLen < sizeof(icmpv6hdr))
			return new PayloadLayer(data, dataLen, prevLayer, packet);

		icmpv6hdr* hdr = (icmpv6hdr*)data;
		ICMPv6MessageType messageType = static_cast<ICMPv6MessageType>(hdr->type);

		switch (messageType)
		{
		case ICMPv6MessageType::ICMPv6_ECHO_REQUEST:
		case ICMPv6MessageType::ICMPv6_ECHO_REPLY:
			return new ICMPv6EchoLayer(data, dataLen, prevLayer, packet);
		case ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION:
			if (!NDPNeighborSolicitationLayer::isDataValid(data, dataLen))
				return new IcmpV6Layer(data, dataLen, prevLayer, packet);
			return new NDPNeighborSolicitationLayer(data, dataLen, prevLayer, packet);
		case ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT:
			if (!NDPNeighborAdvertisementLayer::isDataValid(data, dataLen))
				return new IcmpV6Layer(data, dataLen, prevLayer, packet);
			return new NDPNeighborAdvertisementLayer(data, dataLen, prevLayer, packet);
		case ICMPv6MessageType::ICMPv6_UNKNOWN_MESSAGE:
			return new PayloadLayer(data, dataLen, prevLayer, packet);
		default:
			return new IcmpV6Layer(data, dataLen, prevLayer, packet);
		}
	}

	IcmpV6Layer::IcmpV6Layer(ICMPv6MessageType msgType, uint8_t code, const uint8_t* data, size_t dataLen)
	{
		allocData(sizeof(icmpv6hdr) + dataLen);
		m_Protocol = ICMPv6;

		icmpv6hdr* hdr = (icmpv6hdr*)m_Data;
		hdr->type = static_cast<uint8_t>(msgType);
		hdr->code = code;

		if (data != nullptr && dataLen > 0)
			memcpy(m_Data + sizeof(icmpv6hdr), data, dataLen);
	}

	ICMPv6MessageType IcmpV6Layer::getMessageType() const
	{
		return static_cast<ICMPv6MessageType>(getIcmpv6Header()->type);
	}

	uint8_t IcmpV6Layer::getCode() const
	{
		return getIcmpv6Header()->code;
	}

	uint16_t IcmpV6Layer::getChecksum() const
	{
		return be16toh(getIcmpv6Header()->checksum);
	}

	void IcmpV6Layer::computeCalculateFields()
	{
		calculateChecksum();
	}

	void IcmpV6Layer::calculateChecksum()
	{
		// Pseudo header of 40 bytes which is composed as follows(in order):
		// - 16 bytes for the source address
		// - 16 bytes for the destination address
		// - 4 bytes big endian payload length(the same value as in the IPv6 header)
		// - 3 bytes zero + 1 byte nextheader( 58 decimal) big endian

		getIcmpv6Header()->checksum = 0;

		if (m_PrevLayer != nullptr)
		{
			auto prevLayerAsIPv6 = static_cast<IPv6Layer*>(m_PrevLayer);

			ScalarBuffer<uint16_t> vec[2];

			vec[0].buffer = (uint16_t*)m_Data;
			vec[0].len = m_DataLen;

			const unsigned int pseudoHeaderLen = 40;
			const unsigned int bigEndianLen = htobe32(m_DataLen);
			const unsigned int bigEndianNextHeader = htobe32(PACKETPP_IPPROTO_ICMPV6);

			uint16_t pseudoHeader[pseudoHeaderLen / 2];
			prevLayerAsIPv6->getSrcIPv6Address().copyTo(reinterpret_cast<uint8_t*>(pseudoHeader));
			prevLayerAsIPv6->getDstIPv6Address().copyTo(reinterpret_cast<uint8_t*>(pseudoHeader + 8));
			memcpy(&pseudoHeader[16], &bigEndianLen, sizeof(uint32_t));
			memcpy(&pseudoHeader[18], &bigEndianNextHeader, sizeof(uint32_t));
			vec[1].buffer = pseudoHeader;
			vec[1].len = pseudoHeaderLen;

			// Calculate and write checksum
			getIcmpv6Header()->checksum = htobe16(computeChecksum(vec, 2));
		}
	}

	std::string IcmpV6Layer::toString() const
	{
		std::ostringstream typeStream;
		typeStream << (int)getMessageType();
		return "ICMPv6 Layer, Message type: " + typeStream.str();
	}

	//
	// ICMPv6EchoLayer
	//

	ICMPv6EchoLayer::ICMPv6EchoLayer(ICMPv6EchoType echoType, uint16_t id, uint16_t sequence, const uint8_t* data,
	                                 size_t dataLen)
	{
		allocData(sizeof(icmpv6_echo_hdr) + dataLen);
		m_Protocol = ICMPv6;

		icmpv6_echo_hdr* header = getEchoHeader();

		switch (echoType)
		{
		case REPLY:
			header->type = static_cast<uint8_t>(ICMPv6MessageType::ICMPv6_ECHO_REPLY);
			break;
		case REQUEST:
		default:
			header->type = static_cast<uint8_t>(ICMPv6MessageType::ICMPv6_ECHO_REQUEST);
			break;
		}

		header->code = 0;
		header->checksum = 0;
		header->id = htobe16(id);
		header->sequence = htobe16(sequence);

		if (data != nullptr && dataLen > 0)
			memcpy(getEchoDataPtr(), data, dataLen);
	}

	uint16_t ICMPv6EchoLayer::getIdentifier() const
	{
		return be16toh(getEchoHeader()->id);
	}

	uint16_t ICMPv6EchoLayer::getSequenceNr() const
	{
		return be16toh(getEchoHeader()->sequence);
	}

	std::string ICMPv6EchoLayer::toString() const
	{
		std::ostringstream typeStream;
		typeStream << (int)getMessageType();
		return "ICMPv6 Layer, Echo Request/Reply Message (type: " + typeStream.str() + ")";
	}

	static constexpr const char* icmpV6MessageTypeToString(ICMPv6MessageType type)
	{
		switch (type)
		{
		case ICMPv6MessageType::ICMPv6_DESTINATION_UNREACHABLE:
			return "DestinationUnreachable";
		case ICMPv6MessageType::ICMPv6_PACKET_TOO_BIG:
			return "PacketTooBig";
		case ICMPv6MessageType::ICMPv6_TIME_EXCEEDED:
			return "TimeExceeded";
		case ICMPv6MessageType::ICMPv6_PARAMETER_PROBLEM:
			return "ParameterProblem";
		case ICMPv6MessageType::ICMPv6_PRIVATE_EXPERIMENTATION1:
		case ICMPv6MessageType::ICMPv6_PRIVATE_EXPERIMENTATION2:
		case ICMPv6MessageType::ICMPv6_PRIVATE_EXPERIMENTATION3:
		case ICMPv6MessageType::ICMPv6_PRIVATE_EXPERIMENTATION4:
			return "PrivateExperimentation";
		case ICMPv6MessageType::ICMPv6_RESERVED_EXPANSION_ERROR:
			return "ReservedExpansionError";
		case ICMPv6MessageType::ICMPv6_ECHO_REQUEST:
			return "EchoRequest";
		case ICMPv6MessageType::ICMPv6_ECHO_REPLY:
			return "EchoReply";
		case ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_QUERY:
			return "MulticastListenerQuery";
		case ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_REPORT:
			return "MulticastListenerReport";
		case ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_DONE:
			return "MulticastListenerDone";
		case ICMPv6MessageType::ICMPv6_ROUTER_SOLICITATION:
			return "RouterSolicitation";
		case ICMPv6MessageType::ICMPv6_ROUTER_ADVERTISEMENT:
			return "RouterAdvertisement";
		case ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION:
			return "NeighborSolicitation";
		case ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT:
			return "NeighborAdvertisement";
		case ICMPv6MessageType::ICMPv6_REDIRECT_MESSAGE:
			return "Redirect";
		case ICMPv6MessageType::ICMPv6_ROUTER_RENUMBERING:
			return "RouterRenumbering";
		case ICMPv6MessageType::ICMPv6_ICMP_NODE_INFORMATION_QUERY:
			return "NodeInformationQuery";
		case ICMPv6MessageType::ICMPv6_ICMP_NODE_INFORMATION_RESPONSE:
			return "NodeInformationReply";
		case ICMPv6MessageType::ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE:
			return "InverseNeighborDiscoverySolicitation";
		case ICMPv6MessageType::ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE:
			return "InverseNeighborDiscoveryAdvertisement";
		case ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS:
			return "MulticastListenerDiscoveryReports";
		case ICMPv6MessageType::ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE:
			return "HomeAgentAddressDiscoveryRequest";
		case ICMPv6MessageType::ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE:
			return "HomeAgentAddressDiscoveryReply";
		case ICMPv6MessageType::ICMPv6_MOBILE_PREFIX_SOLICITATION:
			return "MobilePrefixSolicitation";
		case ICMPv6MessageType::ICMPv6_MOBILE_PREFIX_ADVERTISEMENT:
			return "MobilePrefixAdvertisement";
		case ICMPv6MessageType::ICMPv6_CERTIFICATION_PATH_SOLICITATION:
			return "CertificationPathSolicitation";
		case ICMPv6MessageType::ICMPv6_CERTIFICATION_PATH_ADVERTISEMENT:
			return "CertificationPathAdvertisement";
		case ICMPv6MessageType::ICMPv6_EXPERIMENTAL_MOBILITY:
			return "ExperimentalMobility";
		case ICMPv6MessageType::ICMPv6_MULTICAST_ROUTER_ADVERTISEMENT:
			return "MulticastRouterAdvertisement";
		case ICMPv6MessageType::ICMPv6_MULTICAST_ROUTER_SOLICITATION:
			return "MulticastRouterSolicitation";
		case ICMPv6MessageType::ICMPv6_MULTICAST_ROUTER_TERMINATION:
			return "MulticastRouterTermination";
		case ICMPv6MessageType::ICMPv6_RPL_CONTROL_MESSAGE:
			return "RplControl";
		case ICMPv6MessageType::ICMPv6_RESERVED_EXPANSION_INFORMATIONAL:
			return "ReservedExpansionInformational";
		default:
			return "Unknown";
		}
	}

	const FieldDescriptor IcmpV6Layer::SerializedFields::Type{ Layer::SerializedFields::MaxID + 1, "type" };
	const FieldDescriptor IcmpV6Layer::SerializedFields::TypeName{ Layer::SerializedFields::MaxID + 4, "typeName" };
	const FieldDescriptor IcmpV6Layer::SerializedFields::Code{ Layer::SerializedFields::MaxID + 2, "code" };
	const FieldDescriptor IcmpV6Layer::SerializedFields::Checksum{ Layer::SerializedFields::MaxID + 3, "checksum" };

	void IcmpV6Layer::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SerializedFields::Type, static_cast<uint8_t>(getMessageType()));
		serializer.writeField(SerializedFields::TypeName, icmpV6MessageTypeToString(getMessageType()));
		serializer.writeField(SerializedFields::Code, getCode());
		serializer.writeHexField(SerializedFields::Checksum, getChecksum());
	}

	const FieldDescriptor ICMPv6EchoLayer::SerializedFields::Identifier{ IcmpV6Layer::SerializedFields::MaxID + 1,
		                                                                 "id" };
	const FieldDescriptor ICMPv6EchoLayer::SerializedFields::Sequence{ IcmpV6Layer::SerializedFields::MaxID + 2,
		                                                               "sequence" };

	void ICMPv6EchoLayer::serializeLayer(ObjectScope& serializer) const
	{
		IcmpV6Layer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Identifier, getIdentifier());
		serializer.writeField(SerializedFields::Sequence, getSequenceNr());
	}

}  // namespace pcpp
