#pragma once

#include "Layer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "DeprecationUtils.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct arphdr
	/// Represents an ARP protocol header
#pragma pack(push, 1)
	struct arphdr
	{
		/// Hardware type (HTYPE)
		uint16_t hardwareType;
		/// Protocol type (PTYPE). The permitted PTYPE values share a numbering space with those for EtherType
		uint16_t protocolType;
		/// Hardware address length (HLEN). For IPv4, this has the value 0x0800
		uint8_t hardwareSize;
		/// Protocol length (PLEN). Length (in octets) of addresses used in the upper layer protocol. (The upper layer
		/// protocol specified in PTYPE.) IPv4 address size is 4
		uint8_t protocolSize;
		/// Specifies the operation that the sender is performing: 1 (::ARP_REQUEST) for request, 2 (::ARP_REPLY) for
		/// reply
		uint16_t opcode;
		/// Sender hardware address (SHA)
		uint8_t senderMacAddr[6];
		/// Sender protocol address (SPA)
		uint32_t senderIpAddr;
		/// Target hardware address (THA)
		uint8_t targetMacAddr[6];
		/// Target protocol address (TPA)
		uint32_t targetIpAddr;
	};
#pragma pack(pop)
	static_assert(sizeof(arphdr) == 28, "arphdr size is not 28 bytes");

	/// An enum for ARP message type
	enum ArpOpcode
	{
		ARP_REQUEST = 0x0001,  ///< ARP request
		ARP_REPLY = 0x0002     ///< ARP reply (response)
	};

	/// @brief An enum representing the ARP message type
	enum class ArpMessageType
	{
		Unknown,            ///< Unknown ARP message type
		Request,            ///< ARP request
		Reply,              ///< ARP reply
		GratuitousRequest,  ///< Gratuitous ARP request
		GratuitousReply,    ///< Gratuitous ARP reply
	};

	/// @brief A struct representing the build data for an ARP request
	///
	/// An ARP request is a message sent by a machine to request the MAC address of another machine on the network.
	struct ArpRequest
	{
		MacAddress senderMacAddr;
		IPv4Address senderIpAddr;
		IPv4Address targetIpAddr;

		/// @brief Construct a new Arp Request object
		/// @param senderMacAddress The MAC address of the machine sending the query.
		/// @param senderIPAddress The IP address of the machine sending the query.
		/// @param targetIPAddress The IP address of the target machine being queried.
		ArpRequest(MacAddress const& senderMacAddress, IPv4Address const& senderIPAddress,
		           IPv4Address const& targetIPAddress)
		    : senderMacAddr(senderMacAddress), senderIpAddr(senderIPAddress), targetIpAddr(targetIPAddress) {};
	};

	/// @brief A struct representing the build data for an ARP reply
	///
	/// An ARP reply is a message sent by a machine in response to an ARP request. It contains the MAC address of the
	/// answering machine, and is sent to the IP/MAC address of the machine that sent the original ARP request.
	struct ArpReply
	{
		MacAddress senderMacAddr;
		IPv4Address senderIpAddr;
		MacAddress targetMacAddr;
		IPv4Address targetIpAddr;

		/// @brief Construct a new Arp Reply object
		/// @param senderMacAddress The MAC address of the machine sending the reply.
		/// @param senderIPAddress The IP address of the machine sending the reply.
		/// @param targetMacAddress The MAC address of the target machine being replied to.
		/// @param targetIPAddress The IP address of the target machine being replied to.
		/// @remarks The target machine is considered the machine that sent the original ARP request.
		ArpReply(MacAddress const& senderMacAddress, IPv4Address const& senderIPAddress,
		         MacAddress const& targetMacAddress, IPv4Address const& targetIPAddress)
		    : senderMacAddr(senderMacAddress), senderIpAddr(senderIPAddress), targetMacAddr(targetMacAddress),
		      targetIpAddr(targetIPAddress) {};
	};

	/// @brief A struct representing the build data for a gratuitous ARP request
	///
	/// A gratuitous ARP request is an ARP request that is sent by a machine to announce its presence on the network.
	/// It is an ARP request that has both the sender and target IP addresses set to the IP address of the machine
	/// and the target MAC address set to the broadcast address. Normally such a request will not receive a reply.
	///
	/// These requests can be used to update ARP caches on other machines on the network, or to help in detecting IP
	/// address conflicts.
	struct GratuitousArpRequest
	{
		MacAddress senderMacAddr;
		IPv4Address senderIpAddr;

		/// @brief Construct a new Gratuitous Arp Request object
		/// @param senderMacAddress The MAC address of the machine sending the gratuitous ARP request.
		/// @param senderIPAddress The IP address of the machine sending the gratuitous ARP request.
		/// @remarks The target MAC address is set to the broadcast address and the target IP address is set to the
		/// sender's.
		GratuitousArpRequest(MacAddress const& senderMacAddress, IPv4Address const& senderIPAddress)
		    : senderMacAddr(senderMacAddress), senderIpAddr(senderIPAddress) {};
	};

	/// @brief A struct representing the build data a gratuitous ARP reply
	///
	/// A gratuitous ARP reply is an ARP reply that is sent by a machine to announce its presence on the network.
	/// It is gratuitous in the sense that it is not in response to an ARP request, but sent unsolicited to the network.
	struct GratuitousArpReply
	{
		MacAddress senderMacAddr;
		IPv4Address senderIpAddr;

		/// @brief Construct a new Gratuitous Arp Reply object
		/// @param senderMacAddress The MAC address of the machine sending the gratuitous ARP reply.
		/// @param senderIPAddress The IP address of the machine sending the gratuitous ARP reply.
		/// @remarks The target MAC address is set to the broadcast address and the target IP address is set to the
		/// sender's.
		GratuitousArpReply(MacAddress const& senderMacAddress, IPv4Address const& senderIPAddress)
		    : senderMacAddr(senderMacAddress), senderIpAddr(senderIPAddress) {};
	};

	/// @class ArpLayer
	/// Represents an ARP protocol layer. Currently only IPv4 ARP messages are supported
	class ArpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		ArpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, ARP)
		{
			m_DataLen = sizeof(arphdr);
		}

		/// @brief A constructor that creates an ARP header
		/// @param[in] opCode ARP message type (ARP request or ARP reply)
		/// @param[in] senderMacAddr The sender MAC address (will be put in arphdr#senderMacAddr)
		/// @param[in] senderIpAddr The sender IP address (will be put in arphdr#senderIpAddr)
		/// @param[in] targetMacAddr The target MAC address (will be put in arphdr#targetMacAddr)
		/// @param[in] targetIpAddr The target IP address (will be put in arphdr#targetIpAddr)
		/// @remarks No validation is done on the input parameters. The caller must ensure that the input creates a
		/// valid header.
		ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const IPv4Address& senderIpAddr,
		         const MacAddress& targetMacAddr, const IPv4Address& targetIpAddr);

		/// A constructor that allocates a new ARP header
		/// @param[in] opCode ARP message type (ARP request or ARP reply)
		/// @param[in] senderMacAddr The sender MAC address (will be put in arphdr#senderMacAddr)
		/// @param[in] targetMacAddr The target MAC address (will be put in arphdr#targetMacAddr)
		/// @param[in] senderIpAddr The sender IP address (will be put in arphdr#senderIpAddr)
		/// @param[in] targetIpAddr The target IP address (will be put in arphdr#targetIpAddr)
		/// @deprecated This constructor has been deprecated. Please use one of the other overloads.
		/// @remarks This constructor zeroes the target MAC address for ARP requests to keep backward compatibility.
		PCPP_DEPRECATED("This constructor has been deprecated. Please use one of the other overloads.")
		ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr,
		         const IPv4Address& senderIpAddr, const IPv4Address& targetIpAddr);

		/// @brief A constructor that creates an ARP request header.
		/// @param arpRequest The ARP request data
		explicit ArpLayer(ArpRequest const& arpRequest);

		/// @brief A constructor that creates an ARP reply header.
		/// @param arpReply The ARP reply data
		explicit ArpLayer(ArpReply const& arpReply);

		/// @brief A constructor that creates a gratuitous ARP request header.
		/// @param gratuitousArpRequest The gratuitous ARP request data
		explicit ArpLayer(GratuitousArpRequest const& gratuitousArpRequest);

		/// @brief A constructor that creates a gratuitous ARP reply header.
		/// @param gratuitousArpReply The gratuitous ARP reply data
		explicit ArpLayer(GratuitousArpReply const& gratuitousArpReply);

		~ArpLayer() override = default;

		/// Get a pointer to the ARP header. Notice this points directly to the data, so every change will change the
		/// actual packet data
		/// @return A pointer to the @ref arphdr
		inline arphdr* getArpHeader() const
		{
			return reinterpret_cast<arphdr*>(m_Data);
		}

		/// Get the ARP opcode
		/// @return The ARP opcode
		/// @remarks The opcode may not be one of the values in @ref ArpOpcode
		ArpOpcode getOpcode() const;

		/// Get the sender hardware address (SHA) in the form of MacAddress
		/// @return A MacAddress containing the sender hardware address (SHA)
		inline MacAddress getSenderMacAddress() const
		{
			return MacAddress(getArpHeader()->senderMacAddr);
		}

		/// Get the target hardware address (THA) in the form of MacAddress
		/// @return A MacAddress containing the target hardware address (THA)
		inline MacAddress getTargetMacAddress() const
		{
			return MacAddress(getArpHeader()->targetMacAddr);
		}

		/// Get the sender protocol address (SPA) in the form of IPv4Address
		/// @return An IPv4Address containing the sender protocol address (SPA)
		inline IPv4Address getSenderIpAddr() const
		{
			return getArpHeader()->senderIpAddr;
		}

		/// Get the target protocol address (TPA) in the form of IPv4Address
		/// @return An IPv4Address containing the target protocol address (TPA)
		inline IPv4Address getTargetIpAddr() const
		{
			return getArpHeader()->targetIpAddr;
		}

		// implement abstract methods

		/// Does nothing for this layer (ArpLayer is always last)
		void parseNextLayer() override
		{}

		/// @return The size of @ref arphdr
		size_t getHeaderLen() const override
		{
			return sizeof(arphdr);
		}

		/// Calculate the following fields:
		/// - @ref arphdr#hardwareType = Ethernet (1)
		/// - @ref arphdr#hardwareSize = 6
		/// - @ref arphdr#protocolType = ETHERTYPE_IP (assume IPv4 over ARP)
		/// - @ref arphdr#protocolSize = 4 (assume IPv4 over ARP)
		void computeCalculateFields() override;

		/// @brief Attempts to determine the ARP message type based on the header signature.
		/// @return An @ref ArpMessageType representing the ARP message type.
		ArpMessageType getMessageType() const;

		/// Is this packet an ARP request?
		bool isRequest() const;

		/// Is this packet an ARP reply?
		bool isReply() const;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelNetworkLayer;
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an ARP layer
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an ARP layer
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return canReinterpretAs<arphdr>(data, dataLen);
		}
	};

}  // namespace pcpp
