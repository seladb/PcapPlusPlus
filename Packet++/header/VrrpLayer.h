#pragma once

#include "Layer.h"
#include "IpAddress.h"
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// For more info see:
	///     https://datatracker.ietf.org/doc/html/rfc2338
	///     https://datatracker.ietf.org/doc/html/rfc3768
	///     https://datatracker.ietf.org/doc/html/rfc5798

	/// VRRPv2 Packet Format
	///    0                   1                   2                   3
	///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///   |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///   |   Auth Type   |   Adver Int   |          Checksum             |
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///   |                         IP Address (1)                        |
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///   |                            .                                  |
	///   |                            .                                  |
	///   |                            .                                  |
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///   |                         IP Address (n)                        |
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///   |                     Authentication Data (1)                   |
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///   |                     Authentication Data (2)                   |
	///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	/// VRRPv3 Packet Format
	///     0                   1                   2                   3
	///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///    |                    IPv4 Fields or IPv6 Fields                 |
	///   ...                                                             ...
	///    |                                                               |
	///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///    |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
	///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///    |(rsvd) |     Max Adver Int     |          Checksum             |
	///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	///    |                                                               |
	///    +                                                               +
	///    |                       IPvX Address(es)                        |
	///    +                                                               +
	///    +                                                               +
	///    +                                                               +
	///    +                                                               +
	///    |                                                               |
	///    +                                                               +
	///    |                                                               |
	///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	/// @struct vrrp_header
	/// VRRP generic header
	struct vrrp_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/// Type
		uint8_t type : 4;

		/// Version bits
		uint8_t version : 4;
#else
		/// Version bits
		uint8_t version : 4;

		/// Type
		uint8_t type : 4;
#endif
		/// The Virtual Router Identifier (VRID) field identifies the virtual router this packet is reporting status
		/// for
		uint8_t vrId;

		/// This specifies the sending VRRP router's priority for the virtual router
		uint8_t priority;

		/// Specifies how many IPvX addresses are present in this Packet
		uint8_t ipAddrCount;

		/// This specifies authentication type(v2) or (Max) Advertisement interval (in seconds(v2) or
		/// centi-seconds(v3)).
		uint16_t authTypeAdvInt;

		/// This specifies checksum field that is used to detect data corruption in the VRRP message.
		/// VRRPv2 uses normal checksum algorithm, while VRRPv3 uses "pseudo-header" checksum algorithm.
		uint16_t checksum;

		/// This specifies one or more IPvX addresses that are associated with the virtual router.
		uint8_t* ipAddresses[];
	};
	static_assert(sizeof(vrrp_header) == 8, "vrrp_header size is not 8 bytes");

	/// @class VrrpLayer
	/// A base class for all VRRP (Virtual Router Redundancy Protocol) protocol classes. This is an abstract class and
	/// cannot be instantiated, only its child classes can be instantiated. The inherited classes represent the
	/// different versions of the protocol: VRRPv2 and VRRPv3
	class VrrpLayer : public Layer
	{
	private:
		bool addIPAddressesAt(const std::vector<IPAddress>& ipAddresses, int offset);

		uint8_t getIPAddressLen() const;

		bool isIPAddressValid(IPAddress& ipAddress) const;

		uint8_t* getFirstIPAddressPtr() const;

		uint8_t* getNextIPAddressPtr(uint8_t* ipAddressPtr) const;

		IPAddress getIPAddressFromData(uint8_t* data) const;

		void copyIPAddressToData(uint8_t* data, const IPAddress& ipAddress) const;

		IPAddress::AddressType m_AddressType;

	protected:
		VrrpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType vrrpVer,
		          IPAddress::AddressType addressType)
		    : Layer(data, dataLen, prevLayer, packet, vrrpVer), m_AddressType(addressType)
		{}

		explicit VrrpLayer(ProtocolType subProtocol, uint8_t virtualRouterId, uint8_t priority);

		vrrp_header* getVrrpHeader() const
		{
			return reinterpret_cast<vrrp_header*>(m_Data);
		}

		void setAddressType(IPAddress::AddressType addressType);

	public:
		/// VRRP message types
		enum VrrpType
		{
			/// Unknown VRRP message
			VrrpType_Unknown = 0,

			/// VRRP advertisement message
			VrrpType_Advertisement = 1
		};

		/// An enum describing VRRP special priority values
		enum VrrpPriority
		{
			/// Default priority for a backup VRRP router (value of 100)
			Default,
			/// Current Master has stopped participating in VRRP (value of 0)
			Stop,
			/// This VRRP router owns the virtual router's IP address(es) (value of 255)
			Owner,
			/// Other priority
			Other
		};

		~VrrpLayer() override = default;

		/// @return The VRRP IP Address type
		IPAddress::AddressType getAddressType() const;

		/// A static method that validates the input data
		/// @param[in] data VRRP raw data (byte stream)
		/// @param[in] dataLen The length of the byte stream
		/// @return One of the values ::VRRPv2, ::VRRPv3 according to detected VRRP version or ::UnknownProtocol if
		/// couldn't detect VRRP version
		static ProtocolType getVersionFromData(uint8_t* data, size_t dataLen);

		/// @return VRRP version of this message
		uint8_t getVersion() const;

		/// @return VRRP type set in vrrp_header#type as VrrpLayer::VrrpType enum.
		VrrpType getType() const;

		/// @return The virtual router id (vrId) in this message
		uint8_t getVirtualRouterID() const;

		/// Set the virtual router ID
		/// @param virtualRouterID new ID to set
		void setVirtualRouterID(uint8_t virtualRouterID);

		/// @return The priority in this message

		uint8_t getPriority() const;

		/// @return An enum describing VRRP priority
		VrrpPriority getPriorityAsEnum() const;

		/// Set the priority
		/// @param priority new priority to set
		void setPriority(uint8_t priority);

		/// @return VRRP checksum of this message
		uint16_t getChecksum() const;

		/// Fill the checksum from header and data and write the result to @ref vrrp_header#checksum
		void calculateAndSetChecksum();

		/// Calculate the checksum from header and data and write the result to @ref vrrp_header#checksum
		/// @return The checksum result
		virtual uint16_t calculateChecksum() const = 0;

		/// @return True if VRRP checksum is correct
		bool isChecksumCorrect() const;

		/// @return The count of VRRP virtual IP addresses in this message
		uint8_t getIPAddressesCount() const;

		/// @return A list of the virtual IP addresses in this message
		std::vector<IPAddress> getIPAddresses() const;

		/// Add a list of virtual IP addresses at a the end of the virtual IP address list. The
		/// vrrp_header#ipAddressCount field will be incremented accordingly
		/// @param[in] ipAddresses A vector containing all the virtual IP address
		/// @return true if added successfully, false otherwise
		bool addIPAddresses(const std::vector<IPAddress>& ipAddresses);

		/// Add a virtual IP address at a the end of the virtual IP address list. The vrrp_header#ipAddressCount field
		/// will be incremented accordingly
		/// @param[in] ipAddress Virtual IP address to add
		/// @return true if add successfully, false otherwise
		bool addIPAddress(const IPAddress& ipAddress);

		/// Remove a virtual IP address at a certain index. The vrrp_header#ipAddressCount field will be decremented
		/// accordingly
		/// @param[in] index The index of the virtual IP address to be removed
		/// @return True if virtual IP address was removed successfully or false otherwise. If false is returned an
		/// appropriate error message will be printed to log
		bool removeIPAddressAtIndex(int index);

		/// Remove all virtual IP addresses in the message. The vrrp_header#ipAddressCount field will be set to 0
		/// @return True if virtual IP addresses were cleared successfully or false otherwise. If false is returned an
		/// appropriate error message will be printed to log
		bool removeAllIPAddresses();

		// implement abstract methods

		/// Does nothing for this layer (VRRP layer is always last)
		void parseNextLayer() override
		{}

		/// Calculate the VRRP checksum
		void computeCalculateFields() override;

		/// @return The message size in bytes which include the size of the basic header + the size of the IP
		/// address(es)
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelNetworkLayer;
		}
	};

	/// @class VrrpV2Layer
	/// Represents VRRPv2 (Virtual Router Redundancy Protocol ver 2) layer. This class represents all the different
	/// messages of VRRPv2
	class VrrpV2Layer : public VrrpLayer
	{
	private:
		struct vrrpv2_auth_adv
		{
			uint8_t authType;
			uint8_t advInt;
		};

	public:
		/// VRRP v2 authentication types
		enum class VrrpAuthType : uint8_t
		{
			/// No Authentication
			NoAuthentication = 0,
			/// Simple Text Password
			SimpleTextPassword = 1,
			/// IP Authentication Header
			IPAuthenticationHeader = 2,
			/// Cisco VRRP MD5 Authentication
			MD5 = 3,
			/// Other/Unknown Authentication Type
			Other = 4
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		VrrpV2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : VrrpLayer(data, dataLen, prevLayer, packet, VRRPv2, IPAddress::IPv4AddressType)
		{}

		/// A constructor that allocates a new VRRP v2 layer
		/// @param virtualRouterId Virtual router ID
		/// @param priority Priority
		/// @param advInt Advertisement interval
		/// @param authType Authentication type (default value is 0)
		explicit VrrpV2Layer(uint8_t virtualRouterId, uint8_t priority, uint8_t advInt, uint8_t authType = 0);

		/// A destructor for this layer (does nothing)
		~VrrpV2Layer() override = default;

		/// @return The VRRP advertisement interval in this message
		uint8_t getAdvInt() const;

		/// Set advertisement interval value in this message
		/// @param advInt value to set
		void setAdvInt(uint8_t advInt);

		/// @return The authentication type in this message
		uint8_t getAuthType() const;

		/// @return The VRRP authentication type as enum
		VrrpAuthType getAuthTypeAsEnum() const;

		/// Set VRRP authentication type
		/// @param authType value to set
		void setAuthType(uint8_t authType);

		// implement abstract methods

		/// Calculate the checksum from header and data and write the result to @ref vrrp_header#checksum
		/// @return The checksum result
		uint16_t calculateChecksum() const override;

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an VRRPv2 layer
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an VRRPv2 layer
		static bool isDataValid(uint8_t const* data, size_t dataLen)
		{
			return canReinterpretAs<vrrp_header>(data, dataLen);
		}
	};

	/// @class VrrpV3Layer
	/// Represents VRRPv3 (Virtual Router Redundancy Protocol ver 3) layer. This class represents all the different
	/// messages of VRRP
	class VrrpV3Layer : public VrrpLayer
	{
	private:
		struct vrrpv3_rsvd_adv
		{
			uint16_t maxAdvInt;
		};

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @param[in] addressType The IP address type to set for this layer
		VrrpV3Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, IPAddress::AddressType addressType)
		    : VrrpLayer(data, dataLen, prevLayer, packet, VRRPv3, addressType)
		{}

		/// A constructor that allocates a new VRRPv3
		/// @param addressType The IP address type to set for this layer
		/// @param virtualRouterId Virtual router ID
		/// @param priority Priority
		/// @param maxAdvInt Max advertisement interval
		explicit VrrpV3Layer(IPAddress::AddressType addressType, uint8_t virtualRouterId, uint8_t priority,
		                     uint16_t maxAdvInt);

		/// A destructor for this layer (does nothing)
		~VrrpV3Layer() override = default;

		/// @return The maximum advertisement interval in this message
		uint16_t getMaxAdvInt() const;

		/// Set the maximum advertisement interval value
		/// @param maxAdvInt Value to set
		void setMaxAdvInt(uint16_t maxAdvInt);

		// implement abstract methods

		/// Calculate the checksum from header and data and write the result to @ref vrrp_header#checksum
		/// @return The checksum result
		uint16_t calculateChecksum() const override;

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an VRRPv3 layer
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an VRRPv3 layer
		static bool isDataValid(uint8_t const* data, size_t dataLen)
		{
			return canReinterpretAs<vrrp_header>(data, dataLen);
		}
	};
}  // namespace pcpp
