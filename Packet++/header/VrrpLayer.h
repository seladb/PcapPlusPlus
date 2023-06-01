#ifndef PACKETPP_VRRP_LAYER
#define PACKETPP_VRRP_LAYER

#include "Layer.h"
#include "IpAddress.h"
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp {
	/**
	For more info see:
		https://datatracker.ietf.org/doc/html/rfc2338
		https://datatracker.ietf.org/doc/html/rfc3768
		https://datatracker.ietf.org/doc/html/rfc5798
	*/

	/* VRRPv2 Packet Format
		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |   Auth Type   |   Adver Int   |          Checksum             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         IP Address (1)                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                            .                                  |
	   |                            .                                  |
	   |                            .                                  |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         IP Address (n)                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                     Authentication Data (1)                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                     Authentication Data (2)                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	/**
	 * @struct vrrpv2_auth_adv
	 * VRRPv2 authentication advertisement
	 */
	struct vrrpv2_auth_adv {
		/** The authentication type field identifies the authentication method being utilized */
		uint8_t authType;

		/** This specifies Advertisement interval indicates the time interval (in seconds) between ADVERTISEMENTS. */
		uint8_t advInt;
	};

	/* VRRPv3 Packet Format
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                    IPv4 Fields or IPv6 Fields                 |
	   ...                                                             ...
		|                                                               |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|(varLenFlag) |     Max Adver Int     |          Checksum       |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                                                               |
		+                                                               +
		|                       IPvX Address(es)                        |
		+                                                               +
		+                                                               +
		+                                                               +
		+                                                               +
		|                                                               |
		+                                                               +
		|                                                               |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	/**
	 * @struct vrrpv3_rsvd_adv
	 * VRRPv3 maximum advertisement
	 */
	struct vrrpv3_rsvd_adv {
		/** This specifies Maximum Advertisement Interval indicates the time interval (in centi-seconds) between ADVERTISEMENTS.   */
		uint16_t maxAdvInt;
	};

	/**
	 * @struct vrrp_packet
	 * VRRP packet
	 */
	struct vrrp_packet {
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** Type */
		uint8_t type: 4,

		/** Version bits */
		version: 4;
#else
		/** Version bits */
		uint8_t verson:4,

		/** Type */
		type: 4;
#endif
		/** The Virtual Router Identifier (VRID) field identifies the virtual router this packet is reporting status for*/
		uint8_t vrId;

		/** This specifies the sending VRRP router's priority for the virtual router */
		uint8_t priority;

		/** Specifies how many IPvX addresses are present in this Packet */
		uint8_t ipAddrCount;

		/** This specifies authentication type(v2) or (Max) Advertisement interval (in seconds(v2) or centi-seconds(v3)). */
		uint16_t authTypeAdvInt;

		/** This specifies checksum field that is used to detect data corruption in the VRRP message.
		 * VRRPv2 uses normal checksum algorithm, while VRRPv3 uses "pseudo-header" checksum algorithm. */
		uint16_t checksum;

		/** This specifies one or more IPvX addresses that are associated with the virtual router. */
		uint8_t *ipAddresses[];
	};

	/**
	 * VRRP versions
	 */
	enum VrrpVersion {
		/** VRRP version 2 */
		Vrrp_Version_2 = 2,

		/** VRRP version 3 */
		Vrrp_Version_3 = 3
	};

	/**
	 * VRRP message types
	 */
	enum VrrpType {
		/** VRRP advertisement packet */
		VrrpType_Advertisement = 1
	};

	/**
	 * @class VrrpLayer
	 * A base class for all VRRP (Virtual Router Redundancy Protocol) protocol classes. This is an abstract class and cannot be instantiated,
	 * only its child classes can be instantiated. The inherited classes represent the different versions of the protocol:
	 * VRRPv2 and VRRPv3
	 */
	class VrrpLayer : public Layer {
	private:
		/**
		* A method that add IP Addresses to data offset
		* @param ipAddresses [in] IP Address vector
		* @param offset [in] Data offset
		* @return true if add successfully, false otherwise.
		*/
		bool addIPAddressesAt(const std::vector<IPAddress> &ipAddresses, int offset);

		IPAddress::AddressType m_AddressType;

	protected:
		VrrpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet, ProtocolType vrrpVer,
				  IPAddress::AddressType addressType)
				: Layer(data, dataLen, prevLayer, packet) {
			m_Protocol = vrrpVer;
			m_AddressType = addressType;
		}

		/**
		 * A constructor that allocates a new VRRP
		 * @param[in] subProtocol The VRRP protocol
		 */
		explicit VrrpLayer(ProtocolType subProtocol);

	public:

		virtual ~VrrpLayer() {}

		/**
		* A method that get IP Address type
		* @return The VRRP IP Address type
		*/
		IPAddress::AddressType getAddressType() const;

		/**
		* A method that set IP Address type
		* @param addressType [in] IP Address type
		*/
		void setAddressType(IPAddress::AddressType addressType);

		/**
		 * A static method that validates the input data
		 * @param[in] data The VRRP raw data (byte stream)
		 * @param[in] dataLen The length of byte stream
		 * @return One of the values ::VRRPv2, ::VRRPv3 according to detected VRRP version or ::UnknownProtocol if couldn't detect
	 	 * VRRP version
		 */
		static ProtocolType getVersionFromData(uint8_t *data, size_t dataLen);

		/**
		 * Fill the checksum from header and data and possibly write the result to @ref vrrp_packet#checksum
		 */
		virtual void calculateAndSetChecksum() = 0;

		/**
		 * Calculate the checksum from header and data and possibly write the result to @ref vrrp_packet#checksum
		 * @return The checksum result
		 */
		virtual uint16_t calculateChecksum() const = 0;

		/**
		 * A method that validates the VRRP layer checksum
		 * @return True if the checksum is correct
		 */
		bool isChecksumCorrect() const;

		/**
		* Set packet to layer
		* @param[in] packet The packet to be attached
		* @return The VRRP authentication type description
		*/
		void setPacket(vrrp_packet *packet);

		/**
		* A method that gets type name
		* @return The VRRP type in this message
		*/
		std::string getTypeName() const;

		/**
		* A method that get priority description
		* @return The VRRP priority description
		*/
		std::string getPriorityDesc() const;

		/**
		* A virtual method to get authentication type description by version
		* @return The VRRP authentication type description
		*/
		virtual std::string getAuthTypeDesc() const = 0;

		/**
		* Get authentication type description
		* @param[in] authType The authentication type
		* @return The priority in this message
		*/
		static std::string getAuthTypeDescByType(uint8_t authType);

		/**
		 * Get a pointer to the raw VRRPv2/VRRPv3 header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref vrrp_packet
		 */
		vrrp_packet *getPacketPtr() const { return (vrrp_packet *) m_Data; }

		/**
		 * A method that gets length of virtual address
		 * @return Virtual IP address length
		 */
		uint8_t getIPAddressLen() const;

		/**
		 * A method that gets VRRP version
		 * @return VRRP version in this message.
		 * VRRP version
		 */
		uint8_t getVersionFromData() const;

		/**
		* A method that gets VRRP version
		* @return The version in this message
		*/
		uint8_t getVersion() const;

		/**
		 * A method that gets VRRP type
		 * @return VRRP type set in vrrp_packet#type as ::VrrpType enum.
		 */
		VrrpType getType() const;

		/**
		* A method that gets VRRP vrId
		* @return The virtual router id in this message
		*/
		uint8_t getVrId() const;

		/**
		* A method that gets VRRP priority
		* @return The priority in this message
		*/
		uint8_t getPriority() const;

		/**
		* A method that gets (maximum) VRRP advertisement interval
		* @return The (maximum) advertisement interval in this message
		*/
		virtual uint16_t getAdvInt() const = 0;

		/**
		* A method that gets VRRP checksum
		* @return The checksum in this message
		*/
		uint16_t getChecksum() const;

		/**
		 * A method that gets count of VRRP virtual IP addresses
		 * @return The count of virtual IP addresses in this message
		 */
		uint16_t getIPAddressesCount() const;

		/**
		 * A method that gets VRRP virtual IP addresses
		 * @return The virtual IP addresses in this message
		 */
		std::vector<IPAddress> getIPAddresses() const;

		/**
		 * A method that gets first VRRP virtual IP address
		 * @return A pointer to the first virtual IP address or NULL if no virtual IP address exist. Notice the return value is a pointer to the real data,
		 * so changes in the return value will affect the packet data
		 */
		uint8_t *getFirstIPAddress() const;

		/**
		 * Get the virtual IP address that comes next to a given virtual IP address. If "ipAddress" is NULL then NULL will be returned.
		 * If "ipAddress" is the last virtual IP address or if it is out of layer bounds NULL will be returned also. Notice the return value is a
		 * pointer to the real data casted to IPAddress type (as opposed to a copy of the option data). So changes in the return
		 * value will affect the packet data
		 * @param[in] ipAddress The virtual IP address to start searching from
		 * @return The next virtual IP address or NULL if "ipAddress" is NULL, last or out of layer bounds
		 */
		uint8_t *getNextIPAddress(uint8_t *ipAddress) const;

		/**
		 * Add virtual IP address at a the end of the virtual IP address list. The vrrp_packet#ipAddressCount field will be
		 * incremented accordingly
		 * @param[in] ipAddresses A vector containing all the virtual IP address
		 * @return true if add successfully, false otherwise.
		 */
		bool addIPAddresses(const std::vector<IPAddress> &ipAddresses);

		/**
		 * Add a new virtual IP address at a the end of the virtual IP address list. The vrrp_packet#ipAddressCount field will be
		 * incremented accordingly
		 * @param[in] ipAddress A vector containing all the virtual IP address
		 * @return true if add successfully, false otherwise.
		 */
		bool addIPAddress(IPAddress &ipAddress);

		/**
		 * Remove a virtual IP address at a certain index. The vrrp_packet#ipAddressCount field will be decremented accordingly
		 * @param[in] index The index of the virtual IP address to be removed
		 * @return True if virtual IP address was removed successfully or false otherwise. If false is returned an appropriate error message
		 * will be printed to log
		 */
		bool removeIPAddressAtIndex(int index);

		/**
		 * Remove all virtual IP addresses in the message. The vrrp_packet#ipAddressCount field will be set to 0
		 * @return True if virtual IP addresses were cleared successfully or false otherwise. If false is returned an appropriate error message
		 * will be printed to log
		 */
		bool removeAllIPAddresses();

		/**
		 * Copy IP address to data
		 * @param[in] data A data pointer
		 * @param[in] ipAddress IP address
		 */
		void copyIPAddressToData(uint8_t *data, const IPAddress &ipAddress) const;

		/**
		 * Get IP address from data
		 * @return true if get successfully, otherwise return false.
		 */
		bool getIPAddressFromData(uint8_t *data, IPAddress &ipAddress) const;

		/**
		 * Judge whether the IP address is valid
		 * @param[in] ipAddress IP address
		 * @return true if ipAddress is valid, otherwise return false.
		 */
		bool isIPAddressValid(IPAddress &ipAddress) const;

		/**
		 * Judge whether the packet is IPv4
		 * @return IPv4 address of VRRP packet
		 */
		uint8_t isIPv4Packet() const;

		/**
		 * Judge whether the packet is IPv6
		 * @return IPv6 address of VRRP packet
		 */
		uint8_t isIPv6Packet() const;

		// implement abstract methods

		/**
		 * Does nothing for this layer (VRRP layer is always last)
		 */
		void parseNextLayer() {}

		/**
		 * Calculate the VRRP checksum
		 */
		void computeCalculateFields();

		/**
		 * @return The message size in bytes which include the size of the basic header + the size of the IP address(es)
		 */
		size_t getHeaderLen() const { return m_DataLen; }

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }
	};

	/**
	 * @class VrrpV2Layer
	 * Represents VRRPv2 (Virtual Router Redundancy Protocol ver 2) layer. This class represents all the different messages of VRRPv2
	 */
	class VrrpV2Layer : public VrrpLayer {
	public:
		/** A constructor that creates the layer from an existing packet raw data
		* @param[in] data A pointer to the raw data
		* @param[in] dataLen Size of the data in bytes
		* @param[in] prevLayer A pointer to the previous layer
		* @param[in] packet A pointer to the Packet instance where layer will be stored in
		*/
		VrrpV2Layer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
				: VrrpLayer(data, dataLen, prevLayer, packet, VRRPv2, IPAddress::IPv4AddressType) {}

		/**
		 * A constructor that allocates a new VRRPv2
		 */
		VrrpV2Layer() : VrrpLayer(VRRPv2) { setAddressType(IPAddress::IPv4AddressType); };

		/**
		 * A destructor for this layer (does nothing)
		 */
		~VrrpV2Layer() {}

		// implement abstract methods

		/**
		* @return The VRRP authentication type description
		*/
		std::string getAuthTypeDesc() const;

		/**
		* A method that gets VRRP advertisement interval
		* @return The advertisement interval in this message
		*/
		uint16_t getAdvInt() const;

		/**
		* A method that gets VRRP authentication type
		* @return The authentication type in this message
		*/
		uint8_t getAuthType() const;

		/**
		* Calculate and set the checksum from header and data and possibly write the result to @ref vrrp_packet#checksum
		*/
		void calculateAndSetChecksum();

		/**
		* Calculate the checksum from header and data and possibly write the result to @ref vrrp_packet#checksum
		* @return The checksum result
		*/
		uint16_t calculateChecksum() const;
	};

	/**
	 * @class VrrpV3Layer
	 * Represents VRRPv3 (Virtual Router Redundancy Protocol ver 3) layer. This class represents all the different messages of VRRP
	 */
	class VrrpV3Layer : public VrrpLayer {
	public:
		/** A constructor that creates the layer from an existing packet raw data
		* @param[in] data A pointer to the raw data
		* @param[in] dataLen Size of the data in bytes
		* @param[in] prevLayer A pointer to the previous layer
		* @param[in] packet A pointer to the Packet instance where layer will be stored in
		*/
		VrrpV3Layer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet, IPAddress::AddressType addressType)
				: VrrpLayer(data, dataLen, prevLayer, packet, VRRPv3, addressType) {}

		/**
		 * @param[in] addressType IP version of virtual IP address
		 * A constructor that allocates a new VRRPv3
		 */
		explicit VrrpV3Layer(IPAddress::AddressType addressType) : VrrpLayer(
				VRRPv3) { setAddressType(addressType); };

		/**
		 * A destructor for this layer (does nothing)
		 */
		~VrrpV3Layer() {}

		// implement abstract methods


		/**
		 * A method that gets VRRP authentication type description
		* @return The VRRP authentication type description
		*/
		std::string getAuthTypeDesc() const;

		/**
		* A method that gets VRRP maximum advertisement interval
		* @return The maximum advertisement interval in this message
		*/
		uint16_t getAdvInt() const;

		/**
		* Fill the checksum from header and data and possibly write the result to @ref vrrp_packet#checksum
		*/
		void calculateAndSetChecksum();

		/**
		* Calculate the checksum from header and data and possibly write the result to @ref vrrp_packet#checksum
		* @return The checksum result
		*/
		uint16_t calculateChecksum() const;
	};
}

#endif // PACKETPP_VRRP_LAYER
