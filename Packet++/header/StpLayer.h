#ifndef PACKETPP_STP_LAYER
#define PACKETPP_STP_LAYER

#include "Layer.h"
#include "MacAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @struct stp_header
	 * Represents an Spanning Tree Protocol header
	 */
	#pragma pack(push, 1)
	struct stp_header
	{
		/// Destination MAC
		uint8_t dstMac[6];
		/// Source MAC
		uint8_t srcMac[6];
		/// Frame Length
		uint16_t frameLength;
		/// Logical Link Control (LLC) header
		uint8_t llcHeader[3];
	};
	#pragma pack(pop)

	/**
	 * @struct stp_conf_bpdu
	 * Represents payload configuration of BPDU for STP
	 */
	#pragma pack(push, 1)
	struct stp_conf_bpdu
	{
		/// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
		uint16_t protoId;
		/// Protocol version. 0x0 for STP
		uint8_t version;
		/// Type of the BPDU. 0x0 for configuration
		uint8_t type;
		/// Flag for indicate purpose of BPDU
		uint8_t flag;
		/// Root bridge ID
		uint64_t rootId;
		/// Cost of path
		uint32_t pathCost;
		/// Bridge ID
		uint64_t bridgeId;
		/// Port ID
		uint16_t portId;
		/// Age of the BPDU
		uint16_t msgAge;
		/// Maximum age of the BPDU
		uint16_t maxAge;
		/// BPDU transmission interval
		uint16_t helloTime;
		/// Delay for STP
		uint16_t forwardDelay;
	};
	#pragma pack(pop)

	/**
	 * @struct stp_tcn_bpdu
	 * Represents payload of network changes announcements of BPDU
	 */
	#pragma pack(push, 1)
	struct stp_tcn_bpdu
	{
		/// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
		uint16_t protoId;
		/// Protocol version. 0x0 for STP
		uint8_t version;
		/// Type of the BPDU. 0x80 for TCN
		uint8_t type;
	};
	#pragma pack(pop)

	/**
	 * @struct rstp_bpdu
	 * Represents payload configuration of BPDU for Rapid STP (RSTP)
	 */
	#pragma pack(push, 1)
	struct rstp_conf_bpdu
	{
		/// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
		uint16_t protoId;
		/// Protocol version. 0x2 for RSTP
		uint8_t version;
		/// Type of the BPDU. 0x2 for RSTP/MSTP
		uint8_t type;
		/// Flag for indicate purpose of BPDU
		uint8_t flag;
		/// Root bridge ID
		uint64_t rootId;
		/// Cost of path
		uint32_t pathCost;
		/// Bridge ID
		uint64_t bridgeId;
		/// Port ID
		uint16_t portId;
		/// Age of the BPDU
		uint16_t msgAge;
		/// Maximum age of the BPDU
		uint16_t maxAge;
		/// BPDU transmission interval
		uint16_t helloTime;
		/// Delay for STP
		uint16_t forwardDelay;
		/// Version1 length. The value is 0x0
		uint8_t version1Len;
	};
	#pragma pack(pop)

	/**
	 * @struct mstp_bpdu
	 * Represents payload configuration of BPDU for Multiple STP (MSTP)
	 */
	#pragma pack(push, 1)
	struct mstp_conf_bpdu
	{
		/// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
		uint16_t protoId;
		/// Protocol version. 0x3 for MSTP
		uint8_t version;
		/// Type of the BPDU. 0x2 for RSTP/MSTP
		uint8_t type;
		/// Flag for indicate purpose of BPDU
		uint8_t flag;
		/// Root bridge ID
		uint64_t rootId;
		/// Cost of path
		uint32_t pathCost;
		/// Bridge ID
		uint64_t bridgeId;
		/// Port ID
		uint16_t portId;
		/// Age of the BPDU
		uint16_t msgAge;
		/// Maximum age of the BPDU
		uint16_t maxAge;
		/// BPDU transmission interval
		uint16_t helloTime;
		/// Delay for STP
		uint16_t forwardDelay;
		/// Version1 length. The value is 0x0
		uint8_t version1Len;
		/// Version3 length.
		uint16_t version3Len;
		/// Configuration id format selector
		uint8_t mstConfigFormatSelector;
		/// Configuration id name
		uint8_t mstConfigName[32];
		/// Configuration id revision
		uint16_t mstConfigRevision;
		/// Configuration id digest
		uint8_t mstConfigDigest[16];
		/// CIST internal root path cost
		uint32_t irpc;
		/// CIST bridge id
		uint64_t bridgeId;
		/// CIST remaining hop count
		uint8_t remainId;
	};
	#pragma pack(pop)

	/**
	 * @struct msti_conf_msg
	 * Represents MSTI configuration messages. Each message contains 16 bytes and MSTP can contain 0 to 64 MSTI messages.
	 */
	#pragma pack(push, 1)
	struct msti_conf_msg
	{
		/// MSTI flags
		uint8_t flags;
		/// Regional root switching id
		uint64_t regionalRootId;
		/// Total path cost from local port to regional port
		uint32_t pathCost;
		/// Priority value of switching device
		uint8_t bridgePriority;
		/// Priority value of port
		uint8_t portPriority;
		/// Remaining hops of BPDU
		uint8_t remainingHops;
	};
	#pragma pack(pop)

	/**
	 * @class StpLayer
	 * Represents an Spanning Tree Protocol Layer
	 */
	class StpLayer : public Layer
	{
	protected:
		StpLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { }

	public:
		/// STP protocol uses "01:80:C2:00:00:00" multicast address as destination MAC
		static pcpp::MacAddress StpMulticastDstMAC;
		/// STP Uplink Fast protocol uses "01:00:0C:CD:CD:CD" as destination MAC
		static pcpp::MacAddress StpUplinkFastMulticastDstMAC;

		enum StpType
		{
			/// Not an STP packet
			NotSTP,
			/// Configuration BPDU
			ConfigurationBPDU,
			/// Network topology change BPDU
			TopologyChangeBPDU,
			/// Rapid Spanning Tree Protocol
			Rapid,
			/// Multiple Spanning Tree Protocol
			Multiple
			// TODO: Per VLAN Spanning Tree + (PVST+)
			// TODO: Rapid Per VLAN Spanning Tree + (RPVST+)
			// TODO: Cisco Uplink Fast
		};

		/**
		 * Get a pointer to STP header
		 * @return stp_header* A pointer to STP header
		 */
		stp_header *getStpHeader() const { return (stp_header*)m_Data; }

		/**
		 * Get the source MAC address
		 * @return The source MAC address
		 */
		MacAddress getSourceMac() const { return MacAddress(getStpHeader()->srcMac); }

		/**
		 * Get the destination MAC address
		 * @return The destination MAC address
		 */
		MacAddress getDestMac() const { return MacAddress(getStpHeader()->dstMac); }

		/**
		 * Get the frame length
		 * @return uint16_t The frame length
		 */
		uint16_t getFrameLength() const { return getStpHeader()->frameLength; }

		/**
		 * Get the Logical Link Control (LLC) header
		 * @return uint32_t The LLC header
		 */
		uint32_t getLLCHeader() const { return (uint32_t(getStpHeader()->llcHeader[0]) << 16) | (uint32_t(getStpHeader()->llcHeader[1]) << 8) | uint32_t(getStpHeader()->llcHeader[2]); }

		// overridden methods

		/// Parses the next layer. STP is the always last so does nothing for this layer
		void parseNextLayer() {}

		/// Does nothing for this layer
		void computeCalculateFields() {}

		/**
		 * @return The OSI layer level of STP (Data Link Layer).
		 */
		OsiModelLayer getOsiModelLayer() const { return OsiModelDataLinkLayer; }

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/**
		 * Get the type of Spanning Tree
		 * @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree packet
		 * @param[in] dataLen The length of the byte stream
		 * @return StpType Type of the Spanning Tree
		 */
		static StpType getStpType(const uint8_t* data, size_t dataLen);
	};

	/**
	 * @class StpConfigurationBPDULayer
	 * Represents configuration BPDU message of Spanning Tree Protocol
	 */
	class StpConfigurationBPDULayer : public StpLayer
	{
		private:
		public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StpConfigurationBPDULayer(uint8_t* data, size_t dataLen, Packet* packet) : StpLayer(data, dataLen, packet) { }
	
		// overridden methods
		
		/**
		 * @return Get the size of the STP Configuration BPDU header
		 */
		size_t getHeaderLen() const { return sizeof(rstp_conf_bpdu); }

		/**
         * @return Returns the protocol info as readable string
         */
        std::string toString() const;
	};

	/**
	 * @class StpTopologyChangeBPDULayer
	 * Represents network topology change BPDU message of Spanning Tree Protocol
	 */
	class StpTopologyChangeBPDULayer : public StpLayer
	{
		private:
		public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StpTopologyChangeBPDULayer(uint8_t* data, size_t dataLen, Packet* packet) : StpLayer(data, dataLen, packet) { }
	
		// overridden methods
		
		/**
		 * @return Get the size of the STP network topology change BPDU header
		 */
		size_t getHeaderLen() const { return sizeof(stp_tcn_bpdu); }

		/**
         * @return Returns the protocol info as readable string
         */
        std::string toString() const;
	};

	/**
	 * @class RapidStpLayer
	 * Represents Rapid Spanning Tree Protocol (RSTP)
	 */
	class RapidStpLayer : public StpLayer
	{
		private:
		public:
		
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		RapidStpLayer(uint8_t* data, size_t dataLen, Packet* packet) : StpLayer(data, dataLen, packet) { }

		// overridden methods
		
		/**
		 * @return Get the size of the RSTP header
		 */
		size_t getHeaderLen() const { return sizeof(rstp_conf_bpdu); }

		/**
         * @return Returns the protocol info as readable string
         */
        std::string toString() const;
	};

	/**
	 * @class MultipleStpLayer
	 * Represents Multiple Spanning Tree Protocol (MSTP)
	 */
	class MultipleStpLayer : public StpLayer
	{
		private:
		public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		MultipleStpLayer(uint8_t* data, size_t dataLen, Packet* packet) : StpLayer(data, dataLen, packet) { }

		// overridden methods
		
		/**
		 * @return Get the size of the MSTP header
		 */
		size_t getHeaderLen() const { return sizeof(mstp_conf_bpdu); }

		/**
         * @return Returns the protocol info as readable string
         */
        std::string toString() const;
	};
} // namespace pcpp

#endif /* PACKETPP_STP_LAYER */
