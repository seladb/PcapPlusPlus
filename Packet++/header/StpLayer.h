#ifndef PACKETPP_STP_LAYER
#define PACKETPP_STP_LAYER

#include "EndianPortable.h"
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
 * @struct stp_tcn_bpdu
 * Represents payload of network changes announcements of BPDU
 */
#pragma pack(push, 1)
	struct stp_tcn_bpdu
	{
		/// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
		uint16_t protoId;
		/// Protocol version. 0x0 for STP, 0x2 for RSTP, 0x3 for MSTP
		uint8_t version;
		/// Type of the BPDU. 0x0 for configuration, 0x2 for RSTP/MSTP, 0x80 for TCN
		uint8_t type;
	};
#pragma pack(pop)

/// Spanning Tree protocol common header
typedef stp_tcn_bpdu stp_header;

/**
 * @struct stp_conf_bpdu
 * Represents payload configuration of BPDU for STP
 */
#pragma pack(push, 1)
	struct stp_conf_bpdu
	{
		/// Common TCN header
		struct stp_tcn_bpdu tcn_header;
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
 * @struct rstp_conf_bpdu
 * Represents payload configuration of BPDU for Rapid STP (RSTP)
 */
#pragma pack(push, 1)
	struct rstp_conf_bpdu
	{
		/// Common Configuration BPDU header
		struct stp_conf_bpdu conf_header;
		/// Version1 length. The value is 0x0
		uint8_t version1Len;
	};
#pragma pack(pop)

/**
 * @struct mstp_conf_bpdu
 * Represents payload configuration of BPDU for Multiple STP (MSTP)
 */
#pragma pack(push, 1)
	struct mstp_conf_bpdu
	{
		/// Common Rapid STP header
		struct rstp_conf_bpdu rstp_header;
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
		uint64_t cistBridgeId;
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
		/// Regional root switching id (Priority (4 bits) + ID (12 bits) + Regional root (48 bits - MAC address))
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
		StpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: Layer(data, dataLen, prevLayer, packet)
		{
			m_Protocol = STP;
		}

		static pcpp::MacAddress IDtoMacAddress(uint64_t id);

	  public:
		/// STP protocol uses "01:80:C2:00:00:00" multicast address as destination MAC
		static pcpp::MacAddress StpMulticastDstMAC;
		/// STP Uplink Fast protocol uses "01:00:0C:CD:CD:CD" as destination MAC
		static pcpp::MacAddress StpUplinkFastMulticastDstMAC;

		/**
		 * Get a pointer to base Spanning tree header
		 * @return stp_header* A pointer to spanning tree header
		 */
		inline stp_header *getStpHeader() const { return (stp_header *)(m_Data); }

		/**
		 * Returns the protocol id. Fixed at 0x0 for STP messages which represents IEEE 802.1d
		 * @return uint16_t ID of the protocol
		 */
		inline uint16_t getProtoId() const { return getStpHeader()->protoId; }

		/**
		 * Returns the version. Fixed at 0x0 for STP messages
		 * @return uint8_t Version number
		 */
		inline uint8_t getVersion() const { return getStpHeader()->version; }

		/**
		 * Returns the type of configuration message.
		 * @return uint8_t Type of configuration message
		 */
		inline uint8_t getType() const { return getStpHeader()->type; }

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
		static bool isDataValid(const uint8_t *data, size_t dataLen);

		/**
		 * A method to create STP layer from existing packet
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return StpLayer* A newly allocated STP layer of one of the following types (according to the message type):
		 * StpConfigurationBPDULayer, StpTopologyChangeBPDULayer, RapidStpLayer, MultipleStpLayer
		 */
		static StpLayer *parseStpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);
	};

	/**
	 * @class StpTopologyChangeBPDULayer
	 * Represents network topology change BPDU message of Spanning Tree Protocol
	 */
	class StpTopologyChangeBPDULayer : public StpLayer
	{
	  public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StpTopologyChangeBPDULayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: StpLayer(data, dataLen, prevLayer, packet)
		{
		}

		/**
		 * Get a pointer to network topology change (TCN) BPDU message
		 * @return stp_tcn_bpdu* A pointer to TCN BPDU message
		 */
		inline stp_tcn_bpdu* getStpTcnHeader() { return getStpHeader(); }

		// overridden methods

		/**
		 * @return Get the size of the STP network topology change BPDU header
		 */
		size_t getHeaderLen() const { return sizeof(stp_tcn_bpdu); }

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const { return "Spanning Tree Topology Change Notification"; }

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree Topology Change BPDU packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t *data, size_t dataLen) { return data && dataLen >= sizeof(stp_tcn_bpdu); }
	};

	/**
	 * @class StpConfigurationBPDULayer
	 * Represents configuration BPDU message of Spanning Tree Protocol
	 */
	class StpConfigurationBPDULayer : public StpTopologyChangeBPDULayer
	{
	  public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StpConfigurationBPDULayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: StpTopologyChangeBPDULayer(data, dataLen, prevLayer, packet)
		{
		}

		/**
		 * Get a pointer to configuration BPDU message
		 * @return stp_conf_bpdu* A pointer to configuration BPDU message
		 */
		inline stp_conf_bpdu *getStpConfHeader() const { return (stp_conf_bpdu *)(m_Data); }

		/**
		 * Returns the flags of configuration message which indicates purpose of BPDU
		 * @return uint8_t Flags of the configuration message
		 */
		inline uint8_t getFlag() const { return getStpConfHeader()->flag; }

		/**
		 * Returns the root bridge identifier
		 * @return uint64_t root bridge identifier
		 */
		inline uint64_t getRootId() const { return be64toh(getStpConfHeader()->rootId); }

		/**
		 * Returns the priority of root bridge
		 * @return uint16_t Priority of root bridge
		 */
		inline uint16_t getRootPriority() const { return be16toh(getStpConfHeader()->rootId) & 0xf000; }

		/**
		 * Returns the system identifier extension of root bridge
		 * @return uint16_t System extension of root bridge
		 */
		inline uint16_t getRootSystemIDExtension() const { return be16toh(getStpConfHeader()->rootId) & 0x0fff; }

		/**
		 * Returns the system identifier of root bridge
		 * @return pcpp::MacAddress System identifier of root bridge
		 */
		inline pcpp::MacAddress getRootSystemID() const { return IDtoMacAddress(getRootId()); }

		/**
		 * Returns the value of the cost of path
		 * @return uint32_t Cost of path
		 */
		inline uint32_t getPathCost() const { return be32toh(getStpConfHeader()->pathCost); }

		/**
		 * Returns the bridge identifier
		 * @return uint64_t Bridge identifier
		 */
		inline uint64_t getBridgeId() const { return be64toh(getStpConfHeader()->bridgeId); }

		/**
		 * Returns the priority of bridge
		 * @return uint16_t Priority of bridge
		 */
		inline uint16_t getBridgePriority() const { return be16toh(getStpConfHeader()->bridgeId) & 0xf000; }

		/**
		 * Returns the system identifier extension of bridge
		 * @return uint16_t System extension of bridge
		 */
		inline uint16_t getBridgeSystemIDExtension() const { return be16toh(getStpConfHeader()->bridgeId) & 0x0fff; }

		/**
		 * Returns the system identifier of bridge
		 * @return pcpp::MacAddress System identifier of bridge
		 */
		inline pcpp::MacAddress getBridgeSystemID() const { return IDtoMacAddress(getBridgeId()); }

		/**
		 * Returns the port identifier
		 * @return uint16_t Port identifier
		 */
		inline uint16_t getPortId() const { return be16toh(getStpConfHeader()->portId); }

		/**
		 * Returns age of the BPDU message
		 * @return double Age of BPDU
		 */
		inline double getMessageAge() const { return be16toh(getStpConfHeader()->msgAge) / 256.0; }

		/**
		 * Returns maximum age of the BPDU message
		 * @return double Maximum age of BPDU
		 */
		inline double getMaximumAge() const { return be16toh(getStpConfHeader()->maxAge) / 256.0; }

		/**
		 * Returns the BPDU transmission interval
		 * @return double Value of the transmission interval
		 */
		inline double getTransmissionInterval() const { return be16toh(getStpConfHeader()->helloTime) / 256.0; }

		/**
		 * Returns the delay for STP message
		 * @return double Value of the forward delay
		 */
		inline double getForwardDelay() const { return be16toh(getStpConfHeader()->forwardDelay) / 256.0; }

		// overridden methods

		/**
		 * @return Get the size of the STP Configuration BPDU header
		 */
		size_t getHeaderLen() const { return sizeof(stp_conf_bpdu); }

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const { return "Spanning Tree Configuration"; }

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree Configuration BPDU packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t *data, size_t dataLen)
		{
			return data && dataLen >= sizeof(stp_conf_bpdu);
		}
	};

	/**
	 * @class RapidStpLayer
	 * Represents Rapid Spanning Tree Protocol (RSTP)
	 */
	class RapidStpLayer : public StpConfigurationBPDULayer
	{
	  public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		RapidStpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: StpConfigurationBPDULayer(data, dataLen, prevLayer, packet)
		{
		}

		/**
		 * Get a pointer to Rapid STP header
		 * @return rstp_conf_bpdu* A pointer to Rapid STP header
		 */
		inline rstp_conf_bpdu *getRstpConfHeader() const { return (rstp_conf_bpdu *)(m_Data); }

		/**
		 * Returns the length of version1 field. Fixed at 0x0 for Rapid STP
		 * @return uint8_t Length of the version1 field
		 */
		inline uint8_t getVersion1Len() const { return getRstpConfHeader()->version1Len; }

		// overridden methods

		/**
		 * @return Get the size of the RSTP header
		 */
		size_t getHeaderLen() const { return sizeof(rstp_conf_bpdu); }

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const { return "Rapid Spanning Tree"; }

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Rapid STP packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t *data, size_t dataLen)
		{
			return data && dataLen >= sizeof(rstp_conf_bpdu);
		}
	};

	/**
	 * @class MultipleStpLayer
	 * Represents Multiple Spanning Tree Protocol (MSTP)
	 */
	class MultipleStpLayer : public RapidStpLayer
	{
	  public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		MultipleStpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: RapidStpLayer(data, dataLen, prevLayer, packet)
		{
		}

		/**
		 * Get a pointer to Multiple STP header
		 * @return mstp_conf_bpdu* A pointer to Multiple STP header
		 */
		inline mstp_conf_bpdu *getMstpHeader() const { return (mstp_conf_bpdu *)(m_Data); }

		/**
		 * Returns the length of version3 field.
		 * @return uint16_t
		 */
		inline uint16_t getVersion3Len() const { return be16toh(getMstpHeader()->version3Len); }

		/**
		 * Returns the configuration ID format selector
		 * @return uint8_t Configuration ID of format selector
		 */
		inline uint8_t getMstConfigurationFormatSelector() const { return getMstpHeader()->mstConfigFormatSelector; }

		/**
		 * Returns the pointer to configuration name field.
		 * @return std::string Configuration name
		 */
		std::string getMstConfigurationName() const;

		/**
		 * Returns the revision of configuration ID
		 * @return uint16_t Revision of configuration ID
		 */
		inline uint16_t getMstConfigRevision() const { return getMstpHeader()->mstConfigRevision; }

		/**
		 * Returns the pointer to configuration message digest. The field itself always 16 bytes long.
		 * @return uint8_t* A pointer to configuration digest
		 */
		inline uint8_t *getMstConfigDigest() const { return getMstpHeader()->mstConfigDigest; }

		/**
		 * Returns CIST internal root path cost
		 * @return uint32_t Value of the internal root path cost
		 */
		inline uint32_t getCISTIrpc() const { return be32toh(getMstpHeader()->irpc); }

		/**
		 * Returns CIST bridge identifier
		 * @return uint64_t Value of the bridge identifier
		 */
		inline uint64_t getCISTBridgeId() const { return be64toh(getMstpHeader()->cistBridgeId); }

		/**
		 * Returns the priority of CIST bridge
		 * @return uint16_t Priority of CIST bridge
		 */
		inline uint16_t getCISTBridgePriority() const { return be16toh(getMstpHeader()->cistBridgeId) & 0xf000; }

		/**
		 * Returns the system identifier extension of CIST bridge
		 * @return uint16_t System extension of CIST bridge
		 */
		inline uint16_t getCISTBridgeSystemIDExtension() const
		{
			return be16toh(getMstpHeader()->cistBridgeId) & 0x0fff;
		}

		/**
		 * Returns the system identifier of CIST bridge
		 * @return pcpp::MacAddress System identifier of CIST bridge
		 */
		inline pcpp::MacAddress getCISTBridgeSystemID() const { return IDtoMacAddress(getCISTBridgeId()); }

		/**
		 * Returns the remaining hop count
		 * @return uint8_t Value of remaining hop count
		 */
		inline uint8_t getRemainingHopCount() const { return getMstpHeader()->remainId; }

		/**
		 * Returns the total number of MSTI configuration messages
		 * @return uint8_t Number of MSTI configuration messages. Can be between 0 and 64.
		 */
		inline uint8_t getNumberOfMSTIConfMessages() const { return (getVersion3Len() - 64) / sizeof(msti_conf_msg); }

		/**
		 * Returns a reference to MSTI configuration messages. An MSTP packet can contain between 0 to 64 MSTI messages.
		 * The number of messages can be obtained by using getNumberOfMSTIConfMessages()
		 * @return msti_conf_msg* An array pointer to MSTI configuration messages. Returns NULL if there is no MSTI
		 * message.
		 */
		msti_conf_msg *getMstiConfMessages() const;

		// overridden methods

		/**
		 * @return Get the size of the MSTP header
		 */
		size_t getHeaderLen() const { return sizeof(mstp_conf_bpdu); }

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const { return "Multiple Spanning Tree"; }

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Multiple STP packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t *data, size_t dataLen)
		{
			return data && dataLen >= sizeof(mstp_conf_bpdu);
		}
	};
} // namespace pcpp

#endif /* PACKETPP_STP_LAYER */
