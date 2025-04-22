#pragma once

#include "Layer.h"
#include "MacAddress.h"
#include <cstring>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct stp_tcn_bpdu
	/// Represents payload of network changes announcements of BPDU
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
	static_assert(sizeof(stp_tcn_bpdu) == 4, "stp_tcn_bpdu size is not 4 bytes");

	/// Spanning Tree protocol common header
	typedef stp_tcn_bpdu stp_header;
	static_assert(sizeof(stp_header) == 4, "stp_header size is not 4 bytes");

	/// @struct stp_conf_bpdu
	/// Represents payload configuration of BPDU for STP
#pragma pack(push, 1)
	struct stp_conf_bpdu : stp_tcn_bpdu
	{
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
	static_assert(sizeof(stp_conf_bpdu) == 35, "stp_conf_bpdu size is not 35 bytes");

	/// @struct rstp_conf_bpdu
	/// Represents payload configuration of BPDU for Rapid STP (RSTP)
#pragma pack(push, 1)
	struct rstp_conf_bpdu : stp_conf_bpdu
	{
		/// Version1 length. The value is 0x0
		uint8_t version1Len;
	};
#pragma pack(pop)
	static_assert(sizeof(rstp_conf_bpdu) == 36, "rstp_conf_bpdu size is not 36 bytes");

	/// @struct mstp_conf_bpdu
	/// Represents payload configuration of BPDU for Multiple STP (MSTP)
#pragma pack(push, 1)
	struct mstp_conf_bpdu : rstp_conf_bpdu
	{
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
	static_assert(sizeof(mstp_conf_bpdu) == 102, "mstp_conf_bpdu size is not 102 bytes");

	/// @struct msti_conf_msg
	/// Represents MSTI configuration messages. Each message contains 16 bytes and MSTP can contain 0 to 64 MSTI
	/// messages.
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
	static_assert(sizeof(msti_conf_msg) == 16, "msti_conf_msg size is not 16 bytes");

	/// @class StpLayer
	/// Represents an Spanning Tree Protocol Layer
	class StpLayer : public Layer
	{
	protected:
		StpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, STP)
		{}

		explicit StpLayer(size_t dataLen)
		{
			m_DataLen = dataLen;
			m_Data = new uint8_t[dataLen];
			memset(m_Data, 0, dataLen);
			m_Protocol = STP;
		}

		static pcpp::MacAddress IDtoMacAddress(uint64_t id);
		static uint64_t macAddressToID(const pcpp::MacAddress& addr);

	public:
		/// STP protocol uses "01:80:C2:00:00:00" multicast address as destination MAC
		static pcpp::MacAddress StpMulticastDstMAC;
		/// STP Uplink Fast protocol uses "01:00:0C:CD:CD:CD" as destination MAC
		static pcpp::MacAddress StpUplinkFastMulticastDstMAC;

		/// Get a pointer to base Spanning tree header
		/// @return A pointer to spanning tree header
		stp_header* getStpHeader() const
		{
			return reinterpret_cast<stp_header*>(m_Data);
		}

		/// Returns the protocol id. Fixed at 0x0 for STP messages which represents IEEE 802.1d
		/// @return ID of the protocol
		uint16_t getProtoId() const
		{
			return getStpHeader()->protoId;
		}

		/// Sets the protocol id
		/// @param[in] value ID of the protocol

		void setProtoId(uint16_t value)
		{
			getStpHeader()->protoId = value;
		}

		/// Returns the version. Fixed at 0x0 for STP messages
		/// @return Version number
		uint8_t getVersion() const
		{
			return getStpHeader()->version;
		}

		/// Sets the version
		/// @param[in] value Version number
		void setVersion(uint8_t value)
		{
			getStpHeader()->version = value;
		}

		/// Returns the type of configuration message.
		/// @return Type of configuration message
		uint8_t getType() const
		{
			return getStpHeader()->type;
		}

		/// Sets the type of configuration message
		/// @param[in] value Type of configuration message
		void setType(uint8_t value)
		{
			getStpHeader()->type = value;
		}

		// overridden methods

		/// @return The size of STP packet
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// @return The OSI layer level of STP (Data Link Layer).
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an Spanning Tree packet
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// A method to create STP layer from existing packet
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored
		/// @return A newly allocated STP layer of one of the following types (according to the message type):
		/// StpConfigurationBPDULayer, StpTopologyChangeBPDULayer, RapidStpLayer, MultipleStpLayer
		static StpLayer* parseStpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	};

	/// @class StpTopologyChangeBPDULayer
	/// Represents network topology change BPDU message of Spanning Tree Protocol
	class StpTopologyChangeBPDULayer : public StpLayer
	{
	protected:
		explicit StpTopologyChangeBPDULayer(size_t dataLen) : StpLayer(dataLen)
		{}

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		StpTopologyChangeBPDULayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : StpLayer(data, dataLen, prevLayer, packet)
		{}

		/// Empty c'tor to create a new network topology change (TCN) BPDU layer.
		/// Initializes the protocol identifier, version and STP type fields with correct values
		StpTopologyChangeBPDULayer();

		/// Get a pointer to network topology change (TCN) BPDU message
		/// @return A pointer to TCN BPDU message
		stp_tcn_bpdu* getStpTcnHeader()
		{
			return getStpHeader();
		}

		// overridden methods

		/// @return The size of STP TCN message
		size_t getHeaderLen() const override
		{
			return sizeof(stp_tcn_bpdu);
		}

		/// Parses next layer
		void parseNextLayer() override;

		/// @return Returns the protocol info as readable string
		std::string toString() const override
		{
			return "Spanning Tree Topology Change Notification";
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree Topology Change BPDU
		/// packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an Spanning Tree packet
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return canReinterpretAs<stp_tcn_bpdu>(data, dataLen);
		}
	};

	/// @class StpConfigurationBPDULayer
	/// Represents configuration BPDU message of Spanning Tree Protocol
	class StpConfigurationBPDULayer : public StpTopologyChangeBPDULayer
	{
	protected:
		explicit StpConfigurationBPDULayer(size_t dataLen) : StpTopologyChangeBPDULayer(dataLen)
		{}

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		StpConfigurationBPDULayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : StpTopologyChangeBPDULayer(data, dataLen, prevLayer, packet)
		{}

		/// Empty c'tor to create a new configuration BPDU layer.
		/// Initializes the protocol identifier, version and STP type fields with correct values
		StpConfigurationBPDULayer();

		/// Get a pointer to configuration BPDU message
		/// @return A pointer to configuration BPDU message
		stp_conf_bpdu* getStpConfHeader() const
		{
			return reinterpret_cast<stp_conf_bpdu*>(m_Data);
		}

		/// Returns the flags of configuration message which indicates purpose of BPDU
		/// @return Flags of the configuration message
		uint8_t getFlag() const
		{
			return getStpConfHeader()->flag;
		}

		/// Returns the flags of configuration message which indicates purpose of BPDU
		/// @param[in] value Flags of the configuration message
		void setFlag(uint8_t value)
		{
			getStpConfHeader()->flag = value;
		}

		/// Returns the root bridge identifier
		/// @return Root bridge identifier
		uint64_t getRootId() const;

		/// Sets the root bridge identifier
		/// @param[in] value Root bridge identifier
		void setRootId(uint64_t value);

		/// Returns the priority of root bridge
		/// @return Priority of root bridge
		uint16_t getRootPriority() const;

		/// Sets the priority of root bridge
		/// @param[in] value Priority of root bridge
		void setRootPriority(uint16_t value);

		/// Returns the system identifier extension of root bridge
		/// @return System extension of root bridge
		uint16_t getRootSystemIDExtension() const;

		/// Sets the system identifier extension of root bridge
		/// @param[in] value System extension of root bridge
		void setRootSystemIDExtension(uint16_t value);

		/// Returns the system identifier of root bridge
		/// @return System identifier of root bridge
		pcpp::MacAddress getRootSystemID() const
		{
			return IDtoMacAddress(getRootId());
		}

		/// Sets the system identifier of root bridge
		/// @param[in] value System identifier of root bridge
		void setRootSystemID(const pcpp::MacAddress& value);

		/// Returns the value of the cost of path
		/// @return Cost of path
		uint32_t getPathCost() const;

		/// Sets the value of the cost of path
		/// @param[in] value Cost of path
		void setPathCost(uint32_t value);

		/// Returns the bridge identifier
		/// @return Bridge identifier
		uint64_t getBridgeId() const;

		/// Sets the bridge identifier
		/// @param[in] value Bridge identifier
		void setBridgeId(uint64_t value);

		/// Returns the priority of bridge
		/// @return Priority of bridge
		uint16_t getBridgePriority() const;

		/// Sets the priority of bridge
		/// @param[in] value Priority of bridge
		void setBridgePriority(uint16_t value);

		/// Returns the system identifier extension of bridge
		/// @return System extension of bridge
		uint16_t getBridgeSystemIDExtension() const;

		/// Sets the system identifier extension of bridge
		/// @param[in] value System extension of bridge
		void setBridgeSystemIDExtension(uint16_t value);

		/// Returns the system identifier of bridge
		/// @return System identifier of bridge
		pcpp::MacAddress getBridgeSystemID() const
		{
			return IDtoMacAddress(getBridgeId());
		}

		/// Sets the system identifier of bridge
		/// @param[in] value System identifier of bridge
		void setBridgeSystemID(const pcpp::MacAddress& value);

		/// Returns the port identifier
		/// @return Port identifier
		uint16_t getPortId() const;

		/// Sets the port identifier
		/// @param[in] value Port identifier
		void setPortId(uint16_t value);

		/// Returns age of the BPDU message
		/// @return Age of BPDU in seconds
		double getMessageAge() const;

		/// Sets age of the BPDU message
		/// @param[in] value Age of BPDU in seconds
		void setMessageAge(double value);

		/// Returns maximum age of the BPDU message
		/// @return Maximum age of BPDU in seconds
		double getMaximumAge() const;

		/// Sets maximum age of the BPDU message
		/// @param[in] value Maximum age of BPDU in seconds
		void setMaximumAge(double value);

		/// Returns the BPDU transmission interval
		/// @return Value of the transmission interval in seconds
		double getTransmissionInterval() const;

		/// Sets the BPDU transmission interval
		/// @param[in] value Value of the transmission interval in seconds
		void setTransmissionInterval(double value);

		/// Returns the delay for STP message
		/// @return Value of the forward delay in seconds
		double getForwardDelay() const;

		/// Sets the delay for STP message
		/// @param[in] value Value of the forward delay in seconds
		void setForwardDelay(double value);

		// overridden methods

		/// @return The size of STP configuration BPDU message
		size_t getHeaderLen() const override
		{
			return sizeof(stp_conf_bpdu);
		}

		/// Parses next layer
		void parseNextLayer() override;

		/// @return Returns the protocol info as readable string
		std::string toString() const override
		{
			return "Spanning Tree Configuration";
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree Configuration BPDU packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an Spanning Tree packet
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return canReinterpretAs<stp_conf_bpdu>(data, dataLen);
		}
	};

	/// @class RapidStpLayer
	/// Represents Rapid Spanning Tree Protocol (RSTP)
	class RapidStpLayer : public StpConfigurationBPDULayer
	{
	protected:
		explicit RapidStpLayer(size_t dataLen) : StpConfigurationBPDULayer(dataLen)
		{}

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		RapidStpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : StpConfigurationBPDULayer(data, dataLen, prevLayer, packet)
		{}

		/// Empty c'tor to create a new Rapid STP layer.
		/// Initializes the protocol identifier, version and STP type fields with correct values
		RapidStpLayer();

		/// Get a pointer to Rapid STP header
		/// @return A pointer to Rapid STP header
		rstp_conf_bpdu* getRstpConfHeader() const
		{
			return reinterpret_cast<rstp_conf_bpdu*>(m_Data);
		}

		/// Returns the length of version1 field. Fixed at 0x0 for Rapid STP
		/// @return Length of the version1 field
		uint8_t getVersion1Len() const
		{
			return getRstpConfHeader()->version1Len;
		}

		/// Returns the length of version1 field
		/// @param[in] value Length of the version1 field
		void setVersion1Len(uint8_t value)
		{
			getRstpConfHeader()->version1Len = value;
		}

		// overridden methods

		/// @return The size of Rapid STP message
		size_t getHeaderLen() const override
		{
			return sizeof(rstp_conf_bpdu);
		}

		/// Parses next layer
		void parseNextLayer() override;

		/// @return Returns the protocol info as readable string
		std::string toString() const override
		{
			return "Rapid Spanning Tree";
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an Rapid STP packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an Spanning Tree packet
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return canReinterpretAs<rstp_conf_bpdu>(data, dataLen);
		}
	};

	/// @class MultipleStpLayer
	/// Represents Multiple Spanning Tree Protocol (MSTP). It has limited capabilities (no crafting / limited editing)
	/// over MSTI configuration
	class MultipleStpLayer : public RapidStpLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		MultipleStpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : RapidStpLayer(data, dataLen, prevLayer, packet)
		{}

		/// Empty c'tor to create a new Multiple STP layer.
		/// Initializes the protocol identifier, version and STP type fields with correct values
		MultipleStpLayer();

		/// Get a pointer to Multiple STP header
		/// @return A pointer to Multiple STP header
		mstp_conf_bpdu* getMstpHeader() const
		{
			return reinterpret_cast<mstp_conf_bpdu*>(m_Data);
		}

		/// @return Length of version3 field
		uint16_t getVersion3Len() const;

		/// Sets the length of version3 field
		/// @param[in] value Length of version3 field
		void setVersion3Len(uint16_t value);

		/// Returns the configuration ID format selector
		/// @return Configuration ID of format selector
		uint8_t getMstConfigurationFormatSelector() const
		{
			return getMstpHeader()->mstConfigFormatSelector;
		}

		/// Sets the configuration ID format selector
		/// @param[in] value Configuration ID of format selector
		void setMstConfigurationFormatSelector(uint8_t value)
		{
			getMstpHeader()->mstConfigFormatSelector = value;
		}

		/// Returns the pointer to configuration name field
		/// @return Configuration name
		std::string getMstConfigurationName() const;

		/// Sets the configuration name field
		/// @param[in] value Configuration name. Length should be less than 32, if longer value provided first 32
		/// characters are used
		void setMstConfigurationName(const std::string& value);

		/// Returns the revision of configuration ID
		/// @return Revision of configuration ID
		uint16_t getMstConfigRevision() const;

		/// Sets the revision of configuration ID
		/// @param[in] value Revision of configuration ID
		void setMstConfigRevision(uint16_t value);

		/// Returns the pointer to configuration message digest. The field itself always 16 bytes long.
		/// @return A pointer to configuration digest
		uint8_t* getMstConfigDigest() const
		{
			return getMstpHeader()->mstConfigDigest;
		}

		/// Sets the pointer to configuration message digest. The field itself always 16 bytes long.
		/// @param[in] value Pointer to digest
		/// @param[in] len Length of the digest, should be less than 16. If longer first 16 bytes are used
		void setMstConfigDigest(const uint8_t* value, uint8_t len);

		/// Returns CIST internal root path cost
		/// @return Value of the internal root path cost
		uint32_t getCISTIrpc() const;

		/// Sets CIST internal root path cost
		/// @param[in] value Value of the internal root path cost
		void setCISTIrpc(uint32_t value);

		/// Returns CIST bridge identifier
		/// @return Value of the bridge identifier
		uint64_t getCISTBridgeId() const;

		/// Sets CIST bridge identifier
		/// @param[in] value Value of the bridge identifier
		void setCISTBridgeId(uint64_t value);

		/// Returns the priority of CIST bridge
		/// @return Priority of CIST bridge
		uint16_t getCISTBridgePriority() const;

		/// Sets the priority of CIST bridge
		/// @param[in] value Priority of CIST bridge
		void setCISTBridgePriority(uint16_t value);

		/// Returns the system identifier extension of CIST bridge
		/// @return System extension of CIST bridge
		uint16_t getCISTBridgeSystemIDExtension() const;

		/// Sets the system identifier extension of CIST bridge
		/// @param[in] value System extension of CIST bridge
		void setCISTBridgeSystemIDExtension(uint16_t value);

		/// Returns the system identifier of CIST bridge
		/// @return System identifier of CIST bridge
		pcpp::MacAddress getCISTBridgeSystemID() const
		{
			return IDtoMacAddress(getCISTBridgeId());
		}

		/// Sets the system identifier of CIST bridge
		/// @param[in] value System identifier of CIST bridge
		void setCISTBridgeSystemID(const pcpp::MacAddress& value);

		/// Returns the remaining hop count
		/// @return Value of remaining hop count
		uint8_t getRemainingHopCount() const
		{
			return getMstpHeader()->remainId;
		}

		/// Returns the remaining hop count
		/// @param[in] value Value of remaining hop count
		void setRemainingHopCount(uint8_t value)
		{
			getMstpHeader()->remainId = value;
		}

		/// Returns the total number of MSTI configuration messages
		/// @return Number of MSTI configuration messages. Can be between 0 and 64.
		uint8_t getNumberOfMSTIConfMessages() const
		{
			return (getVersion3Len() - (sizeof(mstp_conf_bpdu) - sizeof(rstp_conf_bpdu) - sizeof(uint16_t))) /
			       sizeof(msti_conf_msg);
		}

		/// Returns a reference to MSTI configuration messages. An MSTP packet can contain between 0 to 64 MSTI
		/// messages. The number of messages can be obtained by using getNumberOfMSTIConfMessages()
		/// @return An array pointer to MSTI configuration messages. Returns nullptr if there is no MSTI message.
		msti_conf_msg* getMstiConfMessages() const;

		// overridden methods

		/// Parses next layer
		void parseNextLayer() override
		{}

		/// @return Returns the protocol info as readable string
		std::string toString() const override
		{
			return "Multiple Spanning Tree";
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an Multiple STP packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an Spanning Tree packet
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return canReinterpretAs<mstp_conf_bpdu>(data, dataLen);
		}
	};
}  // namespace pcpp
