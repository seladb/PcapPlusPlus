#ifndef PACKETPP_NDP_LAYER
#define PACKETPP_NDP_LAYER

#include "IcmpV6Layer.h"
#include "IpAddress.h"
#include "Layer.h"
#include "MacAddress.h"
#include "TLVData.h"

#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * An enum representing the available option types for Neighbor Discovery in IPv6 (see RFC 4861)
 */
enum class NDPNeighborOptionTypes : int
{
	NDP_OPTION_SOURCE_LINK_LAYER = 1,
	NDP_OPTION_TARGET_LINK_LAYER = 2,
	NDP_OPTION_PREFIX_INFORMATION = 3,
	NDP_OPTION_REDIRECTED_HEADER = 4,
	NDP_OPTION_MTU = 5,
	NDP_OPTION_UNKNOWN = 255
};

/**
 * @class NdpOption
 * A wrapper class for NDP options. This class does not create or modify NDP option records, but rather
 * serves as a wrapper and provides useful methods for retrieving data from them
 */
class NdpOption : public TLVRecord<uint8_t, uint8_t>
{
public:
	/**
	 * A c'tor for this class that gets a pointer to the option raw data (byte array)
	 * @param[in] optionRawData A pointer to the NDP option raw data
	 */
	NdpOption(uint8_t *optionRawData) : TLVRecord(optionRawData) {}

	/**
	 * A d'tor for this class, currently does nothing
	 */
	~NdpOption() {}

	/**
	 * @return NDP option type casted as pcpp::NDPNeighborOptionTypes enum. If the data is null a value
	 * of NDP_OPTION_UNKNOWN is returned
	 */
	NDPNeighborOptionTypes getNdpOptionType() const
	{
		if (m_Data == NULL)
			return NDPNeighborOptionTypes::NDP_OPTION_UNKNOWN;

		return static_cast<NDPNeighborOptionTypes>(m_Data->recordType);
	}

	// implement abstract methods

	size_t getTotalSize() const
	{
		if (m_Data == NULL)
			return (size_t)0;

		return (size_t)m_Data->recordLen * 8;
	}

	size_t getDataSize() const
	{
		if (m_Data == NULL)
			return 0;

		return (size_t)m_Data->recordLen * 8 - (2 * sizeof(uint8_t)); // length value is stored in units of 8 octets
	}
};

/**
 * @class NdpOptionBuilder
 * A class for building NDP option records. This builder receives the NDP option parameters in its c'tor,
 * builds the NDP option raw buffer and provides a build() method to get a NdpOption object out of it
 */
class NdpOptionBuilder : public TLVRecordBuilder
{
public:
	/**
	 * A c'tor for building NDP options which their value is a byte array. The NdpOption object can be later
	 * retrieved by calling build(). Each option is padded to have a 64-bit boundary.
	 * @param[in] optionType NDP option type
	 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in any
	 * way.
	 * @param[in] optionValueLen Option value length in bytes
	 */
	NdpOptionBuilder(NDPNeighborOptionTypes optionType, const uint8_t *optionValue, uint8_t optionValueLen)
		: TLVRecordBuilder((uint8_t)optionType, optionValue, optionValueLen) {}

	/**
	 * Build the NdpOption object out of the parameters defined in the c'tor. Padding bytes are added to the
	 * option for option length with 64-bit boundaries.
	 * @return The NdpOption object
	 */
	NdpOption build() const;
};

/**
 * @class NDPLayerBase
 * Represents a base for NDP packet types
 */
class NDPLayerBase : public IcmpV6Layer
{
public:
	virtual ~NDPLayerBase() {}

	/**
	 * @return The number of NDP options in this layer
	 */
	size_t getNdpOptionCount() const;

	/**
	 * Get a NDP option by type.
	 * @param[in] option NDP option type
	 * @return An NdpOption object that contains the first option that matches this type, or logical NULL
	 * (NdpOption#isNull() == true) if no such option found
	 */
	NdpOption getNdpOption(NDPNeighborOptionTypes option) const;

	/**
	 * @return The first NDP option in the packet. If the current layer contains no options the returned value will
	 * contain a logical NULL (NdpOption#isNull() == true)
	 */
	NdpOption getFirstNdpOption() const;

	/**
	 * Get the NDP option that comes after a given option. If the given option was the last one, the
	 * returned value will contain a logical NULL (IdpOption#isNull() == true)
	 * @param[in] option An NDP option object that exists in the current layer
	 * @return A NdpOption object that contains the NDP option data that comes next, or logical NULL if the given
	 * NDP option: (1) was the last one; or (2) contains a logical NULL; or (3) doesn't belong to this packet
	 */
	NdpOption getNextNdpOption(NdpOption &option) const;

	/**
	 * Add a new NDP option at the end of the layer (after the last NDP option)
	 * @param[in] optionBuilder An NdpOptionBuilder object that contains the NDP option data to be added
	 * @return A NdpOption object that contains the newly added NDP option data or logical NULL
	 * (NdpOption#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
	 * printed to log
	 */
	NdpOption addNdpOption(const NdpOptionBuilder &optionBuilder);

	/**
	 * Remove all NDP options from the layer
	 * @return True if options removed successfully or false if some error occurred (an appropriate error message will
	 * be printed to log)
	 */
	bool removeAllNdpOptions();

protected:
	NDPLayerBase() = default;

	NDPLayerBase(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: IcmpV6Layer(data, dataLen, prevLayer, packet)	{}

private:
	TLVRecordReader<NdpOption> m_OptionReader;

	virtual size_t getNdpHeaderLen() const = 0;
	virtual uint8_t *getNdpOptionsBasePtr() const { return m_Data + getNdpHeaderLen(); };
	NdpOption addNdpOptionAt(const NdpOptionBuilder &optionBuilder, int offset);
};

/**
 * @class NDPNeighborSolicitationLayer
 * Represents a NDP Neighbor Solicitation protocol layer
 */
class NDPNeighborSolicitationLayer : public NDPLayerBase
{
public:
	/**
	 * @struct ndpneighborsolicitationhdr
	 * Represents neighbor solicitation message format
	 */
#pragma pack(push, 1)
	struct ndpneighborsolicitationhdr : icmpv6hdr
	{
		/** Reserved */
		uint32_t reserved;
		/** Target address - Target address of solicitation message */
		uint8_t targetIP[16];
	};
#pragma pack(pop)

	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	NDPNeighborSolicitationLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: NDPLayerBase(data, dataLen, prevLayer, packet) {}

	/**
	 * A constructor for a new NDPNeighborSolicitationLayer object
	 * @param[in] code Code field
	 * @param[in] targetIP Target IP address for which the solicitation shall be created
	 */
	NDPNeighborSolicitationLayer(uint8_t code, const IPv6Address &targetIP);

	/**
	 * A constructor for a new NDPNeighborSolicitationLayer object
	 * @param[in] code Code field
	 * @param[in] targetIP Target IP address for which the solicitation shall be created
	 * @param[in] srcMac Mac address which shall be put in the linklayer option
	 */
	NDPNeighborSolicitationLayer(uint8_t code, const IPv6Address &targetIP, const MacAddress &srcMac);

	virtual ~NDPNeighborSolicitationLayer() {}

	/**
	 * @return Get the IP address specified as the target IP address in the solicitation message
	 */
	IPv6Address getTargetIP() const	{ return IPv6Address(getNdpHeader()->targetIP); };

	/**
	 * Checks if the layer has a link layer address option set
	 * @return true if link layer address option is available, false otherwise
	 */
	bool hasLinkLayerAddress() const;

	/**
	 * Get the Link Layer Address
	 * @return Mac address which is specified in the link layer address option
	 */
	MacAddress getLinkLayerAddress() const;

	std::string toString() const;

private:
	void initLayer(uint8_t code, const IPv6Address &targetIP);
	ndpneighborsolicitationhdr *getNdpHeader() const { return (ndpneighborsolicitationhdr *)m_Data;	}
	size_t getNdpHeaderLen() const { return sizeof(ndpneighborsolicitationhdr);	};
};

/**
 * @class NDPNeighborAdvertisementLayer
 * Represents a NDP Neighbor Advertisement protocol layer
 */
class NDPNeighborAdvertisementLayer : public NDPLayerBase
{
public:
	/**
	 * @struct ndpneighboradvertisementhdr
	 * Represents neighbor advertisement message format
	 */
#pragma pack(push, 1)
	struct ndpneighboradvertisementhdr : icmpv6hdr
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint32_t
			/** Unused field */
			reserved : 5,
			/** Flag indicating that this entry should override the old one */
			override : 1,
			/** Flag indicating that the advertisement was sent in response to a Neighbor Solicitation from the
			Destination address */
			solicited : 1,
			/** Flag indicating that the advertisement is sent by a router */
			router : 1,
			/** Unused field */
			reserved2 : 24;
#else
		uint32_t
			/** Flag indicating that the advertisement is sent by a router */
			router : 1,
			/** Flag indicating that the advertisement was sent in response to a Neighbor Solicitation from the
			   Destination address */
			solicited : 1,
			/** Flag indicating that this entry should override the old one */
			override : 1,
			/** Unused field */
			reserved : 29;
#endif
		/** Target address - Either source address of advertisement or address for requested MAC */
		uint8_t targetIP[16];
	};
#pragma pack(pop)

	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	NDPNeighborAdvertisementLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: NDPLayerBase(data, dataLen, prevLayer, packet) {}

	/**
	 * A constructor that allocates a new NDP Advertisement Layer with target link-layer address option
	 * @param[in] code Code field
	 * @param[in] targetIP The target IP address from the Neighbor Solicitation message (solicited advertisements) or
	 * the address whose link-layer address has changed (unsolicited advertisement)
	 * @param[in] targetMac Adds the target link-layer address into the option field of the layer
	 * @param[in] routerFlag The router flag
	 * @param[in] unicastFlag The solicited flag
	 * @param[in] overrideFlag The override flag
	 */
	NDPNeighborAdvertisementLayer(uint8_t code, const IPv6Address &targetIP, const MacAddress &targetMac,
								  bool routerFlag, bool unicastFlag, bool overrideFlag);

	/**
	 * A constructor that allocates a new NDP Advertisement Layer
	 * @param code Code field
	 * @param targetIP The target IP address from the Neighbor Solicitation message (solicited advertisements) or the
	 * address whose link-layer address has changed (unsolicited advertisement)
	 * @param routerFlag The router flag
	 * @param unicastFlag The solicited flag
	 * @param overrideFlag The override flag
	 */
	NDPNeighborAdvertisementLayer(uint8_t code, const IPv6Address &targetIP, bool routerFlag, bool unicastFlag,
								  bool overrideFlag);

	virtual ~NDPNeighborAdvertisementLayer() {}

	/**
	 * @return Get the target MAC address
	 */
	MacAddress getTargetMac() const;

	/**
	 * @return Get the target IP address
	 */
	IPv6Address getTargetIP() const	{ return IPv6Address(getNdpHeader()->targetIP);	}

	/**
	 * @return Get information if the target link-layer address was added in the option field of the header
	 */
	bool hasTargetMacInfo() const;

	/**
	 * @return Get the router flag
	 */
	bool getRouterFlag() const { return getNdpHeader()->router;	}

	/**
	 * @return Get the unicast flag
	 */
	bool getUnicastFlag() const { return getNdpHeader()->solicited; }

	/**
	 * @return Get the override flag
	 */
	bool getOverrideFlag() const { return getNdpHeader()->override;	}

	std::string toString() const;

private:
	void initLayer(uint8_t code, const IPv6Address &targetIP, bool routerFlag, bool unicastFlag, bool overrideFlag);
	ndpneighboradvertisementhdr *getNdpHeader() const {	return (ndpneighboradvertisementhdr *)m_Data; }
	size_t getNdpHeaderLen() const { return sizeof(ndpneighboradvertisementhdr); };
};

} // namespace pcpp
#endif /* PACKETPP_NDP_LAYER */
