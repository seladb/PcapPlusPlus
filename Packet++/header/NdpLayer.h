#ifndef PACKETPP_NDP_LAYER
#define PACKETPP_NDP_LAYER

#include "IpAddress.h"
#include "Layer.h"
#include "MacAddress.h"

#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * An enum representing the available option types for Neighbor Discovery in IPv6 (see RFC4861)
 */
enum NDPNeighborOptionTypes
{
	NDP_OPTION_SOURCE_LINK_LAYER = 1,
	NDP_OPTION_TARGET_LINK_LAYER = 2,
	NDP_OPTION_PREFIX_INFORMATION = 3,
	NDP_OPTION_REDIRECTED_HEADER = 4,
	NDP_OPTION_MTU = 5
};

/**
 * @struct ndpoptionbase
 * Represents a base for neighbor discovery options
 */
#pragma pack(push, 1)
struct ndpoptionbase
{
	/* 8-bit identifier of the type of option */
	uint8_t type;
	/* The length of the option (including the type and length fields) in units of 8 octets. */
	uint8_t length;
};
#pragma pack(pop)

/**
 * @struct ndpoptionlinklayer
 * Represents the link layer neighbor discovery option
 */
#pragma pack(push, 1)
struct ndpoptionlinklayer : ndpoptionbase
{
	/** Link layer address */
	uint8_t linklayerAddress[6];
};
#pragma pack(pop)

/**
 * @class NDPLayerBase
 * Represents a base for NDP packet types
 */
class NDPLayerBase : public Layer
{
  protected:
	NDPLayerBase() = default;

	NDPLayerBase(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: Layer(data, dataLen, prevLayer, packet)
	{
	}

	virtual ~NDPLayerBase()	{}

	ndpoptionbase *GetOptionOfType(size_t headerLen, NDPNeighborOptionTypes type) const;

	void CreateLinkLayerOption(ndpoptionlinklayer *ptrToOption, NDPNeighborOptionTypes optionType,
							   const MacAddress &linkLayerAddr);
};

/**
 * @class NDPNeighborAdvertisementLayer
 * Represents an NDP Neighbor Advertisement protocol layer
 */
class NDPNeighborAdvertisementLayer : public NDPLayerBase
{
  public:

	/**
	 * @struct ndpneighboradvertisementhdr
	 * Represents neighbor advertisement message format
	 */
#pragma pack(push, 1)
	struct ndpneighboradvertisementhdr
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
		: NDPLayerBase(data, dataLen, prevLayer, packet)
	{
		m_Protocol = NDPNeighborAdvertisement;
	}

	/**
	 * A constructor that allocates a new NDP Advertisement Layer with target link-layer address option
	 * @param targetIP The target IP address from the Neighbor Solicitation message (solicited advertisements) or the
	 * address whose link-layer address has changed (unsolicited advertisement)
	 * @param targetMac Adds the target link-layer address into the option field of the layer
	 * @param byRouter The router flag
	 * @param unicastResponse The solicited flag
	 * @param override The override flag
	 */
	NDPNeighborAdvertisementLayer(const IPv6Address &targetIP, const MacAddress &targetMac, bool byRouter,
								  bool unicastResponse, bool override);

	/**
	 * A constructor that allocates a new NDP Advertisement Layer
	 * @param targetIP The target IP address from the Neighbor Solicitation message (solicited advertisements) or the
	 * address whose link-layer address has changed (unsolicited advertisement)
	 * @param byRouter The router flag
	 * @param unicastResponse The solicited flag
	 * @param override The override flag
	 */
	NDPNeighborAdvertisementLayer(const IPv6Address &targetIP, bool byRouter, bool unicastResponse, bool override);

	virtual ~NDPNeighborAdvertisementLayer() {}

	/**
	 * @return A pointer to the @ref ndpneighboradvertisementhdr
	 */
	ndpneighboradvertisementhdr *getNdpHeader() const { return (ndpneighboradvertisementhdr *)m_Data; }

	/**
	 * @return The Length of the NDPNeighborAdvertisement header. Whether returns length of the advertisement header
	 * if no link layer option is set, or length of header + option
	 */
	size_t getHeaderLen() const
	{
		return hasTargetMacInfo() ? sizeof(ndpneighboradvertisementhdr) + sizeof(ndpoptionlinklayer)
								  : sizeof(ndpneighboradvertisementhdr);
	}

	/**
	 * @return Get the target MAC address
	 */
	MacAddress getTargetMac() const;

	/**
	 * @return Get the target IP address
	 */
	IPv6Address getTargetIP() const
    {
        return IPv6Address(getNdpHeader()->targetIP);
    }

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
	bool getOverrideFlag() const { return getNdpHeader()->override; }

	/**
	 * Does nothing for this layer
	 */
	void computeCalculateFields() {}

	/**
	 * Currently the last layer.
	 */
	void parseNextLayer() {}

	std::string toString() const;

	OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }

  private:
	void setNeighborAdvertisementHeaderFields(const IPv6Address &targetIP, bool byRouter, bool unicastResponse,
											  bool override);
};

/**
 * @class NDPNeighborSolicitationLayer
 * Represents an NDP Neighbor Solicitation protocol layer
 */
class NDPNeighborSolicitationLayer : public NDPLayerBase
{
  public:

	/**
	 * @struct ndpneighborsolicitationhdr
	 * Represents neighbor solicitation message format
	 */
#pragma pack(push, 1)
	struct ndpneighborsolicitationhdr
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
		: NDPLayerBase(data, dataLen, prevLayer, packet)
	{
		m_Protocol = NDPNeighborSolicitation;
	}

	/**
	 * A constructor for a new NDPNeighborSolicitationLayer object
	 * @param[in] targetIP Target IP address for which the solicitation shall be created
	 */
	NDPNeighborSolicitationLayer(const IPv6Address &targetIP);

	/**
	 * A constructor for a new NDPNeighborSolicitationLayer object
	 * @param[in] targetIP Target IP address for which the solicitation shall be created
	 * @param[in] srcMac Mac address which shall be put in the linklayer option
	 */
	NDPNeighborSolicitationLayer(const IPv6Address &targetIP, const MacAddress &srcMac);

	virtual ~NDPNeighborSolicitationLayer() {}

	/**
	 * @return A pointer to the @ref ndpneighborsolicitationhdr
	 */
	ndpneighborsolicitationhdr *getNdpHeader() const { return (ndpneighborsolicitationhdr *)m_Data; }

	/**
	 * @return Get the IP address specified as the target IP address in the solicitation message
	 */
	IPv6Address getTargetIP() const
	{
		return IPv6Address(getNdpHeader()->targetIP);
	};

	/**
	 * Checks if the layer has a link layer address option set
	 * @return true if link layer address option is available
	 * @return false if not
	 */
	bool hasLinkLayerAddress() const;

	/**
	 * Get the Link Layer Address
	 * @return Mac address which is specified in the link layer address option
	 */
	MacAddress getLinkLayerAddress() const;

	/**
	 * @return The length of the NDPNeighborSolicitation header.
	 */
	size_t getHeaderLen() const
	{
		return hasLinkLayerAddress() ? sizeof(ndpneighborsolicitationhdr) + sizeof(ndpoptionlinklayer)
									 : sizeof(ndpneighborsolicitationhdr);
	}

	/**
	 * Does nothing for this layer
	 */
	void computeCalculateFields() {}

	/**
	 * Currently the last layer.
	 */
	void parseNextLayer() {}

	std::string toString() const;

	OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }
};

} // namespace pcpp
#endif /* PACKETPP_NDP_LAYER */
