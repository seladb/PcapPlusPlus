#ifndef PACKETPP_RIP_LAYER
#define PACKETPP_RIP_LAYER

#include <memory>
#include <vector>
#include <sstream>

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @struct riphdr
 * Represents an RIP protocol header
 */
#pragma pack(push, 1)
struct riphdr
{
	// Command
	uint8_t command;
	// Version
	uint8_t version;
	// Must be zero
	uint16_t reserve;
};

struct RipEntry
{
	// Address Family Identifier
	uint16_t family;
	// Route Tag
	uint16_t tag;
	// IP Address
	uint8_t prefix[4];
	// Subnet Mask. Must be zero in RIP-1
	uint8_t mask[4];
	// Next Hop. Must be zero in RIP-1
	uint8_t nexthop[4];
	// Metric
	uint32_t metric;
};
#pragma pack(pop)

class RipTableEntry
{
  public:
	RipTableEntry(std::istream &is);
	void ToV1StructuredOutput(std::ostream &os);
	void ToV2StructuredOutput(std::ostream &os);
	uint16_t get_family();
	uint16_t get_tag();
	uint32_t get_prefix();
	uint32_t get_mask();
	uint32_t get_nexthop();
	uint32_t get_metric();

  private:
	RipEntry re;
	uint16_t family;
	uint16_t tag;
	uint32_t prefix;
	uint32_t mask;
	uint32_t nexthop;
	uint32_t metric;
};

/**
 * @class RipLayer
 * Represents an RIP protocol layer
 */
class RipLayer : public Layer
{
  public:
	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref riphdr)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	RipLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet)
	{
		// set protocol
		m_Protocol = RIP;

		// calculate rte
		size_t len = Layer::getLayerPayloadSize();
		uint8_t *dt = Layer::getLayerPayload();
		// convert uint8_t to char then to string
		std::string s((char *)dt, len);
		std::istringstream iss(s);
		std::istream &stream = iss;

		while (len > 0)
		{
			auto temp_rte = std::make_shared<RipTableEntry>(stream);
			rtes.push_back(temp_rte);
			len = len - sizeof(RipEntry);
		}
	}

	static bool isRipPort(uint16_t port)
	{
		return port == 520;
	}

	/**
	 * Get a pointer to the RIP header. Notice this points directly to the data, so every change will change the actual
	 * packet data
	 * @return A pointer to the @ref riphdr
	 */
	riphdr *getRipHeader() const
	{
		return (riphdr *)m_Data;
	}

	/**
	 * @return RIP command
	 */
	uint8_t getCommand() const;

	/**
	 * @return RIP version
	 */
	uint8_t getVersion() const;

	/**
	 * @return RIP Route Table Entry size
	 */
	uint32_t getRteSize() const;

	/**
	 * @return RIP Route Table Entry
	 */
	std::shared_ptr<RipTableEntry> getRte(uint32_t index);

	void ToStructuredOutput(std::ostream &os) const;

	// implement abstract methods

	void parseNextLayer(){};

	/**
	 * @return Size of @ref riphdr
	 */
	size_t getHeaderLen() const
	{
		return sizeof(riphdr);
	}

	void computeCalculateFields();

	std::string toString() const;

	OsiModelLayer getOsiModelLayer() const
	{
		return OsiModelApplicationLayer;
	}

  private:
	std::vector<std::shared_ptr<RipTableEntry>> rtes;
};

} // namespace pcpp

#endif /* PACKETPP_RIP_LAYER */
