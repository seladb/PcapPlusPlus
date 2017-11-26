#ifndef PACKETPP_MPLS_LAYER
#define PACKETPP_MPLS_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class MplsLayer
	 * Represents a MPLS (Multi-Protocol Label Switching) layer
	 */
	class MplsLayer : public Layer
	{
	private:

		#pragma pack(push, 1)
		struct mpls_header
		{
			uint16_t    hiLabel;
			uint8_t		misc;
			uint8_t		ttl;
		};
		#pragma pack(pop)

		inline mpls_header* getMplsHeader() { return (mpls_header*)m_Data; };

	public:
		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		MplsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = MPLS; }

		/**
		 * A constructor that allocates a new MPLS header
		 * @param[in] mplsLabel MPLS label
		 * @param[in] ttl Time-to-leave value
		 * @param[in] expermentalUseValue Experimental use value
		 * @param[in] bottomOfStack Bottom-of-stack value which indicate whether the next layer will also be a MPLS label or not
		 */
		MplsLayer(uint32_t mplsLabel, uint8_t ttl, uint8_t expermentalUseValue, bool bottomOfStack);

		virtual ~MplsLayer() {}

		/**
		 * @return TTL value of the MPLS header
		 */
		inline uint8_t getTTL() { return getMplsHeader()->ttl; }

		/**
		 * Set the TTL value
		 * @param[in] ttl The TTL value to set
		 */
		inline void setTTL(uint8_t ttl) { getMplsHeader()->ttl = ttl; }

		/**
		 * Get an indication whether the next layer is also be a MPLS label or not
		 * @return True if it's the last MPLS layer, false otherwise
		 */
		bool isBottomOfStack();

		/**
		 * Set the bottom-of-stack bit in the MPLS label
		 * @param[in] val Set or unset the bit
		 */
		void setBottomOfStack(bool val);

		/**
		 * @return The exp value (3 bits) of the MPLS label
		 */
		uint8_t getExperimentalUseValue();

		/**
		 * Set the exp value (3 bits) of the MPLS label
		 * @param[in] val The exp value to set. val must be a valid number meaning between 0 and 7 (inclusive)
		 * @return True if exp value was set successfully or false if val has invalid value
		 */
		bool setExperimentalUseValue(uint8_t val);

		/**
		 * @return The MPLS label value (20 bits)
		 */
		uint32_t getMplsLabel();

		/**
		 * Set the MPLS label (20 bits)
		 * @param[in] label The label to set. label must be a valid number meaning between 0 and 0xFFFFF (inclusive)
		 * @return True if label was set successfully or false if label has invalid value
		 */
		bool setMplsLabel(uint32_t label);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, MplsLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of MPLS header (4 bytes)
		 */
		inline size_t getHeaderLen() { return sizeof(mpls_header); }

		/**
		 * Set/unset the bottom-of-stack bit according to next layer: if it's a MPLS layer then bottom-of-stack will be unset. If it's not a
		 * MPLS layer this bit will be set
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_MPLS_LAYER */
