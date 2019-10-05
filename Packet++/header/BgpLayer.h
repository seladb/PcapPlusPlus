#ifndef PACKETPP_BGP_LAYER
#define PACKETPP_BGP_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	static const size_t BGP_MARKER_SIZE_BYTES = 16;

	/**
	 * @struct bgp_header
	 * Represents a BGP protocol header
	 */
#pragma pack(push, 1)
	struct bgp_header {
		/** Reserved marker */
		uint8_t marker[BGP_MARKER_SIZE_BYTES];

		/** Length (in bytes) of the message, including this header */
		uint16_t messageLength;

		/** Type of message */
		uint8_t messageType;
	};
#pragma pack(pop)

	/**
	* An enum of all supported BGP message types
	*/
	enum BgpMessageType
	{
		BGP_UNKNOWN,

		BGP_OPEN,
		BGP_UPDATE,
		BGP_NOTIFICATION,
		BGP_KEEP_ALIVE,
		BGP_ROUTE_REFRESH,

		BGP_NUM_MESSAGE_TYPES
	};

	/**
	 * @class BgpLayer
	 * Represents a BGP layer
	 */
	class BgpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		BgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = BGP; }

		/**
		 * A constructor that allocates a new BGP header
		 * @param[in] messageType Message type
		 */
		BgpLayer(uint8_t messageType);

		virtual ~BgpLayer() {}

		/**
		 * Get a pointer to the basic BGP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref bgp_header
		 */
		inline bgp_header* getBgpHeader() const { return (bgp_header*)m_Data; }

		/**
		 * @return The BGP message type
		 */
		BgpMessageType getMessageType();

		/**
		 * @param[in] type Type to check
		 * @return True if the layer if of the given type, false otherwise
		 */
		bool isMessageOfType(BgpMessageType type);

		// implement abstract methods

		/**
		 *
		 */
		void parseNextLayer();

		/**
		 * @return Size of vlan_header
		 */
		inline size_t getHeaderLen() { return sizeof(bgp_header); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString();

		OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_BGP_LAYER */
