#ifndef PACKETPP_LLC_LAYER
#define PACKETPP_LLC_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @struct llc_header
	 * Logical Link Control (LLC) header
	 */
	#pragma pack(push, 1)
	struct llc_header
	{
		/// Destination Service Access Point
		uint8_t dsap,
		/// Source Service Access Point
		ssap,
		/// Control Field
		control;
	};
	#pragma pack(pop)

	/**
	 * @class LLCLayer
	 * Represents Logical Link Control layer messages
	 */
	class LLCLayer : public Layer
	{
	public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to llc_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		LLCLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = LLC; }

		/**
		 * A constructor that creates the LLC layer from provided values
		 * @param[in] dsap Destination Service Access Point
		 * @param[in] ssap Source Service Access Point
		 * @param[in] control Control Field
		 */
		LLCLayer(uint8_t dsap, uint8_t ssap, uint8_t control);

		/**
		 * Get a pointer to Logical Link Control (LLC) layer header
		 * @return Pointer to LLC header
		 */
		inline llc_header *getLlcHeader() const { return (llc_header*)m_Data; };

		// overridden methods

		/// Parses the next layer. Currently only STP supported as next layer
		void parseNextLayer();

		/// Does nothing for this layer
		void computeCalculateFields() {}

		/**
		 * @return Get the size of the LLC header
		 */
		size_t getHeaderLen() const { return sizeof(llc_header); }

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;

		/**
		 * @return The OSI layer level of LLC (Data Link Layer).
		 */
		OsiModelLayer getOsiModelLayer() const { return OsiModelDataLinkLayer; }

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an LLC packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an LLC packet
		 */
		static bool isDataValid(const uint8_t *data, size_t dataLen);
	};

} // namespace pcpp

#endif /* PACKETPP_LLC_LAYER */
