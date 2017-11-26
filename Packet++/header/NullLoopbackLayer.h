#ifndef PACKETPP_NULL_LOOPBACK_LAYER
#define PACKETPP_NULL_LOOPBACK_LAYER

/// @file

#include "Layer.h"

namespace pcpp
{

	/** IPv4 protocol **/
	#define PCPP_BSD_AF_INET          2
	/** XEROX NS protocols */
	#define PCPP_BSD_AF_NS            6
	/** ISO */
	#define PCPP_BSD_AF_ISO           7
	/** AppleTalk */
	#define PCPP_BSD_AF_APPLETALK     16
	/** IPX */
	#define PCPP_BSD_AF_IPX           23
	/** OpenBSD (and probably NetBSD), BSD/OS IPv6 */
	#define PCPP_BSD_AF_INET6_BSD     24
	/** FreeBSD IPv6 */
	#define PCPP_BSD_AF_INET6_FREEBSD 28
	/** Darwin IPv6 */
	#define PCPP_BSD_AF_INET6_DARWIN  30

	/**
	 * @class NullLoopbackLayer
	 * Represents a NULL/Loopback layer
	 */
	class NullLoopbackLayer : public Layer
	{
	public:
		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NullLoopbackLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = NULL_LOOPBACK; }

		/**
		 * A constructor that allocates a new Null/Loopback header
		 * @param[in] family The family protocol to set
		 */
		NullLoopbackLayer(uint32_t family);

		/**
		 * A destructor for this layer (does nothing)
		 */
		~NullLoopbackLayer() {}

		/**
		 * @return The protocol family in this layer
		 */
		uint32_t getFamily();

		/**
		 * Set a protocol family
		 * @param[in] family The family protocol to set
		 */
		void setFamily(uint32_t family);


		// implement abstract methods

		/**
		 * Identifies the next layers by family:
		 * - for ::PCPP_BSD_AF_INET the next layer is IPv4Layer
		 * - for ::PCPP_BSD_AF_INET6_BSD, ::PCPP_BSD_AF_INET6_FREEBSD, ::PCPP_BSD_AF_INET6_DARWIN the next layer is IPv6Layer
		 * - for other values the next layer in PayloadLayer (unknown protocol)
		 */
		void parseNextLayer();

		/**
		 * @return Size of Null/Loopback header = 4B
		 */
		inline size_t getHeaderLen() { return sizeof(uint32_t); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelDataLinkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_NULL_LOOPBACK_LAYER */
