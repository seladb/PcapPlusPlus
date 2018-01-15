#ifndef PACKETPP_PACKET
#define PACKETPP_PACKET

#include "RawPacket.h"
#include "Layer.h"
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class Packet
	 * This class represents a parsed packet. It contains the raw data (RawPacket instance), and a linked list of layers, each layer is a parsed
	 * protocol that this packet contains. The layers linked list is ordered where the first layer is the lowest in the packet (currently it's always
	 * Ethernet protocol as PcapPlusPlus supports only Ethernet packets), the next layer will be L2.5 or L3 (e.g VLAN, IPv4, IPv6, etc.), and so on.
	 * etc.), etc. The last layer in the linked list will be the highest in the packet.
	 * For example: for a standard HTTP request packet the layer will look like this: EthLayer -> IPv4Layer -> TcpLayer -> HttpRequestLayer <BR>
	 * Packet instance isn't read only. The user can add or remove layers, update current layer, etc.
	 */
	class Packet {
		friend class Layer;
	private:
		RawPacket* m_RawPacket;
		Layer* m_FirstLayer;
		Layer* m_LastLayer;
		uint64_t m_ProtocolTypes;
		size_t m_MaxPacketLen;
		bool m_FreeRawPacket;

	public:

		/**
		 * A constructor for creating a new packet. Very useful when creating packets.
		 * When using this constructor an empty raw buffer is allocated (with the size of maxPacketLen) and a new RawPacket is created
		 * @param[in] maxPacketLen The expected packet length in bytes
		 */
		Packet(size_t maxPacketLen = 1);

		/**
		 * A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets that came from the network.
		 * When using this constructor a pointer to the RawPacket is saved (data isn't copied) and the RawPacket is parsed, meaning all layers
		 * are created and linked to each other in the right order. In this overload of the constructor the user can specify whether to free
		 * the instance of raw packet when the Packet is free or not
		 * @param[in] rawPacket A pointer to the raw packet
		 * @param[in] freeRawPacket Optional parameter. A flag indicating if the destructor should also call the raw packet destructor or not. Default value is false
		 * @param[in] parseUntil Optional parameter. Parse the packet until you reach a certain protocol (inclusive). Can be useful for cases when you need to parse only up to a
		 * certain layer and want to avoid the performance impact and memory consumption of parsing the whole packet. Default value is ::UnknownProtocol which means don't take this
		 * parameter into account
		 * @param[in] parseUntilLayer Optional parameter. Parse the packet until you reach a certain layer in the OSI model (inclusive). Can be useful for cases when you need to
		 * parse only up to a certain OSI layer (for example transport layer) and want to avoid the performance impact and memory consumption of parsing the whole packet.
		 * Default value is ::OsiModelLayerUnknown which means don't take this parameter into account
		 */
		Packet(RawPacket* rawPacket, bool freeRawPacket = false, ProtocolType parseUntil = UnknownProtocol, OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

		/**
		 * A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets that came from the network.
		 * When using this constructor a pointer to the RawPacket is saved (data isn't copied) and the RawPacket is parsed, meaning all layers
		 * are created and linked to each other in the right order. In this overload of the constructor the user can specify whether to free
		 * the instance of raw packet when the Packet is free or not. This constructor should be used to parse the packet up to a certain layer
		 * @param[in] rawPacket A pointer to the raw packet
		 * @param[in] parseUntil Optional parameter. Parse the packet until you reach a certain protocol (inclusive). Can be useful for cases when you need to parse only up to a
		 * certain layer and want to avoid the performance impact and memory consumption of parsing the whole packet
		 */
		Packet(RawPacket* rawPacket, ProtocolType parseUntil);

		/**
		 * A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets that came from the network.
		 * When using this constructor a pointer to the RawPacket is saved (data isn't copied) and the RawPacket is parsed, meaning all layers
		 * are created and linked to each other in the right order. In this overload of the constructor the user can specify whether to free
		 * the instance of raw packet when the Packet is free or not. . This constructor should be used to parse the packet up to a certain layer in the OSI model
		 * @param[in] rawPacket A pointer to the raw packet
		 * @param[in] parseUntilLayer Optional parameter. Parse the packet until you reach a certain layer in the OSI model (inclusive). Can be useful for cases when you need to
		 * parse only up to a certain OSI layer (for example transport layer) and want to avoid the performance impact and memory consumption of parsing the whole packet
		 */
		Packet(RawPacket* rawPacket, OsiModelLayer parseUntilLayer);

		/**
		 * A destructor for this class. Frees all layers allocated by this instance (Notice: it doesn't free layers that weren't allocated by this
		 * class, for example layers that were added by addLayer() or insertLayer() ). In addition it frees the raw packet if it was allocated by
		 * this instance (meaning if it was allocated by this instance constructor)
		 */
		virtual ~Packet();

		/**
		 * A copy constructor for this class. This copy constructor copies all the raw data and re-create all layers. So when the original Packet
		 * is being freed, no data will be lost in the copied instance
		 * @param[in] other The instance to copy from
		 */
		Packet(const Packet& other);

		/**
		 * Assignment operator overloading. It first frees all layers allocated by this instance (Notice: it doesn't free layers that weren't allocated by this
		 * class, for example layers that were added by addLayer() or insertLayer() ). In addition it frees the raw packet if it was allocated by
		 * this instance (meaning if it was allocated by this instance constructor).
		 * Afterwards it copies the data from the other packet in the same way used in the copy constructor.
		 * @param[in] other The instance to copy from
		 */
		Packet& operator=(const Packet& other);

		/**
		 * Get a pointer to the Packet's RawPacket
		 * @return A pointer to the Packet's RawPacket
		 */
		inline RawPacket* getRawPacket() { return m_RawPacket; }

		/**
		 * Set a RawPacket and re-construct all packet layers
		 * @param[in] rawPacket Raw packet to set
		 * @param[in] freeRawPacket A flag indicating if the destructor should also call the raw packet destructor or not
		 * @param[in] parseUntil Parse the packet until it reaches this protocol. Can be useful for cases when you need to parse only up to a certain layer and want to avoid the
		 * performance impact and memory consumption of parsing the whole packet. Default value is ::UnknownProtocol which means don't take this parameter into account
		 * @param[in] parseUntilLayer Parse the packet until certain layer in OSI model. Can be useful for cases when you need to parse only up to a certain layer and want to avoid the
		 * performance impact and memory consumption of parsing the whole packet. Default value is ::OsiModelLayerUnknown which means don't take this parameter into account
		 */
		void setRawPacket(RawPacket* rawPacket, bool freeRawPacket, ProtocolType parseUntil = UnknownProtocol, OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

		/**
		 * Get a pointer to the Packet's RawPacket in a read-only manner
		 * @return A pointer to the Packet's RawPacket
		 */
		inline RawPacket* getRawPacketReadOnly() const { return m_RawPacket; }

		/**
		 * Get a pointer to the first (lowest) layer in the packet
		 * @return A pointer to the first (lowest) layer in the packet
		 */
		inline Layer* getFirstLayer() { return m_FirstLayer; }

		/**
		 * Get a pointer to the last (highest) layer in the packet
		 * @return A pointer to the last (highest) layer in the packet
		 */
		inline Layer* getLastLayer() { return m_LastLayer; }

		/**
		 * Add a new layer as the last layer in the packet. This method gets a pointer to the new layer as a parameter
		 * and attaches it to the packet. Notice after calling this method the input layer is attached to the packet so
		 * every change you make in it affect the packet; Also it cannot be attached to other packets
		 * @param[in] newLayer A pointer to the new layer to be added to the packet
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool addLayer(Layer* newLayer);

		/**
		 * Insert a new layer after an existing layer in the packet. This method gets a pointer to the new layer as a
		 * parameter and attaches it to the packet. Notice after calling this method the input layer is attached to the
		 * packet so every change you make in it affect the packet; Also it cannot be attached to other packets
		 * @param[in] prevLayer A pointer to an existing layer in the packet which the new layer should followed by. If
		 * this layer isn't attached to a packet and error will be printed to log and false will be returned
		 * @param[in] newLayer A pointer to the new layer to be added to the packet
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool insertLayer(Layer* prevLayer, Layer* newLayer);

		/**
		 * Remove an existing layer from the packet
		 * @param[in] layer The layer to remove
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool removeLayer(Layer* layer);

		/**
		 * A templated method to get a layer of a certain type (protocol). If no layer of such type is found, NULL is returned
		 * @return A pointer to the layer of the requested type, NULL if not found
		 */
		template<class TLayer>
		TLayer* getLayerOfType();

		/**
		 * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
		 * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
		 * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(3) will be returned
		 * If no layer of such type is found, NULL is returned
		 * @param[in] after A pointer to the layer to start search from
		 * @return A pointer to the layer of the requested type, NULL if not found
		 */
		template<class TLayer>
		TLayer* getNextLayerOfType(Layer* after);

		/**
		 * Check whether the packet contains a certain protocol
		 * @param[in] protocolType The protocol type to search
		 * @return True if the packet contains the protocol, false otherwise
		 */
		inline bool isPacketOfType(ProtocolType protocolType) { return m_ProtocolTypes & protocolType; }

		/**
		 * Each layer can have fields that can be calculate automatically from other fields using Layer#computeCalculateFields(). This method forces all layers to calculate these
		 * fields values
		 */
		void computeCalculateFields();

		/**
		 * Each layer can print a string representation of the layer most important data using Layer#toString(). This method aggregates this string from all layers and
		 * print it to a complete string containing all packet's relevant data
		 * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set to false
		 * @return A string containing most relevant data from all layers (looks like the packet description in Wireshark)
		 */
		std::string toString(bool timeAsLocalTime = true);

		/**
		 * Similar to toString(), but instead of one string it outputs a list of strings, one string for every layer
		 * @param[out] result A string vector that will contain all strings
		 * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set to false
		 */
		void toStringList(std::vector<std::string>& result, bool timeAsLocalTime = true);

	private:
		void copyDataFrom(const Packet& other);

		void destructPacketData();

		bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
		bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

		void reallocateRawData(size_t newSize);

		std::string printPacketInfo(bool timeAsLocalTime);
	};

	template<class TLayer>
	TLayer* Packet::getLayerOfType()
	{
		if (dynamic_cast<TLayer*>(m_FirstLayer) != NULL)
			return (TLayer*)m_FirstLayer;

		return getNextLayerOfType<TLayer>(m_FirstLayer);
	}

	template<class TLayer>
	TLayer* Packet::getNextLayerOfType(Layer* after)
	{
		if (after == NULL)
			return NULL;

		Layer* curLayer = after->getNextLayer();
		while ((curLayer != NULL) && (dynamic_cast<TLayer*>(curLayer) == NULL))
		{
			curLayer = curLayer->getNextLayer();
		}

		return (TLayer*)curLayer;
	}

} // namespace pcpp

#endif /* PACKETPP_PACKET */
