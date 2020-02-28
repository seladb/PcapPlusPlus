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
	class Packet
	{
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
		virtual ~Packet() { destructPacketData(); }

		/**
		 * A copy constructor for this class. This copy constructor copies all the raw data and re-create all layers. So when the original Packet
		 * is being freed, no data will be lost in the copied instance
		 * @param[in] other The instance to copy from
		 */
		Packet(const Packet& other) { copyDataFrom(other); }

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
		RawPacket* getRawPacket() const { return m_RawPacket; }

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
		RawPacket* getRawPacketReadOnly() const { return m_RawPacket; }

		/**
		 * Get a pointer to the first (lowest) layer in the packet
		 * @return A pointer to the first (lowest) layer in the packet
		 */
		Layer* getFirstLayer() const { return m_FirstLayer; }

		/**
		 * Get a pointer to the last (highest) layer in the packet
		 * @return A pointer to the last (highest) layer in the packet
		 */
		Layer* getLastLayer() const { return m_LastLayer; }

		/**
		 * Add a new layer as the last layer in the packet. This method gets a pointer to the new layer as a parameter
		 * and attaches it to the packet. Notice after calling this method the input layer is attached to the packet so
		 * every change you make in it affect the packet; Also it cannot be attached to other packets
		 * @param[in] newLayer A pointer to the new layer to be added to the packet
		 * @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct.  Default is false.
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool addLayer(Layer* newLayer, bool ownInPacket = false) { return insertLayer(m_LastLayer, newLayer, ownInPacket); }

		/**
		 * Insert a new layer after an existing layer in the packet. This method gets a pointer to the new layer as a
		 * parameter and attaches it to the packet. Notice after calling this method the input layer is attached to the
		 * packet so every change you make in it affect the packet; Also it cannot be attached to other packets
		 * @param[in] prevLayer A pointer to an existing layer in the packet which the new layer should followed by. If
		 * this layer isn't attached to a packet and error will be printed to log and false will be returned
		 * @param[in] newLayer A pointer to the new layer to be added to the packet
		 * @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct.  Default is false.
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool insertLayer(Layer* prevLayer, Layer* newLayer, bool ownInPacket = false);


		/**
		 * Remove an existing layer from the packet. The layer to removed is identified by its type (protocol). If the
		 * packet has multiple layers of the same type in the packet the user may specify the index of the layer to remove 
		 * (the default index is 0 - remove the first layer of this type). If the layer was allocated during packet creation 
		 * it will be deleted and any pointer to it will get invalid. However if the layer was allocated by the user and
		 * manually added to the packet it will simply get detached from the packet, meaning the pointer to it will stay 
		 * valid and its data (that was removed from the packet) will be copied back to the layer. In that case it's 
		 * the user's responsibility to delete the layer instance
		 * @param[in] layerType The layer type (protocol) to remove
		 * @param[in] index If there are multiple layers of the same type, indicate which instance to remove. The default
		 * value is 0, meaning remove the first layer of this type
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool removeLayer(ProtocolType layerType, int index = 0);

		/**
		 * Remove the first layer in the packet. The layer will be deleted if it was allocated during packet creation, or detached
		 * if was allocated outside of the packet. Please refer to removeLayer() to get more info
		 * @return True if layer removed successfully, or false if removing the layer failed or if there are no layers in the 
		 * packet. In any case of failure an appropriate error log message will be printed 
		 */
		bool removeFirstLayer();

		/**
		 * Remove the last layer in the packet. The layer will be deleted if it was allocated during packet creation, or detached
		 * if was allocated outside of the packet. Please refer to removeLayer() to get more info
		 * @return True if layer removed successfully, or false if removing the layer failed or if there are no layers in the 
		 * packet. In any case of failure an appropriate error log message will be printed 
		 */
		bool removeLastLayer();

		/**
		 * Remove all layers that come after a certain layer. All layers removed will be deleted if they were allocated during
		 * packet creation or detached if were allocated outside of the packet, please refer to removeLayer() to get more info
		 * @param[in] layer A pointer to the layer to begin removing from. Please note this layer will not be removed, only the 
		 * layers that come after it will be removed. Also, if removal of one layer failed, the method will return immediately and
		 * the following layers won't be deleted
		 * @return True if all layers were removed successfully, or false if failed to remove at least one layer. In any case of
		 * failure an appropriate error log message will be printed
		 */
		bool removeAllLayersAfter(Layer* layer);

		/**
		 * Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather seperated from the
		 * packet - e.g it will be removed from the layer chain of the packet and its data will be copied from the packet buffer
		 * into an internal layer buffer. After a layer is detached, it can be added into another packet (but it's impossible to 
		 * attach a layer to multiple packets in the same time). After layer is detached, it's the user's responsibility to 
		 * delete it when it's not needed anymore
		 * @param[in] layerType The layer type (protocol) to detach from the packet
		 * @param[in] index If there are multiple layers of the same type, indicate which instance to detach. The default
		 * value is 0, meaning detach the first layer of this type
		 * @return A pointer to the detached layer or NULL if detaching process failed. In any case of failure an 
		 * appropriate error log message will be printed
		 */
		Layer* detachLayer(ProtocolType layerType, int index = 0);

		/**
		 * Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather seperated from the
		 * packet - e.g it will be removed from the layer chain of the packet and its data will be copied from the packet buffer
		 * into an internal layer buffer. After a layer is detached, it can be added into another packet (but it's impossible to 
		 * attach a layer to multiple packets at the same time). After layer is detached, it's the user's responsibility to 
		 * delete it when it's not needed anymore
		 * @param[in] layer A pointer to the layer to detach
		 * @return True if the layer was detached successfully, or false if something went wrong. In any case of failure an 
		 * appropriate error log message will be printed
		 */
		bool detachLayer(Layer* layer) { return removeLayer(layer, false); }

		/**
		 * Get a pointer to the layer of a certain type (protocol). This method goes through the layers and returns a layer
		 * that matches the give protocol type
		 * @param[in] layerType The layer type (protocol) to fetch
		 * @param[in] index If there are multiple layers of the same type, indicate which instance to fetch. The default
		 * value is 0, meaning fetch the first layer of this type
		 * @return A pointer to the layer or NULL if no such layer was found
		 */
		Layer* getLayerOfType(ProtocolType layerType, int index = 0) const;

		/**
		 * A templated method to get a layer of a certain type (protocol). If no layer of such type is found, NULL is returned
		 * @param[in] reverseOrder The optional paramter that indicates that the lookup should run in reverse order, the default value is false
		 * @return A pointer to the layer of the requested type, NULL if not found
		 */
		template<class TLayer>
		TLayer* getLayerOfType(bool reverseOrder = false) const;

		/**
		 * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
		 * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
		 * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(3) will be returned
		 * If no layer of such type is found, NULL is returned
		 * @param[in] startLayer A pointer to the layer to start search from
		 * @return A pointer to the layer of the requested type, NULL if not found
		 */
		template<class TLayer>
		TLayer* getNextLayerOfType(Layer* startLayer) const;

		/**
		 * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
		 * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
		 * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(1) will be returned
		 * If no layer of such type is found, NULL is returned
		 * @param[in] startLayer A pointer to the layer to start search from
		 * @return A pointer to the layer of the requested type, NULL if not found
		 */
		template<class TLayer>
		TLayer* getPrevLayerOfType(Layer* startLayer) const;

		/**
		 * Check whether the packet contains a certain protocol
		 * @param[in] protocolType The protocol type to search
		 * @return True if the packet contains the protocol, false otherwise
		 */
		bool isPacketOfType(ProtocolType protocolType) const { return m_ProtocolTypes & protocolType; }

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
		void toStringList(std::vector<std::string>& result, bool timeAsLocalTime = true) const;

	private:
		void copyDataFrom(const Packet& other);

		void destructPacketData();

		bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
		bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

		void reallocateRawData(size_t newSize);

		bool removeLayer(Layer* layer, bool tryToDelete);

		std::string printPacketInfo(bool timeAsLocalTime) const;

		Layer* createFirstLayer(LinkLayerType linkType);
	}; // class Packet


	// implementation of inline methods

	template<class TLayer>
	TLayer* Packet::getLayerOfType(bool reverse) const
	{
		if (!reverse)
		{
			if (dynamic_cast<TLayer*>(getFirstLayer()) != NULL)
				return (TLayer*)getFirstLayer();

			return getNextLayerOfType<TLayer>(getFirstLayer());
		}

		// lookup in reverse order
		if (dynamic_cast<TLayer*>(getLastLayer()) != NULL)
			return (TLayer*)getLastLayer();

		return getPrevLayerOfType<TLayer>(getLastLayer());
	}

	template<class TLayer>
	TLayer* Packet::getNextLayerOfType(Layer* curLayer) const
	{
		if (curLayer == NULL)
			return NULL;

		curLayer = curLayer->getNextLayer();
		while ((curLayer != NULL) && (dynamic_cast<TLayer*>(curLayer) == NULL))
		{
			curLayer = curLayer->getNextLayer();
		}

		return (TLayer*)curLayer;
	}

	template<class TLayer>
	TLayer* Packet::getPrevLayerOfType(Layer* curLayer) const
	{
		if (curLayer == NULL)
			return NULL;

		curLayer = curLayer->getPrevLayer();
		while (curLayer != NULL && dynamic_cast<TLayer*>(curLayer) == NULL)
		{
			curLayer = curLayer->getPrevLayer();
		}

		return static_cast<TLayer*>(curLayer);
	}

} // namespace pcpp

#endif /* PACKETPP_PACKET */
