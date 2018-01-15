#ifndef PACKETPP_LAYER
#define PACKETPP_LAYER

#include <stdint.h>
#include <stdio.h>
#include "ProtocolType.h"
#include <string>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class IDataContainer
	 * An interface (virtual abstract class) that indicates an object that holds a pointer to a buffer data. The Layer class is an example
	 * of such object, hence it inherits this interface
	 */
	class IDataContainer
	{
	public:
		/**
		 * Get a pointer to the data
		 * @param[in] offset Get a pointer in a certain offset. Default is 0 - get a pointer to start of data
		 * @return A pointer to the data
		 */
		virtual uint8_t* getDataPtr(size_t offset = 0) = 0;

		virtual ~IDataContainer() {}
	};

	class Packet;

	/**
	 * @class Layer
	 * Layer is the base class for all protocol layers. Each protocol supported in PcapPlusPlus has a class that inherits Layer.
	 * The protocol layer class expose all properties and methods relevant for viewing and editing protocol fields.
	 * For example: a pointer to a structured header (e.g tcphdr, iphdr, etc.), protocol header size, payload size, compute
	 * fields that can be automatically computed, print protocol data to string, etc.
	 * Each protocol instance is obviously part of a protocol stack (which construct a packet). This protocol stack is represented
	 * in PcapPlusPlus in a linked list, and each layer is an element in this list. That's why each layer has proprties to the next and previous
	 * layer in the protocol stack
	 * The Layer class, as a base class, is abstract and the user can't create an instance of it (it has a private constructor)
	 * Each layer holds a pointer to the relevant place in the packet. The layer sees all the data from this pointer forward until the
	 * end of the packet. Here is an example packet showing this concept:
	 *
	  @verbatim

	  ====================================================
	  |Eth       |IPv4       |TCP       |Packet          |
	  |Header    |Header     |Header    |Payload         |
	  ====================================================

	  |--------------------------------------------------|
	  EthLayer data
				 |---------------------------------------|
				 IPv4Layer data
							 |---------------------------|
							 TcpLayer data
										|----------------|
										PayloadLayer data

	  @endverbatim
	 *
	*/
	class Layer : public IDataContainer {
		friend class Packet;
	public:
		/**
		 * A destructor for this class. Frees the data if it was allocated by the layer constructor (see isAllocatedToPacket() for more info)
		 */
		virtual ~Layer();

		/**
		 * @return A pointer to the next layer in the protocol stack or NULL if the layer is the last one
		 */
		inline Layer* getNextLayer() { return m_NextLayer; }

		/**
		 * @return A pointer to the previous layer in the protocol stack or NULL if the layer is the first one
		 */
		inline Layer* getPrevLayer() { return m_PrevLayer; }

		/**
		 * @return The protocol enum
		 */
		inline ProtocolType getProtocol() { return m_Protocol; }

		/**
		 * @return A pointer to the layer raw data. In most cases it'll be a pointer to the first byte of the header
		 */
		inline uint8_t* getData() { return m_Data; }

		/**
		 * @return The length in bytes of the data from the first byte of the header until the end of the packet
		 */
		inline size_t getDataLen() { return m_DataLen; }

		/**
		 * @return A pointer for the layer payload, meaning the first byte after the header
		 */
		uint8_t* getLayerPayload() { return m_Data + getHeaderLen(); }

		/**
		 * @return The size in bytes of the payload
		 */
		size_t getLayerPayloadSize() { return m_DataLen - getHeaderLen(); }

		/**
		 * Raw data in layers can come from one of sources:
		 * 1. from an existing packet - this is the case when parsing packets received from files or the network. In this case the data was
		 * already allocated by someone else, and layer only holds the pointer to the relevant place inside this data
		 * 2. when creating packets, data is allocated when layer is created. In this case the layer is responsible for freeing it as well
		 *
		 * @return Returns true if the data was allocated by an external source (a packet) or false if it was allocated by the layer itself
		 */
		inline bool isAllocatedToPacket() { return m_Packet != NULL; }

		/**
		 * Copy the raw data of this layer to another array
		 * @param[out] toArr The destination byte array
		 */
		void copyData(uint8_t* toArr);


		// implement abstract methods

		uint8_t* getDataPtr(size_t offset = 0) { return (uint8_t*)(m_Data + offset); }


		// abstract methods

		/**
		 * Each layer is responsible for parsing the next layer
		 */
		virtual void parseNextLayer() = 0;

		/**
		 * @return The header length in bytes
		 */
		virtual size_t getHeaderLen() = 0;

		/**
		 * Each layer can compute field values automatically using this method. This is an abstract method
		 */
		virtual void computeCalculateFields() = 0;

		/**
		 * @return A string representation of the layer most important data (should look like the layer description in Wireshark)
		 */
		virtual std::string toString() = 0;

		/**
		 * @return The OSI Model layer this protocol belongs to
		 */
		virtual OsiModelLayer getOsiModelLayer() = 0;

	protected:
		uint8_t* m_Data;
		size_t m_DataLen;
		Packet* m_Packet;
		ProtocolType m_Protocol;
		Layer* m_NextLayer;
		Layer* m_PrevLayer;
		bool m_IsAllocatedInPacket;

		Layer() : m_Data(NULL), m_DataLen(0), m_Packet(NULL), m_Protocol(UnknownProtocol), m_NextLayer(NULL), m_PrevLayer(NULL), m_IsAllocatedInPacket(false) { }

		Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
			m_Data(data), m_DataLen(dataLen),
			m_Packet(packet), m_Protocol(UnknownProtocol),
			m_NextLayer(NULL), m_PrevLayer(prevLayer), m_IsAllocatedInPacket(false) {}

		// Copy c'tor
		Layer(const Layer& other);
		Layer& operator=(const Layer& other);

		inline void setNextLayer(Layer* nextLayer) { m_NextLayer = nextLayer; }
		inline void setPrevLayer(Layer* prevLayer) { m_PrevLayer = prevLayer; }

		virtual bool extendLayer(int offsetInLayer, size_t numOfBytesToExtend);
		virtual bool shortenLayer(int offsetInLayer, size_t numOfBytesToShorten);
	};

} // namespace pcpp

#endif /* PACKETPP_LAYER */
