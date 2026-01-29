#define LOG_MODULE PacketLogModulePacket

#include "Packet.h"
#include "EthLayer.h"
#include "EthDot3Layer.h"
#include "SllLayer.h"
#include "Sll2Layer.h"
#include "NflogLayer.h"
#include "NullLoopbackLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "CiscoHdlcLayer.h"
#include "PayloadLayer.h"
#include "PacketTrailerLayer.h"
#include "Logger.h"
#include <numeric>
#include <sstream>
#include <memory>
#ifdef _MSC_VER
#	include <time.h>
#	include "SystemUtils.h"
#endif

namespace pcpp
{

	Packet::Packet(size_t maxPacketLen, LinkLayerType linkType)
	    : m_RawPacket(nullptr), m_FirstLayer(nullptr), m_LastLayer(nullptr), m_MaxPacketLen(maxPacketLen),
	      m_FreeRawPacket(true), m_CanReallocateData(true)
	{
		timeval time;
		gettimeofday(&time, nullptr);
		uint8_t* data = new uint8_t[maxPacketLen];
		memset(data, 0, maxPacketLen);
		m_RawPacket = new RawPacket(data, 0, time, true, linkType);
	}

	Packet::Packet(uint8_t* buffer, size_t bufferSize, LinkLayerType linkType)
	    : m_RawPacket(nullptr), m_FirstLayer(nullptr), m_LastLayer(nullptr), m_MaxPacketLen(bufferSize),
	      m_FreeRawPacket(true), m_CanReallocateData(false)
	{
		timeval time;
		gettimeofday(&time, nullptr);
		memset(buffer, 0, bufferSize);
		m_RawPacket = new RawPacket(buffer, 0, time, false, linkType);
	}

	Packet::Packet(RawPacket* rawPacket, bool freeRawPacket, ProtocolType parseUntil, OsiModelLayer parseUntilLayer)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		setRawPacket(rawPacket, freeRawPacket, parseUntil, parseUntilLayer);
	}

	Packet::Packet(RawPacket* rawPacket, ProtocolType parseUntil)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		auto parseUntilFamily = static_cast<ProtocolTypeFamily>(parseUntil);
		setRawPacket(rawPacket, false, parseUntilFamily, OsiModelLayerUnknown);
	}

	Packet::Packet(RawPacket* rawPacket, ProtocolTypeFamily parseUntilFamily)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		setRawPacket(rawPacket, false, parseUntilFamily, OsiModelLayerUnknown);
	}

	Packet::Packet(RawPacket* rawPacket, OsiModelLayer parseUntilLayer)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		setRawPacket(rawPacket, false, UnknownProtocol, parseUntilLayer);
	}

	Packet::Packet(RawPacket* rawPacket, bool takeOwnership, ParseOptions options)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		setRawPacket(rawPacket, takeOwnership, options);
	}

	void Packet::setRawPacket(RawPacket* rawPacket, bool freeRawPacket, ProtocolTypeFamily parseUntil,
	                          OsiModelLayer parseUntilLayer)
	{
		setRawPacket(rawPacket, freeRawPacket, ParseOptions{ parseUntil, parseUntilLayer });
	}

	void Packet::setRawPacket(RawPacket* rawPacket, bool takeOwnership, ParseOptions options)
	{
		destructPacketData();

		m_FirstLayer = nullptr;
		m_LastLayer = nullptr;
		m_MaxPacketLen = rawPacket->getRawDataLen();
		m_FreeRawPacket = takeOwnership;
		m_RawPacket = rawPacket;
		m_CanReallocateData = true;

		if (m_RawPacket == nullptr)
			return;

		parsePacket(options);
	}

	void Packet::parsePacket(ParseOptions options, bool incrementalParsing)
	{
		if (m_RawPacket == nullptr)
		{
			throw std::runtime_error("Cannot parse packet: RawPacket is null");
		}

		// If we aren't doing an incremental parse, destroy all existing layers and start from scratch
		if (!incrementalParsing)
		{
			destroyAllLayers();
		}

		// Flag indicating whether we are currently parsing new layers (as opposed to traversing already parsed ones).
		bool parsingNewLayers = false;

		// If there is no first layer, create it based on the link layer type
		if (m_FirstLayer == nullptr)
		{
			parsingNewLayers = true;

			LinkLayerType linkType = m_RawPacket->getLinkLayerType();
			m_FirstLayer = createFirstLayer(linkType);

			if (m_FirstLayer == nullptr)
			{
				PCPP_LOG_ERROR("Failed to create first layer! Possibly attempting to parse a RawPacket with no data.");
				return;
			}

			// Mark the first layer as allocated in the packet
			m_FirstLayer->m_AllocationInfo.ownedByPacket = true;
		}

		Layer* parseStartLayer = m_FirstLayer;

		// Fast path:
		//   If we are doing an incremental parse and we are not searching for a specific protocol type,
		//   we can directly start from the last parsed layer.
		if (m_LastLayer != nullptr && options.parseUntil == UnknownProtocol)
		{
			// NOTE: Potential edge case, PacketTrailerLayer is considered DataLinkLayer.
			//  If the user requested a higher OSI layer, this condition would not skip the parse.
			//  The parse should still do nothing, as the trailer layer doesn't have a next layer,
			//  but it will have to go through 1 extra iteration.
			if (m_LastLayer->getOsiModelLayer() > options.parseUntilLayer)
			{
				// Already past the OSI target layer, nothing to do
				return;
			}

			parseStartLayer = m_LastLayer;
		}

		// As the stop conditions are inclusive, the parse must go one layer further and then roll back if needed
		bool rollbackLastLayer = false;
		bool foundTargetProtocol = false;
		for (auto* curLayer = parseStartLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			// If we are parsing new layers, update the last layer pointer
			// Otherwise we are just traversing already parsed layers
			if (parsingNewLayers)
			{
				// Mark the current layer as allocated in the packet, as it was just created
				curLayer->m_AllocationInfo.ownedByPacket = true;
				m_LastLayer = curLayer;
			}

			// If the current layer is of a higher OSI layer than the target, stop parsing
			if (curLayer->getOsiModelLayer() > options.parseUntilLayer)
			{
				// If we are traversing already parsed layers, we don't want to roll back as they must be kept as is.
				rollbackLastLayer = parsingNewLayers;
				break;
			}

			// If we are searching for a specific layer protocol, record when we find at least one target.
			const bool matchesTarget = curLayer->isMemberOfProtocolFamily(options.parseUntil);
			if (options.parseUntil != UnknownProtocol && matchesTarget)
			{
				foundTargetProtocol = true;
			}

			// If we have found the target protocol already, we are parsing until we find a different protocol
			if (foundTargetProtocol && !matchesTarget)
			{
				// If we are traversing already parsed layers, we don't want to roll back as they must be kept as is.
				rollbackLastLayer = parsingNewLayers;
				break;
			}

			// If the current layer doesn't have a next layer yet, parse it.
			// This is important for the case of a re-parse where some layers may already have been parsed
			if (!curLayer->hasNextLayer())
			{
				parsingNewLayers = true;  // We are now parsing new layers.

				// Parse the next layer. This will update the next layer pointer of the current layer.
				curLayer->parseNextLayer();
			}
		}

		// Roll back one layer, if parsing with search condition as the conditions are inclusive.
		// Don't delete the first layer. If already past the target layer, treat the same as if the layer was found.
		if (rollbackLastLayer && m_LastLayer != m_FirstLayer)
		{
			m_LastLayer = m_LastLayer->getPrevLayer();
			delete m_LastLayer->m_NextLayer;
			m_LastLayer->m_NextLayer = nullptr;
		}

		// If there is data left in the raw packet that doesn't belong to any layer, create a PacketTrailerLayer
		if (m_LastLayer != nullptr && options.parseUntil == UnknownProtocol &&
		    options.parseUntilLayer == OsiModelLayerUnknown)
		{
			// find if there is data left in the raw packet that doesn't belong to any layer. In that case it's probably
			// a packet trailer. create a PacketTrailerLayer layer and add it at the end of the packet
			int trailerLen = (int)((m_RawPacket->getRawData() + m_RawPacket->getRawDataLen()) -
			                       (m_LastLayer->getData() + m_LastLayer->getDataLen()));
			if (trailerLen > 0)
			{
				PacketTrailerLayer* trailerLayer =
				    new PacketTrailerLayer(static_cast<uint8_t*>(m_LastLayer->getData() + m_LastLayer->getDataLen()),
				                           trailerLen, m_LastLayer, this);

				trailerLayer->m_AllocationInfo.ownedByPacket = true;
				m_LastLayer->setNextLayer(trailerLayer);
				m_LastLayer = trailerLayer;
			}
		}
	}

	void Packet::destructPacketData()
	{
		destroyAllLayers();

		if (m_RawPacket != nullptr && m_FreeRawPacket)
		{
			delete m_RawPacket;
		}
	}

	void Packet::destroyAllLayers()
	{
		Layer* curLayer = m_FirstLayer;
		while (curLayer != nullptr)
		{
			Layer* nextLayer = curLayer->getNextLayer();
			if (curLayer->m_AllocationInfo.ownedByPacket)
			{
				delete curLayer;
			}

			curLayer = nextLayer;
		}

		m_FirstLayer = nullptr;
		m_LastLayer = nullptr;
	}

	Packet& Packet::operator=(const Packet& other)
	{
		destructPacketData();

		copyDataFrom(other);

		return *this;
	}

	void Packet::copyDataFrom(const Packet& other)
	{
		m_RawPacket = new RawPacket(*(other.m_RawPacket));
		m_FreeRawPacket = true;
		m_MaxPacketLen = other.m_MaxPacketLen;
		m_FirstLayer = createFirstLayer(m_RawPacket->getLinkLayerType());
		m_LastLayer = m_FirstLayer;
		m_CanReallocateData = true;
		Layer* curLayer = m_FirstLayer;
		while (curLayer != nullptr)
		{
			curLayer->parseNextLayer();
			curLayer->m_AllocationInfo.ownedByPacket = true;
			curLayer = curLayer->getNextLayer();
			if (curLayer != nullptr)
				m_LastLayer = curLayer;
		}
	}

	void Packet::reallocateRawData(size_t newSize)
	{
		PCPP_LOG_DEBUG("Allocating packet to new size: " << newSize);

		// allocate a new array with size newSize
		m_MaxPacketLen = newSize;

		// set the new array to RawPacket
		if (!m_RawPacket->reallocateData(m_MaxPacketLen))
		{
			PCPP_LOG_ERROR("Couldn't reallocate data of raw packet to " << m_MaxPacketLen << " bytes");
			return;
		}

		// set all data pointers in layers to the new array address
		const uint8_t* dataPtr = m_RawPacket->getRawData();

		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			PCPP_LOG_DEBUG("Setting new data pointer to layer '" << typeid(curLayer).name() << "'");
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);
			dataPtr += curLayer->getHeaderLen();
		}
	}

	bool Packet::insertLayer(Layer* prevLayer, Layer* newLayer, bool ownInPacket)
	{
		if (newLayer == nullptr)
		{
			PCPP_LOG_ERROR("Layer to add is nullptr");
			return false;
		}

		if (newLayer->isAllocatedToPacket())
		{
			PCPP_LOG_ERROR("Layer is already allocated to another packet. Cannot use layer in more than one packet");
			return false;
		}

		if (prevLayer != nullptr && prevLayer->getProtocol() == PacketTrailer)
		{
			PCPP_LOG_ERROR("Cannot insert layer after packet trailer");
			return false;
		}

		size_t newLayerHeaderLen = newLayer->getHeaderLen();
		if (m_RawPacket->getRawDataLen() + newLayerHeaderLen > m_MaxPacketLen)
		{
			if (!m_CanReallocateData)
			{
				PCPP_LOG_ERROR("With the new layer the packet will exceed the size of the pre-allocated buffer: "
				               << m_MaxPacketLen << " bytes");
				return false;
			}
			// reallocate to maximum value of: twice the max size of the packet or max size + new required length
			if (m_RawPacket->getRawDataLen() + newLayerHeaderLen > m_MaxPacketLen * 2)
				reallocateRawData(m_RawPacket->getRawDataLen() + newLayerHeaderLen + m_MaxPacketLen);
			else
				reallocateRawData(m_MaxPacketLen * 2);
		}

		// insert layer data to raw packet
		int indexToInsertData = 0;
		if (prevLayer != nullptr)
			indexToInsertData = prevLayer->m_Data + prevLayer->getHeaderLen() - m_RawPacket->getRawData();
		m_RawPacket->insertData(indexToInsertData, newLayer->m_Data, newLayerHeaderLen);

		// delete previous layer data
		delete[] newLayer->m_Data;

		// add layer to layers linked list
		if (prevLayer != nullptr)
		{
			newLayer->setNextLayer(prevLayer->getNextLayer());
			newLayer->setPrevLayer(prevLayer);
			prevLayer->setNextLayer(newLayer);
		}
		else  // prevLayer == nullptr
		{
			newLayer->setNextLayer(m_FirstLayer);
			if (m_FirstLayer != nullptr)
				m_FirstLayer->setPrevLayer(newLayer);
			m_FirstLayer = newLayer;
		}

		if (newLayer->getNextLayer() == nullptr)
			m_LastLayer = newLayer;
		else
			newLayer->getNextLayer()->setPrevLayer(newLayer);

		// Attach the layer to this packet. If ownInPacket is true, transfer ownership of the layer to the packet.
		newLayer->m_AllocationInfo.attachPacket(this, ownInPacket);

		// re-calculate all layers data ptr and data length

		// first, get ptr and data length of the raw packet
		const uint8_t* dataPtr = m_RawPacket->getRawData();
		size_t dataLen = static_cast<size_t>(m_RawPacket->getRawDataLen());

		// if a packet trailer exists, get its length
		size_t packetTrailerLen = 0;
		if (m_LastLayer != nullptr && m_LastLayer->getProtocol() == PacketTrailer)
			packetTrailerLen = m_LastLayer->getDataLen();

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each one
		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			// set data ptr to layer
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// there is an assumption here that the packet trailer, if exists, corresponds to the L2 (data link) layers.
			// so if there is a packet trailer and this layer is L2 (data link), set its data length to contain the
			// whole data, including the packet trailer. If this layer is L3-7, exclude the packet trailer from its data
			// length
			if (curLayer->getOsiModelLayer() == OsiModelDataLinkLayer)
				curLayer->m_DataLen = dataLen;
			else
				curLayer->m_DataLen = dataLen - packetTrailerLen;

			// advance data ptr and data length
			dataPtr += curLayer->getHeaderLen();
			dataLen -= curLayer->getHeaderLen();
		}

		return true;
	}

	bool Packet::removeLayer(ProtocolType layerType, int index)
	{
		Layer* layerToRemove = getLayerOfType(layerType, index);

		if (layerToRemove != nullptr)
		{
			return removeLayer(layerToRemove, true);
		}
		else
		{
			PCPP_LOG_ERROR("Layer of the requested type was not found in packet");
			return false;
		}
	}

	bool Packet::removeFirstLayer()
	{
		Layer* firstLayer = getFirstLayer();
		if (firstLayer == nullptr)
		{
			PCPP_LOG_ERROR("Packet has no layers");
			return false;
		}

		return removeLayer(firstLayer, true);
	}

	bool Packet::removeLastLayer()
	{
		Layer* lastLayer = getLastLayer();
		if (lastLayer == nullptr)
		{
			PCPP_LOG_ERROR("Packet has no layers");
			return false;
		}

		return removeLayer(lastLayer, true);
	}

	bool Packet::removeAllLayersAfter(Layer* layer)
	{
		Layer* curLayer = layer->getNextLayer();
		while (curLayer != nullptr)
		{
			Layer* tempLayer = curLayer->getNextLayer();
			if (!removeLayer(curLayer, true))
				return false;
			curLayer = tempLayer;
		}

		return true;
	}

	Layer* Packet::detachLayer(ProtocolType layerType, int index)
	{
		Layer* layerToDetach = getLayerOfType(layerType, index);

		if (layerToDetach != nullptr)
		{
			if (removeLayer(layerToDetach, false))
				return layerToDetach;
			else
				return nullptr;
		}
		else
		{
			PCPP_LOG_ERROR("Layer of the requested type was not found in packet");
			return nullptr;
		}
	}

	bool Packet::removeLayer(Layer* layer, bool tryToDelete)
	{
		if (layer == nullptr)
		{
			PCPP_LOG_ERROR("Layer is nullptr");
			return false;
		}

		// verify layer is allocated to a packet
		if (!layer->isAllocatedToPacket())
		{
			PCPP_LOG_ERROR("Layer isn't allocated to any packet");
			return false;
		}

		// verify layer is allocated to *this* packet
		Layer* curLayer = layer;
		while (curLayer->m_PrevLayer != nullptr)
			curLayer = curLayer->m_PrevLayer;
		if (curLayer != m_FirstLayer)
		{
			PCPP_LOG_ERROR("Layer isn't allocated to this packet");
			return false;
		}

		// before removing the layer's data, copy it so it can be later assigned as the removed layer's data
		size_t headerLen = layer->getHeaderLen();
		size_t layerOldDataSize = headerLen;
		auto layerOldData = std::make_unique<uint8_t[]>(layerOldDataSize);
		memcpy(layerOldData.get(), layer->m_Data, layerOldDataSize);

		// remove data from raw packet
		size_t numOfBytesToRemove = headerLen;
		int indexOfDataToRemove = layer->m_Data - m_RawPacket->getRawData();
		if (!m_RawPacket->removeData(indexOfDataToRemove, numOfBytesToRemove))
		{
			PCPP_LOG_ERROR("Couldn't remove data from packet");
			return false;
		}

		// remove layer from layers linked list
		if (layer->m_PrevLayer != nullptr)
			layer->m_PrevLayer->setNextLayer(layer->m_NextLayer);
		if (layer->m_NextLayer != nullptr)
			layer->m_NextLayer->setPrevLayer(layer->m_PrevLayer);

		// take care of head and tail ptrs
		if (m_FirstLayer == layer)
			m_FirstLayer = layer->m_NextLayer;
		if (m_LastLayer == layer)
			m_LastLayer = layer->m_PrevLayer;
		layer->setNextLayer(nullptr);
		layer->setPrevLayer(nullptr);

		// get packet trailer len if exists
		size_t packetTrailerLen = 0;
		if (m_LastLayer != nullptr && m_LastLayer->getProtocol() == PacketTrailer)
			packetTrailerLen = m_LastLayer->getDataLen();

		// re-calculate all layers data ptr and data length

		// first, get ptr and data length of the raw packet
		const uint8_t* dataPtr = m_RawPacket->getRawData();
		size_t dataLen = static_cast<size_t>(m_RawPacket->getRawDataLen());

		curLayer = m_FirstLayer;

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each one
		while (curLayer != nullptr)
		{
			// set data ptr to layer
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// there is an assumption here that the packet trailer, if exists, corresponds to the L2 (data link) layers.
			// so if there is a packet trailer and this layer is L2 (data link), set its data length to contain the
			// whole data, including the packet trailer. If this layer is L3-7, exclude the packet trailer from its data
			// length
			if (curLayer->getOsiModelLayer() == OsiModelDataLinkLayer)
				curLayer->m_DataLen = dataLen;
			else
				curLayer->m_DataLen = dataLen - packetTrailerLen;

			// advance data ptr and data length
			dataPtr += curLayer->getHeaderLen();
			dataLen -= curLayer->getHeaderLen();

			// move to next layer
			curLayer = curLayer->getNextLayer();
		}

		// if layer was allocated by this packet and tryToDelete flag is set, delete it
		if (tryToDelete && layer->m_AllocationInfo.ownedByPacket)
		{
			delete layer;
		}
		// if layer was not allocated by this packet or the tryToDelete is not set, detach it from the packet so it can
		// be reused
		else
		{
			layer->m_AllocationInfo.detach();
			layer->m_Data = layerOldData.release();
			layer->m_DataLen = layerOldDataSize;
		}

		return true;
	}

	Layer* Packet::getLayerOfType(ProtocolType layerType, int index) const
	{
		int curIndex = 0;
		for (Layer* curLayer = getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			if (curLayer->getProtocol() != layerType)
				continue;

			if (curIndex == index)
				return curLayer;

			curIndex++;
		}

		return nullptr;
	}

	bool Packet::isPacketOfType(ProtocolType protocolType) const
	{
		for (Layer* curLayer = getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			if (curLayer->getProtocol() == protocolType)
			{
				return true;
			}
		}

		return false;
	}

	bool Packet::isPacketOfType(ProtocolTypeFamily protocolTypeFamily) const
	{
		Layer* curLayer = getFirstLayer();
		while (curLayer != nullptr)
		{
			if (curLayer->isMemberOfProtocolFamily(protocolTypeFamily))
			{
				return true;
			}
			curLayer = curLayer->getNextLayer();
		}

		return false;
	}

	bool Packet::extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend)
	{
		if (layer == nullptr)
		{
			PCPP_LOG_ERROR("Layer is nullptr");
			return false;
		}

		// verify layer is allocated to this packet
		if (!(layer->getAttachedPacket() == this))
		{
			PCPP_LOG_ERROR("Layer isn't allocated to this packet");
			return false;
		}

		if (m_RawPacket->getRawDataLen() + numOfBytesToExtend > m_MaxPacketLen)
		{
			if (!m_CanReallocateData)
			{
				PCPP_LOG_ERROR(
				    "With the layer extended size the packet will exceed the size of the pre-allocated buffer: "
				    << m_MaxPacketLen << " bytes");
				return false;
			}
			// reallocate to maximum value of: twice the max size of the packet or max size + new required length
			if (m_RawPacket->getRawDataLen() + numOfBytesToExtend > m_MaxPacketLen * 2)
				reallocateRawData(m_RawPacket->getRawDataLen() + numOfBytesToExtend + m_MaxPacketLen);
			else
				reallocateRawData(m_MaxPacketLen * 2);
		}

		// insert layer data to raw packet
		int indexToInsertData = layer->m_Data + offsetInLayer - m_RawPacket->getRawData();
		// passing nullptr to insertData will move the data by numOfBytesToExtend
		// no new data has to be created for this insertion which saves at least little time
		// this move operation occurs on already allocated memory, which is backed by the reallocation if's provided
		// above if offsetInLayer == layer->getHeaderLen() insertData will not move any data but only increase the
		// packet size by numOfBytesToExtend
		m_RawPacket->insertData(indexToInsertData, nullptr, numOfBytesToExtend);

		// re-calculate all layers data ptr and data length
		const uint8_t* dataPtr = m_RawPacket->getRawData();

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each layer
		bool passedExtendedLayer = false;
		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			if (dataPtr > m_RawPacket->getRawData() + m_RawPacket->getRawDataLen())
			{
				PCPP_LOG_ERROR("Layer data pointer exceeds packet's boundary");
				return false;
			}

			// set the data ptr
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// set a flag if arrived to the layer being extended
			if (curLayer->getPrevLayer() == layer)
				passedExtendedLayer = true;

			// change the data length only for layers who come before the extended layer. For layers who come after,
			// data length isn't changed
			if (!passedExtendedLayer)
				curLayer->m_DataLen += numOfBytesToExtend;

			// assuming header length of the layer that requested to be extended hasn't been enlarged yet
			size_t headerLen = curLayer->getHeaderLen() + (curLayer == layer ? numOfBytesToExtend : 0);
			dataPtr += headerLen;
		}

		return true;
	}

	bool Packet::shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten)
	{
		if (layer == nullptr)
		{
			PCPP_LOG_ERROR("Layer is nullptr");
			return false;
		}

		// verify layer is allocated to this packet
		if (!(layer->getAttachedPacket() == this))
		{
			PCPP_LOG_ERROR("Layer isn't allocated to this packet");
			return false;
		}

		// remove data from raw packet
		int indexOfDataToRemove = layer->m_Data + offsetInLayer - m_RawPacket->getRawData();
		if (!m_RawPacket->removeData(indexOfDataToRemove, numOfBytesToShorten))
		{
			PCPP_LOG_ERROR("Couldn't remove data from packet");
			return false;
		}

		// re-calculate all layers data ptr and data length
		const uint8_t* dataPtr = m_RawPacket->getRawData();

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each layer
		Layer* curLayer = m_FirstLayer;
		bool passedExtendedLayer = false;
		while (curLayer != nullptr)
		{
			if (dataPtr > m_RawPacket->getRawData() + m_RawPacket->getRawDataLen())
			{
				PCPP_LOG_ERROR("Layer data pointer exceeds packet's boundary");
				return false;
			}

			// set the data ptr
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// set a flag if arrived to the layer being shortened
			if (curLayer->getPrevLayer() == layer)
				passedExtendedLayer = true;

			size_t headerLen = curLayer->getHeaderLen();

			// change the data length only for layers who come before the shortened layer. For layers who come after,
			// data length isn't changed
			if (!passedExtendedLayer)
				curLayer->m_DataLen -= numOfBytesToShorten;

			// assuming header length of the layer that requested to be extended hasn't been enlarged yet
			headerLen -= (curLayer == layer ? numOfBytesToShorten : 0);
			dataPtr += headerLen;
			curLayer = curLayer->getNextLayer();
		}

		return true;
	}

	void Packet::computeCalculateFields()
	{
		// calculated fields should be calculated from top layer to bottom layer
		for (Layer* curLayer = m_LastLayer; curLayer != nullptr; curLayer = curLayer->getPrevLayer())
		{
			curLayer->computeCalculateFields();
		}
	}

	std::string Packet::printPacketInfo(bool timeAsLocalTime) const
	{
		std::ostringstream dataLenStream;
		dataLenStream << m_RawPacket->getRawDataLen();

		// convert raw packet timestamp to printable format
		timespec timestamp = m_RawPacket->getPacketTimeStamp();
		time_t nowtime = timestamp.tv_sec;
		struct tm* nowtm = nullptr;
#if __cplusplus > 199711L && !defined(_WIN32)
		// localtime_r and gmtime_r are thread-safe versions of localtime and gmtime,
		// but they're defined only in newer compilers (>= C++0x).
		// on Windows localtime and gmtime are already thread-safe so there is not need
		// to use localtime_r and gmtime_r
		struct tm nowtm_r;
		if (timeAsLocalTime)
			nowtm = localtime_r(&nowtime, &nowtm_r);
		else
			nowtm = gmtime_r(&nowtime, &nowtm_r);

		if (nowtm != nullptr)
			nowtm = &nowtm_r;
#else
		// on Window compilers localtime and gmtime are already thread safe.
		// in old compilers (< C++0x) gmtime_r and localtime_r were not defined so we have to fall back to localtime and
		// gmtime
		if (timeAsLocalTime)
			nowtm = localtime(&nowtime);
		else
			nowtm = gmtime(&nowtime);
#endif

		char buf[128];
		if (nowtm != nullptr)
		{
			char tmbuf[64];
			strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
			snprintf(buf, sizeof(buf), "%s.%09lu", tmbuf, (unsigned long)timestamp.tv_nsec);
		}
		else
			snprintf(buf, sizeof(buf), "0000-00-00 00:00:00.000000000");

		return "Packet length: " + dataLenStream.str() + " [Bytes], Arrival time: " + std::string(buf);
	}

	Layer* Packet::createFirstLayer(LinkLayerType linkType)
	{
		size_t rawDataLen = (size_t)m_RawPacket->getRawDataLen();
		if (rawDataLen == 0)
			return nullptr;

		const uint8_t* rawData = m_RawPacket->getRawData();

		switch (linkType)
		{
		case LinkLayerType::LINKTYPE_ETHERNET:
		{
			if (EthLayer::isDataValid(rawData, rawDataLen))
			{
				return new EthLayer(const_cast<uint8_t*>(rawData), rawDataLen, this);
			}
			if (EthDot3Layer::isDataValid(rawData, rawDataLen))
			{
				return new EthDot3Layer(const_cast<uint8_t*>(rawData), rawDataLen, this);
			}
			break;
		}
		case LinkLayerType::LINKTYPE_LINUX_SLL:
		{
			return new SllLayer(const_cast<uint8_t*>(rawData), rawDataLen, this);
		}
		case LinkLayerType::LINKTYPE_LINUX_SLL2:
		{
			if (Sll2Layer::isDataValid(rawData, rawDataLen))
			{
				return new Sll2Layer(const_cast<uint8_t*>(rawData), rawDataLen, this);
			}
			break;
		}
		case LinkLayerType::LINKTYPE_NULL:
		{
			if (NullLoopbackLayer::isDataValid(rawData, rawDataLen))
			{
				return new NullLoopbackLayer(const_cast<uint8_t*>(rawData), rawDataLen, this);
			}
			break;
		}
		case LinkLayerType::LINKTYPE_RAW:
		case LinkLayerType::LINKTYPE_DLT_RAW1:
		case LinkLayerType::LINKTYPE_DLT_RAW2:
		{
			uint8_t ipVer = rawData[0] & 0xf0;
			if (ipVer == 0x40 && IPv4Layer::isDataValid(rawData, rawDataLen))
			{
				return new IPv4Layer(const_cast<uint8_t*>(rawData), rawDataLen, nullptr, this);
			}
			if (ipVer == 0x60 && IPv6Layer::isDataValid(rawData, rawDataLen))
			{
				return new IPv6Layer(const_cast<uint8_t*>(rawData), rawDataLen, nullptr, this);
			}
			break;
		}
		case LinkLayerType::LINKTYPE_IPV4:
		{
			if (IPv4Layer::isDataValid(rawData, rawDataLen))
			{
				return new IPv4Layer(const_cast<uint8_t*>(rawData), rawDataLen, nullptr, this);
			}
			break;
		}
		case LinkLayerType::LINKTYPE_IPV6:
		{
			if (IPv6Layer::isDataValid(rawData, rawDataLen))
			{
				return new IPv6Layer(const_cast<uint8_t*>(rawData), rawDataLen, nullptr, this);
			}
			break;
		}
		case LinkLayerType::LINKTYPE_NFLOG:
		{
			if (NflogLayer::isDataValid(rawData, rawDataLen))
			{
				return new NflogLayer(const_cast<uint8_t*>(rawData), rawDataLen, this);
			}
			break;
		}
		case LinkLayerType::LINKTYPE_C_HDLC:
		{
			if (CiscoHdlcLayer::isDataValid(rawData, rawDataLen))
			{
				return new CiscoHdlcLayer(const_cast<uint8_t*>(rawData), rawDataLen, this);
			}
			break;
		}
		default:
			// For all other link types, we don't have a specific layer. Just break and create a PayloadLayer
			break;
		}

		// unknown link type
		return new PayloadLayer(const_cast<uint8_t*>(rawData), rawDataLen, nullptr, this);
	}

	std::string Packet::toString(bool timeAsLocalTime) const
	{
		std::vector<std::string> stringList;
		toStringList(stringList, timeAsLocalTime);
		return std::accumulate(stringList.begin(), stringList.end(), std::string(),
		                       [](std::string a, const std::string& b) { return std::move(a) + b + '\n'; });
	}

	void Packet::toStringList(std::vector<std::string>& result, bool timeAsLocalTime) const
	{
		result.clear();
		result.push_back(printPacketInfo(timeAsLocalTime));

		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			result.push_back(curLayer->toString());
		}
	}

}  // namespace pcpp
