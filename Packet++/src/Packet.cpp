#define LOG_MODULE PacketLogModulePacket

#include "Packet.h"
#include "EthLayer.h"
#include "SllLayer.h"
#include "NullLoopbackLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "PacketTrailerLayer.h"
#include "Logger.h"
#include <string.h>
#include <typeinfo>
#include <sstream>
#ifdef _MSC_VER
#include <time.h>
#include "SystemUtils.h"
#endif


namespace pcpp
{

Packet::Packet(size_t maxPacketLen) :
	m_RawPacket(NULL),
	m_FirstLayer(NULL),
	m_LastLayer(NULL),
	m_ProtocolTypes(UnknownProtocol),
	m_MaxPacketLen(maxPacketLen),
	m_FreeRawPacket(true)
{
	timeval time;
	gettimeofday(&time, NULL);
	uint8_t* data = new uint8_t[m_MaxPacketLen];
	memset(data, 0, m_MaxPacketLen);
	m_RawPacket = new RawPacket((const uint8_t*)data, 0, time, true, LINKTYPE_ETHERNET);
}

void Packet::setRawPacket(RawPacket* rawPacket, bool freeRawPacket, ProtocolType parseUntil, OsiModelLayer parseUntilLayer)
{
	destructPacketData();

	m_FirstLayer = NULL;
	m_LastLayer = NULL;
	m_ProtocolTypes = UnknownProtocol;
	m_MaxPacketLen = rawPacket->getRawDataLen();
	m_FreeRawPacket = freeRawPacket;
	m_RawPacket = rawPacket;
	if (m_RawPacket == NULL)
		return;

	LinkLayerType linkType = m_RawPacket->getLinkLayerType();

	if (linkType == LINKTYPE_ETHERNET)
	{
		m_FirstLayer = new EthLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), this);
	}
	else if (linkType == LINKTYPE_LINUX_SLL)
	{
		m_FirstLayer = new SllLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), this);
	}
	else if (linkType == LINKTYPE_NULL)
	{
		m_FirstLayer = new NullLoopbackLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), this);
	}
	else if (linkType == LINKTYPE_RAW || linkType == LINKTYPE_DLT_RAW1 || linkType == LINKTYPE_DLT_RAW2)
	{
		uint8_t ipVer = m_RawPacket->getRawData()[0] & 0xf0;
		if (ipVer == 0x40)
			m_FirstLayer = new IPv4Layer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), NULL, this);
		else if (ipVer == 0x60)
			m_FirstLayer = new IPv6Layer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), NULL, this);
		else
			m_FirstLayer = new PayloadLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), NULL, this);
	}
	else // unknown link type
	{
		m_FirstLayer = new EthLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), this);
	}

	m_LastLayer = m_FirstLayer;
	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL && (curLayer->getProtocol() & parseUntil) == 0 && curLayer->getOsiModelLayer() <= parseUntilLayer)
	{
		m_ProtocolTypes |= curLayer->getProtocol();
		curLayer->parseNextLayer();
		curLayer->m_IsAllocatedInPacket = true;
		curLayer = curLayer->getNextLayer();
		if (curLayer != NULL)
			m_LastLayer = curLayer;
	}

	if (curLayer != NULL && (curLayer->getProtocol() & parseUntil) != 0)
	{
		m_ProtocolTypes |= curLayer->getProtocol();
		curLayer->m_IsAllocatedInPacket = true;
	}

	if (curLayer != NULL &&  curLayer->getOsiModelLayer() > parseUntilLayer)
	{
		m_LastLayer = curLayer->getPrevLayer();
		delete curLayer;
		m_LastLayer->m_NextLayer = NULL;
	}

	if (parseUntil == UnknownProtocol && parseUntilLayer == OsiModelLayerUnknown)
	{
		// find if there is data left in the raw packet that doesn't belong to any layer. In that case it's probably a packet trailer.
		// create a PacketTrailerLayer layer and add it at the end of the packet
		int trailerLen = (int)((m_RawPacket->getRawData() + m_RawPacket->getRawDataLen()) - (m_LastLayer->getData() + m_LastLayer->getDataLen()));
		if (trailerLen > 0)
		{
			PacketTrailerLayer* trailerLayer = new PacketTrailerLayer(
					(uint8_t*)(m_LastLayer->getData() + m_LastLayer->getDataLen()),
					trailerLen,
					m_LastLayer,
					this);

			trailerLayer->m_IsAllocatedInPacket = true;
			m_LastLayer->setNextLayer(trailerLayer);
			m_LastLayer = trailerLayer;
			m_ProtocolTypes |= trailerLayer->getProtocol();
		}
	}
}

Packet::Packet(RawPacket* rawPacket, bool freeRawPacket, ProtocolType parseUntil, OsiModelLayer parseUntilLayer)
{
	m_FreeRawPacket = false;
	m_RawPacket = NULL;
	m_FirstLayer = NULL;
	setRawPacket(rawPacket, freeRawPacket, parseUntil, parseUntilLayer);
}

Packet::Packet(RawPacket* rawPacket, ProtocolType parseUntil)
{
	m_FreeRawPacket = false;
	m_RawPacket = NULL;
	m_FirstLayer = NULL;
	setRawPacket(rawPacket, false, parseUntil, OsiModelLayerUnknown);
}

Packet::Packet(RawPacket* rawPacket, OsiModelLayer parseUntilLayer)
{
	m_FreeRawPacket = false;
	m_RawPacket = NULL;
	m_FirstLayer = NULL;
	setRawPacket(rawPacket, false, UnknownProtocol, parseUntilLayer);
}

Packet::Packet(const Packet& other)
{
	copyDataFrom(other);
}

void Packet::destructPacketData()
{
	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		Layer* nextLayer = curLayer->getNextLayer();
		if (curLayer->m_IsAllocatedInPacket)
			delete curLayer;
		curLayer = nextLayer;
	}

	if (m_RawPacket != NULL && m_FreeRawPacket)
	{
		delete m_RawPacket;
	}
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
	m_ProtocolTypes = other.m_ProtocolTypes;
	m_FirstLayer = new EthLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), this);
	m_LastLayer = m_FirstLayer;
	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		curLayer->parseNextLayer();
		curLayer->m_IsAllocatedInPacket = true;
		curLayer = curLayer->getNextLayer();
		if (curLayer != NULL)
			m_LastLayer = curLayer;
	}
}

void Packet::reallocateRawData(size_t newSize)
{
	LOG_DEBUG("Allocating packet to new size: %d", (int)newSize);

	// allocate a new array with size newSize
	m_MaxPacketLen = newSize;

	// set the new array to RawPacket
	if (!m_RawPacket->reallocateData(m_MaxPacketLen))
	{
		LOG_ERROR("Couldn't reallocate data of raw packet to %d bytes", (int)m_MaxPacketLen);
		return;
	}

	// set all data pointers in layers to the new array address
	const uint8_t* dataPtr = m_RawPacket->getRawData();

	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		LOG_DEBUG("Setting new data pointer to layer '%s'", typeid(curLayer).name());
		curLayer->m_Data = (uint8_t*)dataPtr;
		dataPtr += curLayer->getHeaderLen();
		curLayer = curLayer->getNextLayer();
	}
}

bool Packet::addLayer(Layer* newLayer)
{
	return insertLayer(m_LastLayer, newLayer);
}

bool Packet::insertLayer(Layer* prevLayer, Layer* newLayer)
{
	if (newLayer == NULL)
	{
		LOG_ERROR("Layer to add is NULL");
		return false;
	}

	if (newLayer->isAllocatedToPacket())
	{
		LOG_ERROR("Layer is already allocated to another packet. Cannot use layer in more than one packet");
		return false;
	}

	if (prevLayer != NULL && prevLayer->getProtocol() == PacketTrailer)
	{
		LOG_ERROR("Cannot insert layer after packet trailer");
		return false;
	}

	if (m_RawPacket->getRawDataLen() + newLayer->getHeaderLen() > m_MaxPacketLen)
	{
		// reallocate to maximum value of: twice the max size of the packet or max size + new required length
		if (m_RawPacket->getRawDataLen() + newLayer->getHeaderLen() > m_MaxPacketLen*2)
			reallocateRawData(m_RawPacket->getRawDataLen() + newLayer->getHeaderLen() + m_MaxPacketLen);
		else
			reallocateRawData(m_MaxPacketLen*2);
	}

	size_t appendDataLen = newLayer->getHeaderLen();

	// insert layer data to raw packet
	int indexToInsertData = 0;
	if (prevLayer != NULL)
		indexToInsertData = prevLayer->m_Data+prevLayer->getHeaderLen() - m_RawPacket->getRawData();
	m_RawPacket->insertData(indexToInsertData, newLayer->m_Data, appendDataLen);

	//delete previous layer data
	delete[] newLayer->m_Data;

	// add layer to layers linked list
	if (prevLayer != NULL)
	{
		newLayer->setNextLayer(prevLayer->getNextLayer());
		newLayer->setPrevLayer(prevLayer);
		prevLayer->setNextLayer(newLayer);
	}
	else //prevLayer == NULL
	{
		newLayer->setNextLayer(m_FirstLayer);
		if (m_FirstLayer != NULL)
			m_FirstLayer->setPrevLayer(newLayer);
		m_FirstLayer = newLayer;
	}

	if (newLayer->getNextLayer() == NULL)
		m_LastLayer = newLayer;
	else
		newLayer->getNextLayer()->setPrevLayer(newLayer);

	// assign layer with this packet only
	newLayer->m_Packet = this;

	// re-calculate all layers data ptr and data length

	// first, get ptr and data length of the raw packet
	const uint8_t* dataPtr = m_RawPacket->getRawData();
	size_t dataLen = (size_t)m_RawPacket->getRawDataLen();

	// if a packet trailer exists, get its length
	size_t packetTrailerLen = 0;
	if (m_LastLayer != NULL && m_LastLayer->getProtocol() == PacketTrailer)
		packetTrailerLen = m_LastLayer->getDataLen();

	// go over all layers from the first layer to the last layer and set the data ptr and data length for each one
	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		// set data ptr to layer
		curLayer->m_Data = (uint8_t*)dataPtr;

		// there is an assumption here that the packet trailer, if exists, corresponds to the L2 (data link) layers.
		// so if there is a packet trailer and this layer is L2 (data link), set its data length to contain the whole data, including the
		// packet trailer. If this layer is L3-7, exclude the packet trailer from its data length
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

	// add layer protocol to protocol collection
	m_ProtocolTypes |= newLayer->getProtocol();
	return true;
}

bool Packet::removeLayer(Layer* layer)
{
	if (layer == NULL)
	{
		LOG_ERROR("Layer is NULL");
		return false;
	}

	// verify layer is allocated to a packet
	if (!layer->isAllocatedToPacket())
	{
		LOG_ERROR("Layer isn't allocated to any packet");
		return false;
	}

	// verify layer is allocated to *this* packet
	Layer* curLayer = layer;
	while (curLayer->m_PrevLayer != NULL)
		curLayer = curLayer->m_PrevLayer;
	if (curLayer != m_FirstLayer)
	{
		LOG_ERROR("Layer isn't allocated to this packet");
		return false;
	}

	// remove data from raw packet
	size_t numOfBytesToRemove = layer->getHeaderLen();
	int indexOfDataToRemove = layer->m_Data - m_RawPacket->getRawData();
	if (!m_RawPacket->removeData(indexOfDataToRemove, numOfBytesToRemove))
	{
		LOG_ERROR("Couldn't remove data from packet");
		return false;
	}

	// remove layer from layers linked list
	if (layer->m_PrevLayer != NULL)
		layer->m_PrevLayer->setNextLayer(layer->m_NextLayer);
	if (layer->m_NextLayer != NULL)
		layer->m_NextLayer->setPrevLayer(layer->m_PrevLayer);

	// take care of head and tail ptrs
	if (m_FirstLayer == layer)
		m_FirstLayer = layer->m_NextLayer;
	if (m_LastLayer == layer)
		m_LastLayer = layer->m_PrevLayer;
	layer->setNextLayer(NULL);
	layer->setPrevLayer(NULL);

	// get packet trailer len if exists
	size_t packetTrailerLen = 0;
	if (m_LastLayer != NULL && m_LastLayer->getProtocol() == PacketTrailer)
		packetTrailerLen = m_LastLayer->getDataLen();

	// re-calculate all layers data ptr and data length

	// first, get ptr and data length of the raw packet
	const uint8_t* dataPtr = m_RawPacket->getRawData();
	size_t dataLen = (size_t)m_RawPacket->getRawDataLen();

	curLayer = m_FirstLayer;

	// a flag to be set if there is another layer in this packet with the same protocol
	bool anotherLayerWithSameProtocolExists = false;

	// go over all layers from the first layer to the last layer and set the data ptr and data length for each one
	while (curLayer != NULL)
	{
		// set data ptr to layer
		curLayer->m_Data = (uint8_t*)dataPtr;

		// there is an assumption here that the packet trailer, if exists, corresponds to the L2 (data link) layers.
		// so if there is a packet trailer and this layer is L2 (data link), set its data length to contain the whole data, including the
		// packet trailer. If this layer is L3-7, exclude the packet trailer from its data length
		if (curLayer->getOsiModelLayer() == OsiModelDataLinkLayer)
			curLayer->m_DataLen = dataLen;
		else
			curLayer->m_DataLen = dataLen - packetTrailerLen;

		// check if current layer's protocol is the same as removed layer protocol and set the flag accordingly
		if (curLayer->getProtocol() == layer->getProtocol())
			anotherLayerWithSameProtocolExists = true;

		// advance data ptr and data length
		dataPtr += curLayer->getHeaderLen();
		dataLen -= curLayer->getHeaderLen();

		// move to next layer
		curLayer = curLayer->getNextLayer();
	}

	// remove layer protocol from protocol list if necessary
	if (!anotherLayerWithSameProtocolExists)
		m_ProtocolTypes &= ~((uint64_t)layer->getProtocol());

	// if layer was allocated by this packet, delete it
	if (layer->m_IsAllocatedInPacket)
		delete layer;

	return true;
}

bool Packet::extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend)
{
	if (layer == NULL)
	{
		LOG_ERROR("Layer is NULL");
		return false;
	}

	// verify layer is allocated to this packet
	if (!(layer->m_Packet == this))
	{
		LOG_ERROR("Layer isn't allocated to this packet");
		return false;
	}

	if (m_RawPacket->getRawDataLen() + numOfBytesToExtend > m_MaxPacketLen)
	{
		// reallocate to maximum value of: twice the max size of the packet or max size + new required length
		if (m_RawPacket->getRawDataLen() + numOfBytesToExtend > m_MaxPacketLen*2)
			reallocateRawData(m_RawPacket->getRawDataLen() + numOfBytesToExtend + m_MaxPacketLen);
		else
			reallocateRawData(m_MaxPacketLen*2);
	}

	// insert layer data to raw packet
	int indexToInsertData = layer->m_Data + offsetInLayer - m_RawPacket->getRawData();
	uint8_t* tempData = new uint8_t[numOfBytesToExtend];
	m_RawPacket->insertData(indexToInsertData, tempData, numOfBytesToExtend);
	delete[] tempData;

	// re-calculate all layers data ptr and data length
	const uint8_t* dataPtr = m_RawPacket->getRawData();

	// go over all layers from the first layer to the last layer and set the data ptr and data length for each layer
	Layer* curLayer = m_FirstLayer;
	bool passedExtendedLayer = false;
	while (curLayer != NULL)
	{
		// set the data ptr
		curLayer->m_Data = (uint8_t*)dataPtr;

		// set a flag if arrived to the layer being extended
		if (curLayer->getPrevLayer() == layer)
			passedExtendedLayer = true;

		// change the data length only for layers who come before the extended layer. For layers who come after, data length isn't changed
		if (!passedExtendedLayer)
			curLayer->m_DataLen += numOfBytesToExtend;

		// assuming header length of the layer that requested to be extended hasn't been enlarged yet
		size_t headerLen = curLayer->getHeaderLen() + (curLayer == layer ? numOfBytesToExtend : 0);
		dataPtr += headerLen;
		curLayer = curLayer->getNextLayer();
	}

	return true;
}

bool Packet::shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten)
{
	if (layer == NULL)
	{
		LOG_ERROR("Layer is NULL");
		return false;
	}

	// verify layer is allocated to this packet
	if (!(layer->m_Packet == this))
	{
		LOG_ERROR("Layer isn't allocated to this packet");
		return false;
	}

	// remove data from raw packet
	int indexOfDataToRemove = layer->m_Data + offsetInLayer - m_RawPacket->getRawData();
	if (!m_RawPacket->removeData(indexOfDataToRemove, numOfBytesToShorten))
	{
		LOG_ERROR("Couldn't remove data from packet");
		return false;
	}

	// re-calculate all layers data ptr and data length
	const uint8_t* dataPtr = m_RawPacket->getRawData();

	// go over all layers from the first layer to the last layer and set the data ptr and data length for each layer
	Layer* curLayer = m_FirstLayer;
	bool passedExtendedLayer = false;
	while (curLayer != NULL)
	{
		// set the data ptr
		curLayer->m_Data = (uint8_t*)dataPtr;

		// set a flag if arrived to the layer being shortened
		if (curLayer->getPrevLayer() == layer)
			passedExtendedLayer = true;

		// change the data length only for layers who come before the shortened layer. For layers who come after, data length isn't changed
		if (!passedExtendedLayer)
			curLayer->m_DataLen -= numOfBytesToShorten;

		// assuming header length of the layer that requested to be extended hasn't been enlarged yet
		size_t headerLen = curLayer->getHeaderLen() - (curLayer == layer ? numOfBytesToShorten : 0);
		dataPtr += headerLen;
		curLayer = curLayer->getNextLayer();
	}

	return true;
}

void Packet::computeCalculateFields()
{
	// calculated fields should be calculated from top layer to bottom layer

	Layer* curLayer = m_LastLayer;
	while (curLayer != NULL)
	{
		curLayer->computeCalculateFields();
		curLayer = curLayer->getPrevLayer();
	}
}

Packet::~Packet()
{
	destructPacketData();
}

std::string Packet::printPacketInfo(bool timeAsLocalTime)
{
	std::ostringstream dataLenStream;
	dataLenStream << m_RawPacket->getRawDataLen();

	// convert raw packet timestamp to printable format
	timeval timestamp = m_RawPacket->getPacketTimeStamp();
	time_t nowtime = timestamp.tv_sec;
	struct tm *nowtm = NULL;
	if (timeAsLocalTime)
		nowtm = localtime(&nowtime);
	else
		nowtm = gmtime(&nowtime);

	char tmbuf[64], buf[64];
	if (nowtm != NULL)
	{
		strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
		snprintf(buf, sizeof(buf), "%s.%06lu", tmbuf, timestamp.tv_usec);
	}
	else
		snprintf(buf, sizeof(buf), "0000-00-00 00:00:00.000000");
	
	return "Packet length: " + dataLenStream.str() + " [Bytes], Arrival time: " + std::string(buf);
}

std::string Packet::toString(bool timeAsLocalTime)
{
	std::vector<std::string> stringList;
	std::string result;
	toStringList(stringList, timeAsLocalTime);
	for (std::vector<std::string>::iterator iter = stringList.begin(); iter != stringList.end(); iter++)
	{
		result += *iter + "\n";
	}

	return result;
}

void Packet::toStringList(std::vector<std::string>& result, bool timeAsLocalTime)
{
	result.clear();
	result.push_back(printPacketInfo(timeAsLocalTime));
	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		result.push_back(curLayer->toString());
		curLayer = curLayer->getNextLayer();
	}
}

} // namespace pcpp
