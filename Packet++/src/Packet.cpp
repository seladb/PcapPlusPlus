#define LOG_MODULE PacketLogModulePacket

#include <Packet.h>
#include <EthLayer.h>
#include <SllLayer.h>
#include <Logger.h>
#include <string.h>
#include <typeinfo>
#include <sstream>

namespace pcpp
{

Packet::Packet(size_t maxPacketLen) :
	m_RawPacket(NULL),
	m_FirstLayer(NULL),
	m_LastLayer(NULL),
	m_ProtocolTypes(Unknown),
	m_MaxPacketLen(maxPacketLen),
	m_FreeRawPacket(true)
{
	timeval time;
	gettimeofday(&time, NULL);
	uint8_t* data = new uint8_t[m_MaxPacketLen];
	memset(data, 0, m_MaxPacketLen);
	m_RawPacket = new RawPacket((const uint8_t*)data, 0, time, true, LINKTYPE_ETHERNET);
}

void Packet::setRawPacket(RawPacket* rawPacket, bool freeRawPacket)
{
	destructPacketData();

	m_FirstLayer = NULL;
	m_LastLayer = NULL;
	m_ProtocolTypes = Unknown;
	m_MaxPacketLen = rawPacket->getRawDataLen();
	m_FreeRawPacket = freeRawPacket;
	m_RawPacket = rawPacket;
	if(m_RawPacket && m_RawPacket->getLinkLayerType() == LINKTYPE_LINUX_SLL)
	{
		m_FirstLayer = new SllLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), this);
	}
	else
	{
		m_FirstLayer = new EthLayer((uint8_t*)m_RawPacket->getRawData(), m_RawPacket->getRawDataLen(), this);
	}
	m_LastLayer = m_FirstLayer;
	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		m_ProtocolTypes |= curLayer->getProtocol();
		curLayer->parseNextLayer();
		m_LayersAllocatedInPacket.push_back(curLayer);
		curLayer = curLayer->getNextLayer();
		if (curLayer != NULL)
			m_LastLayer = curLayer;
	}
}

Packet::Packet(RawPacket* rawPacket, bool freeRawPacket)
{
	m_FreeRawPacket = false;
	m_RawPacket = NULL;
	setRawPacket(rawPacket, freeRawPacket);
}


Packet::Packet(RawPacket* rawPacket)
{
	m_FreeRawPacket = false;
	m_RawPacket = NULL;
	setRawPacket(rawPacket, false);
}


Packet::Packet(const Packet& other)
{
	copyDataFrom(other);
}

void Packet::destructPacketData()
{
	std::vector<Layer*>::iterator iter = m_LayersAllocatedInPacket.begin();
	while (iter != m_LayersAllocatedInPacket.end())
	{
		delete (*iter);
		iter = m_LayersAllocatedInPacket.erase(iter);
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
		m_LayersAllocatedInPacket.push_back(curLayer);
		curLayer = curLayer->getNextLayer();
		if (curLayer != NULL)
			m_LastLayer = curLayer;
	}
}

void Packet::reallocateRawData(size_t newSize)
{
	LOG_DEBUG("Allocating packet to new size: %d", newSize);

	// allocate a new array with size newSize
	m_MaxPacketLen = newSize;

	// set the new array to RawPacket
	if (!m_RawPacket->reallocateData(m_MaxPacketLen))
	{
		LOG_ERROR("Couldn't reallocate data of raw packet to %d bytes", m_MaxPacketLen);
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

	// assign layer with this packet only
	newLayer->m_Packet = this;

	// re-calculate all layers data ptr and data length
	const uint8_t* dataPtr = m_RawPacket->getRawData();
	int dataLen = m_RawPacket->getRawDataLen();

	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		curLayer->m_Data = (uint8_t*)dataPtr;
		curLayer->m_DataLen = dataLen;
		dataPtr += curLayer->getHeaderLen();
		dataLen -= curLayer->getHeaderLen();
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

	// re-calculate all layers data ptr and data length
	const uint8_t* dataPtr = m_RawPacket->getRawData();
	int dataLen = m_RawPacket->getRawDataLen();

	curLayer = m_FirstLayer;
	bool anotherLayerWithSameProtocolExists = false;
	while (curLayer != NULL)
	{
		curLayer->m_Data = (uint8_t*)dataPtr;
		curLayer->m_DataLen = dataLen;
		if (curLayer->getProtocol() == layer->getProtocol())
			anotherLayerWithSameProtocolExists = true;
		dataPtr += curLayer->getHeaderLen();
		dataLen -= curLayer->getHeaderLen();
		curLayer = curLayer->getNextLayer();
	}

	// remove layer protocol from protocol list if necessary
	if (!anotherLayerWithSameProtocolExists)
		m_ProtocolTypes &= ~((uint64_t)layer->getProtocol());

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
	uint8_t tempData[numOfBytesToExtend];
	m_RawPacket->insertData(indexToInsertData, tempData, numOfBytesToExtend);

	// re-calculate all layers data ptr and data length
	const uint8_t* dataPtr = m_RawPacket->getRawData();
	int dataLen = m_RawPacket->getRawDataLen();

	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		curLayer->m_Data = (uint8_t*)dataPtr;
		curLayer->m_DataLen = dataLen;
		// assuming header length of the layer that requested to be extended hasn't been enlarged yet
		size_t headerLen = curLayer->getHeaderLen() + (curLayer == layer ? numOfBytesToExtend : 0);
		dataPtr += headerLen;
		dataLen -= headerLen;
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
	int dataLen = m_RawPacket->getRawDataLen();

	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		curLayer->m_Data = (uint8_t*)dataPtr;
		curLayer->m_DataLen = dataLen;
		// assuming header length of the layer that requested to be extended hasn't been enlarged yet
		size_t headerLen = curLayer->getHeaderLen() - (curLayer == layer ? numOfBytesToShorten : 0);
		dataPtr += headerLen;
		dataLen -= headerLen;
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

std::string Packet::printPacketInfo()
{
	std::ostringstream dataLenStream;
	dataLenStream << m_RawPacket->getRawDataLen();

	// convert raw packet timestamp to printable format
	timeval timestamp = m_RawPacket->getPacketTimeStamp();
	time_t nowtime = timestamp.tv_sec;
	struct tm *nowtm;
	nowtm = localtime(&nowtime);
	char tmbuf[64], buf[64];
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06lu", tmbuf, timestamp.tv_usec);

	return "Packet length: " + dataLenStream.str() + " [Bytes], Arrival time: " + std::string(buf);
}

std::string Packet::printToString()
{
	std::vector<std::string> stringList;
	std::string result;
	printToStringList(stringList);
	for (std::vector<std::string>::iterator iter = stringList.begin(); iter != stringList.end(); iter++)
	{
		result += *iter + "\n";
	}

	return result;
}

void Packet::printToStringList(std::vector<std::string>& result)
{
	result.clear();
	result.push_back(printPacketInfo());
	Layer* curLayer = m_FirstLayer;
	while (curLayer != NULL)
	{
		result.push_back(curLayer->toString());
		curLayer = curLayer->getNextLayer();
	}
}

} // namespace pcpp
