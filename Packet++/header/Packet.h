#ifndef PACKETPP_PACKET
#define PACKETPP_PACKET

#include "RawPacket.h"
#include "Layer.h"
#include <vector>

class Packet {
	friend class Layer;
private:
	RawPacket* m_RawPacket;
	Layer* m_FirstLayer;
	Layer* m_LastLayer;
	uint64_t m_ProtocolTypes;
	size_t m_MaxPacketLen;
	std::vector<Layer*> m_LayersAllocatedInPacket;
	bool m_FreeRawPacket;

public:
	Packet(size_t maxPacketLen);
	Packet(RawPacket* rawPacket);
	virtual ~Packet();

	// copy c'tor
	Packet(const Packet& other);
	Packet& operator=(const Packet& other);

	inline RawPacket* getRawPacket() { return m_RawPacket; }

	inline Layer* getFirstLayer() { return m_FirstLayer; }
	inline Layer* getLastLayer() { return m_LastLayer; }
	bool addLayer(Layer* newLayer);
	bool insertLayer(Layer* prevLayer, Layer* newLayer);
	bool removeLayer(Layer* layer);

	template<class TLayer>
	TLayer* getLayerOfType();
	template<class TLayer>
	TLayer* getNextLayerOfType(Layer* after);

	inline bool isPacketOfType(ProtocolType protocolType) { return m_ProtocolTypes & protocolType; }
	void computeCalculateFields();

	std::string printToString();
	void printToStringList(std::vector<std::string>& result);

private:
	void copyDataFrom(const Packet& other);

	bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
	bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

	void reallocateRawData(size_t newSize);

	std::string printPacketInfo();
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

#endif /* PACKETPP_PACKET */
