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
	std::vector<Layer*> m_LayersInitialized;
	bool m_FreeRawPacket;

public:
	Packet(size_t maxPacketLen);
	Packet(RawPacket* rawPacket);
	virtual ~Packet();

	inline RawPacket* getRawPacket() { return m_RawPacket; }

	inline Layer* getFirstLayer() { return m_FirstLayer; }
	inline Layer* getLastLayer() { return m_LastLayer; }
	bool addLayer(Layer* newLayer);
	bool insertLayer(Layer* prevLayer, Layer* newLayer);
	bool removeLayer(Layer* layer);
	Layer* getLayerOfType(ProtocolType type);
	Layer* getNextLayerOfType(Layer* after, ProtocolType type);
	inline bool isPacketOfType(ProtocolType protocolType) { return m_ProtocolTypes & protocolType; }
	void computeCalculateFields();

private:
	// can't use copy c'tor and assignment operator
	Packet(const Packet& other );
	Packet& operator=(const Packet& other);

	bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
	bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

	void reallocateRawData(size_t newSize);
};

#endif /* PACKETPP_PACKET */
