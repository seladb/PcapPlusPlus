#ifndef PACKETPP_LAYER
#define PACKETPP_LAYER

#include <stdint.h>
#include <stdio.h>
#include "ProtocolType.h"

class Layer {
	friend class Packet;
protected:
	uint8_t* m_Data;
	size_t m_DataLen;
	bool m_DataAllocatedToPacket;
	ProtocolType m_Protocol;
	Layer* m_NextLayer;
	Layer* m_PrevLayer;

	Layer() : m_Data(NULL), m_DataLen(0), m_DataAllocatedToPacket(false), m_Protocol(Unknown), m_NextLayer(NULL), m_PrevLayer(NULL) { }

	Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) :
		m_Data(data), m_DataLen(dataLen),
		m_DataAllocatedToPacket(true), m_Protocol(Unknown),
		m_NextLayer(NULL), m_PrevLayer(prevLayer) {}

	inline void setNextLayer(Layer* nextLayer) { m_NextLayer = nextLayer; }
	inline void setPrevLayer(Layer* prevLayer) { m_PrevLayer = prevLayer; }

public:
	virtual ~Layer() { if (!m_DataAllocatedToPacket) delete m_Data; }

	inline Layer* getNextLayer() { return m_NextLayer; }
	inline ProtocolType getProtocol() { return m_Protocol; }
	inline size_t getDataLen() { return m_DataLen; }

	void copyData(uint8_t* toArr);

	// abstract methods
	virtual void parseNextLayer() = 0;
	virtual size_t getHeaderLen() = 0;
	virtual void computeCalculateFields() = 0;
private:
	// can't use copy c'tor and assignment operator
	Layer(const Layer& other );
	Layer& operator=(const Layer& other);
};

#endif /* PACKETPP_LAYER */
