/*
 * PayloadLayer.h
 *
 *  Created on: 18 בספט 2014
 *      Author: Elad
 */

#ifndef PACKETPP_PAYLOAD_LAYER
#define PACKETPP_PAYLOAD_LAYER

#include <Layer.h>

class PayloadLayer : public Layer
{
public:
	PayloadLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) {}
	PayloadLayer(const uint8_t* data, size_t dataLen, bool selfAllocated);
	~PayloadLayer() {}

	inline uint8_t* getPayload() { return m_Data; }
	inline size_t getPayloadLen() { return m_DataLen; }

	// implement abstract methods
	void parseNextLayer() {}
	inline size_t getHeaderLen() { return m_DataLen; }
	void computeCalculateFields() {}

};


#endif /* PACKETPP_PAYLOAD_LAYER */
