#include "InfiniBandLayer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <string.h>
#include "EndianPortable.h"

namespace pcpp
{

    void InfiniBandLayer::parseNextLayer()
	{
        if (m_DataLen <= sizeof(rxe_bth))
			return;

		uint8_t* bthData = m_Data + sizeof(rxe_bth);
		size_t bthDataLen = m_DataLen - sizeof(rxe_bth);

        m_NextLayer = new PayloadLayer(bthData, bthDataLen, this, m_Packet);
    }

    void InfiniBandLayer::computeCalculateFields()
	{
        
	}

	std::string InfiniBandLayer::toString() const
	{
        std::ostringstream opCodeStream;
        opCodeStream << getOpcode();

        return "InfiniBand Layer, Opcode: " + opCodeStream.str();
	}

    
    uint8_t InfiniBandLayer::getOpcode() const
    {
        return getBthHeader()->opcode;
    }
}