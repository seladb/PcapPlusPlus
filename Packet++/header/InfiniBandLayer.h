#pragma once

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
    /*
    * IBA header types and methods
    *
    * Some of these are for reference and completeness only since
    * rxe does not currently support RD transport
    * most of this could be moved into IB core. ib_pack.h has
    * part of this but is incomplete
    *
    * Header specific routines to insert/extract values to/from headers
    * the routines that are named __hhh_(set_)fff() take a pointer to a
    * hhh header and get(set) the fff field. The routines named
    * hhh_(set_)fff take a packet info struct and find the
    * header and field based on the opcode in the packet.
    * Conversion to/from network byte order from cpu order is also done.
    */

    #define RXE_ICRC_SIZE		(4)
    #define RXE_MAX_HDR_LENGTH	(80)

    /******************************************************************************
     * Base Transport Header
     ******************************************************************************/
#pragma pack(push, 1)
    struct rxe_bth
    {
        uint8_t			    opcode;
        uint8_t			    flags;
        uint16_t			pkey;
        uint32_t			qpn;
        uint32_t			apsn;
    };
#pragma pack(pop)

    #define BTH_TVER		(0)
    #define BTH_DEF_PKEY		(0xffff)

    #define BTH_SE_MASK		(0x80)
    #define BTH_MIG_MASK		(0x40)
    #define BTH_PAD_MASK		(0x30)
    #define BTH_TVER_MASK		(0x0f)
    #define BTH_FECN_MASK		(0x80000000)
    #define BTH_BECN_MASK		(0x40000000)
    #define BTH_RESV6A_MASK		(0x3f000000)
    #define BTH_QPN_MASK		(0x00ffffff)
    #define BTH_ACK_MASK		(0x80000000)
    #define BTH_RESV7_MASK		(0x7f000000)
    #define BTH_PSN_MASK		(0x00ffffff)

    class InfiniBandLayer : public Layer
	{
    public:

        InfiniBandLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, IB)
		{}

        rxe_bth* getBthHeader() const
        {
            return (rxe_bth*)m_Data;
        }

        uint8_t getOpcode() const;

        void parseNextLayer();

        size_t getHeaderLen() const
        {
            return sizeof(rxe_bth);
        }

        /**
		 * Calculate @ref udphdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelTransportLayer;
		}

        static inline bool isInfiniBandPort(uint16_t port)
        {
            return (port == 4791);
        }
    };

}  // namespace pcpp
