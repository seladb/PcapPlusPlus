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

        InfiniBandLayer( uint8_t opcode, int se,
                    int mig, int pad, uint16_t pkey, uint32_t qpn, int ack_req,
                    uint32_t psn);

        rxe_bth* getBthHeader() const
        {
            return reinterpret_cast<rxe_bth*>(m_Data);
        }

        uint8_t getOpcode() const;
        void setOpcode(uint8_t opcode) const;
        uint8_t getSe() const;
        void setSe(int se) const;
        uint8_t getMig() const;
        void setMig(uint8_t mig) const;
        uint8_t getPad() const;
        void setPad(uint8_t pad) const;
        uint8_t getTver() const;
        void setTver(uint8_t tver) const;
        uint16_t getPkey() const;
        void setPkey(uint16_t pkey) const;
        uint32_t getQpn() const;
        void setQpn(uint32_t qpn) const;
        int getFecn() const;
        void setfecn(int fecn) const;
        int getBecn() const;
        void setbecn(int becn) const;
        uint8_t getResv6a() const;
        void setResv6a() const;
        int getAck() const;
        void setAck(int ack) const;
        void setResv7() const;
        uint32_t getPsn() const;
        void setPsn(uint32_t psn) const;

        void parseNextLayer() override;

        size_t getHeaderLen() const override
        {
            return sizeof(rxe_bth);
        }

        /**
		 * Calculate @ref udphdr#headerChecksum field
		 */
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

        static inline bool isInfiniBandPort(uint16_t port)
        {
            return (port == 4791);
        }
    };

}  // namespace pcpp
