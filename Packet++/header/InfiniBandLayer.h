#pragma once

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * IBA header types and methods
	 *
	 * Some of these are for reference and completeness only since
	 * rxe does not currently support RD transport
	 * most of this could be moved into Infiniband core. ib_pack.h has
	 * part of this but is incomplete
	 *
	 * Header specific routines to insert/extract values to/from headers
	 * the routines that are named __hhh_(set_)fff() take a pointer to a
	 * hhh header and get(set) the fff field. The routines named
	 * hhh_(set_)fff take a packet info struct and find the
	 * header and field based on the opcode in the packet.
	 * Conversion to/from network byte order from cpu order is also done.
	 */

#define RXE_ICRC_SIZE 4
#define RXE_MAX_HDR_LENGTH 80

	/**
	 * @struct bth
	 * Represents an Base Transport Header
	 */
#pragma pack(push, 1)
	struct rxe_bth
	{
		uint8_t opcode;
		uint8_t flags;
		uint16_t pkey;
		uint32_t qpn;
		uint32_t apsn;
	};
#pragma pack(pop)

#define BTH_TVER 0x0
#define BTH_DEF_PKEY 0xffff

#define BTH_SE_MASK 0x80
#define BTH_MIG_MASK 0x40
#define BTH_PAD_MASK 0x30
#define BTH_TVER_MASK 0x0f
#define BTH_FECN_MASK 0x80000000
#define BTH_BECN_MASK 0x40000000
#define BTH_RESV6A_MASK 0x3f000000
#define BTH_QPN_MASK 0x00ffffff
#define BTH_ACK_MASK 0x80000000
#define BTH_RESV7_MASK 0x7f000000
#define BTH_PSN_MASK 0x00ffffff

	/**
	 * @class InfiniBandLayer
	 * Represents an InfiniBand protocol layer
	 */
	class InfiniBandLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to bth_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		InfiniBandLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Infiniband)
		{}

		/**
		 * A constructor that creates a new rxe_bth header and allocates the data
		 * @param[in] opcode The operation code
		 * @param[in] se The solicited event
		 * @param[in] mig The migration state
		 * @param[in] pad The pad count
		 * @param[in] pkey The partition key
		 * @param[in] qpn The destination queue pair (QP) number
		 * @param[in] ack_req The acknowledgment request
		 * @param[in] psn The packet sequence number
		 */
		InfiniBandLayer(uint8_t opcode, int se, int mig, int pad, uint16_t pkey, uint32_t qpn, int ack_req,
		                uint32_t psn);

		/**
		 * Get a pointer to the BTH header. Notice this points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the bth_header
		 */
		rxe_bth* getBthHeader() const
		{
			return reinterpret_cast<rxe_bth*>(m_Data);
		}

		/**
		 * @return The operation code which defines the interpretation of the remaining header and payload bytes
		 */
		uint8_t getOpcode() const;

		/**
		 * Set operation code
		 * @param[in] opcode The opcode to set
		 */
		void setOpcode(uint8_t opcode) const;

		/**
		 * @return solicited event that the responder shall invoke the CQ event handler
		 */
		uint8_t getSe() const;

		/**
		 * Set solicited event
		 * @param[in] se The solicited event to set
		 */
		void setSe(int se) const;

		/**
		 * @return migreq which used to communicate migration state
		 */
		uint8_t getMig() const;

		/**
		 * Set migreq
		 * @param[in] mig The migration state to set. If set to one, indicates the connection or EE context has been
		 * migrated; if set to zero, it means there is no change in the current migration state.
		 */
		void setMig(uint8_t mig) const;

		/**
		 * @return PadCount which Packet payloads are sent as a multiple of 4-byte quantities.
		 * Pad count indicates the number of pad bytes - 0 to 3 - that are appended to the packetpayload.
		 * Pads are used to “stretch” the payload (payloads may be zero or more bytes in length) to be a multiple of 4
		 * bytes
		 */
		uint8_t getPad() const;

		/**
		 * Set PadCount
		 * @param[in] pad The PadCount to set
		 */
		void setPad(uint8_t pad) const;

		/**
		 * @return Transport Header Version that specifies the version of the IBA Transport used for this packet
		 */
		uint8_t getTver() const;

		/**
		 * Set Transport Header Version
		 * @param[in] tvr The transport header version to set
		 */
		void setTver(uint8_t tver) const;

		/**
		 * @return partition key identifying the partition
		 * that the destination QP (RC, UC, UD, XRC) or EE Context (RD) is a member.
		 */
		uint16_t getPkey() const;

		/**
		 * Set partition key
		 * @param[in] pkey The partition key to set
		 */
		void setPkey(uint16_t pkey) const;

		/**
		 * @return destination queue pair (QP) identifier
		 */
		uint32_t getQpn() const;

		/**
		 * Set Queue Pair Number
		 * @param[in] qpn The queue pair number to set
		 */
		void setQpn(uint32_t qpn) const;

		/**
		 * @return FECN
		 * F (FECN): 0 indicates that a FECN indication was not received.
		 * 1 indicates that the packet went through a point of congestion
		 */
		int getFecn() const;

		/**
		 * Set Fecn
		 * @param[in] fecn The FECN to set
		 */
		void setfecn(int fecn) const;

		/**
		 * @return BECN
		 * B (BECN): 0 the packet did not go through a point of congestion or went
		 * through a point of congestion but was not marked. 1 indicates that the
		 * packet indicated by this header was subject to forward congestion. The B
		 * bit is set in an ACK or CN BTH
		 */
		int getBecn() const;

		/**
		 * Set BECN
		 * @param[in] becn The BECN to set
		 */
		void setbecn(int becn) const;

		/**
		 * @return Reserved (variant) - 6 bits. Transmitted as 0, ignored on receive.
		 */
		uint8_t getResv6a() const;

		/**
		 * Set Reserved 6 bits
		 */
		void setResv6a() const;

		/**
		 * @return ackreq that requests responder to schedule an acknowledgment on the associated QP.
		 */
		int getAck() const;

		/**
		 * Set acknowledgment for requests
		 * @param[in] ack The acknowledgment to set
		 */
		void setAck(int ack) const;

		/**
		 * Transmitted as 0, ignored on receive.
		 */
		void setResv7() const;

		/**
		 * @return packet sequence number that is used to identify the position of a packet
		 * within a sequence of packets.
		 */
		uint32_t getPsn() const;

		/**
		 * Set packet sequence number
		 * @param[in] psn The packet sequence number to set
		 */
		void setPsn(uint32_t psn) const;

		/**
		 * Currently identifies the following next layers sets to PayloadLayer
		 */
		void parseNextLayer() override;

		/**
		 * @return Size of rxe_bth header
		 */
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

		/**
		 * A static method that check whether is inifiniband RoCE port
		 * @param[in] port The port from UDP destination port
		 * @return True if the port is inifiniband RoCE and can represent an rxe packet
		 */
		static inline bool isInfiniBandPort(uint16_t port)
		{
			return (port == 4791);
		}
	};

}  // namespace pcpp
