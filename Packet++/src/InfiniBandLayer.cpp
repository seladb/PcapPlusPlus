#include "InfiniBandLayer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <string.h>
#include "EndianPortable.h"

namespace pcpp
{
#define RXE_ICRC_SIZE 4
#define RXE_MAX_HDR_LENGTH 80

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

	InfiniBandLayer::InfiniBandLayer(uint8_t opcode, int soliciteEvent, int migrationState, int padCount, uint16_t partitionKey,
									 uint32_t queuePairNumber, int ackReq, uint32_t packetSequenceNumber)
	{
		const size_t headerLen = sizeof(rxe_bth);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		rxe_bth* bthHdr = reinterpret_cast<rxe_bth*>(m_Data);

		bthHdr->opcode = opcode;
		bthHdr->flags = (padCount << 4) & BTH_PAD_MASK;
		if (soliciteEvent)
			bthHdr->flags |= BTH_SE_MASK;
		if (migrationState)
			bthHdr->flags |= BTH_MIG_MASK;
		bthHdr->pkey = htobe16(partitionKey);
		bthHdr->qpn = htobe32(queuePairNumber & BTH_QPN_MASK);
		packetSequenceNumber &= BTH_PSN_MASK;
		if (ackReq)
			packetSequenceNumber |= BTH_ACK_MASK;
		bthHdr->apsn = htobe32(packetSequenceNumber);
		m_Protocol = InfiniBand;
	}

	void InfiniBandLayer::parseNextLayer()
	{
		if (m_DataLen <= sizeof(rxe_bth))
			return;

		uint8_t* bthData = m_Data + sizeof(rxe_bth);
		size_t bthDataLen = m_DataLen - sizeof(rxe_bth);

		m_NextLayer = new PayloadLayer(bthData, bthDataLen, this, m_Packet);
	}

	std::string InfiniBandLayer::toString() const
	{
		std::ostringstream ss;
		ss << "InfiniBand Layer, Opcode: " << static_cast<int>(getOpcode());
		return ss.str();
	}

	uint8_t InfiniBandLayer::getOpcode() const
	{
		return getBthHeader()->opcode;
	}

	void InfiniBandLayer::setOpcode(uint8_t opcode) const
	{
		getBthHeader()->opcode = opcode;
	}

	bool InfiniBandLayer::getSoliciteEvent() const
	{
		return 0 != (BTH_SE_MASK & getBthHeader()->flags);
	}

	void InfiniBandLayer::setSolicitedEvent(bool se) const
	{
		if (se)
			getBthHeader()->flags |= BTH_SE_MASK;
		else
			getBthHeader()->flags &= ~BTH_SE_MASK;
	}

	bool InfiniBandLayer::getMigrationState() const
	{
		return 0 != (BTH_MIG_MASK & getBthHeader()->flags);
	}

	void InfiniBandLayer::setMigrationState(bool mig) const
	{
		if (mig)
			getBthHeader()->flags |= BTH_MIG_MASK;
		else
			getBthHeader()->flags &= ~BTH_MIG_MASK;
	}

	uint8_t InfiniBandLayer::getPadCount() const
	{
		return (BTH_PAD_MASK & getBthHeader()->flags) >> 4;
	}

	void InfiniBandLayer::setPadCount(uint8_t pad) const
	{
		getBthHeader()->flags = (BTH_PAD_MASK & (pad << 4)) | (~BTH_PAD_MASK & getBthHeader()->flags);
	}

	uint8_t InfiniBandLayer::getTransportHeaderVersion() const
	{
		return BTH_TVER_MASK & getBthHeader()->flags;
	}

	void InfiniBandLayer::setTransportHeaderVersion(uint8_t tver) const
	{
		getBthHeader()->flags = (BTH_TVER_MASK & tver) | (~BTH_TVER_MASK & getBthHeader()->flags);
	}

	uint16_t InfiniBandLayer::getPartitionKey() const
	{
		return be16toh(getBthHeader()->pkey);
	}

	void InfiniBandLayer::setPartitionKey(uint16_t pkey) const
	{
		getBthHeader()->pkey = htobe16(pkey);
	}

	uint32_t InfiniBandLayer::getQueuePairNumber() const
	{
		return BTH_QPN_MASK & be32toh(getBthHeader()->qpn);
	}

	void InfiniBandLayer::setQueuePairNumber(uint32_t qpn) const
	{
		uint32_t resvqpn = be32toh(getBthHeader()->qpn);

		getBthHeader()->qpn = htobe32((BTH_QPN_MASK & qpn) | (~BTH_QPN_MASK & resvqpn));
	}

	bool InfiniBandLayer::getFecn() const
	{
		return 0 != (htobe32(BTH_FECN_MASK) & getBthHeader()->qpn);
	}

	void InfiniBandLayer::setFecn(bool fecn) const
	{
		if (fecn)
			getBthHeader()->qpn |= htobe32(BTH_FECN_MASK);
		else
			getBthHeader()->qpn &= ~htobe32(BTH_FECN_MASK);
	}

	bool InfiniBandLayer::getBecn() const
	{
		return 0 != (htobe32(BTH_BECN_MASK) & getBthHeader()->qpn);
	}

	void InfiniBandLayer::setBecn(bool becn) const
	{
		if (becn)
			getBthHeader()->qpn |= htobe32(BTH_BECN_MASK);
		else
			getBthHeader()->qpn &= ~htobe32(BTH_BECN_MASK);
	}

	void InfiniBandLayer::setResv6a() const
	{
		getBthHeader()->qpn = htobe32(~BTH_RESV6A_MASK);
	}

	int InfiniBandLayer::getAck() const
	{
		return 0 != (htobe32(BTH_ACK_MASK) & getBthHeader()->apsn);
	}

	void InfiniBandLayer::setAck(int ack) const
	{
		if (ack)
			getBthHeader()->apsn |= htobe32(BTH_ACK_MASK);
		else
			getBthHeader()->apsn &= ~htobe32(BTH_ACK_MASK);
	}

	uint32_t InfiniBandLayer::getPacketSequenceNumber() const
	{
		return BTH_PSN_MASK & be32toh(getBthHeader()->apsn);
	}

	void InfiniBandLayer::setPacketSequenceNumber(uint32_t psn) const
	{
		uint32_t apsn = be32toh(getBthHeader()->apsn);

		getBthHeader()->apsn = htobe32((BTH_PSN_MASK & psn) | (~BTH_PSN_MASK & apsn));
	}

	bool InfiniBandLayer::isDataValid(const uint8_t* udpData, size_t udpDataLen)
	{
		if (udpData != nullptr && udpDataLen >= sizeof(rxe_bth))
		{
			return true;
		}
		return false;
	}
}  // namespace pcpp
