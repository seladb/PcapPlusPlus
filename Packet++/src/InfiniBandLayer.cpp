#include "InfiniBandLayer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <string.h>
#include "EndianPortable.h"

namespace pcpp
{

	InfiniBandLayer::InfiniBandLayer(uint8_t opcode, int se, int mig, int pad, uint16_t pkey, uint32_t qpn, int ack_req,
	                                 uint32_t psn)
	{
		const size_t headerLen = sizeof(rxe_bth);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		rxe_bth* bthHdr = reinterpret_cast<rxe_bth*>(m_Data);

		bthHdr->opcode = opcode;
		bthHdr->flags = (pad << 4) & BTH_PAD_MASK;
		if (se)
			bthHdr->flags |= BTH_SE_MASK;
		if (mig)
			bthHdr->flags |= BTH_MIG_MASK;
		bthHdr->pkey = htobe16(pkey);
		bthHdr->qpn = htobe32(qpn & BTH_QPN_MASK);
		psn &= BTH_PSN_MASK;
		if (ack_req)
			psn |= BTH_ACK_MASK;
		bthHdr->apsn = htobe32(psn);
		m_Protocol = Infiniband;
	}

	void InfiniBandLayer::parseNextLayer()
	{
		if (m_DataLen <= sizeof(rxe_bth))
			return;

		uint8_t* bthData = m_Data + sizeof(rxe_bth);
		size_t bthDataLen = m_DataLen - sizeof(rxe_bth);

		m_NextLayer = new PayloadLayer(bthData, bthDataLen, this, m_Packet);
	}

	void InfiniBandLayer::computeCalculateFields()
	{}

	std::string InfiniBandLayer::toString() const
	{
		std::ostringstream ss;
		ss << "InfiniBand Layer, Opcode: " << getOpcode();
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

	uint8_t InfiniBandLayer::getSe() const
	{
		return 0 != (BTH_SE_MASK & getBthHeader()->flags);
	}

	void InfiniBandLayer::setSe(int se) const
	{
		if (se)
			getBthHeader()->flags |= BTH_SE_MASK;
		else
			getBthHeader()->flags &= ~BTH_SE_MASK;
	}

	uint8_t InfiniBandLayer::getMig() const
	{
		return 0 != (BTH_MIG_MASK & getBthHeader()->flags);
	}

	void InfiniBandLayer::setMig(uint8_t mig) const
	{
		if (mig)
			getBthHeader()->flags |= BTH_MIG_MASK;
		else
			getBthHeader()->flags &= ~BTH_MIG_MASK;
	}

	uint8_t InfiniBandLayer::getPad() const
	{
		return (BTH_PAD_MASK & getBthHeader()->flags) >> 4;
	}

	void InfiniBandLayer::setPad(uint8_t pad) const
	{
		getBthHeader()->flags = (BTH_PAD_MASK & (pad << 4)) | (~BTH_PAD_MASK & getBthHeader()->flags);
	}

	uint8_t InfiniBandLayer::getTver() const
	{
		return BTH_TVER_MASK & getBthHeader()->flags;
	}

	void InfiniBandLayer::setTver(uint8_t tver) const
	{
		getBthHeader()->flags = (BTH_TVER_MASK & tver) | (~BTH_TVER_MASK & getBthHeader()->flags);
	}

	uint16_t InfiniBandLayer::getPkey() const
	{
		return be16toh(getBthHeader()->pkey);
	}

	void InfiniBandLayer::setPkey(uint16_t pkey) const
	{
		getBthHeader()->pkey = htobe16(pkey);
	}

	uint32_t InfiniBandLayer::getQpn() const
	{
		return BTH_QPN_MASK & be32toh(getBthHeader()->qpn);
	}

	void InfiniBandLayer::setQpn(uint32_t qpn) const
	{

		uint32_t resvqpn = be32toh(getBthHeader()->qpn);

		getBthHeader()->qpn = htobe32((BTH_QPN_MASK & qpn) | (~BTH_QPN_MASK & resvqpn));
	}

	int InfiniBandLayer::getFecn() const
	{
		return 0 != (htobe32(BTH_FECN_MASK) & getBthHeader()->qpn);
	}

	void InfiniBandLayer::setfecn(int fecn) const
	{
		if (fecn)
			getBthHeader()->qpn |= htobe32(BTH_FECN_MASK);
		else
			getBthHeader()->qpn &= ~htobe32(BTH_FECN_MASK);
	}

	int InfiniBandLayer::getBecn() const
	{
		return 0 != (htobe32(BTH_BECN_MASK) & getBthHeader()->qpn);
	}

	void InfiniBandLayer::setbecn(int becn) const
	{
		if (becn)
			getBthHeader()->qpn |= htobe32(BTH_BECN_MASK);
		else
			getBthHeader()->qpn &= ~htobe32(BTH_BECN_MASK);
	}

	uint8_t InfiniBandLayer::getResv6a() const
	{
		return (BTH_RESV6A_MASK & be32toh(getBthHeader()->qpn)) >> 24;
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

	void InfiniBandLayer::setResv7() const
	{
		getBthHeader()->apsn &= ~htobe32(BTH_RESV7_MASK);
	}

	uint32_t InfiniBandLayer::getPsn() const
	{
		return BTH_PSN_MASK & be32toh(getBthHeader()->apsn);
	}

	void InfiniBandLayer::setPsn(uint32_t psn) const
	{
		uint32_t apsn = be32toh(getBthHeader()->apsn);

		getBthHeader()->apsn = htobe32((BTH_PSN_MASK & psn) | (~BTH_PSN_MASK & apsn));
	}
}  // namespace pcpp