#ifndef PACKETPP_L2TP_LAYER
#define PACKETPP_L2TP_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
/**
 * @struct l2tphdr
 * Represents L2TP  protocol header
 */
/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Tunnel ID           |           Session ID          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |             Ns (opt)          |             Nr (opt)          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      Offset Size (opt)        |    Offset pad... (opt)        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

// Rules:
// T == 1 : control message
// T == 0 : data message

// L == 1 : means length filed exists, must be 1 for control message
// L == 0 : length filed not exist

// S == 1 : means ns and nr exists, must be 1 for control message
// S == 0 : means ns and nr not exist

// O == 1 : means offset size exists
// O == 0 : means offset size not exist, must be 0 for control message

// P == 1 : means this data message should be handled firstly
// P == 0 :  must be 0 for control message

// Ver must be 2

#pragma pack(push, 1)
struct l2tphdr_base
{
	uint16_t typeBit : 1, lengthBit : 1, xx : 2, sequenceBit : 1, x : 1, offsetBit : 1, priorityBit : 1, xxxx : 4,
		version : 4;
};

struct l2tphdr_control : l2tphdr_base
{
	uint16_t length;
	uint16_t tunnelID;
	uint16_t sessionID;
	uint16_t ns;
	uint16_t nr;
};

struct l2tphdr_data : l2tphdr_base
{
	uint16_t tunnelID;
	uint16_t sessionID;
	uint16_t offset;
	uint16_t offsetPadding;
};
#pragma pack(pop)

/**
 * @class L2tpLayer
 */
class L2tpLayer : public Layer
{
  public:
	static bool isL2TPPort(uint16_t port)
	{
		return port == 1701;
	}
	void ToStructuredOutput(std::ostream &os) const;

	l2tphdr_base *getL2tpHeader()
	{
		return m_header;
	}

	uint16_t getLength() const;
	uint16_t getTunnelID() const;
	uint16_t getSessionID() const;
	uint16_t getNs() const;
	uint16_t getNr() const;
	uint32_t getOffset() const;
	bool isPriority() const;

	L2tpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = L2TP;
		m_header = (l2tphdr_base *)data;
	}

	// implement abstract methods

	/**
	 * Currently identifies the following next layers: PPP_PPTPLayer
	 * Otherwise sets PayloadLayer
	 */
	void parseNextLayer();

	/**
	 * @return Size of L2TP header (may change if optional fields are added or removed)
	 */
	size_t getHeaderLen() const;

	void computeCalculateFields();

	std::string toString() const;

	OsiModelLayer getOsiModelLayer() const
	{
		return OsiModelDataLinkLayer;
	}

  private:
	l2tphdr_base *m_header;

	enum L2tpField
	{
		L2tpTypeBit = 0,
		L2tpLengthBit = 1,
		L2tpSequenceBit = 2,
		L2tpOffsetBit = 3,
		L2tpPriorityBit = 4,
	};

	bool isFieldTrue(L2tpField field) const;
	bool isControlMessage() const
	{
		return isFieldTrue(L2tpTypeBit);
	}
	bool isDataMessage() const
	{
		return !isFieldTrue(L2tpTypeBit);
	}
};

} // namespace pcpp

#endif /* PACKETPP_L2TP_LAYER */
