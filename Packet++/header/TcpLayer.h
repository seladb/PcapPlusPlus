#ifndef PACKETPP_TCP_LAYER
#define PACKETPP_TCP_LAYER

#include <Layer.h>
#include <stdarg.h>

#pragma pack(push,1)
struct tcphdr {
	uint16_t portSrc;
	uint16_t portDst;
	uint32_t sequenceNumber;
	uint32_t ackNumber;
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint16_t reserved:4,
		dataOffset:4,
		finFlag:1,
		synFlag:1,
		rstFlag:1,
		pshFlag:1,
		ackFlag:1,
		urgFlag:1,
		eceFlag:1,
		cwrFlag:1;
#elif (BYTE_ORDER == BIG_ENDIAN)
	uint16_t dataOffset:4,
		reserved:4,
		cwrFlag:1,
		eceFlag:1,
		urgFlag:1,
		ackFlag:1,
		pshFlag:1,
		rstFlag:1,
		synFlag:1,
		finFlag:1;
#else
#error	"Endian is not LE nor BE..."
#endif
	uint16_t	windowSize;
	uint16_t	headerChecksum;
	uint16_t	urgentPointer;
};
#pragma pack(pop)

//enum TcpFlag
//{
//	TCP_FIN =		0x0001,
//	TCP_SYN =		0x0002,
//	TCP_RST =		0x0004,
//	TCP_PUSH = 		0x0008,
//	TCP_ACK =		0x0010,
//	TCP_URG =		0x0020,
//	TCP_ECN =		0x0040,
//	TCP_CWR =		0x0080,
//	TCP_NS =		0x0100,
//	TCP_RES =		0x0E00, /* 3 reserved bits */
//	TCP_MASK =		0x0FFF
//};

/*
 *  TCP option
 */
enum TcpOption : uint8_t {
	TCPOPT_NOP = 			1,       /* Padding */
	TCPOPT_EOL = 			0,       /* End of options */
	TCPOPT_MSS = 			2,       /* Segment size negotiating */
	TCPOPT_WINDOW = 		3,       /* Window scaling */
	TCPOPT_SACK_PERM = 		4,       /* SACK Permitted */
	TCPOPT_SACK =           5,       /* SACK Block */
	TCPOPT_ECHO =           6,
	TCPOPT_ECHOREPLY =      7,
	TCPOPT_TIMESTAMP =      8,       /* Better RTT estimations/PAWS */
	TCPOPT_CC =             11,
	TCPOPT_CCNEW =          12,
	TCPOPT_CCECHO =         13,
	TCPOPT_MD5 =            19,      /* RFC2385 */
	TCPOPT_MPTCP =          0x1e,    /* Multipath TCP */
	TCPOPT_SCPS =           20,      /* SCPS Capabilities */
	TCPOPT_SNACK =          21,      /* SCPS SNACK */
	TCPOPT_RECBOUND =       22,      /* SCPS Record Boundary */
	TCPOPT_CORREXP =        23,      /* SCPS Corruption Experienced */
	TCPOPT_QS =             27,      /* RFC4782 */
	TCPOPT_USER_TO =        28,      /* RFC5482 */
	TCPOPT_EXP_FD =         0xfd,    /* Experimental, reserved */
	TCPOPT_EXP_FE =         0xfe,    /* Experimental, reserved */
	/* Non IANA registered option numbers */
	TCPOPT_RVBD_PROBE =     76,      /* Riverbed probe option */
	TCPOPT_RVBD_TRPY =      78      /* Riverbed transparency option */
};

#define TCP_OPTIONS_COUNT 24

/*
 *     TCP option lengths
 */
#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_SACK_MIN       2
#define TCPOLEN_ECHO           6
#define TCPOLEN_ECHOREPLY      6
#define TCPOLEN_TIMESTAMP     10
#define TCPOLEN_CC             6
#define TCPOLEN_CCNEW          6
#define TCPOLEN_CCECHO         6
#define TCPOLEN_MD5           18
#define TCPOLEN_MPTCP_MIN      8
#define TCPOLEN_SCPS           4
#define TCPOLEN_SNACK          6
#define TCPOLEN_RECBOUND       2
#define TCPOLEN_CORREXP        2
#define TCPOLEN_QS             8
#define TCPOLEN_USER_TO        4
#define TCPOLEN_RVBD_PROBE_MIN 3
#define TCPOLEN_RVBD_TRPY_MIN 16
#define TCPOLEN_EXP_MIN        2

struct TcpOptionData
{
	TcpOption option;
	uint8_t len;
	uint8_t value[];
};

#define MAX_SUPPORTED_TCP_OPTIONS 100

class TcpLayer : public Layer
{
public:
	TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	TcpLayer(int tcpOptionsCount, ...);
	TcpLayer(uint16_t portSrc, uint16_t portDst, int tcpOptionsCount, ...);
	~TcpLayer();

	inline tcphdr* getTcpHeader() { return (tcphdr*)m_Data; };
	TcpOptionData* getTcpOptionData(TcpOption option);
	inline size_t getTcpOptionsCount() { return m_TcpOptionsInLayerLen; }
	uint16_t calculateChecksum(bool writeResultToPacket);

	// implement abstract methods
	void parseNextLayer();
	inline size_t getHeaderLen() { return m_HeaderLen;}
	void computeCalculateFields();
private:
	static const TcpOptionData TcpOptions[TCP_OPTIONS_COUNT];

	struct TcpOptionPtr
	{
		TcpOption option;
		int dataOffset;
	};
	TcpOptionPtr* m_TcpOptionsInLayer;
	size_t m_TcpOptionsInLayerLen;
	size_t m_HeaderLen;

	void initLayer(int tcpOptionsCount, va_list paramsList);
	const TcpOptionData& getTcpOptionRawData(TcpOption option);
};


#endif /* PACKETPP_TCP_LAYER */
