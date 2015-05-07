#ifndef PACKETPP_TCP_LAYER
#define PACKETPP_TCP_LAYER

#include <Layer.h>
#include <stdarg.h>

/// @file

/**
 * @struct tcphdr
 * Represents an TCP protocol header
 */
#pragma pack(push,1)
struct tcphdr {
	/** Source TCP port */
	uint16_t portSrc;
	/** Destination TCP port */
	uint16_t portDst;
	/** Sequence number */
	uint32_t sequenceNumber;
	/** Acknowledgment number */
	uint32_t ackNumber;
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint16_t reserved:4,
	/** Specifies the size of the TCP header in 32-bit words */
		dataOffset:4,
	/** FIN flag */
		finFlag:1,
	/** SYN flag */
		synFlag:1,
	/** RST flag */
		rstFlag:1,
	/** PSH flag */
		pshFlag:1,
	/** ACK flag */
		ackFlag:1,
	/** URG flag */
		urgFlag:1,
	/** ECE flag */
		eceFlag:1,
	/** CWR flag */
		cwrFlag:1;
#elif (BYTE_ORDER == BIG_ENDIAN)
	/** Specifies the size of the TCP header in 32-bit words */
	uint16_t dataOffset:4,
		reserved:4,
	/** CWR flag */
		cwrFlag:1,
	/** ECE flag */
		eceFlag:1,
	/** URG flag */
		urgFlag:1,
	/** ACK flag */
		ackFlag:1,
	/** PSH flag */
		pshFlag:1,
	/** RST flag */
		rstFlag:1,
	/** SYN flag */
		synFlag:1,
	/** FIN flag */
		finFlag:1;
#else
#error	"Endian is not LE nor BE..."
#endif
	/** The size of the receive window, which specifies the number of window size units (by default, bytes) */
	uint16_t	windowSize;
	/** The 16-bit checksum field is used for error-checking of the header and data */
	uint16_t	headerChecksum;
	/** If the URG flag (@ref tcphdr#urgFlag) is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte */
	uint16_t	urgentPointer;
};
#pragma pack(pop)


/**
 * TCP options enum
 */
enum TcpOption {
	/** Padding */
	TCPOPT_NOP = 			1,
	/** End of options */
	TCPOPT_EOL = 			0,
	/** Segment size negotiating */
	TCPOPT_MSS = 			2,
	/** Window scaling */
	TCPOPT_WINDOW = 		3,
	/** SACK Permitted */
	TCPOPT_SACK_PERM = 		4,
	/** SACK Block */
	TCPOPT_SACK =           5,
	/** Echo (obsoleted by option ::TCPOPT_TIMESTAMP) */
	TCPOPT_ECHO =           6,
	/** Echo Reply (obsoleted by option ::TCPOPT_TIMESTAMP) */
	TCPOPT_ECHOREPLY =      7,
	/** TCP Timestamps */
	TCPOPT_TIMESTAMP =      8,
	/** CC (obsolete) */
	TCPOPT_CC =             11,
	/** CC.NEW (obsolete) */
	TCPOPT_CCNEW =          12,
	/** CC.ECHO(obsolete) */
	TCPOPT_CCECHO =         13,
	/** MD5 Signature Option */
	TCPOPT_MD5 =            19,
	/** Multipath TCP */
	TCPOPT_MPTCP =          0x1e,
	/** SCPS Capabilities */
	TCPOPT_SCPS =           20,
	/** SCPS SNACK */
	TCPOPT_SNACK =          21,
	/** SCPS Record Boundary */
	TCPOPT_RECBOUND =       22,
	/** SCPS Corruption Experienced */
	TCPOPT_CORREXP =        23,
	/** Quick-Start Response */
	TCPOPT_QS =             27,
	/** User Timeout Option (also, other known unauthorized use) */
	TCPOPT_USER_TO =        28,
	/** RFC3692-style Experiment 1 (also improperly used for shipping products) */
	TCPOPT_EXP_FD =         0xfd,
	/** RFC3692-style Experiment 2 (also improperly used for shipping products) */
	TCPOPT_EXP_FE =         0xfe,
	/** Riverbed probe option, non IANA registered option number */
	TCPOPT_RVBD_PROBE =     76,
	/** Riverbed transparency option, non IANA registered option number */
	TCPOPT_RVBD_TRPY =      78
};

/** Number of TCP options */
#define TCP_OPTIONS_COUNT 24


// TCP option lengths

/** ::TCPOPT_MSS length */
#define TCPOLEN_MSS            4
/** ::TCPOPT_WINDOW length */
#define TCPOLEN_WINDOW         3
/** ::TCPOPT_SACK_PERM length */
#define TCPOLEN_SACK_PERM      2
/** ::TCPOPT_SACK length */
#define TCPOLEN_SACK_MIN       2
/** ::TCPOPT_ECHO length */
#define TCPOLEN_ECHO           6
/** ::TCPOPT_ECHOREPLY length */
#define TCPOLEN_ECHOREPLY      6
/** ::TCPOPT_TIMESTAMP length */
#define TCPOLEN_TIMESTAMP     10
/** ::TCPOPT_CC length */
#define TCPOLEN_CC             6
/** ::TCPOPT_CCNEW length */
#define TCPOLEN_CCNEW          6
/** ::TCPOPT_CCECHO length */
#define TCPOLEN_CCECHO         6
/** ::TCPOPT_MD5 length */
#define TCPOLEN_MD5           18
/** ::TCPOPT_MPTCP length */
#define TCPOLEN_MPTCP_MIN      8
/** ::TCPOPT_SCPS length */
#define TCPOLEN_SCPS           4
/** ::TCPOPT_SNACK length */
#define TCPOLEN_SNACK          6
/** ::TCPOPT_RECBOUND length */
#define TCPOLEN_RECBOUND       2
/** ::TCPOPT_CORREXP length */
#define TCPOLEN_CORREXP        2
/** ::TCPOPT_QS length */
#define TCPOLEN_QS             8
/** ::TCPOPT_USER_TO length */
#define TCPOLEN_USER_TO        4
/** ::TCPOPT_RVBD_PROBE length */
#define TCPOLEN_RVBD_PROBE_MIN 3
/** ::TCPOPT_RVBD_TRPY length */
#define TCPOLEN_RVBD_TRPY_MIN 16
/** ::TCPOPT_EXP_FD and ::TCPOPT_EXP_FE length */
#define TCPOLEN_EXP_MIN        2

/**
 * @struct TcpOptionData
 *Representing a TCP option in a TLV (type-length-value) type
 */
struct TcpOptionData
{
	/** TCP option type, should be on of ::TcpOption */
	uint8_t option;
	/** TCP option length */
	uint8_t len;
	/** TCP option value */
	uint8_t value[];
};

/** PcapPlusPlus supports up to 100 TCP options per packet */
#define MAX_SUPPORTED_TCP_OPTIONS 100

/**
 * @class TcpLayer
 * Represents a TCP (Transmission Control Protocol) protocol layer
 */
class TcpLayer : public Layer
{
public:
	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref tcphdr)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	/**
	 * A constructor that allocates a new TCP header with zero or more TCP options. TCP options will be created as part of the header
	 * and the user can get them through getTcpOptionData(). TCP options created will have no value (just type and length)
	 * @param[in] tcpOptionsCount Number of TCP options to create
	 * @param[in] ... A list of 'tcpOptionsCount' TCP options of type ::TcpOption
	 */
	TcpLayer(int tcpOptionsCount, ...);

	/**
	 * A constructor that allocates a new TCP header with source port and destination port and zero or more TCP options. TCP options will be created as part of the header
	 * and the user can get them through getTcpOptionData(). TCP options created will have no value (just type and length)
	 * @param[in] portSrc Source port
	 * @param[in] portDst Destination port
	 * @param[in] tcpOptionsCount Number of TCP options to create
	 * @param[in] ... A list of 'tcpOptionsCount' TCP options of type ::TcpOption
	 */
	TcpLayer(uint16_t portSrc, uint16_t portDst, int tcpOptionsCount, ...);

	~TcpLayer();

	/**
	 * A copy constructor that copy the entire header from the other TcpLayer (including TCP options)
	 */
	TcpLayer(const TcpLayer& other);

	/**
	 * An assignment operator that first delete all data from current layer and then copy the entire header from the other TcpLayer (including TCP options)
	 */
	TcpLayer& operator=(const TcpLayer& other);

	/**
	 * Get a pointer to the TCP header. Notice this points directly to the data, so every change will change the actual packet data
	 * @return A pointer to the @ref tcphdr
	 */
	inline tcphdr* getTcpHeader() { return (tcphdr*)m_Data; };

	/**
	 * Get a pointer to a TCP option. Notice this points directly to the data, so every change will change the actual packet data
	 * @param[in] option The TCP option to get
	 * @return A pointer to the TCP option location in the packet
	 */
	TcpOptionData* getTcpOptionData(TcpOption option);

	/**
	 * @return The number of TCP options on packet
	 */
	inline size_t getTcpOptionsCount() { return m_TcpOptionsInLayerCount; }

	/**
	 * Calculate the checksum from header and data and possibly write the result to @ref tcphdr#headerChecksum
	 * @param[in] writeResultToPacket If set to true then checksum result will be written to @ref tcphdr#headerChecksum
	 * @return The checksum result
	 */
	uint16_t calculateChecksum(bool writeResultToPacket);

	// implement abstract methods

	/**
	 * Currently identifies the following next layers: HttpRequestLayer, HttpResponseLayer. Otherwise sets PayloadLayer
	 */
	void parseNextLayer();

	/**
	 * @return Size of @ref tcphdr + all TCP options
	 */
	inline size_t getHeaderLen() { return m_HeaderLen;}

	/**
	 * Calculate @ref tcphdr#headerChecksum field
	 */
	void computeCalculateFields();

	std::string toString();

private:
	static const TcpOptionData TcpOptions[TCP_OPTIONS_COUNT];

	struct TcpOptionPtr
	{
		TcpOption option;
		int dataOffset;
	};
	TcpOptionPtr* m_TcpOptionsInLayer;
	size_t m_TcpOptionsInLayerCount;
	size_t m_HeaderLen;

	void initLayer(int tcpOptionsCount, va_list paramsList);
	const TcpOptionData& getTcpOptionRawData(TcpOption option);
	void copyLayerData(const TcpLayer& other);
};


#endif /* PACKETPP_TCP_LAYER */
