#ifndef PACKETPP_TCP_LAYER
#define PACKETPP_TCP_LAYER

#include "Layer.h"
#include "TLVData.h"
#include <string.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

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
	enum TcpOptionType {
		/** Padding */
		PCPP_TCPOPT_NOP = 			1,
		/** End of options */
		PCPP_TCPOPT_EOL = 			0,
		/** Segment size negotiating */
		TCPOPT_MSS = 			2,
		/** Window scaling */
		PCPP_TCPOPT_WINDOW = 		3,
		/** SACK Permitted */
		TCPOPT_SACK_PERM = 		4,
		/** SACK Block */
		PCPP_TCPOPT_SACK =           5,
		/** Echo (obsoleted by option ::PCPP_TCPOPT_TIMESTAMP) */
		TCPOPT_ECHO =           6,
		/** Echo Reply (obsoleted by option ::PCPP_TCPOPT_TIMESTAMP) */
		TCPOPT_ECHOREPLY =      7,
		/** TCP Timestamps */
		PCPP_TCPOPT_TIMESTAMP =      8,
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
		TCPOPT_RVBD_TRPY =      78,
		/** Unknown option */
		TCPOPT_Unknown =        255
	};


	// TCP option lengths

	/** pcpp::PCPP_TCPOPT_NOP length */
#define PCPP_TCPOLEN_NOP            1
	/** pcpp::PCPP_TCPOPT_EOL length */
#define PCPP_TCPOLEN_EOL            1
	/** pcpp::TCPOPT_MSS length */
#define PCPP_TCPOLEN_MSS            4
	/** pcpp::PCPP_TCPOPT_WINDOW length */
#define PCPP_TCPOLEN_WINDOW         3
	/** pcpp::TCPOPT_SACK_PERM length */
#define PCPP_TCPOLEN_SACK_PERM      2
	/** pcpp::PCPP_TCPOPT_SACK length */
#define PCPP_TCPOLEN_SACK_MIN       2
	/** pcpp::TCPOPT_ECHO length */
#define PCPP_TCPOLEN_ECHO           6
	/** pcpp::TCPOPT_ECHOREPLY length */
#define PCPP_TCPOLEN_ECHOREPLY      6
	/** pcpp::PCPP_TCPOPT_TIMESTAMP length */
#define PCPP_TCPOLEN_TIMESTAMP     10
	/** pcpp::TCPOPT_CC length */
#define PCPP_TCPOLEN_CC             6
	/** pcpp::TCPOPT_CCNEW length */
#define PCPP_TCPOLEN_CCNEW          6
	/** pcpp::TCPOPT_CCECHO length */
#define PCPP_TCPOLEN_CCECHO         6
	/** pcpp::TCPOPT_MD5 length */
#define PCPP_TCPOLEN_MD5           18
	/** pcpp::TCPOPT_MPTCP length */
#define PCPP_TCPOLEN_MPTCP_MIN      8
	/** pcpp::TCPOPT_SCPS length */
#define PCPP_TCPOLEN_SCPS           4
	/** pcpp::TCPOPT_SNACK length */
#define PCPP_TCPOLEN_SNACK          6
	/** pcpp::TCPOPT_RECBOUND length */
#define PCPP_TCPOLEN_RECBOUND       2
	/** pcpp::TCPOPT_CORREXP length */
#define PCPP_TCPOLEN_CORREXP        2
	/** pcpp::TCPOPT_QS length */
#define PCPP_TCPOLEN_QS             8
	/** pcpp::TCPOPT_USER_TO length */
#define PCPP_TCPOLEN_USER_TO        4
	/** pcpp::TCPOPT_RVBD_PROBE length */
#define PCPP_TCPOLEN_RVBD_PROBE_MIN 3
	/** pcpp::TCPOPT_RVBD_TRPY length */
#define PCPP_TCPOLEN_RVBD_TRPY_MIN 16
	/** pcpp::TCPOPT_EXP_FD and pcpp::TCPOPT_EXP_FE length */
#define PCPP_TCPOLEN_EXP_MIN        2


	/**
	 * @class TcpOption
	 * A wrapper class for TCP options. This class does not create or modify TCP option records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	class TcpOption : public TLVRecord
	{
	public:

		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] optionRawData A pointer to the TCP option raw data
		 */
		TcpOption(uint8_t* optionRawData) : TLVRecord(optionRawData) { }

		/**
		 * A d'tor for this class, currently does nothing
		 */
		~TcpOption() { }

		/**
		 * @return TCP option type casted as pcpp::TcpOptionType enum. If data is null a value
		 * of ::PCPP_TCPOPT_NOP is returned
		 */
		inline TcpOptionType getTcpOptionType()
		{
			if (m_Data == NULL)
				return PCPP_TCPOPT_NOP;

			return (TcpOptionType)m_Data->recordType;
		}

		// implement abstract methods

		inline size_t getTotalSize() const
		{
			if (m_Data == NULL)
				return (size_t)0;

			if (m_Data->recordType == (uint8_t)PCPP_TCPOPT_NOP || m_Data->recordType == (uint8_t)PCPP_TCPOPT_EOL)
				return sizeof(uint8_t);

			return (size_t)m_Data->recordLen;
		}

		size_t getDataSize()
		{
			if (m_Data == NULL)
				return 0;

			if (m_Data->recordType == (uint8_t)PCPP_TCPOPT_NOP || m_Data->recordType == (uint8_t)PCPP_TCPOPT_EOL)
				return (size_t)0;

			return (size_t)m_Data->recordLen - (2*sizeof(uint8_t));
		}
	};


	class TcpOptionBuilder : public TLVRecordBuilder
	{

	public:

		enum NopEolOptionTypes
		{
			NOP,
			EOL
		};

		/**
		 * A c'tor for building IPv4 options which their value is a byte array. The IPv4Option object can later
		 * be retrieved by calling build()
		 * @param[in] optionType IPv4 option type
		 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in any way.
		 * For option types ::IPV4OPT_NOP and ::IPV4OPT_EndOfOtionsList this parameter is ignored (expected to be NULL) as these
		 * option types don't contain any data
		 * @param[in] optionValueLen Option value length in bytes
		 */
		TcpOptionBuilder(TcpOptionType optionType, const uint8_t* optionValue, uint8_t optionValueLen) :
			TLVRecordBuilder((uint8_t)optionType, optionValue, optionValueLen) {}

		TcpOptionBuilder(TcpOptionType optionType, uint8_t optionValue) :
			TLVRecordBuilder((uint8_t)optionType, optionValue) {}

		TcpOptionBuilder(TcpOptionType optionType, uint16_t optionValue) :
			TLVRecordBuilder((uint8_t)optionType, optionValue) {}

		TcpOptionBuilder(TcpOptionType optionType, uint32_t optionValue) :
			TLVRecordBuilder((uint8_t)optionType, optionValue) {}

		TcpOptionBuilder(NopEolOptionTypes optionType);

		/**
		 * Build the TcpOption object out of the parameters defined in the c'tor
		 * @return The TcpOption object
		 */
		TcpOption build() const;
	};


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
		 * A constructor that allocates a new TCP header with zero TCP options
		 */
		TcpLayer();

		/**
		 * A constructor that allocates a new TCP header with source port and destination port and zero TCP options
		 * @param[in] portSrc Source port
		 * @param[in] portDst Destination port
		 */
		TcpLayer(uint16_t portSrc, uint16_t portDst);

		~TcpLayer() {}

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
		inline tcphdr* getTcpHeader() { return (tcphdr*)m_Data; }

		/**
		 * Get a pointer to a TCP option. Notice this points directly to the data, so every change will change the actual packet data
		 * @param[in] option The TCP option to get
		 * @return A pointer to the TCP option location in the packet
		 * TODO doc
		 */
		TcpOption getTcpOption(TcpOptionType option);

		/**
		 * @return The first TCP option, or NULL if no TCP options exist. Notice the return value is a pointer to the real data casted to
		 * TcpOptionData type (as opposed to a copy of the option data). So changes in the return value will affect the packet data
		 * TODO doc
		 */
		TcpOption getFirstTcpOption();

		/**
		 * Get the TCP option which comes next to "tcpOption" parameter. If "tcpOption" is NULL then NULL will be returned.
		 * If "tcpOption" is the last TCP option NULL will be returned. Notice the return value is a pointer to the real data casted to
		 * TcpOptionData type (as opposed to a copy of the option data). So changes in the return value will affect the packet data
		 * @param[in] tcpOption The TCP option to start searching from
		 * @return The next TCP option or NULL if "tcpOption" is NULL or "tcpOption" is the last TCP option
		 * TODO doc
		 */
		TcpOption getNextTcpOption(TcpOption& tcpOption);

		/**
		 * @return The number of TCP options in this layer
		 */
		size_t getTcpOptionCount();

		/**
		 * Add a new TCP option at the end of the layer (after the last TCP option)
		 * @param[in] optionType The type of the newly added option
		 * @param[in] optionLength The length of the option data
		 * @param[in] optionData A pointer to the option data. This data will be copied to added option data. Notice the length of
		 * optionData must be optionLength
		 * @return A pointer to the new added TCP option data or NULL if addition failed. Notice this is a pointer to the
		 * real data casted to TcpOptionData type (as opposed to a copy of the option data). So changes in this return
		 * value will affect the packet data
		 * TODO doc
		 */
		TcpOption addTcpOption(const TcpOptionBuilder& optionBuilder);

		/**
		 * Add a new TCP option after an existing TCP option
		 * @param[in] optionType The type of the newly added option
		 * @param[in] optionLength The length of the option data
		 * @param[in] optionData A pointer to the option data. This data will be copied to added option data. Notice the length of
		 * optionData must be optionLength
		 * @param[in] prevOption The TCP option which the newly added tag will come after. If set to NULL TCP option will be
		 * added as the first TCP option
		 * @return A pointer to the new added TCP option or NULL if addition failed. Notice this is a pointer to the real data
		 * casted to TcpOptionData type (as opposed to a copy of the option data). So changes in this return value will affect
		 * the packet data
		 * TODO doc
		 */
		TcpOption addTcpOptionAfter(const TcpOptionBuilder& optionBuilder, TcpOptionType prevOptionType = TCPOPT_Unknown);

		/**
		 * Remove an existing TCP option from the layer. TCP option is found by type
		 * @param[in] optionType The TCP option type to remove
		 * @return True if TCP option was removed or false if type wasn't found or if removal failed (in each case a proper error
		 * will be written to log)
		 */
		bool removeTcpOption(TcpOptionType optionType);

		/**
		 * Remove all TCP options in this layer
		 * @return True if all TCP options were successfully removed or false if removal failed for some reason
		 * (a proper error will be written to log)
		 */
		bool removeAllTcpOptions();


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
		inline size_t getHeaderLen() { return getTcpHeader()->dataOffset*4 ;}

		/**
		 * Calculate @ref tcphdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelTransportLayer; }

	private:

		TLVRecordReader<TcpOption> m_OptionReader;
		int m_NumOfTrailingBytes;

		void initLayer();
		inline uint8_t* getOptionsBasePtr() { return m_Data + sizeof(tcphdr); }
		TcpOption addTcpOptionAt(const TcpOptionBuilder& optionBuilder, int offset);
		void adjustTcpOptionTrailer(size_t totalOptSize);
		void copyLayerData(const TcpLayer& other);
	};

} // namespace pcpp

#endif /* PACKETPP_TCP_LAYER */
