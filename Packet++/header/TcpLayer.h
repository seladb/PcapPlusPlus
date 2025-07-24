#pragma once

#include "DeprecationUtils.h"
#include "Layer.h"
#include "TLVData.h"
#include <string.h>

#define PCPP_DEPRECATED_TCP_OPTION_TYPE                                                                                \
	PCPP_DEPRECATED("enum TcpOptionType is deprecated; Use enum class TcpOptionEnumType instead")

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct tcphdr
	/// Represents an TCP protocol header
#pragma pack(push, 1)
	struct tcphdr
	{
		/// Source TCP port
		uint16_t portSrc;
		/// Destination TCP port
		uint16_t portDst;
		/// Sequence number
		uint32_t sequenceNumber;
		/// Acknowledgment number
		uint32_t ackNumber;
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/// Accurate ECN flag
		uint16_t accurateEcnFlag : 1;
		/// Reserved bits
		uint16_t reserved : 3;
		/// Specifies the size of the TCP header in 32-bit words
		uint16_t dataOffset : 4;
		/// FIN flag
		uint16_t finFlag : 1;
		/// SYN flag
		uint16_t synFlag : 1;
		/// RST flag
		uint16_t rstFlag : 1;
		/// PSH flag
		uint16_t pshFlag : 1;
		/// ACK flag
		uint16_t ackFlag : 1;
		/// URG flag
		uint16_t urgFlag : 1;
		/// ECE flag
		uint16_t eceFlag : 1;
		/// CWR flag
		uint16_t cwrFlag : 1;
#elif (BYTE_ORDER == BIG_ENDIAN)
		/// Specifies the size of the TCP header in 32-bit words
		uint16_t dataOffset : 4;
		/// Reserved
		uint16_t reserved : 3;
		/// Accurate ECN flag
		uint16_t accurateEcnFlag : 1;
		/// CWR flag
		uint16_t cwrFlag : 1;
		/// ECE flag
		uint16_t eceFlag : 1;
		/// URG flag
		uint16_t urgFlag : 1;
		/// ACK flag
		uint16_t ackFlag : 1;
		/// PSH flag
		uint16_t pshFlag : 1;
		/// RST flag
		uint16_t rstFlag : 1;
		/// SYN flag
		uint16_t synFlag : 1;
		/// FIN flag
		uint16_t finFlag : 1;
#else
#	error "Endian is not LE nor BE..."
#endif
		/// The size of the receive window, which specifies the number of window size units (by default, bytes)
		uint16_t windowSize;
		/// The 16-bit checksum field is used for error-checking of the header and data
		uint16_t headerChecksum;
		/// If the URG flag (@ref tcphdr#urgFlag) is set, then this 16-bit field is an offset from the sequence number
		/// indicating the last urgent data byte
		uint16_t urgentPointer;
	};
#pragma pack(pop)
	static_assert(sizeof(tcphdr) == 20, "tcphdr size is not 20 bytes");

	/// TCP options types
	enum TcpOptionType : uint8_t
	{
		/// Padding
		PCPP_TCPOPT_NOP = 1,
		/// End of options
		PCPP_TCPOPT_EOL = 0,
		/// Segment size negotiating
		TCPOPT_MSS = 2,
		/// Window scaling
		PCPP_TCPOPT_WINDOW = 3,
		/// SACK Permitted
		TCPOPT_SACK_PERM = 4,
		/// SACK Block
		PCPP_TCPOPT_SACK = 5,
		/// Echo (obsoleted by option TcpOptionType::PCPP_TCPOPT_TIMESTAMP)
		TCPOPT_ECHO = 6,
		/// Echo Reply (obsoleted by option TcpOptionType::PCPP_TCPOPT_TIMESTAMP)
		TCPOPT_ECHOREPLY = 7,
		/// TCP Timestamps
		PCPP_TCPOPT_TIMESTAMP = 8,
		/// CC (obsolete)
		TCPOPT_CC = 11,
		/// CC.NEW (obsolete)
		TCPOPT_CCNEW = 12,
		/// CC.ECHO(obsolete)
		TCPOPT_CCECHO = 13,
		/// MD5 Signature Option
		TCPOPT_MD5 = 19,
		/// Multipath TCP
		TCPOPT_MPTCP = 0x1e,
		/// SCPS Capabilities
		TCPOPT_SCPS = 20,
		/// SCPS SNACK
		TCPOPT_SNACK = 21,
		/// SCPS Record Boundary
		TCPOPT_RECBOUND = 22,
		/// SCPS Corruption Experienced
		TCPOPT_CORREXP = 23,
		/// Quick-Start Response
		TCPOPT_QS = 27,
		/// User Timeout Option (also, other known unauthorized use)
		TCPOPT_USER_TO = 28,
		/// RFC3692-style Experiment 1 (also improperly used for shipping products)
		TCPOPT_EXP_FD = 0xfd,
		/// RFC3692-style Experiment 2 (also improperly used for shipping products)
		TCPOPT_EXP_FE = 0xfe,
		/// Riverbed probe option, non IANA registered option number
		TCPOPT_RVBD_PROBE = 76,
		/// Riverbed transparency option, non IANA registered option number
		TCPOPT_RVBD_TRPY = 78,
		/// Unknown option
		TCPOPT_Unknown = 255
	};

	/// TCP options types
	enum class TcpOptionEnumType : uint8_t
	{
		/// Padding
		Nop = 1,
		/// End of options
		Eol = 0,
		/// Segment size negotiating
		Mss = 2,
		/// Window scaling
		Window = 3,
		/// SACK Permitted
		SackPerm = 4,
		/// SACK Block
		Sack = 5,
		/// Echo (obsoleted by option TcpOptionEnumType::Timestamp)
		Echo = 6,
		/// Echo Reply (obsoleted by option TcpOptionEnumType::Timestamp)
		EchoReply = 7,
		/// TCP Timestamps
		Timestamp = 8,
		/// CC (obsolete)
		Cc = 11,
		/// CC.NEW (obsolete)
		CcNew = 12,
		/// CC.ECHO(obsolete)
		CcEcho = 13,
		/// MD5 Signature Option
		Md5 = 19,
		/// Multipath TCP
		MpTcp = 0x1e,
		/// SCPS Capabilities
		Scps = 20,
		/// SCPS SNACK
		Snack = 21,
		/// SCPS Record Boundary
		RecBound = 22,
		/// SCPS Corruption Experienced
		CorrExp = 23,
		/// Quick-Start Response
		Qs = 27,
		/// User Timeout Option (also, other known unauthorized use)
		UserTo = 28,
		/// RFC3692-style Experiment 1 (also improperly used for shipping products)
		ExpFd = 0xfd,
		/// RFC3692-style Experiment 2 (also improperly used for shipping products)
		ExpFe = 0xfe,
		/// Riverbed probe option, non IANA registered option number
		RvbdProbe = 76,
		/// Riverbed transparency option, non IANA registered option number
		RvbdTrpy = 78,
		/// Unknown option
		Unknown = 255
	};

	// TCP option lengths

	/// pcpp::TcpOptionEnumType::Nop length
#define PCPP_TCPOLEN_NOP 1
	/// pcpp::TcpOptionEnumType::Eol length
#define PCPP_TCPOLEN_EOL 1
	/// pcpp::TcpOptionEnumType::Mss length
#define PCPP_TCPOLEN_MSS 4
	/// pcpp::TcpOptionEnumType::Window length
#define PCPP_TCPOLEN_WINDOW 3
	/// pcpp::TcpOptionEnumType::SackPerm length
#define PCPP_TCPOLEN_SACK_PERM 2
	/// pcpp::TcpOptionEnumType::Sack length
#define PCPP_TCPOLEN_SACK_MIN 2
	/// pcpp::TcpOptionEnumType::Echo length
#define PCPP_TCPOLEN_ECHO 6
	/// pcpp::TcpOptionEnumType::EchoReply length
#define PCPP_TCPOLEN_ECHOREPLY 6
	/// pcpp::TcpOptionEnumType::Timestamp length
#define PCPP_TCPOLEN_TIMESTAMP 10
	/// pcpp::TcpOptionEnumType::Cc length
#define PCPP_TCPOLEN_CC 6
	/// pcpp::TcpOptionEnumType::CcNew length
#define PCPP_TCPOLEN_CCNEW 6
	/// pcpp::TcpOptionEnumType::CcEcho length
#define PCPP_TCPOLEN_CCECHO 6
	/// pcpp::TcpOptionEnumType::Md5 length
#define PCPP_TCPOLEN_MD5 18
	/// pcpp::TcpOptionEnumType::MpTcp length
#define PCPP_TCPOLEN_MPTCP_MIN 8
	/// pcpp::TcpOptionEnumType::Scps length
#define PCPP_TCPOLEN_SCPS 4
	/// pcpp::TcpOptionEnumType::Snack length
#define PCPP_TCPOLEN_SNACK 6
	/// pcpp::TcpOptionEnumType::RecBound length
#define PCPP_TCPOLEN_RECBOUND 2
	/// pcpp::TcpOptionEnumType::CorrExp length
#define PCPP_TCPOLEN_CORREXP 2
	/// pcpp::TcpOptionEnumType::Qs length
#define PCPP_TCPOLEN_QS 8
	/// pcpp::TcpOptionEnumType::UserTo length
#define PCPP_TCPOLEN_USER_TO 4
	/// pcpp::TcpOptionEnumType::RvbdProbe length
#define PCPP_TCPOLEN_RVBD_PROBE_MIN 3
	/// pcpp::TcpOptionEnumType::RvbdTrpy length
#define PCPP_TCPOLEN_RVBD_TRPY_MIN 16
	/// pcpp::TcpOptionEnumType::ExpFd and pcpp::TcpOptionEnumType::ExpFe length
#define PCPP_TCPOLEN_EXP_MIN 2

	/// @class TcpOption
	/// A wrapper class for TCP options. This class does not create or modify TCP option records, but rather
	/// serves as a wrapper and provides useful methods for retrieving data from them
	class TcpOption : public TLVRecord<uint8_t, uint8_t>
	{
	public:
		/// A c'tor for this class that gets a pointer to the option raw data (byte array)
		/// @param[in] optionRawData A pointer to the TCP option raw data
		explicit TcpOption(uint8_t* optionRawData) : TLVRecord(optionRawData)
		{}

		/// A d'tor for this class, currently does nothing
		~TcpOption() override = default;

		/// @deprecated This method is deprecated, please use getTcpOptionEnumType()
		PCPP_DEPRECATED("Use getTcpOptionEnumType instead")
		TcpOptionType getTcpOptionType() const
		{
			return getTcpOptionType(m_Data);
		}

		/// @return TCP option type casted as pcpp::TcpOptionEnumType enum. If the data is null a value
		/// of TcpOptionEnumType::Unknown is returned
		TcpOptionEnumType getTcpOptionEnumType() const
		{
			return getTcpOptionEnumType(m_Data);
		}

		/// Check if a pointer can be assigned to the TLV record data
		/// @param[in] recordRawData A pointer to the TLV record raw data
		/// @param[in] tlvDataLen The size of the TLV record raw data
		/// @return True if data is valid and can be assigned
		static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
		{
			const auto* data = reinterpret_cast<const TLVRawData*>(recordRawData);
			if (data == nullptr)
				return false;

			if (tlvDataLen < sizeof(TLVRawData::recordType))
				return false;

			const auto recordType = getTcpOptionEnumType(data);
			if (recordType == TcpOptionEnumType::Nop || recordType == TcpOptionEnumType::Eol)
				return true;

			return TLVRecord<uint8_t, uint8_t>::canAssign(recordRawData, tlvDataLen);
		}

		// implement abstract methods

		size_t getTotalSize() const override
		{
			if (m_Data == nullptr)
				return 0;

			const auto recordType = getTcpOptionEnumType(m_Data);
			if (recordType == TcpOptionEnumType::Nop || recordType == TcpOptionEnumType::Eol)
				return sizeof(uint8_t);

			return static_cast<size_t>(m_Data->recordLen);
		}

		size_t getDataSize() const override
		{
			if (m_Data == nullptr)
				return 0;

			const auto recordType = getTcpOptionEnumType(m_Data);
			if (recordType == TcpOptionEnumType::Nop || recordType == TcpOptionEnumType::Eol)
				return 0;

			return static_cast<size_t>(m_Data->recordLen) - (2 * sizeof(uint8_t));
		}

	private:
		static TcpOptionType getTcpOptionType(const TLVRawData* optionRawData)
		{
			if (optionRawData == nullptr)
				return TcpOptionType::TCPOPT_Unknown;

			return static_cast<TcpOptionType>(optionRawData->recordType);
		}

		static TcpOptionEnumType getTcpOptionEnumType(const TLVRawData* optionRawData)
		{
			if (optionRawData == nullptr)
				return TcpOptionEnumType::Unknown;

			return static_cast<TcpOptionEnumType>(optionRawData->recordType);
		}
	};

	/// @class TcpOptionBuilder
	/// A class for building TCP option records. This builder receives the TCP option parameters in its c'tor,
	/// builds the TCP option raw buffer and provides a build() method to get a TcpOption object out of it
	class TcpOptionBuilder : public TLVRecordBuilder
	{

	public:
		/// An enum to describe NOP and EOL TCP options. Used in one of this class's c'tors
		enum NopEolOptionTypes : uint8_t
		{
			/// NOP TCP option
			NOP,
			/// EOL TCP option
			EOL
		};

		/// An enum to describe NOP and EOL TCP options. Used in one of this class's c'tors
		enum class NopEolOptionEnumType : uint8_t
		{
			/// NOP TCP option
			Nop,
			/// EOL TCP option
			Eol
		};

		/// @deprecated This method is deprecated, please use constructor with TcpOptionEnumType
		PCPP_DEPRECATED_TCP_OPTION_TYPE
		TcpOptionBuilder(TcpOptionType optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue, optionValueLen)
		{}

		/// A c'tor for building TCP options which their value is a byte array. The TcpOption object can be later
		/// retrieved by calling build()
		/// @param[in] optionType TCP option type
		/// @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in
		/// any way.
		/// @param[in] optionValueLen Option value length in bytes
		TcpOptionBuilder(TcpOptionEnumType optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue, optionValueLen)
		{}

		/// @deprecated This method is deprecated, please use constructor with TcpOptionEnumType
		PCPP_DEPRECATED_TCP_OPTION_TYPE
		TcpOptionBuilder(TcpOptionType optionType, uint8_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A c'tor for building TCP options which have a 1-byte value. The TcpOption object can be later retrieved
		/// by calling build()
		/// @param[in] optionType TCP option type
		/// @param[in] optionValue A 1-byte option value
		TcpOptionBuilder(TcpOptionEnumType optionType, uint8_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// @deprecated This method is deprecated, please use constructor with TcpOptionEnumType
		PCPP_DEPRECATED_TCP_OPTION_TYPE
		TcpOptionBuilder(TcpOptionType optionType, uint16_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A c'tor for building TCP options which have a 2-byte value. The TcpOption object can be later retrieved
		/// by calling build()
		/// @param[in] optionType TCP option type
		/// @param[in] optionValue A 2-byte option value
		TcpOptionBuilder(TcpOptionEnumType optionType, uint16_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// @deprecated This method is deprecated, please use constructor with TcpOptionEnumType
		PCPP_DEPRECATED_TCP_OPTION_TYPE
		TcpOptionBuilder(TcpOptionType optionType, uint32_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A c'tor for building TCP options which have a 4-byte value. The TcpOption object can be later retrieved
		/// by calling build()
		/// @param[in] optionType TCP option type
		/// @param[in] optionValue A 4-byte option value
		TcpOptionBuilder(TcpOptionEnumType optionType, uint32_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// @deprecated This method is deprecated, please use constructor with NopEolOptionEnumType
		PCPP_DEPRECATED("enum NopEolOptionTypes is deprecated; Use enum class NopEolOptionEnumType instead")
		explicit TcpOptionBuilder(NopEolOptionTypes optionType);

		/// A c'tor for building TCP NOP and EOL options. These option types are special in that they contain only 1
		/// byte which is the TCP option type (NOP or EOL). The TcpOption object can be later retrieved by calling
		/// build()
		/// @param[in] optionType An enum value indicating which option type to build (NOP or EOL)
		explicit TcpOptionBuilder(NopEolOptionEnumType optionType);

		/// Build the TcpOption object out of the parameters defined in the c'tor
		/// @return The TcpOption object
		TcpOption build() const;
	};

	/// @class TcpLayer
	/// Represents a TCP (Transmission Control Protocol) protocol layer
	class TcpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref tcphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A constructor that allocates a new TCP header with zero TCP options
		TcpLayer();

		/// A constructor that allocates a new TCP header with source port and destination port and zero TCP options
		/// @param[in] portSrc Source port
		/// @param[in] portDst Destination port
		TcpLayer(uint16_t portSrc, uint16_t portDst);

		~TcpLayer() override = default;

		/// A copy constructor that copy the entire header from the other TcpLayer (including TCP options)
		TcpLayer(const TcpLayer& other);

		/// An assignment operator that first delete all data from current layer and then copy the entire header from
		/// the other TcpLayer (including TCP options)
		TcpLayer& operator=(const TcpLayer& other);

		/// Get a pointer to the TCP header. Notice this points directly to the data, so every change will change the
		/// actual packet data
		/// @return A pointer to the @ref tcphdr
		tcphdr* getTcpHeader() const
		{
			return reinterpret_cast<tcphdr*>(m_Data);
		}

		/// @return TCP source port
		uint16_t getSrcPort() const;

		/// @return TCP destination port
		uint16_t getDstPort() const;

		/// @deprecated This method is deprecated, please use getTcpOption(TcpOptionEnumType option)
		PCPP_DEPRECATED_TCP_OPTION_TYPE
		TcpOption getTcpOption(TcpOptionType option) const;

		/// Get a TCP option by type
		/// @param[in] option TCP option type to retrieve
		/// @return An TcpOption object that contains the first option that matches this type, or logical null
		/// (TcpOption#isNull() == true) if no such option found
		TcpOption getTcpOption(TcpOptionEnumType option) const;

		/// @return The first TCP option in the packet. If the current layer contains no options the returned value will
		/// contain a logical null (TcpOption#isNull() == true)
		TcpOption getFirstTcpOption() const;

		/// Get the TCP option that comes after a given option. If the given option was the last one, the
		/// returned value will contain a logical null (TcpOption#isNull() == true)
		/// @param[in] tcpOption A TCP option object that exists in the current layer
		/// @return A TcpOption object that contains the TCP option data that comes next, or logical null if the given
		/// TCP option: (1) was the last one; or (2) contains a logical null; or (3) doesn't belong to this packet
		TcpOption getNextTcpOption(TcpOption& tcpOption) const;

		/// @return The number of TCP options in this layer
		size_t getTcpOptionCount() const;

		/// Add a new TCP option at the end of the layer (after the last TCP option)
		/// @param[in] optionBuilder A TcpOptionBuilder object that contains the TCP option data to be added
		/// @return A TcpOption object that contains the newly added TCP option data or logical null
		/// (TcpOption#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		/// printed to log
		TcpOption addTcpOption(const TcpOptionBuilder& optionBuilder);

		/// @deprecated This method is deprecated, please use insertTcpOptionAfter(const TcpOptionBuilder&
		/// optionBuilder, TcpOptionEnumType prevOptionType = TcpOptionEnumType::Unknown)
		PCPP_DEPRECATED("Use insertTcpOptionAfter instead")
		TcpOption addTcpOptionAfter(const TcpOptionBuilder& optionBuilder,
		                            TcpOptionType prevOptionType = TcpOptionType::TCPOPT_Unknown);

		/// Insert a new TCP option after an existing one
		/// @param[in] optionBuilder A TcpOptionBuilder object that contains the requested TCP option data to be
		/// inserted
		/// @param[in] prevOptionType The TCP option which the newly inserted option should come after. This is an
		/// optional parameter which gets a default value of TcpOptionType::Unknown if omitted, which means the new
		/// option will be inserted as the first option in the layer
		/// @return A TcpOption object containing the newly inserted TCP option data or logical null
		/// (TcpOption#isNull() == true) if insertion failed. In case of a failure a corresponding error message will be
		/// printed to log
		TcpOption insertTcpOptionAfter(const TcpOptionBuilder& optionBuilder,
		                               TcpOptionEnumType prevOptionType = TcpOptionEnumType::Unknown);

		/// @deprecated This method is deprecated, please use removeTcpOption(TcpOptionEnumType)
		PCPP_DEPRECATED_TCP_OPTION_TYPE
		bool removeTcpOption(TcpOptionType optionType);

		/// Remove an existing TCP option from the layer. TCP option is found by type
		/// @param[in] optionType The TCP option type to remove
		/// @return True if TCP option was removed or false if type wasn't found or if removal failed (in each case a
		/// proper error will be written to log)
		bool removeTcpOption(TcpOptionEnumType optionType);

		/// Remove all TCP options in this layer
		/// @return True if all TCP options were successfully removed or false if removal failed for some reason
		/// (a proper error will be written to log)
		bool removeAllTcpOptions();

		/// Calculate the checksum from header and data and possibly write the result to @ref tcphdr#headerChecksum
		/// @param[in] writeResultToPacket If set to true then checksum result will be written to @ref
		/// tcphdr#headerChecksum
		/// @return The checksum result
		uint16_t calculateChecksum(bool writeResultToPacket);

		/// The static method makes validation of input data
		/// @param[in] data The pointer to the beginning of byte stream of TCP packet
		/// @param[in] dataLen The length of byte stream
		/// @return True if the data is valid and can represent a TCP packet
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/// Currently identifies the following next layers: HttpRequestLayer, HttpResponseLayer. Otherwise sets
		/// PayloadLayer
		void parseNextLayer() override;

		/// @return Size of @ref tcphdr + all TCP options
		size_t getHeaderLen() const override
		{
			return getTcpHeader()->dataOffset * 4;
		}

		/// Calculate @ref tcphdr#headerChecksum field
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	private:
		TLVRecordReader<TcpOption> m_OptionReader;
		int m_NumOfTrailingBytes;

		void initLayer();
		uint8_t* getOptionsBasePtr() const
		{
			return m_Data + sizeof(tcphdr);
		}
		TcpOption addTcpOptionAt(const TcpOptionBuilder& optionBuilder, int offset);
		void adjustTcpOptionTrailer(size_t totalOptSize);
		void copyLayerData(const TcpLayer& other);
	};

	// implementation of inline methods

	bool TcpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		const tcphdr* hdr = reinterpret_cast<const tcphdr*>(data);
		return dataLen >= sizeof(tcphdr) && hdr->dataOffset >= 5 /* the minimum TCP header size */
		       && dataLen >= hdr->dataOffset * sizeof(uint32_t);
	}
}  // namespace pcpp

#undef PCPP_DEPRECATED_TCP_OPTION_TYPE
