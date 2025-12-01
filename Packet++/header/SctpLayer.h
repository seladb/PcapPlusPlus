#pragma once

#include "Layer.h"
#include "IpAddress.h"
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct sctphdr
	/// Represents the SCTP common header (RFC 9260, Section 3)
#pragma pack(push, 1)
	struct sctphdr
	{
		/// Source port number (16 bits)
		uint16_t portSrc;
		/// Destination port number (16 bits)
		uint16_t portDst;
		/// Verification tag (32 bits)
		uint32_t verificationTag;
		/// Checksum (32 bits) - CRC32c
		uint32_t checksum;
	};
#pragma pack(pop)
	static_assert(sizeof(sctphdr) == 12, "sctphdr size must be 12 bytes");

	/// @struct sctp_chunk_hdr
	/// Common header for all SCTP chunks (RFC 9260, Section 3.2)
#pragma pack(push, 1)
	struct sctp_chunk_hdr
	{
		/// Chunk type (8 bits)
		uint8_t type;
		/// Chunk flags (8 bits)
		uint8_t flags;
		/// Chunk length (16 bits) - includes header, excludes padding
		uint16_t length;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_chunk_hdr) == 4, "sctp_chunk_hdr size must be 4 bytes");

	/// @struct sctp_data_chunk
	/// DATA chunk header (RFC 9260, Section 3.3.1)
#pragma pack(push, 1)
	struct sctp_data_chunk
	{
		/// Chunk type = 0
		uint8_t type;
		/// Chunk flags: E(0), B(1), U(2), I(3)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Transmission Sequence Number
		uint32_t tsn;
		/// Stream Identifier
		uint16_t streamId;
		/// Stream Sequence Number
		uint16_t streamSeqNum;
		/// Payload Protocol Identifier
		uint32_t ppid;
		// User data follows
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_data_chunk) == 16, "sctp_data_chunk size must be 16 bytes");

	/// @struct sctp_init_chunk
	/// INIT chunk header (RFC 9260, Section 3.3.2)
#pragma pack(push, 1)
	struct sctp_init_chunk
	{
		/// Chunk type = 1
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Initiate Tag
		uint32_t initiateTag;
		/// Advertised Receiver Window Credit
		uint32_t arwnd;
		/// Number of Outbound Streams
		uint16_t numOutboundStreams;
		/// Number of Inbound Streams
		uint16_t numInboundStreams;
		/// Initial TSN
		uint32_t initialTsn;
		// Optional parameters follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_init_chunk) == 20, "sctp_init_chunk size must be 20 bytes");

	/// @struct sctp_init_ack_chunk
	/// INIT ACK chunk header (RFC 9260, Section 3.3.3)
	/// Same structure as INIT chunk
	using sctp_init_ack_chunk = sctp_init_chunk;

	/// @struct sctp_sack_chunk
	/// SACK chunk header (RFC 9260, Section 3.3.4)
#pragma pack(push, 1)
	struct sctp_sack_chunk
	{
		/// Chunk type = 3
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Cumulative TSN Ack
		uint32_t cumulativeTsnAck;
		/// Advertised Receiver Window Credit
		uint32_t arwnd;
		/// Number of Gap Ack Blocks
		uint16_t numGapBlocks;
		/// Number of Duplicate TSNs
		uint16_t numDupTsns;
		// Gap Ack Blocks and Duplicate TSNs follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_sack_chunk) == 16, "sctp_sack_chunk size must be 16 bytes");

	/// @struct sctp_gap_ack_block
	/// Gap Ack Block structure for SACK chunk
#pragma pack(push, 1)
	struct sctp_gap_ack_block
	{
		/// Gap Ack Block Start (offset from Cumulative TSN Ack)
		uint16_t start;
		/// Gap Ack Block End (offset from Cumulative TSN Ack)
		uint16_t end;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_gap_ack_block) == 4, "sctp_gap_ack_block size must be 4 bytes");

	/// @struct sctp_heartbeat_chunk
	/// HEARTBEAT chunk header (RFC 9260, Section 3.3.5)
#pragma pack(push, 1)
	struct sctp_heartbeat_chunk
	{
		/// Chunk type = 4
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		// Heartbeat Information TLV follows
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_heartbeat_chunk) == 4, "sctp_heartbeat_chunk size must be 4 bytes");

	/// @struct sctp_heartbeat_ack_chunk
	/// HEARTBEAT ACK chunk header (RFC 9260, Section 3.3.6)
	using sctp_heartbeat_ack_chunk = sctp_heartbeat_chunk;

	/// @struct sctp_abort_chunk
	/// ABORT chunk header (RFC 9260, Section 3.3.7)
#pragma pack(push, 1)
	struct sctp_abort_chunk
	{
		/// Chunk type = 6
		uint8_t type;
		/// Chunk flags: T bit (0)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		// Zero or more Error Causes follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_abort_chunk) == 4, "sctp_abort_chunk size must be 4 bytes");

	/// @struct sctp_shutdown_chunk
	/// SHUTDOWN chunk header (RFC 9260, Section 3.3.8)
#pragma pack(push, 1)
	struct sctp_shutdown_chunk
	{
		/// Chunk type = 7
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length = 8
		uint16_t length;
		/// Cumulative TSN Ack
		uint32_t cumulativeTsnAck;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_shutdown_chunk) == 8, "sctp_shutdown_chunk size must be 8 bytes");

	/// @struct sctp_shutdown_ack_chunk
	/// SHUTDOWN ACK chunk header (RFC 9260, Section 3.3.9)
#pragma pack(push, 1)
	struct sctp_shutdown_ack_chunk
	{
		/// Chunk type = 8
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length = 4
		uint16_t length;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_shutdown_ack_chunk) == 4, "sctp_shutdown_ack_chunk size must be 4 bytes");

	/// @struct sctp_error_chunk
	/// ERROR chunk header (RFC 9260, Section 3.3.10)
#pragma pack(push, 1)
	struct sctp_error_chunk
	{
		/// Chunk type = 9
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		// One or more Error Causes follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_error_chunk) == 4, "sctp_error_chunk size must be 4 bytes");

	/// @struct sctp_cookie_echo_chunk
	/// COOKIE ECHO chunk header (RFC 9260, Section 3.3.11)
#pragma pack(push, 1)
	struct sctp_cookie_echo_chunk
	{
		/// Chunk type = 10
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		// Cookie follows (variable length)
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_cookie_echo_chunk) == 4, "sctp_cookie_echo_chunk size must be 4 bytes");

	/// @struct sctp_cookie_ack_chunk
	/// COOKIE ACK chunk header (RFC 9260, Section 3.3.12)
#pragma pack(push, 1)
	struct sctp_cookie_ack_chunk
	{
		/// Chunk type = 11
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length = 4
		uint16_t length;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_cookie_ack_chunk) == 4, "sctp_cookie_ack_chunk size must be 4 bytes");

	/// @struct sctp_ecne_chunk
	/// ECNE chunk header (RFC 9260, Section 3.3.13)
#pragma pack(push, 1)
	struct sctp_ecne_chunk
	{
		/// Chunk type = 12
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length = 8
		uint16_t length;
		/// Lowest TSN Number
		uint32_t lowestTsn;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_ecne_chunk) == 8, "sctp_ecne_chunk size must be 8 bytes");

	/// @struct sctp_cwr_chunk
	/// CWR chunk header (RFC 9260, Section 3.3.14)
#pragma pack(push, 1)
	struct sctp_cwr_chunk
	{
		/// Chunk type = 13
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length = 8
		uint16_t length;
		/// Lowest TSN Number
		uint32_t lowestTsn;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_cwr_chunk) == 8, "sctp_cwr_chunk size must be 8 bytes");

	/// @struct sctp_shutdown_complete_chunk
	/// SHUTDOWN COMPLETE chunk header (RFC 9260, Section 3.3.15)
#pragma pack(push, 1)
	struct sctp_shutdown_complete_chunk
	{
		/// Chunk type = 14
		uint8_t type;
		/// Chunk flags: T bit (0)
		uint8_t flags;
		/// Chunk length = 4
		uint16_t length;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_shutdown_complete_chunk) == 4, "sctp_shutdown_complete_chunk size must be 4 bytes");

	/// @struct sctp_auth_chunk
	/// AUTH chunk header (RFC 4895)
#pragma pack(push, 1)
	struct sctp_auth_chunk
	{
		/// Chunk type = 15
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Shared Key Identifier
		uint16_t sharedKeyId;
		/// HMAC Identifier
		uint16_t hmacId;
		// HMAC follows (variable length)
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_auth_chunk) == 8, "sctp_auth_chunk size must be 8 bytes");

	/// @struct sctp_idata_chunk
	/// I-DATA chunk header (RFC 8260)
#pragma pack(push, 1)
	struct sctp_idata_chunk
	{
		/// Chunk type = 64
		uint8_t type;
		/// Chunk flags: E(0), B(1), U(2), I(3)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Transmission Sequence Number
		uint32_t tsn;
		/// Stream Identifier
		uint16_t streamId;
		/// Reserved
		uint16_t reserved;
		/// Message Identifier
		uint32_t mid;
		/// PPID (if B=1) or FSN (if B=0)
		uint32_t ppidOrFsn;
		// User data follows
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_idata_chunk) == 20, "sctp_idata_chunk size must be 20 bytes");

	/// @struct sctp_asconf_ack_chunk
	/// ASCONF-ACK chunk header (RFC 5061)
#pragma pack(push, 1)
	struct sctp_asconf_ack_chunk
	{
		/// Chunk type = 128 (0x80)
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Serial Number
		uint32_t serialNumber;
		// ASCONF Parameters follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_asconf_ack_chunk) == 8, "sctp_asconf_ack_chunk size must be 8 bytes");

	/// @struct sctp_reconfig_chunk
	/// RE-CONFIG chunk header (RFC 6525)
#pragma pack(push, 1)
	struct sctp_reconfig_chunk
	{
		/// Chunk type = 130 (0x82)
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		// Re-configuration parameters follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_reconfig_chunk) == 4, "sctp_reconfig_chunk size must be 4 bytes");

	/// @struct sctp_pad_chunk
	/// PAD chunk header (RFC 4820)
#pragma pack(push, 1)
	struct sctp_pad_chunk
	{
		/// Chunk type = 132 (0x84)
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		// Padding data follows
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_pad_chunk) == 4, "sctp_pad_chunk size must be 4 bytes");

	/// @struct sctp_nr_sack_chunk
	/// NR-SACK (Non-Renegable SACK) chunk header (draft-natarajan-tsvwg-sctp-nrsack)
	/// @note This chunk type is based on an IETF draft that was never published as an RFC.
	/// It is registered with IANA (Type 16) but has limited deployment. Use with caution
	/// in production environments.
#pragma pack(push, 1)
	struct sctp_nr_sack_chunk
	{
		/// Chunk type = 16 (0x10)
		uint8_t type;
		/// Chunk flags: A bit (0x01) - all out-of-order blocks are non-renegable
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Cumulative TSN Ack
		uint32_t cumulativeTsnAck;
		/// Advertised Receiver Window Credit
		uint32_t arwnd;
		/// Number of Gap Ack Blocks
		uint16_t numGapBlocks;
		/// Number of NR Gap Ack Blocks
		uint16_t numNrGapBlocks;
		/// Number of Duplicate TSNs
		uint16_t numDupTsns;
		/// Reserved
		uint16_t reserved;
		// Gap Ack Blocks, NR Gap Ack Blocks, and Duplicate TSNs follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_nr_sack_chunk) == 20, "sctp_nr_sack_chunk size must be 20 bytes");

	/// NR-SACK chunk flag bits
	namespace SctpNrSackFlags
	{
		/// A bit - All out-of-order blocks are non-renegable
		constexpr uint8_t ALL_NON_RENEGABLE = 0x01;
	}

	/// @struct sctp_forward_tsn_chunk
	/// FORWARD TSN chunk header (RFC 3758)
#pragma pack(push, 1)
	struct sctp_forward_tsn_chunk
	{
		/// Chunk type = 192 (0xC0)
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// New Cumulative TSN
		uint32_t newCumulativeTsn;
		// Stream/Sequence pairs follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_forward_tsn_chunk) == 8, "sctp_forward_tsn_chunk size must be 8 bytes");

	/// @struct sctp_forward_tsn_stream
	/// Stream/Sequence pair for FORWARD TSN chunk
#pragma pack(push, 1)
	struct sctp_forward_tsn_stream
	{
		/// Stream Identifier
		uint16_t streamId;
		/// Stream Sequence
		uint16_t streamSeq;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_forward_tsn_stream) == 4, "sctp_forward_tsn_stream size must be 4 bytes");

	/// @struct sctp_asconf_chunk
	/// ASCONF chunk header (RFC 5061)
#pragma pack(push, 1)
	struct sctp_asconf_chunk
	{
		/// Chunk type = 193 (0xC1)
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// Serial Number
		uint32_t serialNumber;
		// Address Parameter followed by ASCONF Parameters
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_asconf_chunk) == 8, "sctp_asconf_chunk size must be 8 bytes");

	/// @struct sctp_iforward_tsn_chunk
	/// I-FORWARD-TSN chunk header (RFC 8260)
#pragma pack(push, 1)
	struct sctp_iforward_tsn_chunk
	{
		/// Chunk type = 194 (0xC2)
		uint8_t type;
		/// Chunk flags (reserved)
		uint8_t flags;
		/// Chunk length
		uint16_t length;
		/// New Cumulative TSN
		uint32_t newCumulativeTsn;
		// Stream/MID/Unordered tuples follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_iforward_tsn_chunk) == 8, "sctp_iforward_tsn_chunk size must be 8 bytes");

	/// @struct sctp_iforward_tsn_stream
	/// Stream/MID tuple for I-FORWARD-TSN chunk (RFC 8260)
	/// The reserved field contains 15 reserved bits and 1 U (Unordered) bit in the LSB
#pragma pack(push, 1)
	struct sctp_iforward_tsn_stream
	{
		/// Stream Identifier
		uint16_t streamId;
		/// Reserved (15 bits) + U bit (1 bit in LSB position)
		/// Use isUnordered() helper or check (reserved & 0x0001) after byte swap
		uint16_t reserved;
		/// Message Identifier
		uint32_t mid;

		/// Check if the U (Unordered) bit is set
		/// @param[in] reservedHostOrder The reserved field in host byte order
		/// @return True if U bit is set (unordered message)
		static bool isUnordered(uint16_t reservedHostOrder)
		{
			return (reservedHostOrder & 0x0001) != 0;
		}
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_iforward_tsn_stream) == 8, "sctp_iforward_tsn_stream size must be 8 bytes");

	/// @struct sctp_param_hdr
	/// SCTP parameter header (TLV format)
#pragma pack(push, 1)
	struct sctp_param_hdr
	{
		/// Parameter Type
		uint16_t type;
		/// Parameter Length (including header)
		uint16_t length;
		// Value follows
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_param_hdr) == 4, "sctp_param_hdr size must be 4 bytes");

	/// @struct sctp_outgoing_ssn_reset_req
	/// Outgoing SSN Reset Request Parameter (RFC 6525, Section 4.1)
#pragma pack(push, 1)
	struct sctp_outgoing_ssn_reset_req
	{
		/// Parameter Type = 13
		uint16_t type;
		/// Parameter Length = 16 + 2*N
		uint16_t length;
		/// Re-configuration Request Sequence Number
		uint32_t reqSeqNum;
		/// Re-configuration Response Sequence Number
		uint32_t respSeqNum;
		/// Sender's Last Assigned TSN
		uint32_t lastTsn;
		// Optional Stream Numbers follow (2 bytes each)
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_outgoing_ssn_reset_req) == 16, "sctp_outgoing_ssn_reset_req size must be 16 bytes");

	/// @struct sctp_incoming_ssn_reset_req
	/// Incoming SSN Reset Request Parameter (RFC 6525, Section 4.2)
#pragma pack(push, 1)
	struct sctp_incoming_ssn_reset_req
	{
		/// Parameter Type = 14
		uint16_t type;
		/// Parameter Length = 8 + 2*N
		uint16_t length;
		/// Re-configuration Request Sequence Number
		uint32_t reqSeqNum;
		// Optional Stream Numbers follow (2 bytes each)
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_incoming_ssn_reset_req) == 8, "sctp_incoming_ssn_reset_req size must be 8 bytes");

	/// @struct sctp_ssn_tsn_reset_req
	/// SSN/TSN Reset Request Parameter (RFC 6525, Section 4.3)
#pragma pack(push, 1)
	struct sctp_ssn_tsn_reset_req
	{
		/// Parameter Type = 15
		uint16_t type;
		/// Parameter Length = 8
		uint16_t length;
		/// Re-configuration Request Sequence Number
		uint32_t reqSeqNum;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_ssn_tsn_reset_req) == 8, "sctp_ssn_tsn_reset_req size must be 8 bytes");

	/// @struct sctp_reconfig_response
	/// Re-configuration Response Parameter (RFC 6525, Section 4.4)
#pragma pack(push, 1)
	struct sctp_reconfig_response
	{
		/// Parameter Type = 16
		uint16_t type;
		/// Parameter Length = 12 or 20
		uint16_t length;
		/// Re-configuration Response Sequence Number
		uint32_t respSeqNum;
		/// Result code
		uint32_t result;
		// Optional Sender's Next TSN and Receiver's Next TSN follow
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_reconfig_response) == 12, "sctp_reconfig_response size must be 12 bytes");

	/// @struct sctp_add_streams_req
	/// Add Outgoing/Incoming Streams Request Parameter (RFC 6525, Section 4.5/4.6)
#pragma pack(push, 1)
	struct sctp_add_streams_req
	{
		/// Parameter Type = 17 or 18
		uint16_t type;
		/// Parameter Length = 12
		uint16_t length;
		/// Re-configuration Request Sequence Number
		uint32_t reqSeqNum;
		/// Number of new streams
		uint16_t numNewStreams;
		/// Reserved
		uint16_t reserved;
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_add_streams_req) == 12, "sctp_add_streams_req size must be 12 bytes");

	/// @struct sctp_asconf_param
	/// ASCONF Parameter header (RFC 5061) - Add IP, Delete IP, Set Primary
#pragma pack(push, 1)
	struct sctp_asconf_param
	{
		/// Parameter Type (0xC001, 0xC002, 0xC004)
		uint16_t type;
		/// Parameter Length
		uint16_t length;
		/// ASCONF-Request Correlation ID
		uint32_t correlationId;
		// Address Parameter follows
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_asconf_param) == 8, "sctp_asconf_param size must be 8 bytes");

	/// @struct sctp_asconf_response
	/// ASCONF Response Parameter header (RFC 5061) - Error Cause Indication, Success
#pragma pack(push, 1)
	struct sctp_asconf_response
	{
		/// Parameter Type (0xC003 or 0xC005)
		uint16_t type;
		/// Parameter Length
		uint16_t length;
		/// ASCONF-Response Correlation ID
		uint32_t correlationId;
		// Error Cause(s) follow for Error Cause Indication (0xC003)
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_asconf_response) == 8, "sctp_asconf_response size must be 8 bytes");

	/// @struct sctp_error_cause
	/// SCTP error cause header
#pragma pack(push, 1)
	struct sctp_error_cause
	{
		/// Cause Code
		uint16_t code;
		/// Cause Length (including header)
		uint16_t length;
		// Cause-specific information follows
	};
#pragma pack(pop)
	static_assert(sizeof(sctp_error_cause) == 4, "sctp_error_cause size must be 4 bytes");

	/// SCTP Chunk Types (IANA Registry)
	enum class SctpChunkType : uint8_t
	{
		/// Payload Data (RFC 9260)
		DATA = 0,
		/// Initiation (RFC 9260)
		INIT = 1,
		/// Initiation Acknowledgement (RFC 9260)
		INIT_ACK = 2,
		/// Selective Acknowledgement (RFC 9260)
		SACK = 3,
		/// Heartbeat Request (RFC 9260)
		HEARTBEAT = 4,
		/// Heartbeat Acknowledgement (RFC 9260)
		HEARTBEAT_ACK = 5,
		/// Abort (RFC 9260)
		ABORT = 6,
		/// Shutdown (RFC 9260)
		SHUTDOWN = 7,
		/// Shutdown Acknowledgement (RFC 9260)
		SHUTDOWN_ACK = 8,
		/// Operation Error (RFC 9260)
		/// @note Named SCTP_ERROR to avoid conflict with Windows ERROR macro
		SCTP_ERROR = 9,
		/// State Cookie (RFC 9260)
		COOKIE_ECHO = 10,
		/// Cookie Acknowledgement (RFC 9260)
		COOKIE_ACK = 11,
		/// Explicit Congestion Notification Echo (RFC 9260)
		ECNE = 12,
		/// Congestion Window Reduced (RFC 9260)
		CWR = 13,
		/// Shutdown Complete (RFC 9260)
		SHUTDOWN_COMPLETE = 14,
		/// Authentication Chunk (RFC 4895)
		AUTH = 15,
		/// NR-SACK - Non-Renegable SACK (draft-natarajan-tsvwg-sctp-nrsack, IANA registered)
		/// @note Experimental - based on expired IETF draft, limited deployment
		NR_SACK = 16,
		/// I-DATA (RFC 8260)
		I_DATA = 64,
		/// Address Configuration Acknowledgment (RFC 5061)
		ASCONF_ACK = 128,
		/// Re-configuration Chunk (RFC 6525)
		RE_CONFIG = 130,
		/// Padding Chunk (RFC 4820)
		PAD = 132,
		/// Forward TSN (RFC 3758)
		FORWARD_TSN = 192,
		/// Address Configuration Change (RFC 5061)
		ASCONF = 193,
		/// I-FORWARD-TSN (RFC 8260)
		I_FORWARD_TSN = 194,
		/// Unknown chunk type
		UNKNOWN = 255
	};

	/// SCTP Parameter Types (IANA Registry)
	enum class SctpParameterType : uint16_t
	{
		/// Heartbeat Info (RFC 9260)
		HEARTBEAT_INFO = 1,
		/// IPv4 Address (RFC 9260)
		IPV4_ADDRESS = 5,
		/// IPv6 Address (RFC 9260)
		IPV6_ADDRESS = 6,
		/// State Cookie (RFC 9260)
		STATE_COOKIE = 7,
		/// Unrecognized Parameter (RFC 9260)
		UNRECOGNIZED_PARAM = 8,
		/// Cookie Preservative (RFC 9260)
		COOKIE_PRESERVATIVE = 9,
		/// Host Name Address (RFC 9260)
		HOST_NAME_ADDRESS = 11,
		/// Supported Address Types (RFC 9260)
		SUPPORTED_ADDRESS_TYPES = 12,
		/// Outgoing SSN Reset Request (RFC 6525)
		OUTGOING_SSN_RESET_REQ = 13,
		/// Incoming SSN Reset Request (RFC 6525)
		INCOMING_SSN_RESET_REQ = 14,
		/// SSN/TSN Reset Request (RFC 6525)
		SSN_TSN_RESET_REQ = 15,
		/// Re-configuration Response (RFC 6525)
		RECONFIG_RESPONSE = 16,
		/// Add Outgoing Streams Request (RFC 6525)
		ADD_OUTGOING_STREAMS_REQ = 17,
		/// Add Incoming Streams Request (RFC 6525)
		ADD_INCOMING_STREAMS_REQ = 18,
		/// ECN Capable (RFC 9260)
		ECN_CAPABLE = 0x8000,
		/// Zero Checksum Acceptable (RFC 9653)
		ZERO_CHECKSUM_ACCEPTABLE = 0x8001,
		/// Random (RFC 4895)
		RANDOM = 0x8002,
		/// Chunk List (RFC 4895)
		CHUNK_LIST = 0x8003,
		/// Requested HMAC Algorithm (RFC 4895)
		REQUESTED_HMAC_ALGO = 0x8004,
		/// Padding (RFC 4820)
		PADDING = 0x8005,
		/// Supported Extensions (RFC 5061)
		SUPPORTED_EXTENSIONS = 0x8008,
		/// Forward TSN Supported (RFC 3758)
		FORWARD_TSN_SUPPORTED = 0xC000,
		/// Add IP Address (RFC 5061)
		ADD_IP_ADDRESS = 0xC001,
		/// Delete IP Address (RFC 5061)
		DELETE_IP_ADDRESS = 0xC002,
		/// Error Cause Indication (RFC 5061)
		ERROR_CAUSE_INDICATION = 0xC003,
		/// Set Primary Address (RFC 5061)
		SET_PRIMARY_ADDRESS = 0xC004,
		/// Success Indication (RFC 5061)
		SUCCESS_INDICATION = 0xC005,
		/// Adaptation Layer Indication (RFC 5061)
		ADAPTATION_LAYER_INDICATION = 0xC006
	};

	/// SCTP Error Cause Codes (IANA Registry)
	enum class SctpErrorCauseCode : uint16_t
	{
		/// Invalid Stream Identifier
		INVALID_STREAM_ID = 1,
		/// Missing Mandatory Parameter
		MISSING_MANDATORY_PARAM = 2,
		/// Stale Cookie
		STALE_COOKIE = 3,
		/// Out of Resource
		OUT_OF_RESOURCE = 4,
		/// Unresolvable Address
		UNRESOLVABLE_ADDRESS = 5,
		/// Unrecognized Chunk Type
		UNRECOGNIZED_CHUNK_TYPE = 6,
		/// Invalid Mandatory Parameter
		INVALID_MANDATORY_PARAM = 7,
		/// Unrecognized Parameters
		UNRECOGNIZED_PARAMS = 8,
		/// No User Data
		NO_USER_DATA = 9,
		/// Cookie Received While Shutting Down
		COOKIE_RECEIVED_WHILE_SHUTTING_DOWN = 10,
		/// Restart Association with New Addresses
		RESTART_WITH_NEW_ADDRESSES = 11,
		/// User Initiated Abort
		USER_INITIATED_ABORT = 12,
		/// Protocol Violation
		PROTOCOL_VIOLATION = 13,
		/// Request to Delete Last Remaining IP (RFC 5061)
		DELETE_LAST_IP = 160,
		/// Operation Refused (RFC 5061)
		OPERATION_REFUSED = 161,
		/// Request to Delete Source IP (RFC 5061)
		DELETE_SOURCE_IP = 162,
		/// Association Aborted (RFC 5061)
		ASSOCIATION_ABORTED = 163,
		/// Request Refused (RFC 5061)
		REQUEST_REFUSED = 164,
		/// Unsupported HMAC Identifier (RFC 4895)
		UNSUPPORTED_HMAC_ID = 261
	};

	/// SCTP Payload Protocol Identifiers (IANA Registry)
	enum class SctpPayloadProtocolId : uint32_t
	{
		/// Reserved
		RESERVED = 0,
		/// IUA (RFC 4233)
		IUA = 1,
		/// M2UA (RFC 3331)
		M2UA = 2,
		/// M3UA (RFC 4666)
		M3UA = 3,
		/// SUA (RFC 3868)
		SUA = 4,
		/// M2PA (RFC 4165)
		M2PA = 5,
		/// V5UA (RFC 3807)
		V5UA = 6,
		/// H.248 (ITU-T)
		H248 = 7,
		/// BICC/Q.2150.3 (ITU-T)
		BICC = 8,
		/// TALI (RFC 3094)
		TALI = 9,
		/// DUA (RFC 4129)
		DUA = 10,
		/// ASAP (RFC 5352)
		ASAP = 11,
		/// ENRP (RFC 5353)
		ENRP = 12,
		/// H.323 over SCTP
		H323 = 13,
		/// Q.IPC/Q.2150.3 (ITU-T)
		QIPC = 14,
		/// SIMCO
		SIMCO = 15,
		/// DDP Segment Chunk (RFC 5043)
		DDP_SEGMENT = 16,
		/// DDP Stream Session Control (RFC 5043)
		DDP_STREAM = 17,
		/// S1AP (3GPP TS 36.412)
		S1AP = 18,
		/// RUA (3GPP TS 25.468)
		RUA = 19,
		/// HNBAP (3GPP TS 25.469)
		HNBAP = 20,
		/// ForCES-HP (RFC 5811)
		FORCES_HP = 21,
		/// ForCES-MP (RFC 5811)
		FORCES_MP = 22,
		/// ForCES-LP (RFC 5811)
		FORCES_LP = 23,
		/// SBC-AP (3GPP TS 29.168)
		SBC_AP = 24,
		/// NBAP (3GPP TS 25.433)
		NBAP = 25,
		/// X2AP (3GPP TS 36.423)
		X2AP = 27,
		/// IRCP (Inter Router Capability Protocol)
		IRCP = 28,
		/// SABP (3GPP TS 25.419)
		SABP = 29,
		/// LCS-AP (3GPP TS 29.171)
		LCS_AP = 30,
		/// MPICH2
		MPICH2 = 31,
		/// Fractal Generator Protocol
		FGP = 32,
		/// Ping Pong Protocol
		PPP = 33,
		/// CalcApp Protocol
		CALCAPP = 34,
		/// SSP (Simple Spreadsheet Protocol)
		SSP = 35,
		/// NPMP-CONTROL
		NPMP_CONTROL = 36,
		/// NPMP-DATA
		NPMP_DATA = 37,
		/// Echo
		ECHO = 38,
		/// Discard
		DISCARD = 39,
		/// Daytime
		DAYTIME = 40,
		/// Character Generator (CHARGEN)
		CHARGEN = 41,
		/// 3GPP RNA (Radio Network Layer Application)
		RNA = 42,
		/// M2AP (3GPP TS 36.443)
		M2AP = 43,
		/// M3AP (3GPP TS 36.444)
		M3AP = 44,
		/// SSH over SCTP
		SSH = 45,
		/// Diameter (RFC 6733)
		DIAMETER = 46,
		/// Diameter DTLS
		DIAMETER_DTLS = 47,
		/// R14P (BER encoded)
		R14P_BER = 48,
		/// R14P (GPB encoded)
		R14P_GPB = 49,
		/// WebRTC DCEP (RFC 8832)
		WEBRTC_DCEP = 50,
		/// WebRTC String (RFC 8831)
		WEBRTC_STRING = 51,
		/// WebRTC Binary Partial (RFC 8831)
		WEBRTC_BINARY_PARTIAL = 52,
		/// WebRTC Binary (RFC 8831)
		WEBRTC_BINARY = 53,
		/// WebRTC String Partial (RFC 8831)
		WEBRTC_STRING_PARTIAL = 54,
		/// WebRTC String Empty (RFC 8831)
		WEBRTC_STRING_EMPTY = 56,
		/// WebRTC Binary Empty (RFC 8831)
		WEBRTC_BINARY_EMPTY = 57,
		/// 3GPP NGAP (3GPP TS 38.413)
		NGAP = 60,
		/// 3GPP XnAP (3GPP TS 38.423)
		XNAP = 61,
		/// 3GPP F1AP (3GPP TS 38.473)
		F1AP = 62,
		/// HTTP/SCTP (experimental)
		HTTP_SCTP = 63,
		/// 3GPP E1AP (3GPP TS 38.463)
		E1AP = 64,
		/// 3GPP E2AP (O-RAN E2 interface, 3GPP TS 36.423)
		E2AP = 65,
		/// 3GPP E2AP over DTLS
		E2AP_DTLS = 66,
		/// 3GPP W1AP (3GPP TS 37.473) - non-DTLS variant
		W1AP_NON_DTLS = 67,
		/// 3GPP NRPPa (3GPP TS 38.455)
		NRPPA = 68,
		/// 3GPP NRPPa over DTLS
		NRPPA_DTLS = 69,
		/// 3GPP F1AP over DTLS
		F1AP_DTLS = 70,
		/// 3GPP E1AP over DTLS
		E1AP_DTLS = 71,
		/// 3GPP W1AP (3GPP TS 37.473)
		W1AP = 72,
		/// 3GPP NGAP over DTLS
		NGAP_DTLS = 73,
		/// 3GPP XnAP over DTLS
		XNAP_DTLS = 74,
		/// DTLS Chunk Key-Management Messages
		DTLS_KEY_MGMT = 4242
	};

	/// RE-CONFIG Response Result Codes (RFC 6525)
	enum class SctpReconfigResult : uint32_t
	{
		/// Success - Nothing to do
		SUCCESS_NOTHING_TO_DO = 0,
		/// Success - Performed
		SUCCESS_PERFORMED = 1,
		/// Denied
		DENIED = 2,
		/// Error - Wrong SSN
		ERROR_WRONG_SSN = 3,
		/// Error - Request already in progress
		ERROR_REQUEST_IN_PROGRESS = 4,
		/// Error - Bad Sequence Number
		ERROR_BAD_SEQUENCE_NUMBER = 5,
		/// In progress
		IN_PROGRESS = 6
	};

	/// Zero Checksum Error Detection Method Identifiers (RFC 9653)
	enum class SctpEdmid : uint32_t
	{
		/// Reserved
		RESERVED = 0,
		/// DTLS (RFC 9147)
		DTLS = 1
	};

	/// HMAC Identifiers (RFC 4895)
	enum class SctpHmacIdentifier : uint16_t
	{
		/// Reserved
		RESERVED = 0,
		/// SHA-1
		SHA1 = 1,
		/// SHA-256
		SHA256 = 3
	};

	/// DATA chunk flag bits
	namespace SctpDataChunkFlags
	{
		/// End fragment bit
		constexpr uint8_t END_FRAGMENT = 0x01;
		/// Beginning fragment bit
		constexpr uint8_t BEGIN_FRAGMENT = 0x02;
		/// Unordered bit
		constexpr uint8_t UNORDERED = 0x04;
		/// Immediate bit (RFC 7053)
		constexpr uint8_t IMMEDIATE = 0x08;
	}  // namespace SctpDataChunkFlags

	/// ABORT and SHUTDOWN COMPLETE chunk flag bits
	namespace SctpAbortFlags
	{
		/// T bit - Verification Tag handling
		constexpr uint8_t T_BIT = 0x01;
	}

	/// Result of chunk bundling validation
	enum class SctpBundlingStatus
	{
		/// Bundling is valid
		VALID,
		/// INIT chunk cannot be bundled with other chunks (RFC 9260)
		INIT_BUNDLED,
		/// INIT-ACK chunk cannot be bundled with other chunks (RFC 9260)
		INIT_ACK_BUNDLED,
		/// SHUTDOWN-COMPLETE chunk cannot be bundled with other chunks (RFC 9260)
		SHUTDOWN_COMPLETE_BUNDLED,
		/// INIT chunk requires verification tag to be zero (RFC 9260)
		INIT_NONZERO_TAG
	};

	// Forward declarations
	class SctpChunk;
	class SctpLayer;
	class SctpInitParameter;

	/// @class SctpChunk
	/// A wrapper class for SCTP chunks. This class does not create or modify chunk records,
	/// but rather serves as a wrapper and provides useful methods for retrieving data from them
	class SctpChunk
	{
	public:
		/// Construct from raw data pointer
		/// @param[in] data Pointer to chunk data
		explicit SctpChunk(uint8_t* data) : m_Data(reinterpret_cast<sctp_chunk_hdr*>(data))
		{}

		/// Default destructor
		~SctpChunk() = default;

		/// @return True if chunk is null/invalid
		bool isNull() const
		{
			return m_Data == nullptr;
		}

		/// @return True if chunk is not null
		bool isNotNull() const
		{
			return m_Data != nullptr;
		}

		/// @return Chunk type as enum
		SctpChunkType getChunkType() const;

		/// @return Chunk type as raw uint8_t
		uint8_t getChunkTypeAsInt() const;

		/// @return Chunk flags
		uint8_t getFlags() const;

		/// @return Chunk length (as specified in header, not including padding)
		uint16_t getLength() const;

		/// @return Total size including padding (aligned to 4 bytes)
		size_t getTotalSize() const;

		/// @return Pointer to chunk value/payload (after the 4-byte header)
		uint8_t* getValue() const;

		/// @return Size of chunk value (length - 4)
		size_t getValueSize() const;

		/// @return Pointer to raw chunk data
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

		/// Get value at offset as specific type
		/// @tparam T Type to retrieve
		/// @param[in] offset Offset into value
		/// @return Value at offset, or 0 if invalid
		template <typename T> T getValueAs(size_t offset = 0) const
		{
			if (m_Data == nullptr || offset + sizeof(T) > getValueSize())
				return T{};
			return *reinterpret_cast<const T*>(getValue() + offset);
		}

		// ==================== DATA Chunk Methods ====================

		/// @return TSN value (for DATA/I-DATA chunks)
		uint32_t getDataTsn() const;

		/// @return Stream Identifier (for DATA/I-DATA chunks)
		uint16_t getDataStreamId() const;

		/// @return Stream Sequence Number (for DATA chunks)
		uint16_t getDataStreamSequenceNumber() const;

		/// @return Payload Protocol Identifier (for DATA chunks, or I-DATA when B=1)
		/// @note RFC 9260 states that SCTP implementations should not perform byte order conversion
		/// on PPID as it's the upper layer's responsibility. However, for API consistency, this library
		/// converts PPID from network to host byte order. Use getValueAs<uint32_t>(12) for raw access.
		uint32_t getDataPayloadProtocolId() const;

		/// @return Pointer to user data (for DATA/I-DATA chunks)
		uint8_t* getDataUserData() const;

		/// @return User data length (for DATA/I-DATA chunks)
		size_t getDataUserDataLength() const;

		/// @return True if this is the beginning fragment (B bit set)
		bool isDataBeginFragment() const;

		/// @return True if this is the ending fragment (E bit set)
		bool isDataEndFragment() const;

		/// @return True if unordered delivery (U bit set)
		bool isDataUnordered() const;

		/// @return True if immediate bit is set (I bit, RFC 7053)
		bool isDataImmediate() const;

		// ==================== INIT/INIT-ACK Chunk Methods ====================

		/// @return Initiate Tag (for INIT/INIT-ACK chunks)
		uint32_t getInitInitiateTag() const;

		/// @return Advertised Receiver Window Credit (for INIT/INIT-ACK/SACK chunks)
		uint32_t getInitArwnd() const;

		/// @return Number of Outbound Streams (for INIT/INIT-ACK chunks)
		uint16_t getInitNumOutboundStreams() const;

		/// @return Number of Inbound Streams (for INIT/INIT-ACK chunks)
		uint16_t getInitNumInboundStreams() const;

		/// @return Initial TSN (for INIT/INIT-ACK chunks)
		uint32_t getInitInitialTsn() const;

		/// @return Pointer to first parameter in INIT/INIT-ACK chunk, or nullptr if none
		uint8_t* getInitFirstParameter() const;

		/// @return Size of parameters section in INIT/INIT-ACK chunk
		size_t getInitParametersLength() const;

		// ==================== SACK Chunk Methods ====================

		/// @return Cumulative TSN Ack (for SACK/SHUTDOWN chunks)
		uint32_t getSackCumulativeTsnAck() const;

		/// @return Advertised Receiver Window Credit (for SACK chunks)
		uint32_t getSackArwnd() const;

		/// @return Number of Gap Ack Blocks (for SACK chunks)
		uint16_t getSackNumGapBlocks() const;

		/// @return Number of Duplicate TSNs (for SACK chunks)
		uint16_t getSackNumDupTsns() const;

		/// Get Gap Ack Blocks (for SACK chunks)
		/// @return Vector of gap ack blocks
		std::vector<sctp_gap_ack_block> getSackGapBlocks() const;

		/// Get Duplicate TSNs (for SACK chunks)
		/// @return Vector of duplicate TSNs
		std::vector<uint32_t> getSackDupTsns() const;

		// ==================== NR-SACK Chunk Methods ====================

		/// @return Cumulative TSN Ack (for NR-SACK chunks)
		uint32_t getNrSackCumulativeTsnAck() const;

		/// @return Advertised Receiver Window Credit (for NR-SACK chunks)
		uint32_t getNrSackArwnd() const;

		/// @return Number of Gap Ack Blocks (for NR-SACK chunks)
		uint16_t getNrSackNumGapBlocks() const;

		/// @return Number of NR (Non-Renegable) Gap Ack Blocks (for NR-SACK chunks)
		uint16_t getNrSackNumNrGapBlocks() const;

		/// @return Number of Duplicate TSNs (for NR-SACK chunks)
		uint16_t getNrSackNumDupTsns() const;

		/// @return True if A bit is set (all out-of-order blocks are non-renegable)
		bool isNrSackAllNonRenegable() const;

		/// Get Gap Ack Blocks (for NR-SACK chunks)
		/// @return Vector of gap ack blocks
		std::vector<sctp_gap_ack_block> getNrSackGapBlocks() const;

		/// Get NR (Non-Renegable) Gap Ack Blocks (for NR-SACK chunks)
		/// @return Vector of NR gap ack blocks
		std::vector<sctp_gap_ack_block> getNrSackNrGapBlocks() const;

		/// Get Duplicate TSNs (for NR-SACK chunks)
		/// @return Vector of duplicate TSNs
		std::vector<uint32_t> getNrSackDupTsns() const;

		// ==================== SHUTDOWN Chunk Methods ====================

		/// @return Cumulative TSN Ack (for SHUTDOWN chunks)
		uint32_t getShutdownCumulativeTsnAck() const;

		// ==================== HEARTBEAT Chunk Methods ====================

		/// @return Pointer to Heartbeat Info data (for HEARTBEAT/HEARTBEAT-ACK chunks)
		uint8_t* getHeartbeatInfo() const;

		/// @return Size of Heartbeat Info data (for HEARTBEAT/HEARTBEAT-ACK chunks)
		size_t getHeartbeatInfoLength() const;

		// ==================== COOKIE-ECHO Chunk Methods ====================

		/// @return Pointer to cookie data (for COOKIE-ECHO chunks)
		uint8_t* getCookieEchoData() const;

		/// @return Size of cookie data (for COOKIE-ECHO chunks)
		size_t getCookieEchoLength() const;

		// ==================== ABORT Chunk Methods ====================

		/// @return True if T bit is set (for ABORT/SHUTDOWN-COMPLETE chunks)
		/// When T bit is set, the Verification Tag is reflected
		bool isAbortTBitSet() const;

		/// @return Pointer to first error cause in ABORT chunk, or nullptr if none
		uint8_t* getAbortFirstErrorCause() const;

		/// @return Size of error causes section in ABORT chunk
		size_t getAbortErrorCausesLength() const;

		// ==================== ERROR Chunk Methods ====================

		/// @return Pointer to first error cause in ERROR chunk, or nullptr if none
		uint8_t* getErrorFirstCause() const;

		/// @return Size of error causes section in ERROR chunk
		size_t getErrorCausesLength() const;

		// ==================== ECNE/CWR Chunk Methods ====================

		/// @return Lowest TSN Number (for ECNE chunks)
		uint32_t getEcneLowestTsn() const;

		/// @return Lowest TSN Number (for CWR chunks)
		uint32_t getCwrLowestTsn() const;

		// ==================== AUTH Chunk Methods ====================

		/// @return Shared Key Identifier (for AUTH chunks)
		uint16_t getAuthSharedKeyId() const;

		/// @return HMAC Identifier (for AUTH chunks)
		uint16_t getAuthHmacId() const;

		/// @return Pointer to HMAC data (for AUTH chunks)
		uint8_t* getAuthHmacData() const;

		/// @return Size of HMAC data (for AUTH chunks)
		size_t getAuthHmacLength() const;

		// ==================== FORWARD-TSN Chunk Methods ====================

		/// @return New Cumulative TSN (for FORWARD-TSN chunks)
		uint32_t getForwardTsnNewCumulativeTsn() const;

		/// Get the number of stream/sequence pairs in FORWARD-TSN chunk
		/// @return Number of stream entries
		size_t getForwardTsnStreamCount() const;

		/// Get stream/sequence pairs from FORWARD-TSN chunk (RFC 3758)
		/// @return Vector of stream/sequence pairs with host byte order values
		std::vector<sctp_forward_tsn_stream> getForwardTsnStreams() const;

		// ==================== ASCONF/ASCONF-ACK Chunk Methods ====================

		/// @return Serial Number (for ASCONF/ASCONF-ACK chunks)
		uint32_t getAsconfSerialNumber() const;

		// ==================== I-DATA Chunk Methods ====================

		/// @return Message Identifier (for I-DATA chunks)
		uint32_t getIDataMessageId() const;

		/// @return PPID or FSN depending on B bit (for I-DATA chunks)
		uint32_t getIDataPpidOrFsn() const;

		// ==================== I-FORWARD-TSN Chunk Methods ====================

		/// Get the number of stream/MID tuples in I-FORWARD-TSN chunk
		/// @return Number of stream entries
		size_t getIForwardTsnStreamCount() const;

		/// Get stream/MID tuples from I-FORWARD-TSN chunk (RFC 8260)
		/// @return Vector of stream/MID tuples with host byte order values
		std::vector<sctp_iforward_tsn_stream> getIForwardTsnStreams() const;

		// ==================== Utility Methods ====================

		/// Check if a flag bit is set
		/// @param[in] flagBit The flag bit to check
		/// @return True if flag is set
		bool isFlagSet(uint8_t flagBit) const;

		/// Get chunk type name as string
		/// @return Chunk type name
		std::string getChunkTypeName() const;

	private:
		sctp_chunk_hdr* m_Data;
	};

	/// @class SctpLayer
	/// Represents an SCTP (Stream Control Transmission Protocol) layer
	class SctpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref sctphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		SctpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A constructor that allocates a new SCTP header with zero chunks
		/// @param[in] srcPort Source port
		/// @param[in] dstPort Destination port
		/// @param[in] tag Verification tag (default 0)
		SctpLayer(uint16_t srcPort, uint16_t dstPort, uint32_t tag = 0);

		/// Default destructor
		~SctpLayer() override = default;

		/// Get a pointer to the SCTP header
		/// @return A pointer to the @ref sctphdr
		sctphdr* getSctpHeader() const
		{
			return reinterpret_cast<sctphdr*>(m_Data);
		}

		/// @return SCTP source port
		uint16_t getSrcPort() const;

		/// @return SCTP destination port
		uint16_t getDstPort() const;

		/// @return Verification tag
		uint32_t getVerificationTag() const;

		/// Set source port
		/// @param[in] port Source port value
		void setSrcPort(uint16_t port);

		/// Set destination port
		/// @param[in] port Destination port value
		void setDstPort(uint16_t port);

		/// Set verification tag
		/// @param[in] tag Verification tag value
		void setVerificationTag(uint32_t tag);

		// ==================== Chunk Management ====================

		/// @return Number of chunks in this SCTP packet
		size_t getChunkCount() const;

		/// Get the first chunk in the packet
		/// @return SctpChunk object or null chunk if no chunks
		SctpChunk getFirstChunk() const;

		/// Get next chunk after the given chunk
		/// @param[in] chunk Current chunk
		/// @return Next SctpChunk or null chunk if no more chunks
		SctpChunk getNextChunk(const SctpChunk& chunk) const;

		/// Get chunk by type
		/// @param[in] chunkType The chunk type to search for
		/// @return First chunk of specified type or null chunk if not found
		SctpChunk getChunk(SctpChunkType chunkType) const;

		// ==================== Checksum ====================

		/// Calculate CRC32c checksum
		/// @param[in] writeResultToPacket If true, writes result to packet
		/// @return Calculated checksum value
		uint32_t calculateChecksum(bool writeResultToPacket);

		/// Verify the checksum of the current packet
		/// @return True if checksum is valid
		bool isChecksumValid() const;

		// ==================== Validation ====================

		/// Validate SCTP data
		/// @param[in] data Pointer to data
		/// @param[in] dataLen Length of data
		/// @return True if data is valid SCTP packet
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		// ==================== Layer Interface ====================

		/// Currently sets PayloadLayer as the next layer
		void parseNextLayer() override;

		/// @return Header length (total SCTP packet length including all chunks)
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Compute calculated fields (checksum)
		void computeCalculateFields() override;

		/// @return String representation of the layer
		std::string toString() const override;

		/// @return OSI model layer (Transport Layer)
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

		// ==================== Chunk Creation Methods ====================

		/// Add a DATA chunk to the SCTP packet
		/// @param[in] tsn Transmission Sequence Number
		/// @param[in] streamId Stream Identifier
		/// @param[in] streamSeq Stream Sequence Number
		/// @param[in] ppid Payload Protocol Identifier (in host byte order, will be converted to network byte order)
		/// @param[in] userData Pointer to user data
		/// @param[in] userDataLen Length of user data
		/// @param[in] beginFragment True if this is the beginning fragment (B bit)
		/// @param[in] endFragment True if this is the ending fragment (E bit)
		/// @param[in] unordered True for unordered delivery (U bit)
		/// @param[in] immediate True for immediate bit (I bit, RFC 7053)
		/// @return True if chunk was added successfully
		/// @note RFC 9260 states that PPID byte order conversion is the upper layer's responsibility.
		/// For API consistency, this method converts PPID from host to network byte order.
		bool addDataChunk(uint32_t tsn, uint16_t streamId, uint16_t streamSeq, uint32_t ppid,
		                  const uint8_t* userData, size_t userDataLen,
		                  bool beginFragment = true, bool endFragment = true,
		                  bool unordered = false, bool immediate = false);

		/// Add an INIT chunk to the SCTP packet
		/// @param[in] initiateTag Initiate Tag
		/// @param[in] arwnd Advertised Receiver Window Credit
		/// @param[in] numOutboundStreams Number of Outbound Streams
		/// @param[in] numInboundStreams Number of Inbound Streams
		/// @param[in] initialTsn Initial TSN
		/// @param[in] parameters Optional parameters data (can be nullptr)
		/// @param[in] parametersLen Length of parameters data
		/// @return True if chunk was added successfully
		bool addInitChunk(uint32_t initiateTag, uint32_t arwnd,
		                  uint16_t numOutboundStreams, uint16_t numInboundStreams,
		                  uint32_t initialTsn,
		                  const uint8_t* parameters = nullptr, size_t parametersLen = 0);

		/// Add an INIT-ACK chunk to the SCTP packet
		/// @param[in] initiateTag Initiate Tag
		/// @param[in] arwnd Advertised Receiver Window Credit
		/// @param[in] numOutboundStreams Number of Outbound Streams
		/// @param[in] numInboundStreams Number of Inbound Streams
		/// @param[in] initialTsn Initial TSN
		/// @param[in] parameters Optional parameters data (can be nullptr)
		/// @param[in] parametersLen Length of parameters data
		/// @return True if chunk was added successfully
		bool addInitAckChunk(uint32_t initiateTag, uint32_t arwnd,
		                     uint16_t numOutboundStreams, uint16_t numInboundStreams,
		                     uint32_t initialTsn,
		                     const uint8_t* parameters = nullptr, size_t parametersLen = 0);

		/// Add a SACK chunk to the SCTP packet
		/// @param[in] cumulativeTsnAck Cumulative TSN Ack
		/// @param[in] arwnd Advertised Receiver Window Credit
		/// @param[in] gapBlocks Vector of Gap Ack Blocks (in host byte order)
		/// @param[in] dupTsns Vector of Duplicate TSNs (in host byte order)
		/// @return True if chunk was added successfully
		bool addSackChunk(uint32_t cumulativeTsnAck, uint32_t arwnd,
		                  const std::vector<sctp_gap_ack_block>& gapBlocks = {},
		                  const std::vector<uint32_t>& dupTsns = {});

		/// Add an NR-SACK (Non-Renegable SACK) chunk to the SCTP packet
		/// @param[in] cumulativeTsnAck Cumulative TSN Ack
		/// @param[in] arwnd Advertised Receiver Window Credit
		/// @param[in] gapBlocks Vector of Gap Ack Blocks (in host byte order)
		/// @param[in] nrGapBlocks Vector of NR (Non-Renegable) Gap Ack Blocks (in host byte order)
		/// @param[in] dupTsns Vector of Duplicate TSNs (in host byte order)
		/// @param[in] allNonRenegable Set A bit (all out-of-order blocks are non-renegable)
		/// @return True if chunk was added successfully
		bool addNrSackChunk(uint32_t cumulativeTsnAck, uint32_t arwnd,
		                    const std::vector<sctp_gap_ack_block>& gapBlocks = {},
		                    const std::vector<sctp_gap_ack_block>& nrGapBlocks = {},
		                    const std::vector<uint32_t>& dupTsns = {},
		                    bool allNonRenegable = false);

		/// Add a HEARTBEAT chunk to the SCTP packet
		/// @param[in] heartbeatInfo Pointer to heartbeat info data
		/// @param[in] heartbeatInfoLen Length of heartbeat info data
		/// @return True if chunk was added successfully
		bool addHeartbeatChunk(const uint8_t* heartbeatInfo, size_t heartbeatInfoLen);

		/// Add a HEARTBEAT-ACK chunk to the SCTP packet
		/// @param[in] heartbeatInfo Pointer to heartbeat info data (copy from HEARTBEAT)
		/// @param[in] heartbeatInfoLen Length of heartbeat info data
		/// @return True if chunk was added successfully
		bool addHeartbeatAckChunk(const uint8_t* heartbeatInfo, size_t heartbeatInfoLen);

		/// Add a SHUTDOWN chunk to the SCTP packet
		/// @param[in] cumulativeTsnAck Cumulative TSN Ack
		/// @return True if chunk was added successfully
		bool addShutdownChunk(uint32_t cumulativeTsnAck);

		/// Add a SHUTDOWN-ACK chunk to the SCTP packet
		/// @return True if chunk was added successfully
		bool addShutdownAckChunk();

		/// Add a SHUTDOWN-COMPLETE chunk to the SCTP packet
		/// @param[in] tBit T bit value (Verification Tag handling)
		/// @return True if chunk was added successfully
		bool addShutdownCompleteChunk(bool tBit = false);

		/// Add an ABORT chunk to the SCTP packet
		/// @param[in] tBit T bit value (Verification Tag handling)
		/// @param[in] errorCauses Optional error causes data
		/// @param[in] errorCausesLen Length of error causes data
		/// @return True if chunk was added successfully
		bool addAbortChunk(bool tBit = false, const uint8_t* errorCauses = nullptr, size_t errorCausesLen = 0);

		/// Add a COOKIE-ECHO chunk to the SCTP packet
		/// @param[in] cookie Pointer to cookie data
		/// @param[in] cookieLen Length of cookie data
		/// @return True if chunk was added successfully
		bool addCookieEchoChunk(const uint8_t* cookie, size_t cookieLen);

		/// Add a COOKIE-ACK chunk to the SCTP packet
		/// @return True if chunk was added successfully
		bool addCookieAckChunk();

		/// Add an ERROR chunk to the SCTP packet
		/// @param[in] errorCauses Pointer to error causes data
		/// @param[in] errorCausesLen Length of error causes data
		/// @return True if chunk was added successfully
		bool addErrorChunk(const uint8_t* errorCauses, size_t errorCausesLen);

		/// Add an ECNE (Explicit Congestion Notification Echo) chunk to the SCTP packet
		/// @param[in] lowestTsn Lowest TSN Number triggering the ECN
		/// @return True if chunk was added successfully
		bool addEcneChunk(uint32_t lowestTsn);

		/// Add a CWR (Congestion Window Reduced) chunk to the SCTP packet
		/// @param[in] lowestTsn Lowest TSN Number acknowledged by ECNE
		/// @return True if chunk was added successfully
		bool addCwrChunk(uint32_t lowestTsn);

		/// Add a FORWARD-TSN chunk to the SCTP packet (RFC 3758)
		/// @param[in] newCumulativeTsn New Cumulative TSN
		/// @param[in] streams Vector of stream/sequence pairs to skip
		/// @return True if chunk was added successfully
		bool addForwardTsnChunk(uint32_t newCumulativeTsn,
		                        const std::vector<sctp_forward_tsn_stream>& streams = {});

		/// Add an I-DATA chunk to the SCTP packet (RFC 8260)
		/// @param[in] tsn Transmission Sequence Number
		/// @param[in] streamId Stream Identifier
		/// @param[in] mid Message Identifier
		/// @param[in] ppidOrFsn PPID if B=1, FSN if B=0
		/// @param[in] userData Pointer to user data
		/// @param[in] userDataLen Length of user data
		/// @param[in] beginFragment True if this is the beginning fragment (B bit)
		/// @param[in] endFragment True if this is the ending fragment (E bit)
		/// @param[in] unordered True for unordered delivery (U bit)
		/// @param[in] immediate True for immediate bit (I bit)
		/// @return True if chunk was added successfully
		bool addIDataChunk(uint32_t tsn, uint16_t streamId, uint32_t mid, uint32_t ppidOrFsn,
		                   const uint8_t* userData, size_t userDataLen,
		                   bool beginFragment = true, bool endFragment = true,
		                   bool unordered = false, bool immediate = false);

		/// Add an I-FORWARD-TSN chunk to the SCTP packet (RFC 8260)
		/// @param[in] newCumulativeTsn New Cumulative TSN
		/// @param[in] streams Vector of stream/MID tuples to skip
		/// @return True if chunk was added successfully
		bool addIForwardTsnChunk(uint32_t newCumulativeTsn,
		                         const std::vector<sctp_iforward_tsn_stream>& streams = {});

		/// Add a PAD chunk to the SCTP packet (RFC 4820)
		/// @param[in] paddingLen Length of padding data (will be filled with zeros)
		/// @return True if chunk was added successfully
		bool addPadChunk(size_t paddingLen);

		/// Add an AUTH chunk to the SCTP packet (RFC 4895)
		/// @param[in] sharedKeyId Shared Key Identifier
		/// @param[in] hmacId HMAC Identifier (use SctpHmacIdentifier values)
		/// @param[in] hmac Pointer to HMAC data (pre-computed)
		/// @param[in] hmacLen Length of HMAC data
		/// @return True if chunk was added successfully
		/// @note This method adds a pre-computed HMAC. The library does not compute HMACs.
		/// Per RFC 4895, the HMAC must be 20 bytes for SHA-1 or 32 bytes for SHA-256.
		bool addAuthChunk(uint16_t sharedKeyId, uint16_t hmacId, const uint8_t* hmac, size_t hmacLen);

		/// Add an ASCONF chunk to the SCTP packet (RFC 5061)
		/// @param[in] serialNumber Sequence number for this ASCONF
		/// @param[in] addressParam Address parameter (IPv4 or IPv6) identifying the sender
		/// @param[in] addressParamLen Length of address parameter
		/// @param[in] asconfParams ASCONF parameters data (Add IP, Delete IP, Set Primary)
		/// @param[in] asconfParamsLen Length of ASCONF parameters
		/// @return True if chunk was added successfully
		bool addAsconfChunk(uint32_t serialNumber, const uint8_t* addressParam, size_t addressParamLen,
		                    const uint8_t* asconfParams = nullptr, size_t asconfParamsLen = 0);

		/// Add an ASCONF-ACK chunk to the SCTP packet (RFC 5061)
		/// @param[in] serialNumber Sequence number from corresponding ASCONF
		/// @param[in] responseParams Response parameters data (Success or Error Cause Indication)
		/// @param[in] responseParamsLen Length of response parameters
		/// @return True if chunk was added successfully
		bool addAsconfAckChunk(uint32_t serialNumber, const uint8_t* responseParams = nullptr,
		                       size_t responseParamsLen = 0);

		/// Add a RE-CONFIG chunk to the SCTP packet (RFC 6525)
		/// @param[in] parameters Re-configuration parameters data
		/// @param[in] parametersLen Length of parameters
		/// @return True if chunk was added successfully
		/// @note Use parameter builder helpers or construct parameters manually
		bool addReconfigChunk(const uint8_t* parameters, size_t parametersLen);

		// ==================== Validation Methods ====================

		/// Validate the current packet for RFC 9260 bundling rules
		/// @return SctpBundlingStatus indicating validation result
		/// @note Per RFC 9260: INIT, INIT-ACK, and SHUTDOWN-COMPLETE MUST NOT be bundled
		/// with any other chunk. INIT chunk packets MUST have verification tag = 0.
		SctpBundlingStatus validateBundling() const;

		/// Check if a specific chunk type can be added without violating bundling rules
		/// @param[in] chunkType The chunk type to check
		/// @return True if the chunk can be added without violating RFC 9260 bundling rules
		bool canAddChunk(SctpChunkType chunkType) const;

		/// Check if the SCTP packet contains a Host Name Address parameter
		/// @return True if a deprecated Host Name Address parameter is found
		/// @note Per RFC 9260, Host Name Address is deprecated and should be rejected
		bool containsHostNameAddress() const;

	private:
		void initLayer();
		uint8_t* getChunksBasePtr() const;
		size_t getChunksDataLen() const;
		bool addChunk(const uint8_t* chunkData, size_t chunkLen);
	};

	// ==================== INIT Parameter Iterator ====================

	/// @class SctpInitParameter
	/// A wrapper class for SCTP INIT/INIT-ACK parameters (TLV format)
	class SctpInitParameter
	{
	public:
		/// Construct from raw data pointer
		/// @param[in] data Pointer to parameter data
		/// @param[in] maxLen Maximum available length for this parameter
		explicit SctpInitParameter(uint8_t* data, size_t maxLen = SIZE_MAX)
		    : m_Data(reinterpret_cast<sctp_param_hdr*>(data)), m_MaxLen(maxLen)
		{}

		/// @return True if parameter is null/invalid
		bool isNull() const
		{
			return m_Data == nullptr;
		}

		/// @return True if parameter is not null
		bool isNotNull() const
		{
			return m_Data != nullptr;
		}

		/// @return Parameter type as enum
		SctpParameterType getType() const;

		/// @return Parameter type as raw uint16_t
		uint16_t getTypeAsInt() const;

		/// @return Parameter length (as specified in header, including header)
		uint16_t getLength() const;

		/// @return Total size including padding (aligned to 4 bytes)
		size_t getTotalSize() const;

		/// @return Pointer to parameter value (after the 4-byte header)
		uint8_t* getValue() const;

		/// @return Size of parameter value (length - 4)
		size_t getValueSize() const;

		/// @return Pointer to raw parameter data
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

		// ==================== Parameter-specific Methods ====================

		/// Get IPv4 address from IPv4 Address parameter
		/// @return IPv4 address, or IPv4Address::Zero if not applicable
		IPv4Address getIPv4Address() const;

		/// Get IPv6 address from IPv6 Address parameter
		/// @return IPv6 address, or IPv6Address::Zero if not applicable
		IPv6Address getIPv6Address() const;

		/// Get supported address types from Supported Address Types parameter
		/// @return Vector of supported address type values
		std::vector<uint16_t> getSupportedAddressTypes() const;

		/// Get State Cookie data from State Cookie parameter
		/// @return Pointer to cookie data, or nullptr if not a State Cookie parameter
		uint8_t* getStateCookie() const;

		/// Get State Cookie length from State Cookie parameter
		/// @return Length of cookie data, or 0 if not a State Cookie parameter
		size_t getStateCookieLength() const;

		/// Get Cookie Preservative suggested lifespan increment
		/// @return Suggested Cookie Lifespan Increment in microseconds, or 0 if not applicable
		uint32_t getCookiePreservativeIncrement() const;

		/// Get Random data from Random parameter (RFC 4895)
		/// @return Pointer to random data, or nullptr if not a Random parameter
		uint8_t* getRandomData() const;

		/// Get Random data length from Random parameter (RFC 4895)
		/// @return Length of random data, or 0 if not a Random parameter
		size_t getRandomDataLength() const;

		/// Get chunk types from Chunk List parameter (RFC 4895)
		/// @return Vector of chunk type values
		std::vector<uint8_t> getChunkList() const;

		/// Get HMAC algorithms from Requested HMAC Algorithm parameter (RFC 4895)
		/// @return Vector of HMAC identifier values
		std::vector<uint16_t> getRequestedHmacAlgorithms() const;

		/// Get supported chunk types from Supported Extensions parameter
		/// @return Vector of chunk type values
		std::vector<uint8_t> getSupportedExtensions() const;

		/// Check if this is a deprecated Host Name Address parameter
		/// @return True if this is a Host Name Address (which should be rejected per RFC 9260)
		bool isHostNameAddress() const;

		/// Get Zero Checksum Acceptable EDMID value (RFC 9653)
		/// @return Error Detection Method Identifier, or 0 if not a Zero Checksum parameter
		uint32_t getZeroChecksumEdmid() const;

		/// Get Unrecognized Parameter value (RFC 9260)
		/// @return Pointer to the unrecognized parameter data, or nullptr if not applicable
		uint8_t* getUnrecognizedParameter() const;

		/// Get Unrecognized Parameter length (RFC 9260)
		/// @return Length of unrecognized parameter data, or 0 if not applicable
		size_t getUnrecognizedParameterLength() const;

		/// Get Adaptation Layer Indication value (RFC 5061)
		/// @return Adaptation Layer Indication value, or 0 if not applicable
		uint32_t getAdaptationLayerIndication() const;

		/// Get parameter type name as string
		/// @return Parameter type name
		std::string getTypeName() const;

	private:
		sctp_param_hdr* m_Data;
		size_t m_MaxLen;
	};

	/// @class SctpInitParameterIterator
	/// Iterator for INIT/INIT-ACK parameters
	class SctpInitParameterIterator
	{
	public:
		/// Construct iterator from INIT/INIT-ACK chunk
		/// @param[in] chunk The INIT or INIT-ACK chunk to iterate
		explicit SctpInitParameterIterator(const SctpChunk& chunk);

		/// @return Current parameter
		SctpInitParameter getParameter() const;

		/// Move to next parameter
		/// @return Reference to this iterator
		SctpInitParameterIterator& next();

		/// @return True if current parameter is valid
		bool isValid() const;

		/// Reset iterator to first parameter
		void reset();

	private:
		uint8_t* m_ParamsBase;
		size_t m_ParamsLen;
		size_t m_CurrentOffset;
	};

	// ==================== Error Cause Classes ====================

	/// @class SctpErrorCause
	/// A wrapper class for SCTP error causes in ABORT/ERROR chunks
	class SctpErrorCause
	{
	public:
		/// Construct from raw data pointer
		/// @param[in] data Pointer to error cause data
		/// @param[in] maxLen Maximum available length for this error cause
		explicit SctpErrorCause(uint8_t* data, size_t maxLen = SIZE_MAX)
		    : m_Data(reinterpret_cast<sctp_error_cause*>(data)), m_MaxLen(maxLen)
		{}

		/// @return True if error cause is null/invalid
		bool isNull() const
		{
			return m_Data == nullptr;
		}

		/// @return True if error cause is not null
		bool isNotNull() const
		{
			return m_Data != nullptr;
		}

		/// @return Error cause code as enum
		SctpErrorCauseCode getCode() const;

		/// @return Error cause code as raw uint16_t
		uint16_t getCodeAsInt() const;

		/// @return Error cause length (as specified in header, including header)
		uint16_t getLength() const;

		/// @return Total size including padding (aligned to 4 bytes)
		size_t getTotalSize() const;

		/// @return Pointer to error cause data (after the 4-byte header)
		uint8_t* getData() const;

		/// @return Size of error cause data (length - 4)
		size_t getDataSize() const;

		/// @return Pointer to raw error cause data
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

		/// Get error cause code name as string
		/// @return Error cause code name
		std::string getCodeName() const;

		// ==================== Cause-specific Methods ====================

		/// Get Invalid Stream Identifier from cause data
		/// @return Stream Identifier, or 0 if not applicable
		uint16_t getInvalidStreamId() const;

		/// Get Stale Cookie staleness value
		/// @return Measure of Staleness in microseconds, or 0 if not applicable
		uint32_t getStaleCookieStaleness() const;

		/// Get TSN from No User Data cause
		/// @return TSN value, or 0 if not applicable
		uint32_t getNoUserDataTsn() const;

		/// Get Missing Mandatory Parameter types (RFC 9260)
		/// @return Vector of missing parameter type values
		std::vector<uint16_t> getMissingMandatoryParams() const;

		/// Get Unrecognized Chunk from cause data (RFC 9260)
		/// @return Pointer to the unrecognized chunk, or nullptr if not applicable
		uint8_t* getUnrecognizedChunk() const;

		/// Get Unrecognized Chunk length (RFC 9260)
		/// @return Length of unrecognized chunk data, or 0 if not applicable
		size_t getUnrecognizedChunkLength() const;

		/// Get Unrecognized Parameters from cause data (RFC 9260)
		/// @return Pointer to unrecognized parameters, or nullptr if not applicable
		uint8_t* getUnrecognizedParameters() const;

		/// Get Unrecognized Parameters length (RFC 9260)
		/// @return Length of unrecognized parameters data, or 0 if not applicable
		size_t getUnrecognizedParametersLength() const;

		/// Get Unresolvable Address from cause data (RFC 9260)
		/// @return Pointer to the address parameter, or nullptr if not applicable
		uint8_t* getUnresolvableAddress() const;

		/// Get Unresolvable Address length (RFC 9260)
		/// @return Length of address parameter, or 0 if not applicable
		size_t getUnresolvableAddressLength() const;

		/// Get New Addresses from Restart with New Addresses cause (RFC 9260)
		/// @return Pointer to new address list, or nullptr if not applicable
		uint8_t* getRestartNewAddresses() const;

		/// Get New Addresses length from Restart with New Addresses cause (RFC 9260)
		/// @return Length of new address list, or 0 if not applicable
		size_t getRestartNewAddressesLength() const;

	private:
		sctp_error_cause* m_Data;
		size_t m_MaxLen;
	};

	/// @class SctpErrorCauseIterator
	/// Iterator for error causes in ABORT/ERROR chunks
	class SctpErrorCauseIterator
	{
	public:
		/// Construct iterator from ABORT or ERROR chunk
		/// @param[in] chunk The ABORT or ERROR chunk to iterate
		explicit SctpErrorCauseIterator(const SctpChunk& chunk);

		/// @return Current error cause
		SctpErrorCause getErrorCause() const;

		/// Move to next error cause
		/// @return Reference to this iterator
		SctpErrorCauseIterator& next();

		/// @return True if current error cause is valid
		bool isValid() const;

		/// Reset iterator to first error cause
		void reset();

	private:
		uint8_t* m_CausesBase;
		size_t m_CausesLen;
		size_t m_CurrentOffset;
	};

	// ==================== RE-CONFIG Parameter Classes ====================

	/// @class SctpReconfigParameter
	/// A wrapper class for SCTP RE-CONFIG parameters (RFC 6525)
	class SctpReconfigParameter
	{
	public:
		/// Construct from raw data pointer
		/// @param[in] data Pointer to parameter data
		/// @param[in] maxLen Maximum available length for this parameter
		explicit SctpReconfigParameter(uint8_t* data, size_t maxLen = SIZE_MAX)
		    : m_Data(reinterpret_cast<sctp_param_hdr*>(data)), m_MaxLen(maxLen)
		{}

		/// @return True if parameter is null/invalid
		bool isNull() const
		{
			return m_Data == nullptr;
		}

		/// @return True if parameter is not null
		bool isNotNull() const
		{
			return m_Data != nullptr;
		}

		/// @return Parameter type as enum
		SctpParameterType getType() const;

		/// @return Parameter type as raw uint16_t
		uint16_t getTypeAsInt() const;

		/// @return Parameter length (as specified in header, including header)
		uint16_t getLength() const;

		/// @return Total size including padding (aligned to 4 bytes)
		size_t getTotalSize() const;

		/// @return Pointer to raw parameter data
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

		// ==================== Outgoing SSN Reset Request (Type 13) ====================

		/// Get Re-configuration Request Sequence Number
		/// @return Request sequence number, or 0 if not applicable
		uint32_t getOutgoingReqSeqNum() const;

		/// Get Re-configuration Response Sequence Number (Outgoing SSN Reset Request only)
		/// @return Response sequence number, or 0 if not applicable
		uint32_t getOutgoingRespSeqNum() const;

		/// Get Sender's Last Assigned TSN (Outgoing SSN Reset Request only)
		/// @return Last assigned TSN, or 0 if not applicable
		uint32_t getOutgoingLastTsn() const;

		/// Get stream numbers from Outgoing/Incoming SSN Reset Request
		/// @return Vector of stream IDs to reset
		std::vector<uint16_t> getResetStreamNumbers() const;

		// ==================== Incoming SSN Reset Request (Type 14) ====================

		/// Get Re-configuration Request Sequence Number
		/// @return Request sequence number, or 0 if not applicable
		uint32_t getIncomingReqSeqNum() const;

		// ==================== SSN/TSN Reset Request (Type 15) ====================

		/// Get Re-configuration Request Sequence Number
		/// @return Request sequence number, or 0 if not applicable
		uint32_t getSsnTsnResetReqSeqNum() const;

		// ==================== Re-configuration Response (Type 16) ====================

		/// Get Re-configuration Response Sequence Number
		/// @return Response sequence number, or 0 if not applicable
		uint32_t getReconfigRespSeqNum() const;

		/// Get Result code from Re-configuration Response
		/// @return Result code as SctpReconfigResult enum
		SctpReconfigResult getReconfigResult() const;

		/// Get Sender's Next TSN from Re-configuration Response (optional field)
		/// @return Sender's Next TSN, or 0 if not present
		uint32_t getReconfigSenderNextTsn() const;

		/// Get Receiver's Next TSN from Re-configuration Response (optional field)
		/// @return Receiver's Next TSN, or 0 if not present
		uint32_t getReconfigReceiverNextTsn() const;

		/// Check if optional TSN fields are present in Re-configuration Response
		/// @return True if Sender's/Receiver's Next TSN fields are present
		bool hasReconfigOptionalTsn() const;

		// ==================== Add Streams Request (Type 17/18) ====================

		/// Get Re-configuration Request Sequence Number
		/// @return Request sequence number, or 0 if not applicable
		uint32_t getAddStreamsReqSeqNum() const;

		/// Get number of new streams from Add Streams Request
		/// @return Number of new streams, or 0 if not applicable
		uint16_t getAddStreamsCount() const;

		/// Get parameter type name as string
		/// @return Parameter type name
		std::string getTypeName() const;

	private:
		sctp_param_hdr* m_Data;
		size_t m_MaxLen;
	};

	/// @class SctpReconfigParameterIterator
	/// Iterator for RE-CONFIG chunk parameters (RFC 6525)
	class SctpReconfigParameterIterator
	{
	public:
		/// Construct iterator from RE-CONFIG chunk
		/// @param[in] chunk The RE-CONFIG chunk to iterate
		explicit SctpReconfigParameterIterator(const SctpChunk& chunk);

		/// @return Current parameter
		SctpReconfigParameter getParameter() const;

		/// Move to next parameter
		/// @return Reference to this iterator
		SctpReconfigParameterIterator& next();

		/// @return True if current parameter is valid
		bool isValid() const;

		/// Reset iterator to first parameter
		void reset();

	private:
		uint8_t* m_ParamsBase;
		size_t m_ParamsLen;
		size_t m_CurrentOffset;
	};

	// ==================== ASCONF Parameter Classes ====================

	/// @class SctpAsconfParameter
	/// A wrapper class for SCTP ASCONF/ASCONF-ACK parameters (RFC 5061)
	class SctpAsconfParameter
	{
	public:
		/// Construct from raw data pointer
		/// @param[in] data Pointer to parameter data
		/// @param[in] maxLen Maximum available length for this parameter
		explicit SctpAsconfParameter(uint8_t* data, size_t maxLen = SIZE_MAX)
		    : m_Data(reinterpret_cast<sctp_param_hdr*>(data)), m_MaxLen(maxLen)
		{}

		/// @return True if parameter is null/invalid
		bool isNull() const
		{
			return m_Data == nullptr;
		}

		/// @return True if parameter is not null
		bool isNotNull() const
		{
			return m_Data != nullptr;
		}

		/// @return Parameter type as enum
		SctpParameterType getType() const;

		/// @return Parameter type as raw uint16_t
		uint16_t getTypeAsInt() const;

		/// @return Parameter length (as specified in header, including header)
		uint16_t getLength() const;

		/// @return Total size including padding (aligned to 4 bytes)
		size_t getTotalSize() const;

		/// @return Pointer to raw parameter data
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

		// ==================== Request Parameters (Add/Delete/Set Primary) ====================

		/// Get ASCONF-Request Correlation ID
		/// @return Correlation ID for matching request/response
		uint32_t getCorrelationId() const;

		/// Get Address Parameter from Add/Delete/Set Primary request
		/// @return Pointer to address parameter (IPv4 or IPv6 TLV), or nullptr if not applicable
		uint8_t* getAddressParameter() const;

		/// Get Address Parameter length
		/// @return Length of address parameter, or 0 if not applicable
		size_t getAddressParameterLength() const;

		/// Get IPv4 address from request (if address is IPv4)
		/// @return IPv4 address, or IPv4Address::Zero if not IPv4
		IPv4Address getIPv4Address() const;

		/// Get IPv6 address from request (if address is IPv6)
		/// @return IPv6 address, or IPv6Address::Zero if not IPv6
		IPv6Address getIPv6Address() const;

		// ==================== Response Parameters (Success/Error) ====================

		/// Get ASCONF-Response Correlation ID
		/// @return Correlation ID copied from request
		uint32_t getResponseCorrelationId() const;

		/// Get Error Causes from Error Cause Indication response
		/// @return Pointer to error causes, or nullptr if not error response
		uint8_t* getErrorCauses() const;

		/// Get Error Causes length
		/// @return Length of error causes, or 0 if not error response
		size_t getErrorCausesLength() const;

		/// Get parameter type name as string
		/// @return Parameter type name
		std::string getTypeName() const;

	private:
		sctp_param_hdr* m_Data;
		size_t m_MaxLen;
	};

	/// @class SctpAsconfParameterIterator
	/// Iterator for ASCONF/ASCONF-ACK chunk parameters (RFC 5061)
	class SctpAsconfParameterIterator
	{
	public:
		/// Construct iterator from ASCONF or ASCONF-ACK chunk
		/// @param[in] chunk The ASCONF or ASCONF-ACK chunk to iterate
		/// @param[in] skipAddressParam For ASCONF chunks, skip the mandatory Address Parameter
		explicit SctpAsconfParameterIterator(const SctpChunk& chunk, bool skipAddressParam = true);

		/// @return Current parameter
		SctpAsconfParameter getParameter() const;

		/// Move to next parameter
		/// @return Reference to this iterator
		SctpAsconfParameterIterator& next();

		/// @return True if current parameter is valid
		bool isValid() const;

		/// Reset iterator to first parameter
		void reset();

	private:
		uint8_t* m_ParamsBase;
		size_t m_ParamsLen;
		size_t m_CurrentOffset;
		size_t m_InitialOffset;
	};

	// ==================== CRC32c Functions ====================

	/// Calculate CRC32c checksum for SCTP packet
	/// @param[in] data Pointer to SCTP packet data
	/// @param[in] length Length of data
	/// @return CRC32c checksum value
	uint32_t calculateSctpCrc32c(const uint8_t* data, size_t length);

	// ==================== HMAC Functions (RFC 4895) ====================

	/// HMAC output sizes
	namespace SctpHmacSize
	{
		/// SHA-1 HMAC output size in bytes
		constexpr size_t SHA1 = 20;
		/// SHA-256 HMAC output size in bytes
		constexpr size_t SHA256 = 32;
	}

	/// Calculate HMAC-SHA1 for SCTP AUTH chunk
	/// @param[in] key Pointer to shared key data
	/// @param[in] keyLen Length of shared key
	/// @param[in] data Pointer to data to authenticate (SCTP packet from AUTH chunk HMAC field to end)
	/// @param[in] dataLen Length of data
	/// @param[out] hmacOut Output buffer for HMAC (must be at least 20 bytes)
	/// @return True if HMAC was calculated successfully
	bool calculateSctpHmacSha1(const uint8_t* key, size_t keyLen,
	                           const uint8_t* data, size_t dataLen,
	                           uint8_t* hmacOut);

	/// Calculate HMAC-SHA256 for SCTP AUTH chunk
	/// @param[in] key Pointer to shared key data
	/// @param[in] keyLen Length of shared key
	/// @param[in] data Pointer to data to authenticate (SCTP packet from AUTH chunk HMAC field to end)
	/// @param[in] dataLen Length of data
	/// @param[out] hmacOut Output buffer for HMAC (must be at least 32 bytes)
	/// @return True if HMAC was calculated successfully
	bool calculateSctpHmacSha256(const uint8_t* key, size_t keyLen,
	                             const uint8_t* data, size_t dataLen,
	                             uint8_t* hmacOut);

	/// Verify HMAC for SCTP AUTH chunk
	/// @param[in] hmacId HMAC algorithm identifier (1=SHA-1, 3=SHA-256)
	/// @param[in] key Pointer to shared key data
	/// @param[in] keyLen Length of shared key
	/// @param[in] data Pointer to data that was authenticated
	/// @param[in] dataLen Length of data
	/// @param[in] expectedHmac Pointer to expected HMAC value
	/// @param[in] expectedHmacLen Length of expected HMAC
	/// @return True if HMAC matches expected value
	bool verifySctpHmac(uint16_t hmacId, const uint8_t* key, size_t keyLen,
	                    const uint8_t* data, size_t dataLen,
	                    const uint8_t* expectedHmac, size_t expectedHmacLen);

	/// Compute HMAC for SCTP AUTH chunk per RFC 4895
	/// This is a convenience function that handles the AUTH chunk HMAC computation procedure:
	/// 1. Finds the AUTH chunk in the packet
	/// 2. Zeros the HMAC field in a copy
	/// 3. Computes HMAC over: AUTH chunk (with zeroed HMAC) + all chunks after AUTH
	/// @param[in] sctpLayer The SCTP layer containing an AUTH chunk
	/// @param[in] key Pointer to shared key data (association shared key per RFC 4895)
	/// @param[in] keyLen Length of shared key
	/// @param[out] hmacOut Output buffer for HMAC (must be at least 32 bytes for SHA-256)
	/// @param[out] hmacOutLen On success, set to actual HMAC length (20 for SHA-1, 32 for SHA-256)
	/// @return True if HMAC was computed successfully, false if no AUTH chunk or invalid parameters
	/// @note Per RFC 4895, the HMAC is computed over the AUTH chunk with its HMAC field set to zero,
	/// followed by all chunks placed after the AUTH chunk in the SCTP packet.
	bool computeSctpAuthHmac(const SctpLayer& sctpLayer, const uint8_t* key, size_t keyLen,
	                         uint8_t* hmacOut, size_t* hmacOutLen);

	/// Verify AUTH chunk HMAC in an SCTP packet per RFC 4895
	/// This is a convenience function that:
	/// 1. Finds the AUTH chunk in the packet
	/// 2. Computes the expected HMAC using the same procedure as computeSctpAuthHmac
	/// 3. Compares with the HMAC in the AUTH chunk using constant-time comparison
	/// @param[in] sctpLayer The SCTP layer containing an AUTH chunk to verify
	/// @param[in] key Pointer to shared key data (association shared key per RFC 4895)
	/// @param[in] keyLen Length of shared key
	/// @return True if AUTH chunk HMAC is valid, false otherwise
	bool verifySctpAuthChunk(const SctpLayer& sctpLayer, const uint8_t* key, size_t keyLen);

	// ==================== Chunk Action Bits (RFC 9260) ====================

	/// Chunk type action bits namespace (RFC 9260 Section 3.2)
	/// The upper 2 bits of the chunk type specify how to handle unrecognized chunks
	namespace SctpChunkActionBits
	{
		/// Mask for extracting action bits from chunk type
		constexpr uint8_t ACTION_MASK = 0xC0;
		/// Stop processing and report in ERROR chunk (bits = 00)
		constexpr uint8_t STOP_AND_REPORT = 0x00;
		/// Stop processing, do not report (bits = 01)
		constexpr uint8_t STOP_NO_REPORT = 0x40;
		/// Skip this chunk and continue, report in ERROR chunk (bits = 10)
		constexpr uint8_t SKIP_AND_REPORT = 0x80;
		/// Skip this chunk and continue, do not report (bits = 11)
		constexpr uint8_t SKIP_NO_REPORT = 0xC0;
	}

	/// Get action bits from a chunk type value (RFC 9260 Section 3.2)
	/// @param[in] chunkType The chunk type byte
	/// @return Action bits (upper 2 bits, one of SctpChunkActionBits values)
	inline uint8_t getSctpChunkActionBits(uint8_t chunkType)
	{
		return chunkType & SctpChunkActionBits::ACTION_MASK;
	}

	/// Check if unrecognized chunk should cause processing to stop (RFC 9260)
	/// @param[in] chunkType The chunk type byte
	/// @return True if processing should stop (action bits = 00 or 01)
	inline bool shouldStopOnUnrecognizedChunk(uint8_t chunkType)
	{
		return (chunkType & SctpChunkActionBits::ACTION_MASK) < SctpChunkActionBits::SKIP_AND_REPORT;
	}

	/// Check if unrecognized chunk should be reported in ERROR (RFC 9260)
	/// @param[in] chunkType The chunk type byte
	/// @return True if chunk should be reported (action bits = 00 or 10)
	inline bool shouldReportUnrecognizedChunk(uint8_t chunkType)
	{
		uint8_t action = chunkType & SctpChunkActionBits::ACTION_MASK;
		return action == SctpChunkActionBits::STOP_AND_REPORT ||
		       action == SctpChunkActionBits::SKIP_AND_REPORT;
	}

	// ==================== Parameter Action Bits (RFC 9260) ====================

	/// Parameter type action bits namespace (RFC 9260 Section 3.2.1)
	/// The upper 2 bits of the parameter type specify how to handle unrecognized parameters
	namespace SctpParamActionBits
	{
		/// Mask for extracting action bits from parameter type
		constexpr uint16_t ACTION_MASK = 0xC000;
		/// Stop processing chunk, report in ERROR/Unrecognized Parameter (bits = 00)
		constexpr uint16_t STOP_AND_REPORT = 0x0000;
		/// Stop processing chunk, do not report (bits = 01)
		constexpr uint16_t STOP_NO_REPORT = 0x4000;
		/// Skip this parameter and continue, report (bits = 10)
		constexpr uint16_t SKIP_AND_REPORT = 0x8000;
		/// Skip this parameter and continue, do not report (bits = 11)
		constexpr uint16_t SKIP_NO_REPORT = 0xC000;
	}

	/// Get action bits from a parameter type value (RFC 9260 Section 3.2.1)
	/// @param[in] paramType The parameter type (host byte order)
	/// @return Action bits (upper 2 bits, one of SctpParamActionBits values)
	inline uint16_t getSctpParamActionBits(uint16_t paramType)
	{
		return paramType & SctpParamActionBits::ACTION_MASK;
	}

	/// Check if unrecognized parameter should cause chunk processing to stop (RFC 9260)
	/// @param[in] paramType The parameter type (host byte order)
	/// @return True if chunk processing should stop (action bits = 00 or 01)
	inline bool shouldStopOnUnrecognizedParam(uint16_t paramType)
	{
		return (paramType & SctpParamActionBits::ACTION_MASK) < SctpParamActionBits::SKIP_AND_REPORT;
	}

	/// Check if unrecognized parameter should be reported (RFC 9260)
	/// @param[in] paramType The parameter type (host byte order)
	/// @return True if parameter should be reported (action bits = 00 or 10)
	inline bool shouldReportUnrecognizedParam(uint16_t paramType)
	{
		uint16_t action = paramType & SctpParamActionBits::ACTION_MASK;
		return action == SctpParamActionBits::STOP_AND_REPORT ||
		       action == SctpParamActionBits::SKIP_AND_REPORT;
	}

}  // namespace pcpp
