#pragma once
#include "Layer.h"
#include "Packet.h"
#include <vector>
#include <string>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class QuicV1Layer
	/// Represents a QUIC v1 (RFC 9000/9001) protocol layer.
	class QuicV1Layer : public Layer
	{
	public:
		/// @enum QuicPacketType
		/// Identifies the kind of QUIC v1 packet, as carried by the Long Packet Type field for
		/// long-header packets (RFC 9000 Section 17.2), or inferred for short-header (1-RTT) and
		/// Version Negotiation packets, which don't carry this field on the wire
		enum class QuicPacketType : uint8_t
		{
			/// Initial packet - carries the start of the cryptographic handshake, plus an
			/// optional address-validation Token
			Initial = 0,
			/// 0-RTT packet - carries application data sent before the handshake completes
			ZeroRTT = 1,
			/// Handshake packet - carries the remainder of the cryptographic handshake
			Handshake = 2,
			/// Retry packet - sent by a server to perform address validation before committing
			/// state to a connection
			Retry = 3,
			/// Version Negotiation packet - sent by a server that doesn't support the client's
			/// requested QUIC version
			VersionNegotiation = 253,
			/// 1-RTT packet - a short-header packet carrying post-handshake application data
			OneRtt = 254,
		};

		/// @enum QuicHeaderForm
		/// Identifies whether a QUIC packet uses the long or short header form (RFC 9000 Section
		/// 17.2 vs. 17.3)
		enum class QuicHeaderForm : uint8_t
		{
			/// Short header - used for 1-RTT packets once the connection ID length is known out
			/// of band
			ShortHeader = 0,
			/// Long header - used for Initial, 0-RTT, Handshake, Retry and Version Negotiation
			/// packets, all of which are exchanged before that connection ID length is known
			LongHeader = 1
		};

		/// @struct ProtectedPayload
		/// A non-owning view of the protected portion of a QUIC packet
		struct ProtectedPayload
		{
			/// Pointer to the beginning of the protected data
			const uint8_t* data;
			/// Length of the protected data in bytes
			size_t length;
		};

		/// A static method that creates a QUIC v11 layer from packet raw data. Returns nullptr if
		/// data is not valid.
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored
		/// @return The newly allocated layer or nullptr if the data isn't valid
		static QuicV1Layer* parseQuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @return The type of this QUIC packet
		virtual QuicPacketType getPacketType() const = 0;

		/// @return The header form (long or short) of this QUIC packet, as read straight off the
		/// wire
		QuicHeaderForm getHeaderForm() const;

		/// @return The value of the Fixed Bit field. Per RFC 9000 this is always 1
		uint8_t getFixedBit() const;

		/// A static method that checks whether the port is considered as QUIC
		/// @param[in] port The port number to be checked
		/// @return True if the port is considered as QUIC, false otherwise
		static bool isQuicPort(uint16_t port)
		{
			return port == 443;
		}

		// implement abstract methods

		/// Wraps any bytes remaining after this packet's header/payload as a subsequent
		/// QuicV1Layer if getHeaderLen() leaves data unconsumed - QUIC
		/// datagrams commonly coalesce multiple packets back to back - falling back to a
		/// PayloadLayer if what follows can't be parsed as QUIC
		void parseNextLayer() override;

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// @return A string representation of the packet, e.g. "QUIC v1 Layer, Initial message"
		std::string toString() const override;

		/// @return @ref OsiModelTransportLayer
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	protected:
		QuicV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, QUICv1)
		{}

		/// @struct quic_common_header
		/// The one-byte prefix shared by every QUIC v1 packet form, holding just the Header Form
		/// and Fixed Bit - enough to tell long-header and short-header packets apart before
		/// committing to either layout
		struct quic_common_header
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t : 6, fixedBit : 1, headerForm : 1;
#else
			uint8_t headerForm : 1, fixedBit : 1, : 6;
#endif
		};

#pragma pack(push, 1)
		/// @struct quic_long_header
		/// The fixed-size prefix of every long-header QUIC v1 packet (Initial, 0-RTT, Handshake,
		/// Retry and Version Negotiation): the common header byte, the 4-byte version, and the
		/// Destination Connection ID length. The variable-length fields that follow (DCID, SCID,
		/// Token, Length) are not part of this struct - they're read via pointer+length accessors
		/// on QuicV1LongHeaderLayer and its subclasses instead
		struct quic_long_header
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t packetNumberLength : 2, reserved : 2, longPacketType : 2, fixedBit : 1, headerForm : 1;
#else
			uint8_t headerForm : 1, fixedBit : 1, longPacketType : 2, reserved : 2, packetNumberLength : 2;
#endif
			uint32_t version;
			uint8_t destinationConnectionIdLength;
		};
#pragma pack(pop)
		static_assert(sizeof(quic_long_header) == 6, "quic_long_header size is not 6 bytes");

#pragma pack(push, 1)
		/// @struct quic_short_header
		/// The single-byte header of a 1-RTT (short-header) QUIC v1 packet. There is no
		/// Destination Connection ID length field here - a 1-RTT packet's connection ID has a
		/// length that's negotiated out of band during the handshake, so it can't be recovered
		/// from the packet alone
		struct quic_short_header
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t packetNumberLength : 2, keyPhase : 1, reserved : 2, spinBit : 1, fixedBit : 1, headerForm : 1;
#else
			uint8_t headerForm : 1, fixedBit : 1, spinBit : 1, reserved : 2, keyPhase : 1, packetNumberLength : 2;
#endif
		};
#pragma pack(pop)
		static_assert(sizeof(quic_short_header) == 1, "quic_short_header size is not 1 byte");

	private:
		quic_common_header* getCommonHeader() const
		{
			return reinterpret_cast<quic_common_header*>(m_Data);
		}
	};

	/// @class QuicV1LongHeaderLayer
	/// Base class for all QUIC v1 packet forms that use the long header (Initial, 0-RTT,
	/// Handshake, Retry and Version Negotiation). Provides parsing shared by all of them: the
	/// QUIC version and the Destination/Source Connection IDs, which sit at a fixed offset
	/// (Destination) or immediately after it (Source) in every long-header packet
	class QuicV1LongHeaderLayer : public QuicV1Layer
	{
	public:
		/// @return The packet type, read from the Long Packet Type field of the long header
		QuicPacketType getPacketType() const override;

		/// @return The QUIC version
		uint32_t getVersion() const;

		/// @return The Destination Connection ID, or an empty vector if the packet doesn't
		/// contain enough data to read it
		std::vector<uint8_t> getDestinationConnectionId() const;

		/// @return The Destination Connection ID as hex string, or an empty string if the packet doesn't
		/// contain enough data to read it
		std::string getDestinationConnectionIdAsString() const;

		/// @return The Source Connection ID, or an empty vector if the packet doesn't contain
		/// enough data to read it
		std::vector<uint8_t> getSourceConnectionId() const;

		/// @return The Source Connection ID as hex string, or an empty string if the packet doesn't contain
		/// enough data to read it
		std::string getSourceConnectionIdAsString() const;

	protected:
		using QuicV1Layer::QuicV1Layer;

		/// @struct OffsetAndLength
		/// The offset (from the start of the packet) and length, in bytes, of a variable-length
		/// field - used internally while walking the packet to locate the Source Connection ID,
		/// Token, and Length fields that follow the Destination Connection ID
		struct OffsetAndLength
		{
			/// The field's length, in bytes
			size_t length;
			/// The field's offset from the start of the packet, in bytes
			size_t offset;

			/// A constructor that creates an instance from a length and offset
			/// @param[in] length The field's length, in bytes
			/// @param[in] offset The field's offset from the start of the packet, in bytes
			OffsetAndLength(size_t length, size_t offset) : length(length), offset(offset)
			{}
		};

		OffsetAndLength getDestConIdOffsetAndLength() const;

		OffsetAndLength getSrcConIdOffsetAndLength() const;

	private:
		static constexpr int destinationConnectionIdOffset = sizeof(quic_long_header);

		static bool isDataValid(const uint8_t* data, size_t dataLen);

		quic_long_header* getLongHeader() const
		{
			return reinterpret_cast<quic_long_header*>(m_Data);
		}

		friend class QuicV1Layer;
	};

	/// @class QuicV1EstablishmentLayer
	/// Base class for the long-header packet forms that carry cryptographic handshake data and a
	/// Length field (Initial, 0-RTT and Handshake). Adds parsing of the QUIC variable-length
	/// integer ("varint") encoding (RFC 9000 Section 16) used for the Length field and, in
	/// QuicV1InitialLayer, the Token Length field as well
	class QuicV1EstablishmentLayer : public QuicV1LongHeaderLayer
	{
	public:
		/// @return The value of the Length field: the number of bytes in the Packet Number and
		/// Payload fields combined, or 0 if the packet doesn't contain enough data to read it
		uint64_t getLength() const;

		// implement abstract methods

		/// @return The header length, computed as the offset of the Length field plus the
		/// varint's own encoded size plus the value of the Length field itself, clamped to the
		/// amount of data actually captured
		size_t getHeaderLen() const override;

		/// Get the protected portion of the QUIC packet.
		/// The returned data points directly into the packet buffer and is not copied.
		/// This includes the Packet Number and the protected payload (including the AEAD authentication tag).
		/// @return A non-owning view of the protected portion of the packet
		ProtectedPayload getProtectedPayload() const;

	protected:
		/// @struct VarintValueAndSize
		/// The decoded value of a QUIC variable-length integer, together with the number of
		/// bytes it occupied on the wire (1, 2, 4 or 8, per RFC 9000 Section 16) - returned by
		/// getVarintValueAndSize so callers can advance past the field without re-decoding
		/// its length
		struct VarintValueAndSize
		{
			/// The varint's decoded value
			uint64_t value;
			/// The varint's encoded size on the wire, in bytes (1, 2, 4 or 8)
			size_t size;

			/// A constructor that creates an instance from a decoded value and its encoded size
			/// @param[in] value The varint's decoded value
			/// @param[in] size The varint's encoded size on the wire, in bytes
			VarintValueAndSize(uint64_t value, size_t size) : value(value), size(size)
			{}
		};

		virtual size_t getLengthOffset() const;

		VarintValueAndSize getVarintValueAndSize(size_t offset) const;

	private:
		using QuicV1LongHeaderLayer::QuicV1LongHeaderLayer;
	};

	/// @class QuicV1InitialLayer
	/// Represents a QUIC v1 Initial packet - the first packet of a connection, carrying the
	/// start of the cryptographic handshake and, optionally, an address-validation Token
	/// (RFC 9000 Section 17.2.2)
	class QuicV1InitialLayer : public QuicV1EstablishmentLayer
	{
	public:
		/// @return The address-validation Token, or an empty vector if the packet carries no
		/// token or doesn't contain enough data to read it
		std::vector<uint8_t> getToken() const;

		/// @return The address-validation Token as hex string, or an empty string if the packet carries no
		/// token or doesn't contain enough data to read it
		std::string getTokenAsString() const;

	private:
		using QuicV1EstablishmentLayer::QuicV1EstablishmentLayer;

		size_t getLengthOffset() const override;

		size_t getTokenLengthOffset() const;

		friend class QuicV1Layer;
	};

	/// @class QuicV1ZeroRttLayer
	/// Represents a QUIC v1 0-RTT packet - carries application data sent before the
	/// cryptographic handshake completes (RFC 9000 Section 17.2.3). Adds no parsing beyond what
	/// QuicV1EstablishmentLayer already provides
	class QuicV1ZeroRttLayer : public QuicV1EstablishmentLayer
	{
		using QuicV1EstablishmentLayer::QuicV1EstablishmentLayer;

		friend class QuicV1Layer;
	};

	/// @class QuicV1HandshakeLayer
	/// Represents a QUIC v1 Handshake packet - carries the remainder of the cryptographic
	/// handshake after the Initial packet (RFC 9000 Section 17.2.4). Adds no parsing beyond what
	/// QuicV1EstablishmentLayer already provides
	class QuicV1HandshakeLayer : public QuicV1EstablishmentLayer
	{
		using QuicV1EstablishmentLayer::QuicV1EstablishmentLayer;

		friend class QuicV1Layer;
	};

	/// @class QuicV1RetryLayer
	/// Represents a QUIC v1 Retry packet - sent by a server to perform address validation before
	/// committing state to a connection (RFC 9000 Section 17.2.5). Carries a Retry Token and,
	/// unlike the other long-header forms, a fixed-size 16-byte integrity tag rather than a
	/// varint-prefixed Length field
	class QuicV1RetryLayer : public QuicV1LongHeaderLayer
	{
	public:
		/// @return The Retry Token, or an empty vector if the packet doesn't contain enough
		/// data - beyond the Source Connection ID - to also hold the 16-byte integrity tag
		std::vector<uint8_t> getRetryToken() const;

		/// @return The Retry Token as hex string, or an empty string if the packet doesn't contain enough
		/// data - beyond the Source Connection ID - to also hold the 16-byte integrity tag
		std::string getRetryTokenAsString() const;

		/// @return The 16-byte Retry Integrity Tag, or an empty vector if the packet doesn't
		/// contain enough data - beyond the Source Connection ID - to hold it
		std::vector<uint8_t> getRetryIntegrityTag() const;

		/// @return The 16-byte Retry Integrity Tag as hex string, or an empty string if the packet doesn't
		/// contain enough data - beyond the Source Connection ID - to hold it
		std::string getRetryIntegrityTagAsString() const;

		// implement abstract methods

		/// @return sizeof(m_DataLen) - a Retry packet has no Length field, so its header is
		/// considered to span the entire packet
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

	private:
		using QuicV1LongHeaderLayer::QuicV1LongHeaderLayer;

		static constexpr size_t retryIntegritySize = 16;

		size_t getRetryTokenOffset() const;

		friend class QuicV1Layer;
	};

	/// @class QuicV1VersionNegotiationLayer
	/// Represents a QUIC Version Negotiation packet - sent by a server that doesn't support the
	/// QUIC version a client requested, listing the versions it does support (RFC 9000 Section
	/// 17.2.1). Identified by a version field of 0 rather than a Long Packet Type value, so
	/// getPacketType() always returns QuicPacketType::VersionNegotiation
	class QuicV1VersionNegotiationLayer : public QuicV1LongHeaderLayer
	{
	public:
		/// @return QuicPacketType::VersionNegotiation
		QuicPacketType getPacketType() const override
		{
			return QuicPacketType::VersionNegotiation;
		}

		/// @return The list of QUIC versions the server supports, in host byte order. Returns
		/// an empty list if a trailing partial version is encountered
		std::vector<uint32_t> getSupportedVersions() const;

		// implement abstract methods

		/// @return sizeof(m_DataLen) - a Version Negotiation packet has no further layers beyond
		/// the list of supported versions, so its header is considered to span the entire packet
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

	private:
		using QuicV1LongHeaderLayer::QuicV1LongHeaderLayer;

		friend class QuicV1Layer;
	};

	/// @class QuicV1OneRttLayer
	/// Represents a QUIC v1 1-RTT packet - a short-header packet carrying post-handshake
	/// application data (RFC 9000 Section 17.3.1). Since the short header carries no explicit
	/// Length field, getHeaderLen() treats the header as spanning the entire packet
	class QuicV1OneRttLayer : public QuicV1Layer
	{
	public:
		/// @return QuicPacketType::OneRtt
		QuicPacketType getPacketType() const override
		{
			return QuicPacketType::OneRtt;
		}

		/// @return The value of the Spin Bit, used for passive latency measurement along the
		/// connection's path
		bool getSpinBit() const
		{
			return getShortHeader()->spinBit;
		}

		/// @return The value of the Key Phase bit, used to identify which packet protection keys
		/// were used to protect this packet
		bool getKeyPhaseBit() const
		{
			return getShortHeader()->keyPhase;
		}

		/// Get the protected portion of the QUIC packet.
		/// The returned data points directly into the packet buffer and is not copied.
		/// @return A non-owning view of the protected portion of the packet
		ProtectedPayload getProtectedPayload() const;

		// implement abstract methods

		/// @return sizeof(m_DataLen) - a 1-RTT packet's short header carries no Length field, so
		/// its header is considered to span the entire packet
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

	private:
		using QuicV1Layer::QuicV1Layer;

		static bool isDataValid(const uint8_t* data, size_t dataLen);

		quic_short_header* getShortHeader() const
		{
			return reinterpret_cast<quic_short_header*>(m_Data);
		}

		friend class QuicV1Layer;
	};
}  // namespace pcpp
