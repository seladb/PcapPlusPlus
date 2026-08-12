#pragma once
#include "Layer.h"
#include "Packet.h"
#include <vector>
#include <string>

/// @file

namespace pcpp
{
	struct quic_common_header
	{
	#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint8_t : 6,
			fixedBit : 1,
			headerForm : 1;
	#else
		uint8_t headerForm : 1,
			fixedBit : 1,
			: 6;
	#endif
	};

	/// @struct quic_long_header
	/// Fixed-size prefix of a QUIC long header (RFC 9000 17.2): the first byte's bitfields,
	/// the 4-byte Version, and the 1-byte DCID Length. Everything after this (DCID, SCID
	/// Length, SCID, and - depending on packet type - Token Length/Token/Length/Packet
	/// Number) is variable-length and follows immediately after this struct in the raw
	/// buffer; QuicLayer's getters compute pointers into that region on demand rather than
	/// copying it.
	#pragma pack(push, 1)
	struct quic_long_header
	{
	#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint8_t packetNumberLength : 2,
			reserved : 2,
			longPacketType : 2,
			fixedBit : 1,
			headerForm : 1;
	#else
		uint8_t headerForm : 1,
			fixedBit : 1,
			longPacketType : 2,
			reserved : 2,
			packetNumberLength : 2;
	#endif
		/// Network (big-endian) byte order on the wire - use QuicLayer::getVersion() for the
		/// host-order value rather than reading this field directly.
		uint32_t version;
		/// Destination Connection ID Length, in bytes
		uint8_t destinationConnectionIdLength;
	};
	#pragma pack(pop)
	static_assert(sizeof(quic_long_header) == 6, "quic_long_header size is not 6 bytes");

	/// @struct quic_short_header
	/// The entire fixed portion of a QUIC short header (RFC 9000 17.3.1) is a single byte -
	/// the Destination Connection ID (whose length is NOT encoded in the packet; the caller
	/// must already know it from earlier connection state) and the Packet Number follow
	/// immediately after this struct in the raw buffer.
	#pragma pack(push, 1)
	struct quic_short_header
	{
	#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint8_t packetNumberLength : 2,
			keyPhase : 1,
			reserved : 2,
			spinBit : 1,
			fixedBit : 1,
			headerForm : 1;
	#else
		uint8_t headerForm : 1,
			fixedBit : 1,
			spinBit : 1,
			reserved : 2,
			keyPhase : 1,
			packetNumberLength : 2;
	#endif
	};
	#pragma pack(pop)
	static_assert(sizeof(quic_short_header) == 1, "quic_short_header size is not 1 byte");

	enum class QuicFrameType : uint8_t
	{
		Padding = 0x00,
		Ping = 0x01,
		Ack = 0x02,
		AckEcn = 0x03,
		Crypto = 0x06,
		ConnectionClose = 0x1c,
		Unknown = 0xff
	};

	struct QuicAckRange
	{
		uint64_t gap;
		uint64_t ackRangeLength;
	};

	struct QuicAckFrame
	{
		uint64_t largestAcknowledged = 0;
		uint64_t ackDelay = 0;
		uint64_t ackRangeCount = 0;
		uint64_t firstAckRange = 0;
		std::vector<QuicAckRange> ackRanges;
		bool hasEcnCounts = false;
		uint64_t ect0Count = 0, ect1Count = 0, ecnCeCount = 0;
	};

	struct QuicCryptoFrame
	{
		uint64_t offset = 0;
		uint64_t length = 0;
		const uint8_t* data = nullptr;  // points into the layer's own m_Data buffer - not owned/copied
	};

	struct QuicConnectionCloseFrame
	{
		uint64_t errorCode = 0;
		uint64_t triggeringFrameType = 0;
		std::string reasonPhrase;
	};

	struct QuicFrame
	{
		QuicFrameType type = QuicFrameType::Unknown;
		size_t frameLength = 0;

		// C++11-compatible alternative to std::optional<T> (not available in C++14, which
		// PcapPlusPlus targets): a bool flag alongside a plain member. Only the member(s)
		// matching `type` are meaningful - e.g. check hasCrypto before reading `crypto`.
		bool hasAck = false;
		QuicAckFrame ack;
		bool hasCrypto = false;
		QuicCryptoFrame crypto;
		bool hasConnectionClose = false;
		QuicConnectionCloseFrame connectionClose;
	};

	/// @class QuicLayer
	/// Represents a QUIC v1 (RFC 9000/9001) protocol layer. Parses both long-header and
	/// short-header packet forms by casting directly onto the raw packet buffer (see
	/// quic_long_header / quic_short_header) rather than copying header fields into owned
	/// storage - the same approach PcapPlusPlus uses for fixed-size headers like iphdr and
	/// udphdr, extended here to also cover QUIC's variable-length fields (DCID, SCID, Token)
	/// via pointer+length accessors instead of copies. Only a handful of scalar offsets that
	/// require walking the variable-length prefix to compute (Token/Length/Packet Number
	/// positions) are cached; everything else is read from the struct on each call.
	///
	/// For Initial packets, additionally exposes frame-level parsing (PADDING/PING/ACK/
	/// CRYPTO/CONNECTION_CLOSE) once decrypted payload bytes are supplied via
	/// setDecryptedInitialPayload() - see the note on that method for why this step can't
	/// happen automatically yet.
	class QuicLayer : public Layer
	{
	public:
		enum class QuicPacketType : uint8_t
		{
			Initial = 0,
			ZeroRTT = 1,
			Handshake = 2,
			Retry = 3,
			OneRtt = 254,
			Unknown = 255
		};

		enum class QuicHeaderForm : u_int8_t
		{
			ShortHeader = 0,
			LongHeader = 1
		};

		/// A static method that creates a QUIV layer from packet raw data. Returns nullptr if
		/// data is not valid.
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored
		/// @return The newly allocated layer ot nullptr if the data isn't valid
		static QuicLayer* parseQuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		virtual QuicPacketType getPacketType() const = 0;

		QuicHeaderForm getHeaderForm() const;

		uint8_t getFixedBit() const;

		/// A static method that checks whether the port is considered as QUIC
		/// @param[in] port The port number to be checked
		static bool isQuicPort(uint16_t port)
		{
			return port == 443;
		}

		// implement abstract methods

		void parseNextLayer() override;

		/// QUIC header fields (Length, packet number, checksums) are not independently
		/// recomputable without a full AEAD re-encryption pass, so this is currently a no-op.
		void computeCalculateFields() override
		{}

		std::string toString() const override
		{
			// TODO
			return "QUIC layer";
		}

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	protected:
		QuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: Layer(data, dataLen, prevLayer, packet, QUIC)
		{}

	private:
		quic_common_header* getCommonHeader() const
		{
			return reinterpret_cast<quic_common_header*>(m_Data);
		}
	};

	class QuicLongHeaderLayer : public QuicLayer
	{
	public:
		class ByteArray : public std::vector<uint8_t>
		{
		public:
			using std::vector<uint8_t>::vector;

			std::string toString() const;

			friend std::ostream& operator<<(std::ostream& os, const ByteArray& byteArray)
			{
				return os << byteArray.toString();
			}
		};

		QuicPacketType getPacketType() const override;

		/// @return The QUIC version
		uint32_t getVersion() const;

		ByteArray getDestinationConnectionId() const;
		ByteArray getSourceConnectionId() const;
	protected:
		using QuicLayer::QuicLayer;

		struct OffsetAndLength
		{
			size_t length;
			size_t offset;

			OffsetAndLength(size_t length, size_t offset): length(length), offset(offset)
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

		friend class QuicLayer;
	};

	class QuicEstablishmentLayer : public QuicLongHeaderLayer
	{
	public:
		uint64_t getLength() const;

		// implement abstract methods

		size_t getHeaderLen() const override;

	protected:
		struct VarintValueAndSize
		{
			uint64_t value;
			size_t size;

			VarintValueAndSize(uint64_t value, size_t size): value(value), size(size)
			{}
		};

		virtual size_t getLengthOffset() const;
		VarintValueAndSize getVarintValueAndSize(size_t offset) const;

	private:
		using QuicLongHeaderLayer::QuicLongHeaderLayer;
	};

	class QuicInitialLayer : public QuicEstablishmentLayer
	{
	public:
		ByteArray getToken() const;

	private:
		using QuicEstablishmentLayer::QuicEstablishmentLayer;

		size_t getLengthOffset() const override;
		size_t getTokenLengthOffset() const;

		friend class QuicLayer;
	};

	class QuicZeroRttLayer : public QuicEstablishmentLayer
	{
		using QuicEstablishmentLayer::QuicEstablishmentLayer;

		friend class QuicLayer;
	};	;

	class QuicHandshakeLayer : public QuicEstablishmentLayer
	{
		using QuicEstablishmentLayer::QuicEstablishmentLayer;

		friend class QuicLayer;
	};

	class QuicOneRttLayer : public QuicLayer
	{
	public:
		QuicPacketType getPacketType() const override
		{
			return QuicPacketType::OneRtt;
		}

		bool getSpinBit() const
		{
			return getShortHeader()->spinBit;
		}

		bool getKeyPhaseBit() const
		{
			return getShortHeader()->keyPhase;
		}

		// implement abstract methods

		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}
	private:
		using QuicLayer::QuicLayer;

		static bool isDataValid(const uint8_t* data, size_t dataLen);

		quic_short_header* getShortHeader() const
		{
			return reinterpret_cast<quic_short_header*>(m_Data);
		}

		friend class QuicLayer;
	};
}  // namespace pcpp
