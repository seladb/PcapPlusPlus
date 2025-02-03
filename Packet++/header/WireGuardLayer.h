#pragma once

#include "Layer.h"
#include "IpAddress.h"
#include "MacAddress.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class WireGuardLayer
	/// Represents a WireGuard protocol layer
	class WireGuardLayer : public Layer
	{
	protected:
#pragma pack(push, 1)
		/// @struct wg_common_header
		/// Represents the common header for all WireGuard message types
		struct wg_common_header
		{
			/// Message type field
			uint8_t messageType;
			/// Reserved field (3 bytes)
			uint8_t reserved[3];
		};
#pragma pack(pop)
		static_assert(sizeof(wg_common_header) == 4, "wg_common_header size is not 4 bytes");

		wg_common_header* getBasicHeader() const
		{
			return reinterpret_cast<wg_common_header*>(m_Data);
		}

		WireGuardLayer() = default;

	public:
		/// WireGuard message types
		enum class WireGuardMessageType
		{
			/// Unknown Initiation message
			Unknown = 0,
			/// Handshake Initiation message
			HandshakeInitiation = 1,
			/// Handshake Response message
			HandshakeResponse = 2,
			/// Cookie Reply message
			CookieReply = 3,
			/// Transport Data message
			TransportData = 4
		};

		/// Constructs a WireGuardLayer object.
		/// @param data Pointer to the raw data representing the WireGuard layer
		/// @param dataLen Length of the data
		/// @param prevLayer Pointer to the previous layer in the packet (if any)
		/// @param packet Pointer to the packet this layer belongs to
		WireGuardLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, WireGuard)
		{}

		/// Checks if the given port numbers are WireGuard ports.
		/// @param portSrc The source port number to check
		/// @param portDst The destination port number to check
		/// @return True if either port matches the WireGuard port (51820), false otherwise
		static bool isWireGuardPorts(uint16_t portSrc, uint16_t portDst)
		{
			return (portSrc == 51820 || portDst == 51820);
		}

		/// Checks if the given data represents a WireGuard message.
		/// @param data Pointer to the raw data
		/// @param dataLen Length of the data
		/// @return True if the data starts with a valid WireGuard message type, false otherwise
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// Parses the raw data into a WireGuard layer.
		/// @param data Pointer to the raw data
		/// @param dataLen Length of the data
		/// @param prevLayer Pointer to the previous layer
		/// @param packet Pointer to the packet
		/// @return A pointer to the parsed WireGuardLayer, or nullptr if parsing fails
		static WireGuardLayer* parseWireGuardLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @return String representation of the message type.
		std::string getMessageTypeAsString() const;

		/// @return The message type as an unsigned 32-bit integer.
		uint8_t getMessageType() const;

		/// @return The reserved field as a 32-bit integer.
		uint32_t getReserved() const;

		/// @param reserved The reserved field to set as a An array containing the 3-byte.
		void setReserved(const std::array<uint8_t, 3>& reserved);

		/// Does nothing for this layer (WireGuard layer is always last)
		void parseNextLayer() override
		{}

		/// @return Size of the header in bytes.
		size_t getHeaderLen() const override;

		/// No fields to compute or update, so this method is left empty.
		void computeCalculateFields() override
		{}

		/// Converts the WireGuard layer to a string representation.
		/// @return String representation of the WireGuard layer
		std::string toString() const override;

		/// @return OSI model layer corresponding to the Network layer
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelNetworkLayer;
		}

		/// @return The message type as a WireGuardMessageType enum value.
		virtual WireGuardMessageType getWireGuardMessageType() const
		{
			return WireGuardMessageType::Unknown;
		}
	};

	/// @class WireGuardHandshakeInitiationLayer
	/// Represents the Handshake Initiation message layer
	class WireGuardHandshakeInitiationLayer : public WireGuardLayer
	{
	private:
#pragma pack(push, 1)
		/// @struct wg_handshake_initiation
		/// Represents the Handshake Initiation message structure
		typedef struct wg_handshake_initiation : wg_common_header
		{
			/// Sender index
			uint32_t senderIndex;
			/// Initiator's ephemeral public key
			uint8_t initiatorEphemeral[32];
			/// Encrypted initiator's static key
			uint8_t encryptedInitiatorStatic[48];
			/// Encrypted timestamp
			uint8_t encryptedTimestamp[28];
			/// MAC1 field
			uint8_t mac1[16];
			/// MAC2 field
			uint8_t mac2[16];
		} wg_handshake_initiation;
#pragma pack(pop)
		wg_handshake_initiation* getHandshakeInitiationHeader() const
		{
			return reinterpret_cast<wg_handshake_initiation*>(getBasicHeader());
		}

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		WireGuardHandshakeInitiationLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new Handshake Initiation message
		/// @param[in] senderIndex The sender's index
		/// @param[in] initiatorEphemeral The initiator's ephemeral public key
		/// @param[in] encryptedInitiatorStatic The encrypted initiator's static key
		/// @param[in] encryptedTimestamp The encrypted timestamp
		/// @param[in] mac1 The MAC1 field
		/// @param[in] mac2 The MAC2 field
		WireGuardHandshakeInitiationLayer(uint32_t senderIndex, const uint8_t initiatorEphemeral[32],
		                                  const uint8_t encryptedInitiatorStatic[48],
		                                  const uint8_t encryptedTimestamp[28], const uint8_t mac1[16],
		                                  const uint8_t mac2[16]);

		/// @return The sender index as a 32-bit integer.
		uint32_t getSenderIndex() const;

		/// @return An array containing the initiator's ephemeral public key.
		std::array<uint8_t, 32> getInitiatorEphemeral() const;

		/// @return An array containing the encrypted initiator's static key.
		std::array<uint8_t, 48> getEncryptedInitiatorStatic() const;

		/// @return An array containing the encrypted timestamp.
		std::array<uint8_t, 28> getEncryptedTimestamp() const;

		/// @return An array containing the MAC1 field.
		std::array<uint8_t, 16> getMac1() const;

		/// @return An array containing the MAC2 field.
		std::array<uint8_t, 16> getMac2() const;

		/// @param senderIndex A 32-bit integer representing the sender index.
		void setSenderIndex(uint32_t senderIndex);

		/// @param initiatorEphemeral An array containing the 32-byte initiator ephemeral public key.
		void setInitiatorEphemeral(const std::array<uint8_t, 32>& initiatorEphemeral);

		/// @param encryptedInitiatorStatic An array containing the 48-byte encrypted initiator's static key.
		void setEncryptedInitiatorStatic(const std::array<uint8_t, 48>& encryptedInitiatorStatic);

		/// @param encryptedTimestamp An array containing the 28-byte encrypted timestamp.
		void setEncryptedTimestamp(const std::array<uint8_t, 28>& encryptedTimestamp);

		/// @param mac1 An array containing the 16-byte MAC1 field.
		void setMac1(const std::array<uint8_t, 16>& mac1);

		/// @param mac2 An array containing the 16-byte MAC2 field.
		void setMac2(const std::array<uint8_t, 16>& mac2);

		// implement abstract methods

		/// @return WireGuardMessageType enum value indicating HandshakeInitiation.
		WireGuardMessageType getWireGuardMessageType() const override
		{
			return WireGuardMessageType::HandshakeInitiation;
		}
	};

	/// @class WireGuardHandshakeResponseLayer
	/// Represents a Handshake Response message
	class WireGuardHandshakeResponseLayer : public WireGuardLayer
	{
	private:
#pragma pack(push, 1)
		/// @struct wg_handshake_response
		/// Represents the Handshake Response message structure
		typedef struct wg_handshake_response : wg_common_header
		{
			/// Sender index
			uint32_t senderIndex;
			/// Receiver index
			uint32_t receiverIndex;
			/// Responder's ephemeral public key
			uint8_t responderEphemeral[32];
			/// Encrypted empty field
			uint8_t encryptedEmpty[16];
			/// MAC1 field
			uint8_t mac1[16];
			/// MAC2 field
			uint8_t mac2[16];
		} wg_handshake_response;
#pragma pack(pop)

		wg_handshake_response* getHandshakeResponseHeader() const
		{
			return reinterpret_cast<wg_handshake_response*>(getBasicHeader());
		}

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		WireGuardHandshakeResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new Handshake Response message
		/// @param[in] senderIndex The sender index
		/// @param[in] receiverIndex The receiver index
		/// @param[in] responderEphemeral The responder's ephemeral public key
		/// @param[in] encryptedEmpty The encrypted empty field
		/// @param[in] mac1 The MAC1 field
		/// @param[in] mac2 The MAC2 field
		WireGuardHandshakeResponseLayer(uint32_t senderIndex, uint32_t receiverIndex,
		                                const uint8_t responderEphemeral[32], const uint8_t encryptedEmpty[16],
		                                const uint8_t mac1[16], const uint8_t mac2[16]);

		/// @return The sender index as a 32-bit unsigned integer.
		uint32_t getSenderIndex() const;

		/// @return The receiver index as a 32-bit unsigned integer.
		uint32_t getReceiverIndex() const;

		/// @return The responder's ephemeral public key as an array of 32 bytes.
		std::array<uint8_t, 32> getResponderEphemeral() const;

		/// @return The encrypted empty field as an array of 16 bytes.
		std::array<uint8_t, 16> getEncryptedEmpty() const;

		/// @return The MAC1 field as an array of 16 bytes.
		std::array<uint8_t, 16> getMac1() const;

		/// @return The MAC2 field as an array of 16 bytes.
		std::array<uint8_t, 16> getMac2() const;

		/// @param senderIndex A 32-bit unsigned integer representing the sender index.
		void setSenderIndex(uint32_t senderIndex);

		/// @param receiverIndex A 32-bit unsigned integer representing the receiver index.
		void setReceiverIndex(uint32_t receiverIndex);

		/// @param responderEphemeral An array containing the 32-byte responder ephemeral public key.
		void setResponderEphemeral(const std::array<uint8_t, 32>& responderEphemeral);

		/// @param encryptedEmpty An array containing the 16-byte encrypted empty field.
		void setEncryptedEmpty(const std::array<uint8_t, 16>& encryptedEmpty);

		/// @param mac1 An array containing the 16-byte MAC1 field.
		void setMac1(const std::array<uint8_t, 16>& mac1);

		/// @param mac2 An array containing the 16-byte MAC2 field.
		void setMac2(const std::array<uint8_t, 16>& mac2);

		// implement abstract methods

		/// @return The message type as a WireGuardMessageType enum value.
		WireGuardMessageType getWireGuardMessageType() const override
		{
			return WireGuardMessageType::HandshakeResponse;
		}
	};

	/// @class WireGuardCookieReplyLayer
	/// Represents a Cookie Reply message
	class WireGuardCookieReplyLayer : public WireGuardLayer
	{
	private:
#pragma pack(push, 1)
		/// @struct wg_cookie_reply
		/// Represents the Cookie Reply message structure
		typedef struct wg_cookie_reply : wg_common_header
		{
			/// Receiver index
			uint32_t receiverIndex;
			/// Nonce field
			uint8_t nonce[24];
			/// Encrypted cookie
			uint8_t encryptedCookie[32];
		} wg_cookie_reply;
#pragma pack(pop)

		wg_cookie_reply* getCookieReplyHeader() const
		{
			return reinterpret_cast<wg_cookie_reply*>(getBasicHeader());
		}

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		WireGuardCookieReplyLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new Cookie Reply message
		/// @param[in] receiverIndex The receiver index
		/// @param[in] nonce The nonce field
		/// @param[in] encryptedCookie The encrypted cookie
		WireGuardCookieReplyLayer(uint32_t receiverIndex, const uint8_t nonce[24], const uint8_t encryptedCookie[32]);

		/// @return The receiver index as a 32-bit unsigned integer.
		uint32_t getReceiverIndex() const;

		/// @return The nonce field as an array of 24 bytes.
		std::array<uint8_t, 24> getNonce() const;

		/// @return The encrypted cookie as an array of 32 bytes.
		std::array<uint8_t, 32> getEncryptedCookie() const;

		/// @param receiverIndex A 32-bit unsigned integer representing the receiver index.
		void setReceiverIndex(uint32_t receiverIndex);

		/// @param nonce An array containing the 24-byte nonce field.
		void setNonce(const std::array<uint8_t, 24>& nonce);

		/// @param encryptedCookie An array containing the 32-byte encrypted cookie.
		void setEncryptedCookie(const std::array<uint8_t, 32>& encryptedCookie);

		// implement abstract methods

		/// @return The message type as a WireGuardMessageType enum value.
		WireGuardMessageType getWireGuardMessageType() const override
		{
			return WireGuardMessageType::CookieReply;
		}
	};

	/// @class WireGuardTransportDataLayer
	/// Represents a Transport Data message
	class WireGuardTransportDataLayer : public WireGuardLayer
	{
	private:
#pragma pack(push, 1)
		/// @struct wg_transport_data
		/// Represents the Transport Data message structure
		typedef struct wg_transport_data : wg_common_header
		{
			/// Receiver index
			uint32_t receiverIndex;
			/// Counter field
			uint64_t counter;
			/// Flexible array member for encrypted data
			uint8_t encryptedData[0];
		} wg_transport_data;
#pragma pack(pop)

		wg_transport_data* getTransportHeader() const
		{
			return reinterpret_cast<wg_transport_data*>(getBasicHeader());
		}

	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		WireGuardTransportDataLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new Transport Data message
		/// @param[in] receiverIndex The receiver index
		/// @param[in] counter The counter field
		/// @param[in] encryptedData The encrypted data
		/// @param[in] encryptedDataLen The length of the encrypted data
		WireGuardTransportDataLayer(uint32_t receiverIndex, uint64_t counter, const uint8_t* encryptedData,
		                            size_t encryptedDataLen);

		/// @return The receiver index as a 32-bit unsigned integer.
		uint32_t getReceiverIndex() const;

		/// @return The counter field as a 64-bit unsigned integer.
		uint64_t getCounter() const;

		/// @return A pointer to the encrypted data field.
		const uint8_t* getEncryptedData() const;

		/// @param receiverIndex A 32-bit unsigned integer representing the receiver index.
		void setReceiverIndex(uint32_t receiverIndex);

		/// @param counter A 64-bit unsigned integer representing the counter field.
		void setCounter(uint64_t counter);

		/// @param encryptedData A pointer to the encrypted data.
		/// @param encryptedDataLen The length of the encrypted data.
		void setEncryptedData(const uint8_t* encryptedData, size_t encryptedDataLen);

		// implement abstract methods

		/// @return The message type as a WireGuardMessageType enum value.
		WireGuardMessageType getWireGuardMessageType() const override
		{
			return WireGuardMessageType::TransportData;
		}
	};
}  // namespace pcpp
