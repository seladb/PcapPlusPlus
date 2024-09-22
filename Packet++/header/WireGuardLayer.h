#pragma once

#include "Layer.h"
#include "IpAddress.h"
#include "MacAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class WireGuardLayer
	 * Represents a WireGuard protocol layer
	 */
	class WireGuardLayer : public Layer
	{
	public:
		/**
		 * WireGuard message types
		 */
		enum class WireGuardMessageType
		{
			/** Handshake Initiation message */
			HandshakeInitiation = 1,
			/** Handshake Response message */
			HandshakeResponse = 2,
			/** Cookie Reply message */
			CookieReply = 3,
			/** Transport Data message */
			TransportData = 4
		};

#pragma pack(push, 1)
		/**
		 * @struct wg_common_header
		 * Represents the common header for all WireGuard message types
		 */
		struct wg_common_header
		{
			/** Message type field */
			uint8_t messageType;
			/** Reserved field (3 bytes) */
			uint8_t reserved[3];
		};
#pragma pack(pop)

		WireGuardLayer()
		{}

		/**
		 * Constructs a WireGuardLayer object.
		 *
		 * @param data Pointer to the raw data representing the WireGuard layer
		 * @param dataLen Length of the data
		 * @param prevLayer Pointer to the previous layer in the packet (if any)
		 * @param packet Pointer to the packet this layer belongs to
		 */
		WireGuardLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Wireguard)
		{}

		wg_common_header* getBasicHeader() const
		{
			return (wg_common_header*)m_Data;
		}

		/**
		 * Checks if the given port numbers are WireGuard ports.
		 *
		 * @param portSrc The source port number to check
		 * @param portDst The destination port number to check
		 * @return True if either port matches the WireGuard port (51820), false otherwise
		 */
		static bool isWireguardPorts(uint16_t portSrc, uint16_t portDst)
		{
			return (portSrc == 51820 || portDst == 51820);
		}

		/**
		 * Checks if the given data represents a WireGuard message.
		 *
		 * @param data Pointer to the raw data
		 * @param dataLen Length of the data
		 * @return True if the data starts with a valid WireGuard message type, false otherwise
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		WireGuardLayer* parseWireGuardLayer();

		std::string getMessageTypeAsString() const;

		uint32_t getMessageType()
		{
			return getBasicHeader()->messageType;
		}

		uint8_t* getReserved()
		{
			return getBasicHeader()->reserved;
		}

		/**
		 * No operation required for parsing the next layer since WireGuard does not have a next layer.
		 */
		void parseNextLayer() override {};
		/**
		 * Calculates the length of the header based on the message type.
		 *
		 * @return Size of the header in bytes. For TransportData, returns the total data length.
		 */
		size_t getHeaderLen() const override;

		/**
		 * No fields to compute or update, so this method is left empty.
		 */
		void computeCalculateFields() override
		{
			// Since WireGuard headers have fixed lengths and no fields to compute (like checksums or lengths),
			// this method does not need to perform any operations. It's left empty.
		}

		/**
		 * Converts the WireGuard layer to a string representation.
		 *
		 * @return String representation of the WireGuard layer
		 */
		std::string toString() const override;

		/**
		 * Returns the OSI model layer that this protocol belongs to.
		 *
		 * @return OSI model layer corresponding to the Network layer
		 */
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelNetworkLayer;
		}
	};

	/**
	 * @class WireGuardHandshakeInitiationLayer
	 * Represents the Handshake Initiation message layer
	 */
	class WireGuardHandshakeInitiationLayer : public WireGuardLayer
	{
	public:
#pragma pack(push, 1)
		typedef struct wg_handshake_initiation : wg_common_header
		{
			/** Sender index */
			uint32_t senderIndex;
			/** Initiator's ephemeral public key */
			uint8_t initiatorEphemeral[32];
			/** Encrypted initiator's static key */
			uint8_t encryptedInitiatorStatic[48];
			/** Encrypted timestamp */
			uint8_t encryptedTimestamp[28];
			/** MAC1 field */
			uint8_t mac1[16];
			/** MAC2 field */
			uint8_t mac2[16];
		} wg_handshake_initiation;
#pragma pack(pop)
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		WireGuardHandshakeInitiationLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor that creates a new Handshake Initiation message
		 * @param[in] senderIndex The sender's index
		 * @param[in] initiatorEphemeral The initiator's ephemeral public key
		 * @param[in] encryptedInitiatorStatic The encrypted initiator's static key
		 * @param[in] encryptedTimestamp The encrypted timestamp
		 * @param[in] mac1 The MAC1 field
		 * @param[in] mac2 The MAC2 field
		 */
		WireGuardHandshakeInitiationLayer(uint32_t senderIndex, const uint8_t initiatorEphemeral[32],
		                                  const uint8_t encryptedInitiatorStatic[48],
		                                  const uint8_t encryptedTimestamp[28], const uint8_t mac1[16],
		                                  const uint8_t mac2[16]);

		uint32_t getMessageType() const;
		const uint8_t* getReserved() const;
		uint32_t getSenderIndex() const;
		const uint8_t* getInitiatorEphemeral() const;
		const uint8_t* getEncryptedInitiatorStatic() const;
		const uint8_t* getEncryptedTimestamp() const;
		const uint8_t* getMac1() const;
		const uint8_t* getMac2() const;

		wg_handshake_initiation* getHandshakeInitiationHeader() const
		{
			return (wg_handshake_initiation*)getBasicHeader();
		}

		// implement abstract methods

		WireGuardMessageType getWireGuardMessageType() const
		{
			return WireGuardMessageType::HandshakeInitiation;
		}
	};

	/**
	 * @class WireGuardHandshakeResponseLayer
	 * Represents a Handshake Response message
	 */
	class WireGuardHandshakeResponseLayer : public WireGuardLayer
	{
	public:
#pragma pack(push, 1)
		/**
		 * @struct wg_handshake_response
		 * Represents the Handshake Response message
		 */
		typedef struct wg_handshake_response : wg_common_header
		{
			/** Sender index */
			uint32_t senderIndex;
			/** Receiver index */
			uint32_t receiverIndex;
			/** Responder's ephemeral public key */
			uint8_t responderEphemeral[32];
			/** Encrypted empty field */
			uint8_t encryptedEmpty[16];
			/** MAC1 field */
			uint8_t mac1[16];
			/** MAC2 field */
			uint8_t mac2[16];
		} wg_handshake_response;
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		WireGuardHandshakeResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor that creates a new Handshake Response message
		 * @param[in] senderIndex The sender index
		 * @param[in] receiverIndex The receiver index
		 * @param[in] responderEphemeral The responder's ephemeral public key
		 * @param[in] encryptedEmpty The encrypted empty field
		 * @param[in] mac1 The MAC1 field
		 * @param[in] mac2 The MAC2 field
		 */
		WireGuardHandshakeResponseLayer(uint32_t senderIndex, uint32_t receiverIndex,
		                                const uint8_t responderEphemeral[32], const uint8_t encryptedEmpty[16],
		                                const uint8_t mac1[16], const uint8_t mac2[16]);

		uint32_t getMessageType() const;
		const uint8_t* getReserved() const;
		uint32_t getSenderIndex() const;
		uint32_t getReceiverIndex() const;
		const uint8_t* getResponderEphemeral() const;
		const uint8_t* getEncryptedEmpty() const;
		const uint8_t* getMac1() const;
		const uint8_t* getMac2() const;

		wg_handshake_response* getHandshakeResponseHeader() const
		{
			return (wg_handshake_response*)getBasicHeader();
		}

		// implement abstract methods

		WireGuardMessageType getWireGuardMessageType() const
		{
			return WireGuardMessageType::HandshakeResponse;
		}
	};

	/**
	 * @class WireGuardCookieReplyLayer
	 * Represents a Cookie Reply message
	 */
	class WireGuardCookieReplyLayer : public WireGuardLayer
	{
	public:
#pragma pack(push, 1)
		/**
		 * @struct wg_cookie_reply
		 * Represents the Cookie Reply message
		 */
		typedef struct wg_cookie_reply : wg_common_header
		{
			/** Receiver index */
			uint32_t receiverIndex;
			/** Nonce field */
			uint8_t nonce[24];
			/** Encrypted cookie */
			uint8_t encryptedCookie[32];
		} wg_cookie_reply;
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		WireGuardCookieReplyLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor that creates a new Cookie Reply message
		 * @param[in] receiverIndex The receiver index
		 * @param[in] nonce The nonce field
		 * @param[in] encryptedCookie The encrypted cookie
		 */
		WireGuardCookieReplyLayer(uint32_t receiverIndex, const uint8_t nonce[24], const uint8_t encryptedCookie[32]);

		uint32_t getMessageType() const;
		const uint8_t* getReserved() const;
		uint32_t getReceiverIndex() const;
		const uint8_t* getNonce() const;
		const uint8_t* getEncryptedCookie() const;

		wg_cookie_reply* getCookieReplyHeader() const
		{
			return (wg_cookie_reply*)getBasicHeader();
		}

		// implement abstract methods

		WireGuardMessageType getWireGuardMessageType() const
		{
			return WireGuardMessageType::CookieReply;
		}
	};

	/**
	 * @class WireGuardTransportDataLayer
	 * Represents a Transport Data message
	 */
	class WireGuardTransportDataLayer : public WireGuardLayer
	{
	public:
#pragma pack(push, 1)
		/**
		 * @struct wg_transport_data
		 * Represents the Transport Data message
		 */
		typedef struct wg_transport_data : wg_common_header
		{
			/** Receiver index */
			uint32_t receiverIndex;
			/** Counter field */
			uint64_t counter;
			/** Flexible array member for encrypted data */
			uint8_t encryptedData[0];
		} wg_transport_data;
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		WireGuardTransportDataLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : WireGuardLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor that creates a new Transport Data message
		 * @param[in] receiverIndex The receiver index
		 * @param[in] counter The counter field
		 * @param[in] encryptedData The encrypted data
		 */
		WireGuardTransportDataLayer(uint32_t receiverIndex, uint64_t counter, const uint8_t* encryptedData,
		                            size_t encryptedDataLen);

		uint32_t getMessageType() const;
		const uint8_t* getReserved() const;
		uint32_t getReceiverIndex() const;
		uint64_t getCounter() const;
		const uint8_t* getEncryptedData() const;

		wg_transport_data* getTransportHeader() const
		{
			return (wg_transport_data*)getBasicHeader();
		}

		// implement abstract methods

		WireGuardMessageType getWireGuardMessageType() const
		{
			return WireGuardMessageType::TransportData;
		}
	};
}  // namespace pcpp
