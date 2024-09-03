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
	 * WireGuard message types
	 */
	enum class WireGuardMessageType
	{
		HandshakeInitiation = 1,  ///< Handshake Initiation message
		HandshakeResponse = 2,    ///< Handshake Response message
		CookieReply = 3,          ///< Cookie Reply message
		TransportData = 4         ///< Transport Data message
	};

	/**
	 * @struct wg_common_header
	 * Represents the common header for all WireGuard message types
	 */
#pragma pack(push, 1)
	struct wg_common_header
	{
		/** Message type field */
		uint8_t messageType;
		/** Reserved field (3 bytes) */
		uint8_t reserved[3];
	};
#pragma pack(pop)

	/**
	 * @struct wg_handshake_initiation
	 * Represents the Handshake Initiation message
	 */
#pragma pack(push, 1)
	struct wg_handshake_initiation
	{
		wg_common_header common;               ///< Common header for all WireGuard messages
		uint32_t senderIndex;                  ///< Sender index
		uint8_t initiatorEphemeral[32];        ///< Initiator's ephemeral public key
		uint8_t encryptedInitiatorStatic[48];  ///< Encrypted initiator's static key
		uint8_t encryptedTimestamp[28];        ///< Encrypted timestamp
		uint8_t mac1[16];                      ///< MAC1 field
		uint8_t mac2[16];                      ///< MAC2 field
	};
#pragma pack(pop)

	/**
	 * @struct wg_handshake_response
	 * Represents the Handshake Response message
	 */
#pragma pack(push, 1)
	struct wg_handshake_response
	{
		wg_common_header common;         ///< Common header for all WireGuard messages
		uint32_t senderIndex;            ///< Sender index
		uint32_t receiverIndex;          ///< Receiver index
		uint8_t responderEphemeral[32];  ///< Responder's ephemeral public key
		uint8_t encryptedEmpty[16];      ///< Encrypted empty field
		uint8_t mac1[16];                ///< MAC1 field
		uint8_t mac2[16];                ///< MAC2 field
	};
#pragma pack(pop)

	/**
	 * @struct wg_cookie_reply
	 * Represents the Cookie Reply message
	 */
#pragma pack(push, 1)
	struct wg_cookie_reply
	{
		wg_common_header common;      ///< Common header for all WireGuard messages
		uint32_t receiverIndex;       ///< Receiver index
		uint8_t nonce[24];            ///< Nonce field
		uint8_t encryptedCookie[32];  ///< Encrypted cookie
	};
#pragma pack(pop)

	/**
	 * @struct wg_transport_data
	 * Represents the Transport Data message
	 */
#pragma pack(push, 1)
	struct wg_transport_data
	{
		wg_common_header common;   ///< Common header for all WireGuard messages
		uint32_t receiverIndex;    ///< Receiver index
		uint64_t counter;          ///< Counter field
		uint8_t encryptedData[0];  ///< Flexible array member for encrypted data
	};
#pragma pack(pop)

	/**
	 * @class WireGuardLayer
	 * Represents a WireGuard protocol layer
	 */
	class WireGuardLayer : public Layer
	{
	public:
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

		/**
		 * Gets a pointer to the Handshake Initiation message.
		 *
		 * @return Pointer to the Handshake Initiation message, or nullptr if data is invalid
		 */
		const wg_handshake_initiation* getHandshakeInitiation() const
		{
			return reinterpret_cast<const wg_handshake_initiation*>(m_Data);
		}

		/**
		 * Gets a pointer to the Handshake Response message.
		 *
		 * @return Pointer to the Handshake Response message, or nullptr if data is invalid
		 */
		const wg_handshake_response* getHandshakeResponse() const
		{
			return reinterpret_cast<const wg_handshake_response*>(m_Data);
		}

		/**
		 * Gets a pointer to the Cookie Reply message.
		 *
		 * @return Pointer to the Cookie Reply message, or nullptr if data is invalid
		 */
		const wg_cookie_reply* getCookieReply() const
		{
			return reinterpret_cast<const wg_cookie_reply*>(m_Data);
		}

		/**
		 * Gets a pointer to the Transport Data message.
		 *
		 * @return Pointer to the Transport Data message, or nullptr if data is invalid
		 */
		const wg_transport_data* getTransportData() const
		{
			return reinterpret_cast<const wg_transport_data*>(m_Data);
		}

		/**
		 * Checks if the given port numbers are WireGuard ports.
		 *
		 * @param portSrc The source port number to check
		 * @param portDst The destination port number to check
		 * @return True if either port matches the WireGuard port (51820), false otherwise
		 */
		static inline bool isWireguardPorts(uint16_t portSrc, uint16_t portDst);

		/**
		 * Checks if the given data represents a WireGuard message.
		 *
		 * @param data Pointer to the raw data
		 * @param dataLen Length of the data
		 * @return True if the data starts with a valid WireGuard message type, false otherwise
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		/**
		 * No operation required for parsing the next layer since WireGuard does not have a next layer.
		 */
		void parseNextLayer() override
		{
			// No next layer to parse for WireGuard, do nothing
		}

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

	// Implementation of inline methods

	/**
	 * Checks if the given port numbers are WireGuard ports.
	 *
	 * @param portSrc The source port number to check
	 * @param portDst The destination port number to check
	 * @return True if either port matches the WireGuard port (51820), false otherwise
	 */
	bool WireGuardLayer::isWireguardPorts(uint16_t portSrc, uint16_t portDst)
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
	bool WireGuardLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < sizeof(wg_common_header))
			return false;

		uint8_t messageType = data[0];
		return messageType >= static_cast<uint8_t>(WireGuardMessageType::HandshakeInitiation) &&
		       messageType <= static_cast<uint8_t>(WireGuardMessageType::TransportData);
	}

}  // namespace pcpp
