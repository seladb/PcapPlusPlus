#pragma once

#include "Layer.h"

/// @file
/// This file introduces classes and structures that represent the SSH (Secure Shell) protocol.
///
/// An overview of this protocol can be found here: https://en.wikipedia.org/wiki/Ssh_(Secure_Shell)
///
/// For more details please refer to RFC 4253: https://tools.ietf.org/html/rfc4253
///
/// These current implementation supports parsing of SSH packets when possible (meaning when they are not encrypted).
/// Creation and editing of SSH packets is currently __not supported__.
///
/// SSH typically uses TCP port 22 so PcapPlusPlus assumes all traffic on this port is SSH traffic.
/// PcapPlusPlus uses some heuristics to determine the type of the SSH message (which will be covered later).
/// If it doesn't find a match to one of the other SSH messages, it assumes it is an encrypted SSH message.
///
/// Following is an overview of the SSH protocol classes currently supported in PcapPlusPlus. They cover the different
/// messages of the SSH protocol:
///
/// @code{.unparsed}
///                          +----------------------------+      SSH version identification
///                      +---|  SSHIdentificationMessage  | ===> as described here:
///                      |   +----------------------------+      https://tools.ietf.org/html/rfc4253#section-4.2
///                      |
///  +------------+      |   +----------------------------+      SSH handshake message
///  |  SSHLayer  |------+---|  SSHHandshakeMessage       | ===> which is typically one of the messages described here:
///  | (abstract) |      |   +----------------------------+      https://tools.ietf.org/html/rfc4253#section-12
///  +------------+      |                 |
///                      |                 |     +----------------------------+
///                      |                 +-----|  SSHKeyExchangeInitMessage | ===> SSH Key Exchange message
///                      |                       +----------------------------+      as described here:
///                      |                                                 https://tools.ietf.org/html/rfc4253#section-7
///                      |
///                      |   +----------------------------+
///                      +---|  SSHEncryptedMessage       | ===> An encrypted SSH message
///                          +----------------------------+
///
/// @endcode
/// The following points describe the heuristics for deciding the
/// message type for each packet:
/// 1. If the data starts with the characters "SSH-" and ends with
/// "\n" (or "\r\n") it's assumed the message is of type
///    pcpp#SSHIdentificationMessage
/// 2. Try to determine if this is a non-encrypted SSH handshake
/// message:
///    - Look at the first 4 bytes of the data which may contain
///    the packet length and see if the value is smaller of
///      equal than the entire layer length.
///    - The next byte contains the padding length, check if it's
///    smaller or equal than the packet length
///    - The next byte contains the message type, check if the
///    value is a valid message type as described in:
///      <https://tools.ietf.org/html/rfc4253#section-12>
///
///    If all of these condition are met, this message is either
///    pcpp#SSHKeyExchangeInitMessage (if message type is
///    pcpp#SSHHandshakeMessage#SSH_MSG_KEX_INIT) or
///    pcpp#SSHHandshakeMessage (for all other message types)
/// 3. If non of these conditions are met, it is assumed this is an
/// encrypted message (pcpp#SSHEncryptedMessage)

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class SSHLayer
	/// This is the base class for the SSH layer. It is an abstract class that cannot be instantiated.
	/// It holds some common functionality, but its most important method is createSSHMessage()
	/// which takes raw data and creates an SSH message according to the heuristics described
	/// in the SSHLayer.h file description
	class SSHLayer : public Layer
	{
	public:
		/// A static method that takes raw packet data and uses the heuristics described in the
		/// SSHLayer.h file description to create an SSH layer instance. This method assumes the data is
		/// indeed SSH data and not some other arbitrary data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @return An instance of one of the classes that inherit SSHLayer as described in the
		/// SSHLayer.h file description
		static SSHLayer* createSSHMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A static method that takes src and dst ports and determines whether it's SSH traffic or not.
		/// @param[in] portSrc The source TCP port to examine
		/// @param[in] portDst The dest TCP port to examine
		/// @return Currently the implementation is very simple and returns "true" if either src or dst ports
		/// are equal to 22, "false" otherwise
		static bool isSSHPort(uint16_t portSrc, uint16_t portDst)
		{
			return portSrc == 22 || portDst == 22;
		}

		// implement abstract methods

		/// Several SSH records can reside in a single packets. This method examins the remaining data and creates
		/// additional SSH records if applicable
		void parseNextLayer() override;

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	protected:
		// protected c'tor, this class cannot be instantiated
		SSHLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, SSH)
		{}

	private:
		// this layer supports only parsing
		SSHLayer();
	};

	/// @class SSHIdentificationMessage
	/// A class that represents SSH identification message as described in RFC 4253:
	/// <https://tools.ietf.org/html/rfc4253#section-4.2>
	///
	/// The message content is typically a string that contains the protocol version, software version and a few more
	/// details. This string can be retrieved using the getIdentificationMessage() method
	class SSHIdentificationMessage : public SSHLayer
	{
	public:
		/// @return The SSH identification message which is typically the content of this message
		std::string getIdentificationMessage();

		/// A static method that takes raw data and tries to parse it as an SSH identification message using the
		/// heuristics described in the SSHLayer.h file description. It returns a SSHIdentificationMessage instance if
		/// such a message can be identified or nullptr otherwise.
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @return An instance of SSHIdentificationMessage or nullptr if this is not an identification message
		static SSHIdentificationMessage* tryParse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/// @return The size of the identification message
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		std::string toString() const override;

	private:
		// this layer supports only parsing
		SSHIdentificationMessage();

		// private c'tor, this class cannot be instantiated
		SSHIdentificationMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSHLayer(data, dataLen, prevLayer, packet)
		{}
	};

	/// @class SSHHandshakeMessage
	/// A class representing all of the non-encrypted SSH handshake messages.
	/// An handshake message typically has the following structure:
	///
	/// @code{.unparsed}
	/// 0         1         2         3         4         5         6
	/// +---------+---------+---------+---------+---------+---------+-----------     ---------+
	/// |            Packet Length              | Padding | Message |  Message  ....  Padding |
	/// |                                       | Length  |  Type   |  Content  ....          |
	/// +---------------------------------------+---------+---------+-----------     ---------+
	/// @endcode
	///
	/// The first 4 bytes hold the packet length, followed by 1 byte that holds the padding length (which comes at the
	/// end of the message), then 1 byte that holds the message type (which can be of type
	/// SSHHandshakeMessage#SSHHandshakeMessageType) and then the message content. At the end of the content there is
	/// typically padding.
	///
	/// This class provides access to all of these values. The message content itself is not parse with the exception of
	/// SSHKeyExchangeInitMessage
	/// which inherits from this class and provides parsing of the Key Exchange Init message.
	class SSHHandshakeMessage : public SSHLayer
	{
	public:
		/// An enum that represents SSH non-encrypted message types
		enum SSHHandshakeMessageType
		{
			/// Key Exchange Init message
			SSH_MSG_KEX_INIT = 20,
			/// New Keys message
			SSH_MSG_NEW_KEYS = 21,
			/// Diffie-Hellman Key Exchange Init message
			SSH_MSG_KEX_DH_INIT = 30,
			///  message
			SSH_MSG_KEX_DH_REPLY = 31,
			/// Diffie-Hellman Group Exchange Init message
			SSH_MSG_KEX_DH_GEX_INIT = 32,
			/// "Diffie-Hellman Group Exchange Reply message
			SSH_MSG_KEX_DH_GEX_REPLY = 33,
			/// Diffie-Hellman Group Exchange Request message
			SSH_MSG_KEX_DH_GEX_REQUEST = 34,
			/// Unknown message
			SSH_MSG_UNKNOWN = 999
		};

		/// @return The message type
		SSHHandshakeMessageType getMessageType() const;

		/// @return A string representation of the message type
		std::string getMessageTypeStr() const;

		/// @return A raw byte stream of the message content
		uint8_t* getSSHHandshakeMessage() const;

		/// @return The message content length in [bytes] which is calculated by the overall packet length
		/// minus the message header (which includes packet length, padding length and message type) and
		/// minus the padding bytes
		size_t getSSHHandshakeMessageLength() const;

		/// @return The padding length in [bytes]
		size_t getPaddingLength() const;

		/// A static method that takes raw packet data and uses some heuristics described in the
		/// SSHLayer.h file description to parse it as SSH handshake message instance
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @return Upon successful parsing the return value would be an instance of SSHKeyExchangeInitMessage
		/// for Key Exchange Init message or SSHHandshakeMessage for any other message type. If parsing fails nullptr
		/// will be returned
		static SSHHandshakeMessage* tryParse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/// @return The size of the SSH handshake message including the padding and message header
		size_t getHeaderLen() const override;

		std::string toString() const override;

	protected:
#pragma pack(push, 1)
		/// An internal struct representing the SSH handshake message header
		struct ssh_message_base
		{
			uint32_t packetLength;
			uint8_t paddingLength;
			uint8_t messageCode;
		};
#pragma pack(pop)
		static_assert(sizeof(ssh_message_base) == 6, "ssh_message_base size is not 6 bytes");

		// this layer supports only parsing
		SSHHandshakeMessage();

		// private c'tor, this class cannot be instantiated
		SSHHandshakeMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSHLayer(data, dataLen, prevLayer, packet)
		{}

		ssh_message_base* getMsgBaseHeader() const
		{
			return reinterpret_cast<ssh_message_base*>(m_Data);
		}
	};

	/// @class SSHKeyExchangeInitMessage
	/// A class representing the SSH Key Exchange Init message. This is a non-encrypted message that contains
	/// information about the algorithms used for key exchange, encryption, MAC and compression. This class provides
	/// methods to access these details
	class SSHKeyExchangeInitMessage : public SSHHandshakeMessage
	{
	public:
		/// A c'tor for this class that accepts raw message data. Please avoid using it as it's used internally
		/// when parsing SSH handshake messages in SSHHandshakeMessage#tryParse()
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		SSHKeyExchangeInitMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// Each SSH Key Exchange Init message contains a random 16-byte value generated by the sender.
		/// This method returns a pointer to this 16-byte cookie. To get the value as a hex string
		/// please refer to getCookieAsHexStream()
		/// @return A pointer to the 16-byte cookie value or nullptr if the message is malformed
		uint8_t* getCookie();

		/// Each SSH Key Exchange Init message contains a random 16-byte value generated by the sender.
		/// This method returns the 16-byte cookie as a hex stream. To get the raw data please refer to
		/// getCookie()
		/// @return A hex stream of the 16-byte cookie value or an empty string if the message is malformed
		std::string getCookieAsHexStream();

		/// @return A comma-separated list of the key exchange algorithms used in this session.
		/// Can be empty if the value is missing or the message is malformed
		std::string getKeyExchangeAlgorithms()
		{
			return getFieldValue(0);
		}

		/// @return A comma-separated list of the algorithms supported for the server host key.
		/// Can be empty if the value is missing or the message is malformed
		std::string getServerHostKeyAlgorithms()
		{
			return getFieldValue(1);
		}

		/// @return A comma-separated list of acceptable symmetric encryption algorithms (also known as ciphers)
		/// from the client to the server. Can be empty if the value is missing or the message is malformed
		std::string getEncryptionAlgorithmsClientToServer()
		{
			return getFieldValue(2);
		}

		/// @return A comma-separated list of acceptable symmetric encryption algorithms (also known as ciphers)
		/// from the server to the client. Can be empty if the value is missing or the message is malformed
		std::string getEncryptionAlgorithmsServerToClient()
		{
			return getFieldValue(3);
		}

		/// @return A comma-separated list of acceptable MAC algorithms from the client to the server.
		/// Can be empty if the value is missing or the message is malformed
		std::string getMacAlgorithmsClientToServer()
		{
			return getFieldValue(4);
		}

		/// @return A comma-separated list of acceptable MAC algorithms from the server to the client.
		/// Can be empty if the value is missing or the message is malformed
		std::string getMacAlgorithmsServerToClient()
		{
			return getFieldValue(5);
		}

		/// @return A comma-separated list of acceptable compression algorithms from the client to the server.
		/// Can be empty if the value is missing or the message is malformed
		std::string getCompressionAlgorithmsClientToServer()
		{
			return getFieldValue(6);
		}

		/// @return A comma-separated list of acceptable compression algorithms from the server to the client.
		/// Can be empty if the value is missing or the message is malformed
		std::string getCompressionAlgorithmsServerToClient()
		{
			return getFieldValue(7);
		}

		/// @return A comma-separated list of language tags from the client to the server.
		/// Can be empty if the value is missing or the message is malformed
		std::string getLanguagesClientToServer()
		{
			return getFieldValue(8);
		}

		/// @return A comma-separated list of language tags from the server to the client.
		/// Can be empty if the value is missing or the message is malformed

		std::string getLanguagesServerToClient()
		{
			return getFieldValue(9);
		}

		/// @return Indicates whether a guessed key exchange packet follows. If a
		/// guessed packet will be sent, the return value is true. If no guessed
		/// packet will be sent or if this value is missing, the return value is false.
		bool isFirstKexPacketFollows();

	private:
		size_t m_FieldOffsets[11];
		bool m_OffsetsInitialized;

		void parseMessageAndInitOffsets();

		std::string getFieldValue(int fieldOffsetIndex);
	};

	/// @class SSHEncryptedMessage
	/// A class representing an SSH encrypted message. In such messages there is very little information to extract from
	/// the packet, hence this class doesn't expose any methods or getters, other than the ones inherited from parent
	/// classes.
	///
	/// It is assumed that any SSH message which does not fit to any of the other SSH message types, according to the
	/// heuristics described in the SSHLayer.h file description, is considered as an encrypted message.
	class SSHEncryptedMessage : public SSHLayer
	{
	public:
		/// A c'tor for this class that accepts raw message data. Please avoid using it as it's used internally
		/// when parsing SSH messages in SSHLayer#createSSHMessage()
		SSHEncryptedMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSHLayer(data, dataLen, prevLayer, packet)
		{}

		// implement abstract methods

		/// @return The size of the message which is equal to the size of the layer
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		std::string toString() const override;
	};

}  // namespace pcpp
