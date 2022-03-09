#ifndef PACKETPP_SSL_LAYER
#define PACKETPP_SSL_LAYER

#include "PointerVector.h"
#include "Layer.h"
#include "SSLCommon.h"
#include "SSLHandshake.h"

/**
 * @file
 * This file as well as SSLCommon.h and SSLHandshake.h provide structures that represent SSL/TLS protocol.
 * Main features:
 * - All common SSL/TLS version are supported from SSL 3.0 to TLS 1.3
 * - All SSL/TLS message types are supported (at least the message types that are not encrypted)
 * - More than 300 cipher-suites are supported
 * - Only parsing capabilities exist, editing and creation of messages are not supported
 * - X509 certificate parsing is not supported
 *
 * <BR><BR>
 *
 * __SSL Records:__   <BR>
 *
 * The SSL/TLS protocol has 4 types of records:
 * - Handshake record type
 * - Change cipher spec record type
 * - Alert record type
 * - Application data record type
 *
 * Each record type corresponds to a layer class, and these classes inherit from one base class which is pcpp::SSLLayer.
 * The pcpp::SSLLayer is an abstract class which cannot be instantiated. Only its 4 derived classes can be instantiated.
 * This means you'll never see a layer of type pcpp::SSLLayer, you'll only see the type of the derived classes.
 * A basic class diagram looks like this:
  @verbatim
                                 +----------------------------+
                             +---|     SSLHandshakeLayer      | ===> Handshake record type
                             |   +----------------------------+
                             |
                             |   +----------------------------+
                             +---|  SSLChangeCipherSpecLayer  | ===> Change cipher spec record type
                             |   +----------------------------+
                             |
  +------------+             |   +----------------------------+
  |  SSLLayer  |-------------+---|      SSLAlertLayer         | ===> Alert record type
  | (abstract) |             |   +----------------------------+
  +------------+             |
                             |   +----------------------------+
                             +---|   SSLApplicationDataLayer  | ===> Application data record type
                                 +----------------------------+

  @endverbatim
 *
 * A single packet may include several SSL/TLS records, meaning several layer instances of these types, for example:
 *
  @verbatim

            +--------------------------+
            |          EthLayer        |
            +--------------------------+
            |          IPv4Layer       |
            +--------------------------+
            |          TcpLayer        |
            +--------------------------+
            |    SSLHandshakeLayer     | \
            +--------------------------+  \
            | SSLChangeCipherSpecLayer | -------- 3 SSL/TLS records in the same packet!
            +--------------------------+  /
            |    SSLHandshakeLayer     | /
            +--------------------------+

  @endverbatim
 *
 * <BR><BR>
 *
 * __SSL/TLS Handshake records:__    <BR>
 *
 * The SSL/TLS handshake records are the most complex ones. These type of records encapsulate all messages between
 * client and server during SSL/TLS connection establishment. To accomplish that a SSL/TLS handshake record holds
 * zero or more handshake messages (usually it holds 1 message). These messages form the handshake negotiation between
 * the client and the server. There are several types of handshake messages. Some of the are sent from client to server
 * and some from server to client. PcapPlusPlus supports 11 of these types (definitely the most common ones). For each
 * message there is a designated class which parses the message and exposes its attributes in an easy-to-use manner.
 * Here are the list of supported messages:
 * - Client-hello
 * - Server-hello
 * - Certificate
 * - Hello-request
 * - Server-key-exchange
 * - Client-key-exchange
 * - Certificate-request
 * - Server-hello-done
 * - Certificate-verify
 * - Finished
 * - New-session-ticket
 *
 * All handshake messages classes inherit from a base abstract class: pcpp::SSLHandshakeMessage which cannot be instantiated.
 * Also, all of them reside in SSLHandshake.h. Following is a simple diagram of these classes:
 *
 @verbatim

                                          SSLHandshakeMessage
                                             |
 +-------------------------------+           |--- SSLClientHelloMessage        ==> Client-hello message
 |       SSLHandshakeLayer       |           |
 +-------------------------------+           |--- SSLServerHelloMessage        ==> Server-hello message
 | -List of SSLHandshakeMessage  |           |
 |     Message1                  |           |---SSLCertificateMessage         ==> Certificate message
 |     Message2                  |           |
 |     ...                       |           |---SSLHelloRequestMessage        ==> Hello-request message
 |                               |           |
 +-------------------------------+           |---SSLServerKeyExchangeMessage   ==> Server-key-exchange message
                                             |
                                             |---SSLClientKeyExchangeMessage   ==> Client-key-exchange message
                                             |
                                             |---SSLCertificateRequestMessage  ==> Certificate-request message
                                             |
                                             |---SSLServerHelloDoneMessage     ==> Server-hello-done message
                                             |
                                             |---SSLCertificateVerifyMessage   ==> Certificate-verify message
                                             |
                                             |---SSLFinishedMessage            ==> Finished message
                                             |
                                             |---SSLNewSessionTicketMessage    ==> New-session-ticket message

 @endverbatim
 *
 * In addition, for all handshake messages which aren't supported in PcapPlusPlus or for encrypted handshake messages
 * There is another class: pcpp::SSLUnknownMessage
 *
 * <BR><BR>
 *
 * __Cipher suites:__    <BR>
 *
 * Cipher suites are named combinations of authentication, encryption, message authentication code (MAC) and key exchange
 * algorithms used to negotiate the security settings for a network connection using SSL/TLS.
 * There are many known cipher-suites. PcapPlusPlus support above 300 of them, according to this list:
 * http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 * There is a designated class in PcapPlusPlus called pcpp::SSLCipherSuite which represents the cipher-suites and provides
 * access to their attributes. Then there is a static instance of this class for each one of the supported cipher-suites.
 * This means there are 300+ static instances of pcpp::SSLCipherSuite representing the different cipher suites. The user can
 * access them through static methods in pcpp::SSLCipherSuite or from client-hello and server-hello messages where they appear
 *
 * <BR><BR>
 *
 * __SSL/TLS extensions:__    <BR>
 *
 * SSL/TLS handshake messages, specifically client-hello and server-hello usually include extensions. There are various
 * types of extensions - some are more broadly used, some are less. In PcapPlusPlus there is a base class for all
 * extensions: pcpp::SSLExtension. This class is instantiable and represents a generic extension, which means extension data
 * isn't parsed and given to the user as raw data. Currently there are only two extension that are fully parsed which are
 * server-name-indication (pcpp::SSLServerNameIndicationExtension) and SupportedVersions (pcpp::SSLSupportedVersionsExtension).
 * Both inherit from pcpp::SSLExtension and add additional parsing relevant for the specific extension.
 * All other extensions aren't parsed and are represented by instance of pcpp::SSLExtension.
 * Access to extensions is done through the handshake messages classes, specifically pcpp::SSLClientHelloMessage and pcpp::SSLServerHelloMessage
 */


/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class SSLLayer
	 * The base class for the 4 record type classes. Each record type is represented as a layer. See SSLLayer.h for
	 * detailed explanation of the TLS/SSL protocol support in PcapPlusPlus.
	 * This class provides the common functionality used by all record types and also contains static methods for identifying
	 * an creating SSL/TLS record type layers
	 */
	class SSLLayer : public Layer
	{
	public:

		/**
		 * A static method that checks whether the port is considered as SSL/TLS
		 * @param[in] port The port number to be checked
		 */
		static inline bool isSSLPort(uint16_t port);

		/**
		 * A static methods that gets raw data of a layer and checks whether this data is a SSL/TLS record or not. This check is
		 * done using the source/dest port and matching of a legal record type in the raw data. The list of ports identified
		 * as SSL/TLS is hard-coded and includes the following ports:
		 * - Port 443 [HTTPS]
		 * - Port 261 [NSIIOPS]
		 * - Port 448 [DDM-SSL]
		 * - Port 563 [NNTPS]
		 * - Port 614 [SSHELL]
		 * - Port 465 [SMTPS]
		 * - Port 636 [LDAPS]
		 * - Port 989 [FTPS - data]
		 * - Port 990 [FTPS - control]
		 * - Port 992 [Telnet over TLS/SSL]
		 * - Port 993 [IMAPS]
		 * - Port 994 [IRCS]
		 * - Port 995 [POP3S]
		 * @param[in] srcPort The source port of the packet that contains the raw data. Source port (or dest port) are a
		 * criteria to identify SSL/TLS packets
		 * @param[in] dstPort The dest port of the packet that contains the raw data. Dest port (or source port) are a
		 * criteria to identify SSL/TLS packets
		 * @param[in] data The data to check
		 * @param[in] dataLen Length (in bytes) of the data
		 * @param[in] ignorePorts SSL/TLS ports are only relevant for parsing the first SSL/TLS message, but are not relevant
		 * for parsing subsequent messages. This parameter can be set to "true" to skip SSL/TLS ports check. This is an
		 * optional parameter and its default is "false"
		 */
		static bool IsSSLMessage(uint16_t srcPort, uint16_t dstPort, uint8_t* data, size_t dataLen, bool ignorePorts = false);

		/**
		 * A static method that creates SSL/TLS layers by raw data. This method parses the raw data, finds if and which
		 * SSL/TLS record it is and creates the corresponding record layer. It's the responsibility of the user to free
		 * the created object when done using it
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return A pointer to the newly created record layer. If no SSL/TLS record could be identified from the raw data
		 * NULL is returned
		 */
		static SSLLayer* createSSLMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * Get a pointer to the record header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref ssl_tls_record_layer
		 */
		ssl_tls_record_layer* getRecordLayer() const { return (ssl_tls_record_layer*)m_Data; }

		/**
		 * @return The SSL/TLS version used in this record (parsed from the record)
		 */
		SSLVersion getRecordVersion() const;

		/**
		 * @return The SSL/TLS record type as parsed from the record
		 */
		SSLRecordType getRecordType() const;

		// implement abstract methods

		/**
		 * @return The record size as extracted from the record data (in ssl_tls_record_layer#length)
		 */
		size_t getHeaderLen() const;

		/**
		 * Several SSL/TLS records can reside in a single packets. So this method checks the remaining data and if it's
		 * identified as SSL/TLS it creates another SSL/TLS record layer as the next layer
		 */
		void parseNextLayer();

		OsiModelLayer getOsiModelLayer() const { return OsiModelPresentationLayer; }

	protected:
		SSLLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = SSL; }

	}; // class SSLLayer


	/**
	 * @class SSLHandshakeLayer
	 * Represents SSL/TLS handshake layer. This layer may contain one or more handshake messages (all of them inherit from
	 * the base class SSLHandshakeMessage) which are the SSL/TLS handshake message sent between a client and a server until
	 * they establish a secure connection (e.g client-hello, server-hello, certificate, client-key-exchange,
	 * server-key-exchange, etc.). Usually this layer will contain just one message (as the first example below
	 * demonstrates). But there are cases a layer may contain more than 1 message. To better explain this layer structure
	 * we'll use 2 examples. The first will be client-hello message. The layer structure will look like this:
	  @verbatim

			  |------------------- SSLHandshakeLayer ----------------------|
			  +----------------------+-------------------------------------+
			  | ssl_tls_record_layer |       SSLClientHelloMessage         |
			  |        struct        |                                     |
			  +----------------------+-------------------------------------+
			   /     |       \               |          \         \      \
			  /    version    \      |   handshake       \         \      \
			 /     TLS1_0      \            type          \         \     rest of
		  type                  \    | SSL_CLIENT_HELLO    \         \    message fields...
	  SSL_HANDSHAKE           length                   handshake      \
		  (22)                 xxx   |                  version      message
														 TLS1_2      length
									 |                                yyy
	  @endverbatim

	 * Second example is a multiple-message handshake layer comprises of server-hello, certificate and server-key-exchange
	 * messages:

	  @verbatim

			  |---------------------------------------------- SSLHandshakeLayer -----------------------------------------------------|
			  +----------------------+-------------------------------------+---------------------------+-----------------------------+
			  | ssl_tls_record_layer |       SSLServerHelloMessage         |   SSLCertificateMessage   | SSLServerKeyExchangeMessage |
			  |        struct        |                                     |                           |                             |
			  +----------------------+-------------------------------------+---------------------------+-----------------------------+
			   /     |       \               |          \         \               |           \               |            \
			  /    version    \      |   handshake       \        rest of  |      |          rest      |      |            rest
			 /     TLS1_0      \            type          \       message      handshake   of fields...   handshake    of fields...
		  type                  \    | SSL_SERVER_HELLO    \      fields...|     type                  |     type
	  SSL_HANDSHAKE           length                   handshake             SSL_CERTIFICATE             SSL_SERVER_KEY_EXCHANGE
		  (22)                 xxx   |               version,length        |                           |

									 |                                     |                           |

	  @endverbatim
	 */
	class SSLHandshakeLayer: public SSLLayer
	{
	public:

		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLHandshakeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * @return The number of messages in this layer instance
		 */
		size_t getHandshakeMessagesCount() const { return m_MessageList.size(); }

		/**
		 * Get a pointer to an handshake message by index. The message are numbered according to their order of appearance
		 * in the layer. If index is out of bounds (less than 0 or larger than total amount of message) NULL will be
		 * returned
		 * @param[in] index The index of the message to return
		 * @return The pointer to the message object or NULL if index is out of bounds
		 */
		SSLHandshakeMessage* getHandshakeMessageAt(int index) const;

		/**
		 * A templated method to get a message of a certain type. If no message of such type is found, NULL is returned
		 * @return A pointer to the message of the requested type, NULL if not found
		 */
		template<class THandshakeMessage>
		THandshakeMessage* getHandshakeMessageOfType() const;

		/**
		 * A templated method to get the first message of a certain type, starting to search from a certain message.
		 * For example: if the layer looks like: HelloRequest(1) -> HelloRequest(2)
		 * and the user put HelloRequest(1) as a parameter and wishes to search for an HelloRequest message, the
		 * HelloRequest(2) will be returned.<BR>
		 * If no layer of such type is found, NULL is returned
		 * @param[in] after A pointer to the message to start search from
		 * @return A pointer to the message of the requested type, NULL if not found
		 */
		template<class THandshakeMessage>
		THandshakeMessage* getNextHandshakeMessageOfType(SSLHandshakeMessage* after) const;

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields() {}

	private:
		PointerVector<SSLHandshakeMessage> m_MessageList;
	}; // class SSLHandshakeLayer


	/**
	 * @class SSLChangeCipherSpecLayer
	 * Represents SSL/TLS change-cipher-spec layer. This layer has no additional fields besides common fields described in
	 * SSLLayer
	 */
	class SSLChangeCipherSpecLayer : public SSLLayer
	{
	public:

		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLChangeCipherSpecLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: SSLLayer(data, dataLen, prevLayer, packet) {}

		~SSLChangeCipherSpecLayer() {}

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields() {}
	}; // class SSLChangeCipherSpecLayer


	/**
	 * @class SSLAlertLayer
	 * Represents SSL/TLS alert layer. Inherits from SSLLayer and adds parsing functionality such as retrieving the alert
	 * level and description
	 */
	class SSLAlertLayer : public SSLLayer
	{
	public:

		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLAlertLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: SSLLayer(data, dataLen, prevLayer, packet) {}

		~SSLAlertLayer() {}

		/**
		 * @return SSL/TLS alert level. Will return ::SSL_ALERT_LEVEL_ENCRYPTED if alert is encrypted
		 */
		SSLAlertLevel getAlertLevel() const;

		/**
		 * @return SSL/TLS alert description. Will return ::SSL_ALERT_ENCRYPTED if alert is encrypted
		 */
		SSLAlertDescription getAlertDescription();

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields() {}
	}; // class SSLAlertLayer


	/**
	 * @class SSLApplicationDataLayer
	 * Represents SSL/TLS application data layer. This message contains the encrypted data transferred from client to
	 * server and vice-versa after the SSL/TLS handshake was completed successfully
	 */
	class SSLApplicationDataLayer : public SSLLayer
	{
	public:

		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLApplicationDataLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: SSLLayer(data, dataLen, prevLayer, packet) {}

		~SSLApplicationDataLayer() {}

		/**
		 * @return A pointer to the encrypted data. This data can be decrypted only if you have the symmetric key
		 * that was agreed between the client and the server during SSL/TLS handshake process
		 */
		uint8_t* getEncryptedData() const;

		/**
		 * @return The length in bytes of the encrypted data returned in getEncryptedData()
		 */
		size_t getEncryptedDataLen() const;

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields() {}
	}; // class SSLApplicationDataLayer


	template<class THandshakeMessage>
	THandshakeMessage* SSLHandshakeLayer::getHandshakeMessageOfType() const
	{
		size_t vecSize = m_MessageList.size();
		for (size_t i = 0; i < vecSize; i++)
		{
			SSLHandshakeMessage* curElem = const_cast<SSLHandshakeMessage*>(m_MessageList.at(i));
			 if (dynamic_cast<THandshakeMessage*>(curElem) != NULL)
				 return (THandshakeMessage*)curElem;
		}

		// element not found
		return NULL;
	} // getHandshakeMessageOfType


	template<class THandshakeMessage>
	THandshakeMessage* SSLHandshakeLayer::getNextHandshakeMessageOfType(SSLHandshakeMessage* after) const
	{
		size_t vecSize = m_MessageList.size();
		size_t afterIndex;

		// find the index of "after"
		for (afterIndex = 0; afterIndex < vecSize; afterIndex++)
		{
			SSLHandshakeMessage* curElem = const_cast<SSLHandshakeMessage*>(m_MessageList.at(afterIndex));
			if (curElem == after)
				break;
		}

		// "after" not found
		if (afterIndex == vecSize)
			return NULL;

		for (size_t i = afterIndex+1; i < vecSize; i++)
		{
			SSLHandshakeMessage* curElem = const_cast<SSLHandshakeMessage*>(m_MessageList.at(i));
			 if (dynamic_cast<THandshakeMessage*>(curElem) != NULL)
				 return (THandshakeMessage*)curElem;
		}

		// element not found
		return NULL;
	} // getNextHandshakeMessageOfType


	// implementation of inline methods

	bool SSLLayer::isSSLPort(uint16_t port)
	{
		if (port == 443) // HTTPS, this is likely case
			return true;

		switch (port)
		{
		case 261: // NSIIOPS
		case 448: // DDM-SSL
		case 465: // SMTPS
		case 563: // NNTPS
		case 614: // SSHELL
		case 636: // LDAPS
		case 989: // FTPS - data
		case 990: // FTPS - control
		case 992: // Telnet over TLS/SSL
		case 993: // IMAPS
		case 994: // IRCS
		case 995: // POP3S
			return true;
		default:
			return false;
		}
	} // isSSLPort

} // namespace pcpp

#endif /* PACKETPP_SSL_LAYER */
