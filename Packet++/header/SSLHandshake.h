#ifndef PACKETPP_SSL_HANDSHAKE_MESSAGE
#define PACKETPP_SSL_HANDSHAKE_MESSAGE

#include <utility>
#include "SSLCommon.h"
#include "PointerVector.h"

#ifndef PCPP_DEPRECATED
#if defined(__GNUC__) || defined(__clang__)
#define PCPP_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define PCPP_DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: DEPRECATED feature is not implemented for this compiler")
#define PCPP_DEPRECATED
#endif
#endif

/**
 * @file
 * See detailed explanation of the TLS/SSL protocol support in PcapPlusPlus in SSLLayer.h
 */

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{


/**
 * @class SSLCipherSuite
 * Represents a cipher-suite and enables access all information about it such as all algorithms it encapsulates,
 * its ID (as appears in the client-hello or server-hello messages),
 * its name (e.g "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA") etc. PcapPlusPlus contains static instances of this type
 * for all known cipher-suites and enables access to them through name or ID (see getCipherSuiteByID() and
 * getCipherSuiteByName() ). List of cipher-suite was taken from here:
 * http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
class SSLCipherSuite
{
public:
	/**
	 * A c'tor for this class, should never be used by a user
	 * @param[in] id Cipher-suite ID
	 * @param[in] keyExAlg Key-exchange algorithm used in this cipher-suite
	 * @param[in] authAlg Authentication algorithm used in this cipher-suite
	 * @param[in] symKeyAlg Symmetric key algorithm used in this cipher-suite
	 * @param[in] MACAlg MAC algorithm used in this cipher-suite
	 * @param[in] name String representation of this cipher-suite
	 */
	SSLCipherSuite(uint16_t id, SSLKeyExchangeAlgorithm keyExAlg,
			SSLAuthenticationAlgorithm authAlg,
			SSLSymetricEncryptionAlgorithm symKeyAlg,
			SSLHashingAlgorithm MACAlg,
			const char* name)
	: m_Id(id), m_KeyExAlg(keyExAlg), m_AuthAlg(authAlg), m_SymKeyAlg(symKeyAlg), m_MACAlg(MACAlg), m_Name(name) {}

	/**
	 * @return Cipher-suite ID
	 */
	uint16_t getID() const { return m_Id; }

	/**
	 * @return String representation of this cipher-suite
	 */
	std::string asString() const { return m_Name; }

	/**
	 * @return Key-exchange algorithm used in this cipher-suite
	 */
	SSLKeyExchangeAlgorithm getKeyExchangeAlg() const { return m_KeyExAlg; }

	/**
	 * @return Authentication algorithm used in this cipher-suite
	 */
	SSLAuthenticationAlgorithm getAuthAlg() const { return m_AuthAlg; }

	/**
	 * @return Symmetric key algorithm used in this cipher-suite
	 */
	SSLSymetricEncryptionAlgorithm getSymKeyAlg() const { return m_SymKeyAlg; }

	/**
	 * @return MAC algorithm used in this cipher-suite
	 */
	SSLHashingAlgorithm getMACAlg() const { return m_MACAlg; }

	/**
	 * A static method that returns a cipher-suite instance by ID
	 * @param[in] id Cipher-suite ID
	 * @return A cipher-suite instance matching this ID or NULL if ID not found
	 */
	static SSLCipherSuite* getCipherSuiteByID(uint16_t id);

	/**
	 *  A static method that returns a cipher-suite instance by name
	 *  @param[in] name Cipher-suite name (e.g "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
	 *  @return A cipher-suite instance matching this name or NULL if name not found
	 */
	static SSLCipherSuite* getCipherSuiteByName(std::string name);

private:
	uint16_t m_Id;
	SSLKeyExchangeAlgorithm m_KeyExAlg;
	SSLAuthenticationAlgorithm m_AuthAlg;
	SSLSymetricEncryptionAlgorithm m_SymKeyAlg;
	SSLHashingAlgorithm m_MACAlg;
	std::string m_Name;
};


/**
 * @class SSLExtension
 * Represents a SSL/TLS extension. This is a base class that can represent any type of extension. Inherited classes may
 * contain parsing logic for specific extensions. This class provides capabilities such as getting the extension type,
 * length and viewing the extension data as raw (byte array)
 */
class SSLExtension
{
public:
	/**
	 * C'tor for this class
	 * @param[in] data The raw data for the extension
	 */
	SSLExtension(uint8_t* data);

	virtual ~SSLExtension() { }

	/**
	 * @return The type of the extension as enum
	 */
	SSLExtensionType getType() const;

	/**
	 * @return The type of the extension as a numeric value
	 */
	uint16_t getTypeAsInt() const;

	/**
	 * @return The length of the extension data in bytes (not including the type and length fields)
	 */
	uint16_t getLength() const;

	/**
	 * @return The total length of the extension, including type and length fields and the extension data field
	 */
	uint16_t getTotalLength() const;

	/**
	 * @return A pointer to the raw data of the extension
	 */
	uint8_t* getData() const;

protected:

	/**
	 * @struct SSLExtensionStruct
	 * Represents the common fields of the extension
	 */
	struct SSLExtensionStruct
	{
		/** Extension type */
		uint16_t extensionType;
		/** Extension length */
		uint16_t extensionDataLength;
		/** Extension data as raw (byte array) */
		uint8_t	 extensionData[];
	};

	uint8_t* m_RawData;

	SSLExtensionStruct* getExtensionStruct() const { return (SSLExtensionStruct*)m_RawData; }
};


/**
 * @class SSLServerNameIndicationExtension
 * Represents SSL/TLS Server Name Indication extension. Inherits from SSLExtension and add parsing of the hostname
 * written in the extension data
 */
class SSLServerNameIndicationExtension : public SSLExtension
{
public:
	/**
	 * C'tor for this class
	 * @param[in] data The raw data for the extension
	 */
	SSLServerNameIndicationExtension(uint8_t* data) : SSLExtension(data) {}

	/**
	 * @return The hostname written in the extension data
	 */
	std::string getHostName() const;
};


/**
 * @class SSLSupportedVersionsExtension
 * Represents TLS Supported Versions extension. Inherits from SSLExtension and adds parsing of the list
 * of supported versions mentioned in the extension data
 */
class SSLSupportedVersionsExtension : public SSLExtension
{
public:
	/**
	 * C'tor for this class
	 * @param[in] data The raw data for the extension
	 */
	SSLSupportedVersionsExtension(uint8_t* data) : SSLExtension(data) {}

	/**
	 * @return The list of supported versions mentioned in the extension data
	 */
	std::vector<SSLVersion> getSupportedVersions() const;
};


/**
 * @class TLSSupportedGroupsExtension
 * Represents TLS Supported Groups extension. Inherits from SSLExtension and adds parsing of the
 * supported groups (Elliptic Curves) mentioned in the extension data
 */
class TLSSupportedGroupsExtension : public SSLExtension
{
	public:
	/**
	 * C'tor for this class
	 * @param[in] data The raw data for the extension
	 */
	TLSSupportedGroupsExtension(uint8_t* data) : SSLExtension(data) {}

	/**
	 * @return A vector of the supported groups (also known as "Elliptic Curves")
	 */
	std::vector<uint16_t> getSupportedGroups() const;
};


/**
 * @class TLSECPointFormatExtension
 * Represents TLS EC (Elliptic Curves) Point Format extension. Inherits from SSLExtension and adds parsing of the
 * EC point formats mentioned in the extension data
 */
class TLSECPointFormatExtension : public SSLExtension
{
	public:
	/**
	 * C'tor for this class
	 * @param[in] data The raw data for the extension
	 */
	TLSECPointFormatExtension(uint8_t* data) : SSLExtension(data) {}

	/**
	 * @return A vector of the elliptic curves point formats
	 */
	std::vector<uint8_t> getECPointFormatList() const;
};


/**
 * @class SSLx509Certificate
 * Represents a x509v3 certificate. the SSLCertificateMessage class returns an instance of this class as the certificate.
 * Currently this class doesn't do much as it doesn't parse the certificate. It only acts as container to the raw data
 * and returns general info as data as raw, length, etc. In the future I may add full parsing of the certificate
 */
class SSLx509Certificate
{
public:

	/**
	 * C'tor for this class
	 * @param[in] data The raw data of the certificate
	 * @param[in] dataLen The length in bytes of the raw data
	 * @param[in] allDataExists Certificate messages usually spread on more than 1 packet. So a certificate is likely
	 * to split between 2 packets or more. This field indicates whether the raw data contains all ceritificate data
	 * of just a part of it
	 */
	SSLx509Certificate(uint8_t* data, size_t dataLen, bool allDataExists)
		: m_Data(data), m_DataLen(dataLen), m_AllDataExists(allDataExists) {}

	/**
	 * @return A pointer to the raw data
	 */
	uint8_t* getData() const { return m_Data; }

	/**
	 * @return Raw data length
	 */
	size_t getDataLength() const { return m_DataLen; }

	/**
	 * Certificate messages usually spread on more than 1 packet. So a certificate is likely to split between 2 packets
	 * or more. This method provides an indication whether all certificate data exists or only part of it
	 * @return True if this data contains all certificate data, false otherwise
	 */
	bool allDataExists() const { return m_AllDataExists; }

private:
	uint8_t* m_Data;
	size_t m_DataLen;
	bool m_AllDataExists;
};


class SSLHandshakeLayer;


/**
 * @class SSLHandshakeMessage
 * A base class for SSL/TLS handshake messages. This is an abstract class and cannot be instantiated. SSL/TLS handshake
 * messages are contained in SSLHandshakeLayer, meaning a SSLHandshakeLayer instance can contain one or more SSLHandshakeMessage
 * instances. For example: one SSLHandshakeLayer may contain a server-hello, certificate,
 * server-key-exchange, and server-hello-done messages (although it's not such a common case, most handshake layers
 * contain 1 handshake message only)
 */
class SSLHandshakeMessage
{
public:

	virtual ~SSLHandshakeMessage() {}

	/**
	 * @deprecated Deprecated due to typo. Please use createHandshakeMessage()
	 */
	PCPP_DEPRECATED static SSLHandshakeMessage* createHandhakeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) { return createHandshakeMessage(data, dataLen, container);}

	/**
	 * A factory method for creating instances of handshake messages from raw data
	 * @param[in] data The raw data containing 1 handshake message
	 * @param[in] dataLen Raw data length in bytes
	 * @param[in] container A pointer to the SSLHandshakeLayer instance which will contain the created message.
	 * This parameter is required because the handshake message includes a pointer to its container
	 */
	static SSLHandshakeMessage* createHandshakeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

	/**
	 * @return The handshake message type
	 */
	virtual SSLHandshakeType getHandshakeType() const;

	/**
	 * @return The handshake message length in bytes. Notice that sometimes the handshake message is divided between
	 * several packets, in this case this method will return the length of part of the message in the current packet
	 */
	virtual size_t getMessageLength() const;

	/**
	 * @return True if current packet contains the entire message or false otherwise. This method is important
	 * because sometimes handshake messages are divided in consequent packets (happens a lot in certificate messages
	 * which usually contain several KB of data which is larger than standard packet size, so the message is divided between
	 * several packets)
	 */
	virtual bool isMessageComplete() const;

	/**
	 * @return A pointer to the SSLHandshakeLayer instance containing this message
	 */
	 SSLHandshakeLayer* getContainingLayer() const { return m_Container; }

	/**
	 * @return A string representation of the message type (e.g "Client Hello message")
	 */
	virtual std::string toString() const = 0;

protected:

	SSLHandshakeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

	uint8_t* m_Data;
	size_t m_DataLen;
	SSLHandshakeLayer* m_Container;

};


/**
 * @class SSLClientHelloMessage
 * Represents a client-hello message (type 1). Inherits from SSLHandshakeMessage and adds parsing of all fields
 * of this message including the message extensions, cipher-suite list, etc.
 */
class SSLClientHelloMessage : public SSLHandshakeMessage
{
public:

	/**
	 * @struct ClientHelloTLSFingerprint
	 * A struct that contains all the elements needed for creating a Client Hello TLS fingerprinting:
	 * TLS version, a list of Cipher Suite IDs, a list of Extensions IDs, a list of support groups and a list of
	 * EC point formats.
	 * You can read more about this in SSLClientHelloMessage#generateTLSFingerprint().
	 * This struct contains methods to extract the TLS fingerprint itself: toString() and toMD5()
	 */
	struct ClientHelloTLSFingerprint
	{
		/** TLS version */
		uint16_t tlsVersion;
		/** A list of Cipher Suite IDs */
		std::vector<uint16_t> cipherSuites;
		/** A list of extension IDs */
		std::vector<uint16_t> extensions;
		/** A list of Suppotred Groups taken from the "supported groups" TLS extension (if exist in the message) */
		std::vector<uint16_t> supportedGroups;
		/** A list of EC point formats taken from the "EC point formats" TLS extension (if exist in the message) */
		std::vector<uint8_t> ecPointFormats;

		/**
		 * @return A string representing the TLS fingerprint, for example:
		 * <b>771,4866-4867-4865-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2</b>
		 *
		 * This string has the following format: <b>TLSVersion,CipherSuiteIDs,ExtensionIDs,SupportedGroups,ECPointFormats</b>
		 *
		 * The extension IDs, supported groups and EC point formats are each separated by a "-".
		 * If the message doesn't include the "supported groups" or "EC point formats" extensions, they will be replaced
		 * by an empty string for example: <b>771,4866-4867-4865-255,0-11-10-35-22-23-13-43-45-51,,</b>
		 */
		std::string toString();

		/**
		 * @return An MD5 hash of the string generated by toString()
		 */
		std::string toMD5();

		/**
		 * @return A pair of the string and MD5 hash (string is first, MD5 is second).
		 * If you want both this method is more efficient than calling toString() and toMD5() separately
		 */
		std::pair<std::string, std::string> toStringAndMD5();
	};

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and shouldn't be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLClientHelloMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

	virtual ~SSLClientHelloMessage() {}

	/**
	 * @return A struct containing common fields for client-hello and server-hello messages. Notice this points directly
	 * to the data, so every change will change the actual packet data
	 */
	ssl_tls_client_server_hello* getClientHelloHeader() const { return (ssl_tls_client_server_hello*)m_Data; }

	/**
	 * @return Handshake SSL/TLS version (notice it may be different than SSLLayer#getRecordVersion(). Each client-hello
	 * or server-hello message has both record version and handshake version and they may differ from one another)
	 */
	SSLVersion getHandshakeVersion() const;

	/**
	 * @return Session ID length in bytes. If server-hello message doesn't include session ID 0 will be returned
	 */
	uint8_t getSessionIDLength() const;

	/**
	 * @return Session ID as byte array. If server-hello message doesn't include session ID NULL will be returned
	 */
	uint8_t* getSessionID() const;

	/**
	 * @return The number of cipher-suites included in this message
	 */
	int getCipherSuiteCount() const;

	/**
	 * Get a pointer to a cipher-suite by index. The cipher-suites are numbered according to their order of appearance
	 * in the message. If index is out of bounds (less than 0 or larger than total amount of cipher suites) NULL will be
	 * returned. NULL will also be returned if the cipher-suite ID is unknown. If you still want to get the cipher-suite
	 * ID you can use getCipherSuiteID()
	 * @param[in] index The index of the cipher-suite to return
	 * @return The pointer to the cipher-suite object or NULL if index is out of bounds
	 */
	SSLCipherSuite* getCipherSuite(int index) const;

	/**
	 * Get the cipher-suite ID by index. This method just parses the ID from the client-hello message and returns it.
	 * To get more information on the cipher-suite you can use the getCipherSuite() method
	 * @param[in] index The index of the cipher-suite to return
	 * @param[out] isValid Set to "true" if parsing succeeded and the return value is valid or "false" if:
	 * (1) the index is out-of-bounds (less than 0 or larger than total amount of cipher suites) or (2) the parsing failed.
	 * If the value is "false" the return value can be ignored
	 * @return The cipher-suite ID if "isValid" is set to "true". If "isValid" is set to "false" the return value can be ignored
	 */
	uint16_t getCipherSuiteID(int index, bool& isValid) const;

	/**
	 * @return The value of the compression method byte
	 */
	uint8_t getCompressionMethodsValue() const;

	/**
	 * @return The number of extensions in this message
	 */
	int getExtensionCount() const;

	/**
	 * @deprecated Deprecated due to typo. Please use getExtensionsLength()
	 */
	PCPP_DEPRECATED uint16_t getExtensionsLenth() const { return getExtensionsLength(); };

	/**
	 * @return The size (in bytes) of all extensions data in this message. Extracted from the "extensions length" field
	 */
	uint16_t getExtensionsLength() const;

	/**
	 * Get a pointer to an extension by index. The extensions are numbered according to their order of appearance
	 * in the message. If index is out of bounds (less than 0 or larger than total amount of extensions) NULL will be
	 * returned
	 * @param[in] index The index of the extension to return
	 * @return The pointer to the extension or NULL if index is out of bounds
	 */
	SSLExtension* getExtension(int index) const;

	/**
	 * Get a pointer to an extension by numeric type field. Every extension has a 2-byte numeric value representing
	 * its type (for example: renegotiation info extension type is 0x1ff). This method gets the type and returns a
	 * pointer to the extension object
	 * @param[in] type The 2-byte numeric type of the extension
	 * @return A pointer to the extension object of NULL if this type doesn't exist in this message
	 */
	SSLExtension* getExtensionOfType(uint16_t type) const;

	/**
	 * Get a pointer to an extension by its enum type
	 * @param[in] type The type of extension to return
	 * @return A pointer to the extension object or NULL if this type doesn't exist in this message
	 */
	SSLExtension* getExtensionOfType(SSLExtensionType type) const;

	/**
	 * Get a pointer to an extension by its class type. This is a templated method that is used with the type of the
	 * requested extension and returns the first extension instance of this type
	 * @return A pointer to the extension object or NULL if this extension type doesn't exist in this message
	 *
	 */
	template<class TExtension>
	TExtension* getExtensionOfType() const;

	/**
	 * TLS fingerprinting is a way to identify client applications using the details in the TLS Client Hello packet.
	 * It was initially introduced by Lee Brotherston in his 2015 research: <https://blog.squarelemon.com/tls-fingerprinting/>
	 * This implementation of TLS fingerprint is a C++ version of Salesforce's JA3 open source project (originally written in
	 * Python and Zeek):
	 * <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>
	 * @return A SSLClientHelloMessage#ClientHelloTLSFingerprint struct that contains all the elements needed for
	 * creating a TLS fingerprint out of this Client Hello message. This struct has also methods to extract the TLS fingerprint
	 * itself in a string or MD5 formats
	 */
	ClientHelloTLSFingerprint generateTLSFingerprint() const;

	// implement abstract methods

	std::string toString() const;

private:
	PointerVector<SSLExtension> m_ExtensionList;

};


/**
 * @class SSLServerHelloMessage
 * Represents SSL/TLS server-hello message (type 2). Inherits from SSLHandshakeMessage and adds parsing of all fields
 * of this message including the message extensions, cipher-suite, etc.
 */
class SSLServerHelloMessage : public SSLHandshakeMessage
{
public:

	/**
	 * @struct ServerHelloTLSFingerprint
	 * A struct that contains all the elements needed for creating a Server Hello TLS fingerprinting:
	 * TLS version, Cipher Suite ID, and a list of Extensions IDs.
	 * You can read more about this in SSLServerHelloMessage#generateTLSFingerprint().
	 * This struct contains methods to extract the TLS fingerprint itself: toString() and toMD5()
	 */
	struct ServerHelloTLSFingerprint
	{
		/** TLS version */
		uint16_t tlsVersion;
		/** Cipher Suite ID */
		uint16_t cipherSuite;
		/** A list of extension IDs */
		std::vector<uint16_t> extensions;

		/**
		 * @return A string representing the TLS fingerprint, for example: <b>771,49195,65281-16-11</b>
		 *
		 * This string has the following format: <b>TLSVersion,Cipher,Extensions</b>
		 *
		 * The extension ID are separated with a "-"
		 */
		std::string toString();

		/**
		 * @return An MD5 hash of the string generated by toString()
		 */
		std::string toMD5();

		/**
		 * @return A pair of the string and MD5 hash (string is first, MD5 is second).
		 * If you want both this method is more efficient than calling toString() and toMD5() separately
		 */
		std::pair<std::string, std::string> toStringAndMD5();
	};

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and shouldn't be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLServerHelloMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

	virtual ~SSLServerHelloMessage() {}

	/**
	 * @return A struct containing common fields for client-hello and server-hello messages. Notice this points directly
	 * to the data, so every change will change the actual packet data
	 */
	ssl_tls_client_server_hello* getServerHelloHeader() const { return (ssl_tls_client_server_hello*)m_Data; }

	/**
	 * @return Handshake SSL/TLS version (notice it may be different than SSLLayer#getRecordVersion(). Each client-hello
	 * or server-hello message has both record version and handshake version and they may differ from one another).
	 *
	 * <b>NOTE:</b> for TLS 1.3 the handshake version written in ssl_tls_client_server_hello::handshakeVersion is still TLS 1.2,
	 * so a special check is made here see if a SupportedVersions extension exists and if so extract the version from it.
	 * This is the most straight-forward way to detect TLS 1.3.
	 */
	SSLVersion getHandshakeVersion() const;

	/**
	 * @return Session ID length in bytes. If server-hello message doesn't include session ID 0 will be returned
	 */
	uint8_t getSessionIDLength() const;

	/**
	 * @return Session ID as byte array. If server-hello message doesn't include session ID NULL will be returned
	 */
	uint8_t* getSessionID() const;

	/**
	 * @return A pointer to the cipher suite encapsulated in this message (server-hello message contains one
	 * cipher-suite, the one that will be used to for encryption between client and server). May return NULL
	 * if the parsing of the message failed or the cipher-suite ID is unknown. If you still want to get the
	 * cipher-suite ID you can use the getCipherSuiteID() method
	 */
	SSLCipherSuite* getCipherSuite() const;

	/**
	 * Get the cipher-suite ID. This method just parses the ID from the server-hello message and returns it.
	 * To get more information on the cipher-suite you can use the getCipherSuite() method
	 * @param[out] isValid Set to "true" if parsing succeeded and the return value is valid or "false" otherwise.
	 * If the value is "false" the return value can be ignored
	 * @return The cipher-suite ID if "isValid" is set to "true". If "isValid" is set to "false" the return value can be ignored
	 */
	uint16_t getCipherSuiteID(bool& isValid) const;

	/**
	 * @return The value of the compression method byte
	 */
	uint8_t getCompressionMethodsValue() const;

	/**
	 * @return The number of extensions in this message
	 */
	int getExtensionCount() const;

	/**
	 * @deprecated Deprecated due to typo. Please use getExtensionLength()
	 */
	PCPP_DEPRECATED uint16_t getExtensionsLenth() const { return getExtensionsLength(); };

	/**
	 * @return The size (in bytes) of all extensions data in this message. Extracted from the "extensions length" field
	 */
	uint16_t getExtensionsLength() const;

	/**
	 * Get a pointer to an extension by index. The extensions are numbered according to their order of appearance
	 * in the message. If index is out of bounds (less than 0 or larger than total amount of extensions) NULL will be
	 * returned
	 * @param[in] index The index of the extension to return
	 * @return The pointer to the extension or NULL if index is out of bounds
	 */
	SSLExtension* getExtension(int index) const;

	/**
	 * Get a pointer to an extension by numeric type field. Every extension has a 2-byte numeric value representing
	 * its type (for example: renegotiation info extension type is 0x1ff). This method gets the type and returns a
	 * pointer to the extension object
	 * @param[in] type The 2-byte numeric type of the extension
	 * @return A pointer to the extension object of NULL if this type doesn't exist in this message
	 */
	SSLExtension* getExtensionOfType(uint16_t type) const;

	/**
	 * Get a pointer to an extension by its enum type
	 * @param[in] type The type of extension to return
	 * @return A pointer to the extension object or NULL if this type doesn't exist in this message
	 */
	SSLExtension* getExtensionOfType(SSLExtensionType type) const;

	/**
	 * Get a pointer to an extension by its class type. This is a templated method that is used with the type of the
	 * requested extension and returns the first extension instance of this type
	 * @return A pointer to the extension object or NULL if this extension type doesn't exist in this message
	 *
	 */
	template<class TExtension>
	TExtension* getExtensionOfType() const;

	/**
	 * ServerHello TLS fingerprinting is a way to fingerprint TLS Server Hello messages. In conjunction with
	 * ClientHello TLS fingerprinting it can assist in identifying specific client-server communication (for
	 * example: a malware connecting to its backend server).
	 * ServerHello TLS fingerprinting was introduced in Salesforce's JA3S open source project:
	 * <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>
	 * This implementation is a C++ version of Salesforce's JAS3 (originally written in Python and Zeek)
	 * @return A SSLServerHelloMessage#ServerHelloTLSFingerprint struct that contains all the elements needed for
	 * creating a TLS fingerprint out of this Server Hello message. This struct has also methods to extract the TLS fingerprint
	 * itself in a string or MD5 formats
	 */
	ServerHelloTLSFingerprint generateTLSFingerprint() const;

	// implement abstract methods

	std::string toString() const;

private:
	PointerVector<SSLExtension> m_ExtensionList;
};


/**
 * @class SSLCertificateMessage
 * Represents SSL/TLS certificate message (type 11). Inherits from SSLHandshakeMessage and adds parsing functionality
 * such as extracting the certificates data. Notice that in most cases this message is spread over more than 1 packet
 * as its size is too big for a single packet. So SSLCertificateMessage instance will be created just for the first
 * part of the message - the one encapsulated in the first packet. Other parts (encapsulated in the following packets)
 * won't be recognized as SSLCertificateMessage messages
 */
class SSLCertificateMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLCertificateMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

	virtual ~SSLCertificateMessage() {}

	/**
	 * @return The number of certificates encapsulated in this message (as written in the 'length' field of the
	 * message). Notice that because the message may spread over several packets, not all certificates will necessarily
	 * be in this packet. So, for example, there may be a case where this method return 3 (message contains 3
	 * certificates) but this message actually contains only 1 certificate as the other 2 are spread over the other
	 * packets
	 */
	int getNumOfCertificates() const;

	/**
	 * Get a certificate by index
	 * @param[in] index The index of the certificate to retrieve
	 * @return A pointer to the certificate object. Notice that if index < 0 or index > num of certificates encapsulated
	 * in current packet a NULL value will be returned
	 */
	SSLx509Certificate* getCertificate(int index) const;

	// implement abstract methods

	std::string toString() const;

private:
	PointerVector<SSLx509Certificate> m_CertificateList;
};


/**
 * @class SSLHelloRequestMessage
 * Represents SSL/TLS hello-request message (type 0). This message has no additional payload except for the common payload
 * described in SSLHandshakeMessage
 */
class SSLHelloRequestMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLHelloRequestMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	virtual ~SSLHelloRequestMessage() {}

	// implement abstract methods

	std::string toString() const;
};


/**
 * @class SSLServerKeyExchangeMessage
 * Represents SSL/TLS server-key-exchange message (type 12). Inherits from SSLHandshakeMessage and adds parsing
 * functionality such as getting the server key exchange params as raw data (parsing of this may be added in the
 * future)
 */
class SSLServerKeyExchangeMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLServerKeyExchangeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	~SSLServerKeyExchangeMessage() {}

	/**
	 * @return A pointer to the raw data of the server key exchange params. Currently this data can only returned as
	 * raw, parsing may be added in the future. Notice that if the message is spread over more than 1 packet in a way
	 * params doesn't exist in the first packet, NULL will be returned
	 */
	uint8_t* getServerKeyExchangeParams() const;

	/**
	 * @return The size of the params field. Notice that if the message is spread over more than 1 packet in a way the
	 * ssl_tls_handshake_layer cannot be parsed from the packet, 0 will be returned. Also, if only part of the params
	 * exist in current packet (and the rest are on consequent packets), the size that will be returned is the size
	 * of the part that exists in the current packet (and not total size of params)
	 */
	size_t getServerKeyExchangeParamsLength() const;

	// implement abstract methods

	std::string toString() const;
};


/**
 * @class SSLClientKeyExchangeMessage
 * Represents SSL/TLS client-key-exchange message (type 16). Inherits from SSLHandshakeMessage and adds parsing
 * functionality such as getting the server key exchange params as raw data (parsing of this may be added in the
 * future)
 */
class SSLClientKeyExchangeMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLClientKeyExchangeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	~SSLClientKeyExchangeMessage() {}

	/**
	 * @return A pointer to the raw data of the server key exchange params. Currently this data can only be returned
	 * as raw, parsing may be added in the future. Notice that if the message is spread over more than 1 packet in
	 * a way params doesn't exist in the first packet, NULL will be returned
	 */
	uint8_t* getClientKeyExchangeParams() const;

	/**
	 * @return The size of the params field. Notice that if the message is spread over more than 1 packet in a way the
	 * ssl_tls_handshake_layer cannot be parsed from the packet, 0 will be returned. Also, if only part of the params
	 * exist in current packet (and the rest are on consequent packets), the size that will be returned is the size
	 * of the part that exists in the current packet (and not the total size of params)
	 */
	size_t getClientKeyExchangeParamsLength() const;

	// implement abstract methods

	std::string toString() const;
};


/**
 * @class SSLCertificateRequestMessage
 * Represents SSL/TLS certificate-request message (type 13). Inherits from SSLHandshakeMessage and adds parsing
 * functionality such as retrieving client certificate types and authority data
 */
class SSLCertificateRequestMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLCertificateRequestMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

	~SSLCertificateRequestMessage() {}

	/**
	 * @return A reference to a vector containing all client certificate types exist in this message
	 */
	std::vector<SSLClientCertificateType>& getCertificateTypes();

	/**
	 * @return A pointer to the certificate authority data as raw data (byte array). Parsing of this data may be added
	 * in the future. Notice that if this message is spread over several packets in a way none of the certificate
	 * authority data exists in this packet, NULL will be returned
	 */
	uint8_t* getCertificateAuthorityData() const;

	/**
	 * @return The length of certificate authority data returned by getCertificateAuthorityData(). Notice that if
	 * this message is spread over several packets in a way none of certificate authority data exists in the current
	 * packet, 0 will be returned. Also, if some of the data exists in the consequent packets, the length that will be
	 * returned is the length of data exists in the current packet only (and not the total length)
	 */
	size_t getCertificateAuthorityLength() const;

	// implement abstract methods

	std::string toString() const;

private:
	std::vector<SSLClientCertificateType> m_ClientCertificateTypes;
};


/**
 * @class SSLServerHelloDoneMessage
 * Represents SSL/TLS server-hello-done message (type 14). This message has no additional payload except for the common
 * payload described in SSLHandshakeMessage
 */
class SSLServerHelloDoneMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLServerHelloDoneMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	virtual ~SSLServerHelloDoneMessage() {}

	// implement abstract methods

	std::string toString() const;
};


/**
 * @class SSLCertificateVerifyMessage
 * Represents SSL/TLS certificate-verify message (type 15). Inherits from SSLHandshakeMessage and adds parsing
 * functionality such as retrieving signed hash data as raw data (parsing may be added in the future)
 * @todo This message type wasn't tested in unit-tests
 */
class SSLCertificateVerifyMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLCertificateVerifyMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	virtual ~SSLCertificateVerifyMessage() {}

	/**
	 * @return A pointer to the signed hash data as raw data (byte array). Parsing of this data may be added
	 * in the future. Notice that if this message is spread over several packets in a way none of the signed hash data
	 * exists in this packet, NULL will be returned
	 */
	uint8_t* getSignedHash() const;

	/**
	 * @return The length of signed hash data returned by getSignedHash(). Notice that if this message is spread over
	 * several packets in a way none of this data exists in the current packet, 0 will be returned. Also, if some of
	 * the data exists in the consequent packets, the length that will be returned will be the length of data exists in
	 * the current packet only (and not the total length)
	 */
	size_t getSignedHashLength() const;

	// implement abstract methods

	std::string toString() const;
};


/**
 * @class SSLFinishedMessage
 * Represents SSL/TLS finished message (type 20). Inherits from SSLHandshakeMessage and adds parsing
 * functionality such as retrieving signed hash data as raw data (parsing may be added in the future)
 * @todo This message type wasn't tested in unit-tests
 */
class SSLFinishedMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLFinishedMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	virtual ~SSLFinishedMessage() {}

	/**
	 * @return A pointer to the signed hash data as raw data (byte array). Parsing of this data may be added
	 * in the future. Notice that if this message is spread over several packets in a way none of the signed hash data
	 * exists in this packet, NULL will be returned
	 */
	uint8_t* getSignedHash() const;

	/**
	 * @return The length of signed hash data returned by getSignedHash(). Notice that if the message is spread over
	 * several packets in a way none of this data exists in the current packet, 0 will be returned. Also, if some of
	 * the data exists in the consequent packets, the length that will be returned will be the length of data exists
	 * in the current packet only (and not the total length)
	 */
	size_t getSignedHashLength() const;

	// implement abstract methods

	std::string toString() const;
};


/**
 * @class SSLNewSessionTicketMessage
 * Represents SSL/TLS new-session-ticket message (type 4). Inherits from SSLHandshakeMessage and adds parsing
 * functionality such as retrieving session ticket data as raw data (parsing may be added in the future)
 */
class SSLNewSessionTicketMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLNewSessionTicketMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	virtual ~SSLNewSessionTicketMessage() {}

	/**
	 * @return A pointer to the session ticket data as raw data (byte array). Parsing of this data may be added
	 * in the future. Notice that if this message is spread over several packets in a way none of the signed hash data
	 * exists in current packet, NULL will be returned
	 */
	uint8_t* getSessionTicketData() const;

	/**
	 * @return The length of session ticket data returned by getSessionTicketData(). Notice that if this message is
	 * spread over several packets in a way none of this data exists in the current packet, 0 will be returned. Also,
	 * if some of the data exist in the consequent packets, the length that will be returned will be the length of the
	 * data existing in the current packet only (and not the total length)
	 */
	size_t getSessionTicketDataLength() const;

	// implement abstract methods

	std::string toString() const;
};


/**
 * @class SSLUnknownMessage
 * Represents an unknown type of message or an encrypted message that PcapPlusPlus can't determine its type. In these
 * cases length can't always be determined from the message itself (especially if the message is encrypted), so
 * the length of this message will always be the size counted from message start until the end of the layer
 */
class SSLUnknownMessage : public SSLHandshakeMessage
{
public:

	/**
	 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be used
	 * by a user
	 * @param[in] data The message as raw data
	 * @param[in] dataLen Message raw data length in bytes
	 * @param[in] container The SSL handshake layer which shall contain this message
	 */
	SSLUnknownMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container) : SSLHandshakeMessage(data, dataLen, container) {}

	virtual ~SSLUnknownMessage() {}

	// implement virtual and abstract methods

	/**
	 * @return Always ::SSL_HANDSHAKE_UNKNOWN (overridden from SSLHandshakeMessage)
	 */
	SSLHandshakeType getHandshakeType() const;

	/**
	 * @return The length of the data from message start until the end of the layer. Since it's an unknown type
	 * or an encrypted message the length parsed from the message can't be guaranteed to be the correct length. That's
	 * why the length returned is the size until the end of the layer
	 */
	size_t getMessageLength() const;

	std::string toString() const;
};

template<class TExtension>
TExtension* SSLClientHelloMessage::getExtensionOfType() const
{
	size_t vecSize = m_ExtensionList.size();
	for (size_t i = 0; i < vecSize; i++)
	{
		SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
		 if (dynamic_cast<TExtension*>(curElem) != NULL)
			 return (TExtension*)curElem;
	}

	return NULL;
}

template<class TExtension>
TExtension* SSLServerHelloMessage::getExtensionOfType() const
{
	size_t vecSize = m_ExtensionList.size();
	for (size_t i = 0; i < vecSize; i++)
	{
		SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
		 if (dynamic_cast<TExtension*>(curElem) != NULL)
			 return (TExtension*)curElem;
	}

	return NULL;
}

} // namespace pcpp

#endif /* PACKETPP_SSL_HANDSHAKE_MESSAGE */
