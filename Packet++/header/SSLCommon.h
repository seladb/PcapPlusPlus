#ifndef PACKETPP_SSL_LAYER_COMMON
#define PACKETPP_SSL_LAYER_COMMON


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
	 * @struct ssl_tls_record_layer
	 * The common part of all SSL/TLS messages
	 */
#pragma pack(push, 1)
	struct ssl_tls_record_layer
	{
		/** Message (record) type (one of ::SSLRecordType) */
		uint8_t recordType;
		/** Message (record) version (one of ::SSLVersion) */
		uint16_t recordVersion;
		/** Message (record) length in bytes */
		uint16_t length;
	};
#pragma pack(pop)


	/**
	 * @struct ssl_tls_handshake_layer
	 * The common part of all SSL/TLS handshake message types
	 */
#pragma pack(push, 1)
	struct ssl_tls_handshake_layer
	{
		/** Type of the handshake message (one of ::SSLHandshakeType) */
		uint8_t handshakeType;
		/** Length of the message. Length is 3-Byte long, This is the MSB byte */
		uint8_t length1;
		/** Length of the message. Length is 3-Byte long, This is the 2 LSB bytes */
		uint16_t length2;
	};
#pragma pack(pop)


	/**
	 * @struct ssl_tls_client_server_hello
	 * The common header part of client-hello and server-hello handshake messages
	 */
#pragma pack(push, 1)
	struct ssl_tls_client_server_hello : ssl_tls_handshake_layer
	{
		/** SSL/TLS handshake version (one of ::SSLVersion) */
		uint16_t handshakeVersion;
		/** 32-bytes random number */
		uint8_t random[32];
	};
#pragma pack(pop)


	/**
	 * @struct ssl_tls_change_cipher_spec
	 * SSL/TLS change-cipher-spec message structure
	 */
#pragma pack(push, 1)
	struct ssl_tls_change_cipher_spec
	{
		/** Unused byte */
		uint8_t changeCipherSpec;
	};
#pragma pack(pop)


	/**
	 * @struct ssl_tls_alert
	 * SSL/TLS alert message structure
	 */
#pragma pack(push, 1)
	struct ssl_tls_alert
	{
		/** Alert level (one of ::SSLAlertLevel) */
		uint8_t alertLevel;
		/** Alert description (one of ::SSLAlertDescription) */
		uint8_t alertDescription;
	};
#pragma pack(pop)


	/**
	 * SSL/TLS message types
	 */
	enum SSLRecordType
	{
		/** Change-cipher-spec message */
		SSL_CHANGE_CIPHER_SPEC = 20,
		/** SSL alert message */
		SSL_ALERT              = 21,
		/** SSL handshake message */
		SSL_HANDSHAKE          = 22,
		/** SSL data message */
		SSL_APPLICATION_DATA   = 23
	};

	/**
	 * SSL/TLS versions. Only SSL3.0 and above are supported
	 */
	enum SSLVersion
	{
		/** SSLv2.0 */
		SSL2   = 0x0200,
		/** SSLv3.0 */
		SSL3   = 0x0300,
		/** TLSv1.0 */
		TLS1_0 = 0x0301,
		/** TLSv1.1 */
		TLS1_1 = 0x0302,
		/** TLSv1.2 */
		TLS1_2 = 0x0303
	};

	/**
	 * SSL/TLS handshake message types
	 */
	enum SSLHandshakeType
	{
		/** Hello-request message type */
		SSL_HELLO_REQUEST       = 0,
		/** Client-hello message type */
		SSL_CLIENT_HELLO        = 1,
		/** Server-hello message type */
		SSL_SERVER_HELLO        = 2,
		/** New-session-ticket message type */
		SSL_NEW_SESSION_TICKET	= 4,
		/** Certificate message type */
		SSL_CERTIFICATE         = 11,
		/** Server-key-exchange message type */
		SSL_SERVER_KEY_EXCHANGE = 12,
		/** Certificate-request message type */
		SSL_CERTIFICATE_REQUEST = 13,
		/** Server-hello-done message type */
		SSL_SERVER_DONE         = 14,
		/** Certificate-verify message type */
		SSL_CERTIFICATE_VERIFY  = 15,
		/** Client-key-exchange message type */
		SSL_CLIENT_KEY_EXCHANGE = 16,
		/** Finish message type */
		SSL_FINISHED            = 20,
		/** Unknown SSL handshake message */
		SSL_HANDSHAKE_UNKNOWN   = 255
	};

	/**
	 * SSL/TLS alert levels
	 */
	enum SSLAlertLevel
	{
		/** Warning level alert */
		SSL_ALERT_LEVEL_WARNING       = 1,
		/** Fatal level alert */
		SSL_ALERT_LEVEL_FATAL         = 2,
		/** For encrypted alerts the level is unknown so this type will be returned */
		SSL_ALERT_LEVEL_ENCRYPTED     = 255
	};

	/**
	 * SSL/TLS alert description types
	 */
	enum SSLAlertDescription
	{
		/** Close notify alert */
		SSL_ALERT_CLOSE_NOTIFY            =  0,
		/** Unexpected message alert */
		SSL_ALERT_UNEXPECTED_MESSAGE      = 10,
		/** Bad record MAC alert */
		SSL_ALERT_BAD_RECORD_MAC          = 20,
		/** Decryption failed alert */
		SSL_ALERT_DECRYPTION_FAILED       = 21,
		/**  */
		SSL_ALERT_RECORD_OVERFLOW         = 22,
		/** Decompression failure alert */
		SSL_ALERT_DECOMPRESSION_FAILURE   = 30,
		/** Handshake failure alert */
		SSL_ALERT_HANDSHAKE_FAILURE       = 40,
		/** No certificate alert */
		SSL_ALERT_NO_CERTIFICATE          = 41,
		/** Bad certificate alert */
		SSL_ALERT_BAD_CERTIFICATE         = 42,
		/** Unsupported certificate */
		SSL_ALERT_UNSUPPORTED_CERTIFICATE = 43,
		/** Certificate revoked alert */
		SSL_ALERT_CERTIFICATE_REVOKED     = 44,
		/** Certificate expired alert */
		SSL_ALERT_CERTIFICATE_EXPIRED     = 45,
		/** Certificate unknown alert */
		SSL_ALERT_CERTIFICATE_UNKNOWN     = 46,
		/** Illegal parameter alert */
		SSL_ALERT_ILLEGAL_PARAMETER       = 47,
		/** Unknown CA alert */
		SSL_ALERT_UNKNOWN_CA              = 48,
		/** Access denied alert */
		SSL_ALERT_ACCESS_DENIED           = 49,
		/** Decode error alert */
		SSL_ALERT_DECODE_ERROR            = 50,
		/** Decrypt error alert */
		SSL_ALERT_DECRYPT_ERROR           = 51,
		/** Export restriction alert */
		SSL_ALERT_EXPORT_RESTRICTION      = 60,
		/** Protocol version alert */
		SSL_ALERT_PROTOCOL_VERSION        = 70,
		/** Insufficient security alert */
		SSL_ALERT_INSUFFICIENT_SECURITY   = 71,
		/** Internal error alert */
		SSL_ALERT_INTERNAL_ERROR          = 80,
		/** User cancelled alert */
		SSL_ALERT_USER_CANCELLED          = 90,
		/** No negotiation alert */
		SSL_ALERT_NO_RENEGOTIATION        = 100,
		/** Unsupported extension alert */
		SSL_ALERT_UNSUPPORTED_EXTENSION   = 110,
		/** Encrtpyed alert (cannot determine its type) */
		SSL_ALERT_ENCRYPRED				= 255
	};

	/**
	 * SSL/TLS key exchange algorithms
	 */
	enum SSLKeyExchangeAlgorithm
	{
		/** NULL value */
		SSL_KEYX_NULL,
		/** RSA (Rivest-Shamir-Adleman) */
		SSL_KEYX_RSA,
		/** Diffie-Hellman */
		SSL_KEYX_DH,
		/** Diffie-Hellman ephemeral */
		SSL_KEYX_DHE,
		/** Elliptic curve Diffie–Hellman */
		SSL_KEYX_ECDH,
		/** Elliptic curve Diffie–Hellman ephemeral */
		SSL_KEYX_ECDHE,
		/** Fortezza Crypto Card */
		SSL_KEYX_FORTEZZA,
		/** Kerberos 5 */
		SSL_KEYX_KRB5,
		/**  Pre-Shared Key */
		SSL_KEYX_PSK,
		/** GOST */
		SSL_KEYX_GOST,
		/** Secure Remote Password */
		SSL_KEYX_SRP,
		/** PCT */
		SSL_KEYX_PCT,
		/** Unknown algorithm */
		SSL_KEYX_Unknown
	};

	/**
	 * SSL/TLS authentication algorithms
	 */
	enum SSLAuthenticationAlgorithm
	{
		/** NULL value */
		SSL_AUTH_NULL,
		/** RSA (Rivest-Shamir-Adleman) */
		SSL_AUTH_RSA,
		/** Digital Signature Standard */
		SSL_AUTH_DSS,
		/** Anonymous */
		SSL_AUTH_anon,
		/** Diffie-Hellman based key-exchange protocol */
		SSL_AUTH_KEA,
		/** Kerberos 5 */
		SSL_AUTH_KRB5,
		/** Pre-Shared Key */
		SSL_AUTH_PSK,
		/** Elliptic Curve Digital Signature Algorithm */
		SSL_AUTH_ECDSA,
		/** GOST */
		SSL_AUTH_GOST,
		/** SHA-1 (Secure Hash Algorithm) */
		SSL_AUTH_SHA,
		/** PCT */
		SSL_AUTH_PCT,
		/** Diffie-Hellman ephemeral */
		SSL_AUTH_DHE,
		/** Unknown algorithm */
		SSL_AUTH_Unknown
	};

	/**
	 * SSL/TLS symmetric encryption algorithms
	 */
	enum SSLSymetricEncryptionAlgorithm
	{
		/** NULL value */
		SSL_SYM_NULL,
		/** RC4_40 */
		SSL_SYM_RC4_40,
		/** RC4_128 */
		SSL_SYM_RC4_128,
		/** RC2_CBC_40 */
		SSL_SYM_RC2_CBC_40,
		/** IDEA_CBC */
		SSL_SYM_IDEA_CBC,
		/** DES40_CBC */
		SSL_SYM_DES40_CBC,
		/** DES_CBC */
		SSL_SYM_DES_CBC,
		/** 3DES_EDE_CBC */
		SSL_SYM_3DES_EDE_CBC,
		/** FORTEZZA_CBC */
		SSL_SYM_FORTEZZA_CBC,
		/** DES_CBC_40 */
		SSL_SYM_DES_CBC_40,
		/** AES_128_CBC */
		SSL_SYM_AES_128_CBC,
		/** AES_256_CBC */
		SSL_SYM_AES_256_CBC,
		/** CAMELLIA_128_CBC */
		SSL_SYM_CAMELLIA_128_CBC,
		/** CAMELLIA_128_GCM */
		SSL_SYM_CAMELLIA_128_GCM,
		/** CAMELLIA_256_GCM */
		SSL_SYM_CAMELLIA_256_GCM,
		/** RC4_56 */
		SSL_SYM_RC4_56,
		/** RC2_CBC_56 */
		SSL_SYM_RC2_CBC_56,
		/** GOST28147 */
		SSL_SYM_GOST28147,
		/** CAMELLIA_256_CBC */
		SSL_SYM_CAMELLIA_256_CBC,
		/** SEED_CBC */
		SSL_SYM_SEED_CBC,
		/** AES_128 */
		SSL_SYM_AES_128,
		/** AES_256 */
		SSL_SYM_AES_256,
		/** SSL_SYM_AES_128_GCM */
		SSL_SYM_AES_128_GCM,
		/** AES_256_GCM */
		SSL_SYM_AES_256_GCM,
		/** RC4_128_EXPORT40 */
		SSL_SYM_RC4_128_EXPORT40,
		/** RC2_CBC_128_CBC */
		SSL_SYM_RC2_CBC_128_CBC,
		/** IDEA_128_CBC */
		SSL_SYM_IDEA_128_CBC,
		/** DES_64_CBC */
		SSL_SYM_DES_64_CBC,
		/** DES_192_EDE3_CBC */
		SSL_SYM_DES_192_EDE3_CBC,
		/** RC4_64 */
		SSL_SYM_RC4_64,
		/** ARIA_128_CBC*/
		SSL_SYM_ARIA_128_CBC,
		/** ARIA_256_CBC */
		SSL_SYM_ARIA_256_CBC,
		/** ARIA_128_GCM */
		SSL_SYM_ARIA_128_GCM,
		/** ARIA_256_GCM */
		SSL_SYM_ARIA_256_GCM,
		/** CHACHA20_POLY1305 */
		SSL_SYM_CHACHA20_POLY1305,
		/** Unknown algorithm */
		SSL_SYM_Unknown
	};

	/**
	 * SSL/TLS hashing algortihms
	 */
	enum SSLHashingAlgorithm
	{
		/** NULL value */
		SSL_HASH_NULL,
		/** Message-Digest Algorithm */
		SSL_HASH_MD5,
		/** SHA-1 (Secure Hash Algorithm) */
		SSL_HASH_SHA,
		/** SHA-256 (Secure Hash Algorithm) */
		SSL_HASH_SHA256,
		/** GOST 28147 */
		SSL_HASH_GOST28147,
		/**  GOST R 34.11 */
		SSL_HASH_GOSTR3411,
		/** SHA-384 (Secure Hash Algorithm) */
		SSL_HASH_SHA384,
		/** CCM mode (Counter with CBC-MAC) */
		SSL_HASH_CCM,
		/** CCM mode (Counter with CBC-MAC) */
		SSL_HASH_CCM_8,
		/** Unknown algorithm */
		SSL_HASH_Unknown
	};

	/**
	 * SSL/TLS extension types
	 */
	enum SSLExtensionType
	{
		/** Server Name Indication extension */
		SSL_EXT_SERVER_NAME = 0,
		/** Maximum Fragment Length Negotiation extension */
		SSL_EXT_MAX_FRAGMENT_LENGTH = 1,
		/** Client Certificate URLs extension */
		SSL_EXT_CLIENT_CERTIFICATE_URL = 2,
		/** Trusted CA Indication extension */
		SSL_EXT_TRUSTED_CA_KEYS = 3,
		/** Truncated HMAC extension */
		SSL_EXT_TRUNCATED_HMAC = 4,
		/** Certificate Status Request extension */
		SSL_EXT_STATUS_REQUEST = 5,
		/** TLS User Mapping extension */
		SSL_EXT_USER_MAPPING = 6,
		/** Client Authorization  extension */
		SSL_EXT_CLIENT_AUTHZ = 7,
		/** Server Authorization extension */
		SSL_EXT_SERVER_AUTHZ = 8,
		/** Certificate Type extension */
		SSL_EXT_CERT_TYPE = 9,
		/** Supported Elliptic Curves extension */
		SSL_EXT_ELLIPTIC_CURVES = 10,
		/** Elliptic Curves Point Format extension */
		SSL_EXT_EC_POINT_FORMATS = 11,
		/** Secure Remote Password extension */
		SSL_EXT_SRP = 12,
		/** Signature Algorithms extension */
		SSL_EXT_SIGNATURE_ALGORITHMS = 13,
		/** Use Secure Real-time Transport Protocol extension */
		SSL_EXT_USE_SRTP = 14,
		/** TLS Heartbit extension */
		SSL_EXT_HEARTBEAT = 15,
		/** Application Layer Protocol Negotiation (ALPN) extension */
		SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
		/** Status Request extension */
		SSL_EXT_STATUS_REQUEST_V2 = 17,
		/** Signed Certificate Timestamp extension */
		SSL_EXT_SIGNED_CERTIFICATE_TIMESTAMP = 18,
		/** Client Certificate Type extension */
		SSL_EXT_CLIENT_CERTIFICATE_TYPE = 19,
		/** Server Certificate Type extension */
		SSL_EXT_SERVER_CERTIFICATE_TYPE = 20,
		/** ClientHello Padding extension */
		SSL_EXT_PADDING = 21,
		/** Encrypt-then-MAC extension */
		SSL_EXT_ENCRYPT_THEN_MAC = 22,
		/** Extended Master Secret extension */
		SSL_EXT_EXTENDED_MASTER_SECRET = 23,
		/** Token Binding extension */
		SSL_EXT_TOKEN_BINDING = 24,
		/** SessionTicket TLS extension */
		SSL_EXT_SESSIONTICKET_TLS = 35,
		/** Renegotiation Indication extension */
		SSL_EXT_RENEGOTIATION_INFO = 65281,
		/** Unknown extension */
		SSL_EXT_Unknown
	};

	/**
	 * SSL/TLS client certificate types
	 */
	enum SSLClientCertificateType
	{
		/** RSA_SIGN */
		SSL_CCT_RSA_SIGN = 1,
		/** DSS_SIGN */
		SSL_CCT_DSS_SIGN = 2,
		/** RSA_FIXED_DH */
		SSL_CCT_RSA_FIXED_DH = 3,
		/** DSS_FIXED_DH */
		SSL_CCT_DSS_FIXED_DH = 4,
		/** RSA_EPHEMERAL_DH_RESERVED */
		SSL_CCT_RSA_EPHEMERAL_DH_RESERVED = 5,
		/** DSS_EPHEMERAL_DH_RESERVED */
		SSL_CCT_DSS_EPHEMERAL_DH_RESERVED = 6,
		/** FORTEZZA_DMS_RESERVED */
		SSL_CCT_FORTEZZA_DMS_RESERVED = 20,
		/** ECDSA_SIGN */
		SSL_CCT_ECDSA_SIGN = 64,
		/** FIXED_ECDH */
		SSL_CCT_RSA_FIXED_ECDH = 65,
		/** ECDSA_FIXED_ECDH */
		SSL_CCT_ECDSA_FIXED_ECDH = 66,
		/** Unknown client certificate type */
		SSL_CCT_UNKNOWN
	};

} //namespace pcpp

#endif // PACKETPP_SSL_LAYER_COMMON
