#pragma once
#include <chrono>
#include "Asn1Codec.h"
#include "CryptoDataReader.h"
#include "X509ExtensionDataDecoder.h"

/// @namespace pcpp
/// The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @enum X509Version
	/// Represents the version of an X.509 certificate
	enum class X509Version : uint8_t
	{
		/// X.509 Version 1
		V1 = 0,
		/// X.509 Version 2
		V2 = 1,
		/// X.509 Version 3
		V3 = 2,
	};

	/// @class X509Algorithm
	/// Represents cryptographic algorithms used in X.509 certificates
	/// This class encapsulates various hashing and signature algorithms that can be used
	/// in X.509 certificates for signing and key exchange.
	class X509Algorithm
	{
	public:
		/// Define enum types and the corresponding int values
		enum Value : uint8_t
		{
			/// SHA-1 hashing algorithm
			SHA1,
			/// SHA-256 hashing algorithm
			SHA256,
			/// SHA-384 hashing algorithm
			SHA384,
			/// SHA-512 hashing algorithm
			SHA512,
			/// MD5 hashing algorithm (considered cryptographically broken)
			MD5,

			/// RSA encryption/signature algorithm
			RSA,
			/// RSA with SHA-1 signature algorithm
			RSAWithSHA1,
			/// RSA with SHA-256 signature algorithm
			RSAWithSHA256,
			/// RSA with SHA-384 signature algorithm
			RSAWithSHA384,
			/// RSA with SHA-512 signature algorithm
			RSAWithSHA512,
			/// RSA Probabilistic Signature Scheme (PSS)
			RSAPSS,

			/// Elliptic Curve Digital Signature Algorithm
			ECDSA,
			/// ECDSA with SHA-1 signature algorithm
			ECDSAWithSHA1,
			/// ECDSA with SHA-256 signature algorithm
			ECDSAWithSHA256,
			/// ECDSA with SHA-384 signature algorithm
			ECDSAWithSHA384,
			/// ECDSA with SHA-512 signature algorithm
			ECDSAWithSHA512,

			/// Digital Signature Algorithm
			DSA,
			/// DSA with SHA-1 signature algorithm
			DSAWithSHA1,
			/// DSA with SHA-256 signature algorithm
			DSAWithSHA256,

			/// EdDSA using Curve25519 (Ed25519)
			ED25519,
			/// EdDSA using Curve448 (Ed448)
			ED448,
			/// Diffie-Hellman key exchange algorithm
			DiffieHellman,

			/// Unknown or unsupported algorithm
			Unknown,
		};

		X509Algorithm() = default;

		// cppcheck-suppress noExplicitConstructor
		/// Construct LdapOperationType from Value enum
		/// @param[in] value the operation type enum value
		constexpr X509Algorithm(Value value) : m_Value(value)
		{}

		/// @return A string representation of the operation type
		std::string toString() const;

		/// @return The OID value of the operation type
		std::string getOidValue() const;

		/// A static method that creates LdapOperationType from an integer value
		/// @param[in] value The operation type integer value
		/// @return The operation type that corresponds to the integer value. If the integer value
		/// doesn't correspond to any operation type, LdapOperationType::Unknown is returned
		static X509Algorithm fromOidValue(const Asn1ObjectIdentifier& value);

		// Allow switch and comparisons.
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(LdapOperationType)
		explicit operator bool() const = delete;

	private:
		Value m_Value = Unknown;
	};

	/// @class X520DistinguishedName
	/// Represents a distinguished name in an X.509 certificate
	class X520DistinguishedName
	{
	public:
		/// Define enum types and the corresponding int values
		enum Value : uint8_t
		{
			/// Common Name (CN) - Typically the fully qualified domain name (FQDN)
			CommonName,
			/// Surname (SN) - Family name of a person
			Surname,
			/// Serial Number - Serial number of the certificate
			SerialNumber,
			/// Country Name (C) - Two-letter ISO 3166-1 alpha-2 country code
			Country,
			/// Locality (L) - City or locality name
			Locality,
			/// State or Province Name (ST) - State or province name
			StateOrProvince,
			/// Organization Name (O) - Name of the organization
			Organization,
			/// Organizational Unit (OU) - Department or division within an organization
			OrganizationalUnit,
			/// Title - Job title or position
			Title,
			/// Given Name (GN) - First name of a person
			GivenName,
			/// Initials - Initials of a person's name
			Initials,
			/// Pseudonym - A person's nickname or alias
			Pseudonym,
			/// Generation Qualifier - A qualifier indicating a person's generation (e.g., Jr., Sr., III)
			GenerationQualifier,
			/// Distinguished Name Qualifier - Disambiguates similar distinguished names
			DnQualifier,
			/// Domain Component (DC) - Domain component in domain names (e.g., "example" in "example.com")
			DomainComponent,
			/// Email Address - Email address in the format user\@domain
			EmailAddress,
			/// Postal Code - Postal or ZIP code
			PostalCode,
			/// Street Address - Physical street address
			StreetAddress,
			/// Business Category - Type of business or organization
			BusinessCategory,
			/// Unknown or unsupported distinguished name type
			Unknown
		};

		X520DistinguishedName() = default;

		constexpr X520DistinguishedName(Value value) : m_Value(value)
		{}

		/// @return A string representation of the distinguished name
		std::string toString() const;

		/// Gets the short name (abbreviation) of the distinguished name
		/// @return The short name (e.g., "CN" for CommonName)
		std::string getShortName() const;

		/// @return The OID value of the distinguished name
		std::string getOidValue() const;

		/// Creates an X520DistinguishedName from an OID value
		/// @param[in] value The ASN.1 object identifier
		/// @return The corresponding X520DistinguishedName value, or Unknown if no match is found
		static X520DistinguishedName fromOidValue(const Asn1ObjectIdentifier& value);

		// Allow switch and comparisons.
		constexpr operator Value() const
		{
			return m_Value;
		}
		explicit operator bool() const = delete;

	private:
		Value m_Value = Unknown;
	};

	/// @class X509ExtensionType
	/// Represents an X.509 extension type
	class X509ExtensionType
	{
	public:
		/// @enum Value
		/// Enumeration of supported X.509 extension types
		enum Value : uint8_t
		{
			/// Basic Constraints - Indicates if the subject is a CA and the maximum path length
			BasicConstraints,
			/// Key Usage - Defines the purpose of the key contained in the certificate
			KeyUsage,
			/// Extended Key Usage - Indicates one or more purposes for which the certified public key may be used
			ExtendedKeyUsage,
			/// Subject Key Identifier - Provides a means of identifying certificates that contain a particular public
			/// key
			SubjectKeyIdentifier,
			/// Authority Key Identifier - Identifies the public key used to verify the signature on this certificate
			AuthorityKeyIdentifier,
			/// Subject Alternative Name - Allows identities to be bound to the subject of the certificate
			SubjectAltName,
			/// Issuer Alternative Name - Allows additional identities to be associated with the issuer
			IssuerAltName,
			/// CRL Distribution Points - Identifies how CRL information is obtained
			CrlDistributionPoints,
			/// Authority Information Access - Describes how to access CA information and services
			AuthorityInfoAccess,
			/// Certificate Policies - Contains a sequence of one or more policy terms
			CertificatePolicies,
			/// Policy Mappings - Used in CA certificates to indicate that one or more policies can be considered
			/// equivalent
			PolicyMappings,
			/// Policy Constraints - Specifies constraints on path validation
			PolicyConstraints,
			/// Name Constraints - Indicates a name space within which all subject names in subsequent certificates must
			/// be located
			NameConstraints,
			/// Inhibit Any Policy - Indicates that the special anyPolicy OID is not considered an explicit match for
			/// other certificate policies
			InhibitAnyPolicy,
			/// Signed Certificate Timestamp - Contains a list of SCTs from Certificate Transparency logs
			CTPrecertificateSCTs,
			/// Subject Information Access - Describes how to access additional information about the subject
			SubjectInfoAccess,
			/// Freshest CRL - Identifies how delta CRL information is obtained
			FreshestCRL,
			/// TLS Feature - Indicates which TLS features are required for the certificate to be used
			TLSFeature,
			/// OCSP No Check - Indicates that an OCSP client should trust the certificate for OCSP signing
			OcspNoCheck,
			/// Subject Directory Attributes - Conveys identification attributes of the subject
			SubjectDirectoryAttributes,
			/// Unknown or unsupported extension type
			Unknown
		};

		X509ExtensionType() = default;

		// cppcheck-suppress noExplicitConstructor
		/// Construct X509ExtensionType from Value enum
		/// @param[in] value the extension type enum value
		constexpr X509ExtensionType(Value value) : m_Value(value)
		{}

		/// @return A string representation of the extension type
		std::string toString() const;

		/// @return The OID value of the extension
		std::string getOidValue() const;

		/// Creates an X509ExtensionType from an OID value
		/// @param[in] value The ASN.1 object identifier
		/// @return The corresponding X509ExtensionType value, or Unknown if no match is found
		static X509ExtensionType fromOidValue(const Asn1ObjectIdentifier& value);

		// Allow switch and comparisons.
		constexpr operator Value() const
		{
			return m_Value;
		}
		explicit operator bool() const = delete;

	private:
		Value m_Value = Unknown;
	};

	/// @class X509SerialNumber
	/// Represents the serial number of an X.509 certificate
	class X509SerialNumber
	{
	public:
		/// Constructs an X509SerialNumber from a serial number hex string
		/// @param[in] serialNumber The serial number as a hex string
		explicit X509SerialNumber(const std::string& serialNumber) : m_SerialNumber(serialNumber)
		{}

		/// Converts the serial number to a formatted string
		/// @param[in] delimiter The delimiter to use between the bytes (default: ":")
		/// @return A formatted string representation of the serial number
		std::string toString(const std::string& delimiter = ":") const;

	private:
		std::string m_SerialNumber;
	};

	/// @class X509Timestamp
	/// Represents a timestamp in an X.509 certificate
	class X509Timestamp
	{
	public:
		/// Constructs an X509Timestamp from an ASN.1 time record
		/// @param[in] timeRecord Pointer to the ASN.1 time record. Note: this class doesn't assume
		/// ownership over the record
		explicit X509Timestamp(Asn1TimeRecord* timeRecord) : m_Record(timeRecord)
		{}

		/// Converts the timestamp to a formatted string
		/// @param[in] format The format string (strftime format, default: "%Y-%m-%d %H:%M:%S")
		/// @param[in] timezone The timezone to use in the format of "Z" for UTC or +=HHMM for other timezones
		/// (default: "Z" for UTC)
		/// @param[in] includeMilliseconds Whether to include milliseconds in the output
		/// @return A formatted string representation of the timestamp
		std::string toString(const std::string& format = "%Y-%m-%d %H:%M:%S", const std::string& timezone = "Z",
		                     bool includeMilliseconds = false) const;

		/// Gets the timestamp as a system_clock::time_point
		/// @param[in] timezone The timezone to use in the format of "Z" for UTC or +=HHMM for other timezones
		/// (default: "Z" for UTC)
		/// @return A time_point representing the timestamp
		std::chrono::system_clock::time_point getTimestamp(const std::string& timezone = "Z") const;

	private:
		Asn1TimeRecord* m_Record;
	};

	/// @class X509Key
	/// Represents a key in an X.509 certificate
	class X509Key
	{
	public:
		/// Constructs an X509Key from a byte vector
		/// @param[in] key The key data as a vector of bytes
		explicit X509Key(const std::vector<uint8_t>& key) : m_Key(key)
		{}

		/// Converts the key to a formatted string
		/// @param[in] delimiter The delimiter to use between the bytes (default: ":")
		/// @return A formatted string representation of the key
		std::string toString(const std::string& delimiter = ":") const;

		/// Gets the raw key bytes
		/// @return A const reference to the vector containing the key bytes
		const std::vector<uint8_t>& getBytes() const;

	private:
		std::vector<uint8_t> m_Key;
	};

	/// @namespace X509Internal
	/// Internal implementation details for X.509 certificate parsing
	namespace X509Internal
	{
		// Forward declarations
		class X509Certificate;
		class X509TBSCertificate;
		class X509Name;
		class X509SubjectPublicKeyInfo;
		class X509Extension;
		class X509Extensions;

		/// @class X509Base
		/// @tparam Asn1RecordType The type of ASN.1 record this class wraps
		/// Base class for X.509 data structures that wrap ASN.1 records
		template <typename Asn1RecordType> class X509Base
		{
		protected:
			explicit X509Base(Asn1RecordType* root) : m_Root(root)
			{}

			Asn1RecordType* m_Root;
		};

		/// @class X509VersionRecord
		/// Internal class for handling X.509 version records
		class X509VersionRecord : public X509Base<Asn1ConstructedRecord>
		{
			using X509Base::X509Base;
			friend class X509TBSCertificate;

		public:
			/// Gets the X.509 version from the version record
			/// @return The X.509 version
			X509Version getVersion() const;

			/// Checks if the given ASN.1 record is a valid version record
			/// @param[in] record The ASN.1 record to check
			/// @return true if the record is a valid version record, false otherwise
			static bool isValidVersionRecord(const Asn1Record* record);

		private:
			static constexpr int versionOffset = 0;
		};

		/// @class X509RelativeDistinguishedName
		/// Internal class for handling X.509 Relative Distinguished Names (RDNs)
		class X509RelativeDistinguishedName : public X509Base<Asn1SetRecord>
		{
			using X509Base::X509Base;
			friend class X509Name;

		public:
			/// Gets the type of the RDN
			/// @return The X520DistinguishedName type of this RDN
			X520DistinguishedName getType() const;

			/// Gets the value of the RDN
			/// @return The string value of this RDN
			std::string getValue() const;

		private:
			static constexpr int typeOffset = 0;
			static constexpr int valueOffset = 1;

			Asn1Record* getRecord(int index) const;
		};

		/// @class X509Name
		/// Internal class for handling X.509 distinguished names
		class X509Name : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;
			friend class X509TBSCertificate;

		public:
			/// Gets all Relative Distinguished Names (RDNs) in this name
			/// @return A vector of X509RelativeDistinguishedName objects
			std::vector<X509RelativeDistinguishedName> getRDNs() const;
		};

		/// @class X509AlgorithmIdentifier
		/// Internal class for handling X.509 algorithm identifiers
		class X509AlgorithmIdentifier : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;
			friend class X509SubjectPublicKeyInfo;
			friend class X509TBSCertificate;
			friend class X509Certificate;

		public:
			/// Gets the algorithm represented by this identifier
			/// @return The X509Algorithm value
			X509Algorithm getAlgorithm() const;

		private:
			static constexpr int algorithmOffset = 0;
		};

		/// @class X509Validity
		/// Internal class for handling X.509 certificate validity periods
		class X509Validity : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;
			friend class X509TBSCertificate;

		public:
			/// Gets the notBefore timestamp of the validity period
			/// @return The notBefore timestamp
			X509Timestamp getNotBefore() const;

			/// Gets the notAfter timestamp of the validity period
			/// @return The notAfter timestamp
			X509Timestamp getNotAfter() const;

		private:
			static constexpr int notBeforeOffset = 0;
			static constexpr int notAfterOffset = 1;
		};

		/// @class X509SubjectPublicKeyInfo
		/// Internal class for handling X.509 subject public key information
		class X509SubjectPublicKeyInfo : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;
			friend class X509TBSCertificate;

		public:
			/// Gets the algorithm identifier for the public key
			/// @return The X509AlgorithmIdentifier for the public key
			X509AlgorithmIdentifier getAlgorithm() const;

			/// Gets the subject's public key
			/// @return The X509Key containing the public key
			X509Key getSubjectPublicKey() const;

		private:
			static constexpr int algorithmOffset = 0;
			static constexpr int subjectPublicKeyOffset = 1;
		};

		/// @class X509Extension
		/// Internal class for handling X.509 extension records
		class X509Extension : public X509Base<Asn1SequenceRecord>
		{
			friend class X509Extensions;
			using X509Base::X509Base;

		public:
			/// Gets the type of this extension
			/// @return The X509ExtensionType of this extension
			X509ExtensionType getType() const;

			/// Checks if this extension is marked as critical
			/// @return true if the extension is critical, false otherwise
			bool isCritical() const;

			/// Gets the value of this extension
			/// @return The extension value as a string
			std::string getValue() const;

		private:
			static constexpr int extensionIdOffset = 0;

			int m_CriticalOffset = -1;
			int m_ExtensionValueOffset = 1;

			X509Extension(Asn1SequenceRecord* root);
		};

		/// @class X509Extensions
		/// Internal class for handling X.509 extensions record
		class X509Extensions : public X509Base<Asn1ConstructedRecord>
		{
			using X509Base::X509Base;
			friend class X509TBSCertificate;

		public:
			/// Gets all extensions in this record
			/// @return A vector of X509Extension objects
			std::vector<X509Extension> getExtensions() const;

			/// Checks if the given ASN.1 record is a valid extensions record
			/// @param[in] record The ASN.1 record to check
			/// @return true if the record is a valid extensions record, false otherwise
			static bool isValidExtensionsRecord(const Asn1Record* record);
		};

		/// @class X509TBSCertificate
		/// Internal class for handling the To-Be-Signed (TBS) portion of an X.509 certificate
		class X509TBSCertificate : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;
			friend class X509Certificate;

		public:
			/// Gets the version of the TBS certificate
			/// @return The X509Version of the certificate
			X509Version getVersion() const;

			/// Gets the serial number of the TBS certificate
			/// @return The X509SerialNumber of the certificate
			X509SerialNumber getSerialNumber() const;

			/// Gets the signature algorithm of the TBS certificate
			/// @return The X509AlgorithmIdentifier for the signature
			X509AlgorithmIdentifier getSignature() const;

			/// Gets the issuer name from the TBS certificate
			/// @return The X509Name of the issuer
			X509Name getIssuer() const;

			/// Gets the validity period of the TBS certificate
			/// @return The X509Validity object containing notBefore and notAfter timestamps
			X509Validity getValidity() const;

			/// Gets the subject name from the TBS certificate
			/// @return The X509Name of the subject
			X509Name getSubject() const;

			/// Gets the subject's public key information
			/// @return The X509SubjectPublicKeyInfo containing the public key
			X509SubjectPublicKeyInfo getSubjectPublicKeyInfo() const;

			/// Gets the extensions from the TBS certificate
			/// @return A unique_ptr to X509Extensions, or nullptr if no extensions are present
			std::unique_ptr<X509Extensions> getExtensions() const;

		private:
			int m_VersionOffset = -1;
			int m_SerialNumberOffset = 0;
			int m_SignatureOffset = 1;
			int m_IssuerOffset = 2;
			int m_ValidityOffset = 3;
			int m_SubjectOffset = 4;
			int m_SubjectPublicKeyInfoOffset = 5;
			int m_IssuerUniqueID = -1;
			int m_SubjectUniqueID = -1;
			int m_ExtensionsOffset = -1;

			X509TBSCertificate(Asn1SequenceRecord* root);
		};

		/// @class X509Certificate
		/// Internal class for handling X.509 certificate parsing and encoding
		class X509Certificate
		{
		public:
			/// Gets the TBS (To Be Signed) portion of the certificate
			/// @return The X509TBSCertificate containing the TBS data
			X509TBSCertificate getTbsCertificate() const;

			/// Gets the signature algorithm used to sign the certificate
			/// @return The X509AlgorithmIdentifier for the signature
			X509AlgorithmIdentifier getSignatureAlgorithm() const;

			/// Gets the signature value from the certificate
			/// @return The X509Key containing the signature
			X509Key getSignature() const;

			/// Gets the root ASN.1 record of the certificate
			/// @return Pointer to the root ASN.1 sequence record
			Asn1SequenceRecord* getAsn1Root() const;

			/// Decodes an X.509 certificate from binary data
			/// @param[in] data Pointer to the binary certificate data
			/// @param[in] dataLen Length of the binary data
			/// @return A unique_ptr to the decoded X509Certificate, or nullptr on failure
			static std::unique_ptr<X509Certificate> decode(const uint8_t* data, size_t dataLen);

			/// Encodes the certificate to binary DER format
			/// @return A vector containing the DER-encoded certificate
			std::vector<uint8_t> encode();

		private:
			static constexpr int tbsCertificateOffset = 0;
			static constexpr int signatureAlgorithmOffset = 1;
			static constexpr int signatureOffset = 2;

			explicit X509Certificate(std::unique_ptr<Asn1Record> root) : m_Root(std::move(root))
			{}

			std::unique_ptr<Asn1Record> m_Root;
		};
	}  // namespace X509Internal

	// Forward declarations
	class X509Certificate;

	/// @class X509Name
	/// Represents a name in an X.509 certificate
	class X509Name
	{
		friend class X509Certificate;

	public:
		/// @struct RDN
		/// Represents a Relative Distinguished Name (RDN) in an X.509 certificate
		struct RDN
		{
			X520DistinguishedName type;  ///< The type of the distinguished name
			std::string value;           ///< The value of the distinguished name

			/// Equality comparison operator
			bool operator==(const RDN& other) const
			{
				return type == other.type && value == other.value;
			}

			/// Inequality comparison operator
			bool operator!=(const RDN& other) const
			{
				return !(*this == other);
			}

			/// Stream output operator for RDN
			friend std::ostream& operator<<(std::ostream& os, const RDN& rdn)
			{
				os << "RDN{type=" << rdn.type.getShortName() << ", value=" << rdn.value << "}";
				return os;
			}
		};

		/// Converts the X509Name to a string representation, e.g C=US, ST=California, CN=example.com
		/// @param[in] delimiter The delimiter to use between RDNs (default: ", ")
		/// @return A string representation of the X509Name
		std::string toString(const std::string& delimiter = ", ") const;

		/// Gets the list of Relative Distinguished Names (RDNs)
		/// @return A vector of RDN objects
		const std::vector<RDN>& getRDNs() const
		{
			return m_RDNs;
		}

	private:
		explicit X509Name(const X509Internal::X509Name& internalName);
		std::vector<RDN> m_RDNs;
	};

	/// @class X509Extension
	/// Represents an X.509 extension
	class X509Extension
	{
		friend class X509Certificate;

	public:
		/// Gets the type of this X.509 extension
		/// @return The X509ExtensionType representing the extension type
		X509ExtensionType getType() const
		{
			return m_Type;
		}

		/// Checks if this extension is marked as critical
		/// @return true if the extension is critical, false otherwise
		bool isCritical() const
		{
			return m_IsCritical;
		}

		/// Gets the extension parsed data
		/// @return A unique_ptr to an object containing the parsed extension data if such class exists
		///         (not all extensions have parsed data classes), or nullptr if it doesn't
		std::unique_ptr<X509ExtensionData> getData() const;

		/// Gets the extension data as a hex string
		/// @return A string containing the extension data in hex format
		std::string getRawDataAsHexString() const
		{
			return m_Data;
		}

	private:
		X509Extension(const X509Internal::X509Extension& internalExtension);

		bool m_IsCritical;
		X509ExtensionType m_Type;
		std::string m_Data;
	};

	/// @class X509Certificate
	/// Represents an X.509 certificate
	class X509Certificate : public internal::CryptoDataReader<X509Certificate>
	{
	public:
		/// Gets the version of the certificate
		/// @return The X509Version of the certificate
		X509Version getVersion() const;

		/// Gets the serial number of the certificate
		/// @return The certificate's serial number
		X509SerialNumber getSerialNumber() const;

		/// Gets the issuer of the certificate
		/// @return The certificate's issuer name
		X509Name getIssuer() const;

		/// Gets the subject of the certificate
		/// @return The certificate's subject name
		X509Name getSubject() const;

		/// Gets the notBefore timestamp of the certificate's validity period
		/// @return The notBefore timestamp
		X509Timestamp getNotBefore() const;

		/// Gets the notAfter timestamp of the certificate's validity period
		/// @return The notAfter timestamp
		X509Timestamp getNotAfter() const;

		/// Gets the public key algorithm used in the certificate
		/// @return The public key algorithm
		X509Algorithm getPublicKeyAlgorithm() const;

		/// Gets the public key from the certificate
		/// @return The public key
		X509Key getPublicKey() const;

		/// Gets the signature algorithm used to sign the certificate
		/// @return The signature algorithm
		X509Algorithm getSignatureAlgorithm() const;

		/// Gets the signature of the certificate
		/// @return The certificate's signature
		X509Key getSignature() const;

		/// Gets the list of extensions in the certificate
		/// @return A vector containing the certificate's extensions
		const std::vector<X509Extension>& getExtensions() const;

		/// Checks if the certificate has a specific extension
		/// @param[in] extensionType The extension type to check for
		/// @return true if the extension is present, false otherwise
		bool hasExtension(const X509ExtensionType& extensionType) const;

		/// Gets an extension by its type
		/// @param[in] extensionType The type of extension to get
		/// @return Pointer to the extension if found or nullptr otherwise
		const X509Extension* getExtension(X509ExtensionType extensionType) const;

		/// Converts the certificate to DER-encoded format
		/// @return A byte vector containing the DER-encoded data
		std::vector<uint8_t> toDER() const;

		/// Converts the certificate to PEM-encoded format
		/// @return A string containing the PEM-encoded data
		std::string toPEM() const;

		/// Converts the certificate to a JSON string representation
		/// @param[in] indent Number of spaces to use for indentation (-1 for no pretty printing)
		/// @return A JSON string representation of the certificate
		std::string toJson(int indent = -1) const;

		/// Gets the raw internal certificate object
		/// @return Pointer to the internal X509Certificate implementation
		const X509Internal::X509Certificate* getRawCertificate() const;

		// Prevent copying
		X509Certificate(const X509Certificate&) = delete;
		X509Certificate& operator=(const X509Certificate&) = delete;

	private:
		// Constructor/Destructor
		X509Certificate(uint8_t* derData, size_t derDataLen, bool ownDerData);
		X509Certificate(std::unique_ptr<uint8_t[]> derData, size_t derDataLen);

		friend class internal::CryptoDataReader<X509Certificate>;

		std::unique_ptr<X509Internal::X509Certificate> m_X509Internal;
		X509Internal::X509TBSCertificate m_TBSCertificate;
		mutable std::vector<X509Extension> m_Extensions;
		mutable bool m_ExtensionsParsed = false;
		std::unique_ptr<uint8_t[]> m_DerData;

		static constexpr const char* pemLabel = "CERTIFICATE";
	};
}  // namespace pcpp
