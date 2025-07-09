#pragma once
#include <chrono>
#include "Asn1Codec.h"

namespace pcpp
{
	enum class X509Version : uint8_t
	{
		V1 = 0,
		V2 = 1,
		V3 = 2,
	};

	class X509Algorithm
	{
	public:
		enum Value : uint8_t
		{
			SHA1,
			SHA256,
			SHA384,
			SHA512,
			MD5,

			RSA,
			RSAWithSHA1,
			RSAWithSHA256,
			RSAWithSHA384,
			RSAWithSHA512,
			RSAPSS,

			ECDSA,
			ECDSAWithSHA1,
			ECDSAWithSHA256,
			ECDSAWithSHA384,
			ECDSAWithSHA512,

			DSA,
			DSAWithSHA1,
			DSAWithSHA256,

			ED25519,
			ED448,
			DiffieHellman,

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

	class X520DistinguishedName
	{
	public:
		enum Value : uint8_t
		{
			CommonName,
			Surname,
			SerialNumber,
			Country,
			Locality,
			StateOrProvince,
			Organization,
			OrganizationalUnit,
			Title,
			GivenName,
			Initials,
			Pseudonym,
			GenerationQualifier,
			DnQualifier,
			DomainComponent,
			EmailAddress,
			PostalCode,
			StreetAddress,
			BusinessCategory,
			Unknown
		};

		X520DistinguishedName() = default;

		constexpr X520DistinguishedName(Value value)
			: m_Value(value)
		{}

		std::string toString() const;
		std::string getShortName() const;
		std::string getOidValue() const;

		static X520DistinguishedName fromOidValue(const Asn1ObjectIdentifier& value);

		constexpr operator Value() const { return m_Value; }
		explicit operator bool() const = delete;

	private:
		Value m_Value = Unknown;
	};

	class X509ExtensionType
	{
	public:
		enum Value : uint8_t
		{
			BasicConstraints,
			KeyUsage,
			ExtendedKeyUsage,
			SubjectKeyIdentifier,
			AuthorityKeyIdentifier,
			SubjectAltName,
			IssuerAltName,
			CrlDistributionPoints,
			AuthorityInfoAccess,
			CertificatePolicies,
			PolicyMappings,
			PolicyConstraints,
			NameConstraints,
			InhibitAnyPolicy,
			CTPrecertificateSCTs,
			SubjectInfoAccess,
			FreshestCRL,
			TLSFeature,
			OcspNoCheck,
			SubjectDirectoryAttributes,
			Unknown
		};

		X509ExtensionType() = default;

		// cppcheck-suppress noExplicitConstructor
		constexpr X509ExtensionType(Value value) : m_Value(value) {}

		std::string toString() const;
		std::string getOidValue() const;

		static X509ExtensionType fromOidValue(const Asn1ObjectIdentifier& value);

		constexpr operator Value() const { return m_Value; }
		explicit operator bool() const = delete;

	private:
		Value m_Value = Unknown;
	};

	class X509SerialNumber
	{
	public:
		std::string toString(const std::string& delimiter = ":") const;
		X509SerialNumber(const std::string& serialNumber) : m_SerialNumber(serialNumber)
		{}

	private:
		std::string m_SerialNumber;
	};

	class X509Timestamp
	{
	public:
		std::string toString(const std::string& format = "%Y-%m-%d %H:%M:%S", const std::string& timezone = "Z",
					 bool includeMilliseconds = false) const;

		std::chrono::system_clock::time_point getTimestamp(const std::string& timezone = "Z") const;

		X509Timestamp(Asn1TimeRecord* timeRecord) : m_Record(timeRecord)
		{}

	private:
		Asn1TimeRecord* m_Record;
	};

	class X509Key
	{
	public:
		std::string toString(const std::string& delimiter = ":") const;
		const std::vector<uint8_t>& getBytes() const;

		X509Key(const std::vector<uint8_t>& key) : m_Key(key)
		{}

	private:
		std::vector<uint8_t> m_Key;
	};

	namespace X509Internal
	{
		// Forward declarations
		class X509Certificate;
		class X509TBSCertificate;
		class X509Name;
		class X509SubjectPublicKeyInfo;
		class X509Extension;
		class X509Extensions;

		template <typename Asn1RecordType> class X509Base
		{
			friend class X509Certificate;
			friend class X509TBSCertificate;
			friend class X509Name;
			friend class X509SubjectPublicKeyInfo;
			friend class X509Extension;
			explicit X509Base(Asn1RecordType* root) : m_Root(root) {}

		protected:
			Asn1RecordType* m_Root;
		};

		class X509VersionRecord : public X509Base<Asn1ConstructedRecord>
		{
			using X509Base::X509Base;

		public:
			X509Version getVersion() const;

			static bool isValidVersionRecord(const Asn1Record* record);

		private:
			static constexpr int m_VersionOffset = 0;
		};

		class X509RelativeDistinguishedName : public X509Base<Asn1SetRecord>
		{
			using X509Base::X509Base;

		public:
			X520DistinguishedName getType() const;
			std::string getValue() const;

		private:
			static constexpr int m_TypeOffset = 0;
			static constexpr int m_ValueOffset = 1;

			Asn1Record* getRecord(int index) const;
		};

		class X509Name : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;

		public:
			std::vector<X509RelativeDistinguishedName> getRDNs() const;
		};

		class X509AlgorithmIdentifier : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;

		public:
			X509Algorithm getAlgorithm() const;

		private:
			static constexpr int m_AlgorithmOffset = 0;

		};

		class X509Validity : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;

		public:
			X509Timestamp getNotBefore() const;
			X509Timestamp getNotAfter() const;

		private:
			static constexpr int m_NotBeforeOffset = 0;
			static constexpr int m_NotAfterOffset = 1;
		};

		class X509SubjectPublicKeyInfo : public X509Base<Asn1SequenceRecord>
		{
			using X509Base::X509Base;

		public:
			X509AlgorithmIdentifier getAlgorithm() const;
			X509Key getSubjectPublicKey() const;

		private:
			static constexpr int m_AlgorithmOffset = 0;
			static constexpr int m_SubjectPublicKeyOffset = 1;
		};

		class X509Extension : public X509Base<Asn1SequenceRecord>
		{
			friend class X509Extensions;
			using X509Base::X509Base;

		public:
			X509ExtensionType getType() const;
			bool getCritical() const;
			std::string getValue() const;

		private:
			static constexpr int m_ExtensionIdOffset = 0;

			int m_CriticalOffset = -1;
			int m_ExtensionValueOffset = 1;

			X509Extension(Asn1SequenceRecord* root);
		};

		class X509Extensions : public X509Base<Asn1ConstructedRecord>
		{
			using X509Base::X509Base;

		public:
			std::vector<X509Extension> getExtensions() const;

			static bool isValidExtensionsRecord(const Asn1Record* record);
		};

		class X509TBSCertificate : public X509Base<Asn1SequenceRecord>
		{
			friend class X509Certificate;
			using X509Base::X509Base;

		public:
			X509Version getVersion() const;
			X509SerialNumber getSerialNumber() const;
			X509AlgorithmIdentifier getSignature() const;
			X509Name getIssuer() const;
			X509Validity getValidity() const;
			X509Name getSubject() const;
			X509SubjectPublicKeyInfo getSubjectPublicKeyInfo() const;
			// TODO: getIssuerUniqueID()
			// TODO: getSubjectUniqueID()
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
			int getIndex(int offset) const { return m_VersionOffset + offset; }
		};

		class X509Certificate
		{
		public:
			X509TBSCertificate getTbsCertificate() const;
			X509AlgorithmIdentifier getSignatureAlgorithm() const;
			X509Key getSignature() const;
			Asn1SequenceRecord* getAsn1Root() const;

			static std::unique_ptr<X509Certificate> decode(const uint8_t* data, size_t dataLen);
			std::vector<uint8_t> encode();

		private:
			static constexpr int m_TBSCertificateOffset = 0;
			static constexpr int m_SignatureAlgorithmOffset = 1;
			static constexpr int m_SignatureOffset = 2;

			explicit X509Certificate(std::unique_ptr<Asn1Record> root) : m_Root(std::move(root))
			{}

			std::unique_ptr<Asn1Record> m_Root;
		};
	}

	// Forward declerations
	class X509Certificate;

	class X509Name
	{
		friend class X509Certificate;

	public:
		struct RDN
		{
			X520DistinguishedName type;
			std::string value;

			bool operator==(const RDN& other) const
			{
				return type == other.type && value == other.value;
			}

			bool operator!=(const RDN& other) const
			{
				return !(*this == other);
			}

			friend std::ostream& operator<<(std::ostream& os, const RDN& rdn)
			{
				os << "RDN{type=" << rdn.type.getShortName() << ", value=" << rdn.value << "}";
				return os;
			}
		};

		std::string toString(const std::string& delimiter = ", ") const;
		std::vector<RDN> getRDNs() const { return m_RDNs; };

	private:
		X509Name(const X509Internal::X509Name& internalName);

		std::vector<RDN> m_RDNs;
	};

	class X509Certificate
	{
	public:
		static std::unique_ptr<X509Certificate> fromDER(const uint8_t* derData, size_t derDataLen, bool ownDerData = false);
		static std::unique_ptr<X509Certificate> fromDER(const std::string& derData);
		static std::unique_ptr<X509Certificate> fromDERFile(const std::string& derFileName);

		X509Version getVersion() const;

		// Basic info
		X509SerialNumber getSerialNumber() const;
		X509Name getIssuer() const;
		X509Name getSubject() const;

		// Validity
		X509Timestamp getNotBefore() const;
		X509Timestamp getNotAfter() const;

		// Public Key
		X509Algorithm getPublicKeyAlgorithm() const;
		X509Key getPublicKey() const;

		// Signature
		X509Algorithm getSignatureAlgorithm() const;
		X509Key getSignature() const;

		// Extensions
		size_t getExtensionCount() const;
		bool hasExtension(const X509ExtensionType& extensionType) const;

		// Utility
		std::vector<uint8_t> toDER() const;

		std::string toJson(int indent = -1) const;

		const X509Internal::X509Certificate* getRawCertificate() const;

		// Prevent copying
		X509Certificate(const X509Certificate&) = delete;
		X509Certificate& operator=(const X509Certificate&) = delete;

	private:
		// Constructor/Destructor
		X509Certificate(uint8_t* derData, size_t derDataLen, bool ownDerData);

		std::unique_ptr<X509Internal::X509Certificate> m_X509Internal;
		X509Internal::X509TBSCertificate m_TBSCertificate;
		std::unique_ptr<uint8_t[]> m_DerData;
	};
}  // namespace pcpp
