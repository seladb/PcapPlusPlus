#pragma once

/// @file

#include "CryptoDataReader.h"
#include "Asn1Codec.h"
#include <string>
#include <memory>
#include <utility>

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	namespace internal
	{
		/// @class PrivateKeyDataView
		/// A base class for different types of private key data
		class PrivateKeyDataView
		{
		protected:
			explicit PrivateKeyDataView(Asn1SequenceRecord* root, std::string decoderType)
			    : m_Root(root), m_DecoderType(std::move(decoderType))
			{}

			~PrivateKeyDataView() = default;

			template <class Asn1RecordType>
			Asn1RecordType* castSubRecordAs(int index, const std::string& fieldName) const
			{
				try
				{
					return m_Root->getSubRecords().at(index)->template castAs<Asn1RecordType>();
				}
				catch (const std::exception&)
				{
					throw std::runtime_error("Invalid " + m_DecoderType + " data: " + fieldName);
				}
			}

		private:
			Asn1SequenceRecord* m_Root;
			std::string m_DecoderType;
		};

		/// @class RSAPrivateKeyDataView
		/// A class that contains RSA private key data
		class RSAPrivateKeyDataView : public PrivateKeyDataView
		{
		public:
			/// @return The version of the RSA private key
			uint8_t getVersion() const;

			/// @return The modulus of the RSA private key
			std::string getModulus() const;

			/// @return The public exponent of the RSA private key
			uint64_t getPublicExponent() const;

			/// @return The private exponent of the RSA private key
			std::string getPrivateExponent() const;

			/// @return The first prime factor of the RSA private key
			std::string getPrime1() const;

			/// @return The second prime factor of the RSA private key
			std::string getPrime2() const;

			/// @return The first exponent of the RSA private key
			std::string getExponent1() const;

			/// @return The second exponent of the RSA private key
			std::string getExponent2() const;

			/// @return The coefficient of the RSA private key
			std::string getCoefficient() const;

		protected:
			explicit RSAPrivateKeyDataView(Asn1SequenceRecord* root, std::string decoderType)
			    : PrivateKeyDataView(root, decoderType)
			{}

			~RSAPrivateKeyDataView() = default;

		private:
			static constexpr int versionOffset = 0;
			static constexpr int modulusOffset = 1;
			static constexpr int publicExponentOffset = 2;
			static constexpr int privateExponentOffset = 3;
			static constexpr int prime1Offset = 4;
			static constexpr int prime2Offset = 5;
			static constexpr int exponent1Offset = 6;
			static constexpr int exponent2Offset = 7;
			static constexpr int coefficientOffset = 8;
		};

		/// @class ECPrivateKeyDataView
		/// A class that contains EC private key data
		class ECPrivateKeyDataView : public PrivateKeyDataView
		{
		public:
			/// @return The version of the EC private key
			uint8_t getVersion() const;

			/// @return The private key itself
			std::string getPrivateKey() const;

			/// @return The parameters of the EC private key
			std::unique_ptr<Asn1ObjectIdentifier> getParameters() const;

			/// @return The public key of the EC private key
			std::string getPublicKey() const;

		protected:
			explicit ECPrivateKeyDataView(Asn1SequenceRecord* root, std::string decoderType);

			~ECPrivateKeyDataView() = default;

		private:
			static constexpr int versionOffset = 0;
			static constexpr int privateKeyOffset = 1;

			int m_ParametersOffset = -1;
			int m_PublicKeyOffset = -1;
		};

		/// @class CryptographicKey
		/// A base class for different types of private and public cryptographic keys
		template <typename CryptoKey> class CryptographicKey
		{
		public:
			/// Converts the cryptographic key to DER-encoded format
			/// @return A byte vector containing the DER-encoded data
			std::vector<uint8_t> toDER() const
			{
				return m_Root->encode();
			}

			/// Converts the cryptographic key to PEM-encoded format
			/// @return A string containing the PEM-encoded data
			std::string toPEM() const
			{
				return PemCodec::encode(m_Root->encode(), CryptoKey::pemLabel);
			}

		protected:
			CryptographicKey(std::unique_ptr<uint8_t[]> derData, size_t derDataLen)
			    : m_DerData(std::move(derData)), m_Root(Asn1Record::decode(m_DerData.get(), derDataLen))
			{}

			CryptographicKey(uint8_t* derData, size_t derDataLen, bool ownDerData)
			{
				m_Root = Asn1Record::decode(derData, derDataLen);
				if (ownDerData)
				{
					m_DerData.reset(derData);
				}
			}

			~CryptographicKey() = default;

			Asn1SequenceRecord* getRoot() const
			{
				try
				{
					return m_Root->castAs<Asn1SequenceRecord>();
				}
				catch (const std::bad_cast&)
				{
					throw std::runtime_error("Invalid " + std::string(CryptoKey::keyType) + " data");
				}
			}

			template <class Asn1RecordType>
			Asn1RecordType* castSubRecordAs(int index, const std::string& fieldName) const
			{
				try
				{
					return getRoot()->getSubRecords().at(index)->template castAs<Asn1RecordType>();
				}
				catch (const std::exception&)
				{
					throw std::runtime_error("Invalid " + std::string(CryptoKey::keyType) + " data: " + fieldName);
				}
			}

		private:
			std::unique_ptr<uint8_t[]> m_DerData;
			std::unique_ptr<Asn1Record> m_Root;
		};
	}  // namespace internal

	/// @class CryptographicKeyAlgorithm
	/// Represents cryptographic algorithms used in PKCS#8 private keys
	/// This class encapsulates various hashing and signature algorithms that can be used
	/// in PKCS#8 private keys.
	class CryptographicKeyAlgorithm
	{
	public:
		/// Define enum types and the corresponding int values
		enum Value : uint8_t
		{
			/// RSA encryption/signature algorithm
			RSA,
			/// Digital Signature Algorithm
			DSA,
			/// Elliptic Curve Digital Signature Algorithm
			ECDSA,
			/// EdDSA using Curve25519 (Ed25519)
			ED25519,
			/// EdDSA using Curve448 (Ed448)
			ED448,
			/// Diffie-Hellman key exchange algorithm
			DiffieHellman,
			/// Diffie-Hellman using Curve448 (Goldilocks curve)
			X448,
			/// Unknown or unsupported algorithm
			Unknown,
		};

		CryptographicKeyAlgorithm() = default;

		// cppcheck-suppress noExplicitConstructor
		/// @brief Constructs a CryptographicKeyAlgorithm object from a Value enum
		/// @param[in] value The Value enum value
		constexpr CryptographicKeyAlgorithm(Value value) : m_Value(value)
		{}

		/// @return A string representation of the algorithm
		std::string toString() const;

		/// @return The OID value of the algorithm
		std::string getOidValue() const;

		/// @brief Creates a CryptographicKeyAlgorithm object from an OID value
		/// @param[in] value The OID value
		/// @return The CryptographicKeyAlgorithm object corresponding to the OID value. If the OID value
		/// doesn't correspond to any algorithm, CryptographicKeyAlgorithm::Unknown is returned
		static CryptographicKeyAlgorithm fromOidValue(const Asn1ObjectIdentifier& value);

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

	/// @class RSAPrivateKey
	/// @brief Represents an RSA private key in PKCS#1 format
	/// This class provides methods to decode and access the components of an RSA private key.
	class RSAPrivateKey : public internal::CryptographicKey<RSAPrivateKey>,
	                      public internal::CryptoDataReader<RSAPrivateKey>,
	                      public internal::RSAPrivateKeyDataView
	{
	protected:
		RSAPrivateKey(std::unique_ptr<uint8_t[]> derData, size_t derDataLen)
		    : CryptographicKey(std::move(derData), derDataLen), RSAPrivateKeyDataView(getRoot(), keyType)
		{}

		RSAPrivateKey(uint8_t* derData, size_t derDataLen, bool ownDerData)
		    : CryptographicKey(derData, derDataLen, ownDerData), RSAPrivateKeyDataView(getRoot(), keyType)
		{}

	private:
		static constexpr const char* pemLabel = "RSA PRIVATE KEY";
		static constexpr const char* keyType = "RSA private key";

		using CryptographicKey::CryptographicKey;
		friend class internal::CryptographicKey<RSAPrivateKey>;
		friend class internal::CryptoDataReader<RSAPrivateKey>;
	};

	/// @class ECPrivateKey
	/// @brief Represents an EC private key in SEC1 format
	/// This class provides methods to decode and access the components of an EC private key.
	class ECPrivateKey : public internal::CryptographicKey<ECPrivateKey>,
	                     public internal::CryptoDataReader<ECPrivateKey>,
	                     public internal::ECPrivateKeyDataView
	{
	protected:
		ECPrivateKey(std::unique_ptr<uint8_t[]> derData, size_t derDataLen)
		    : CryptographicKey(std::move(derData), derDataLen), ECPrivateKeyDataView(getRoot(), keyType)
		{}

		ECPrivateKey(uint8_t* derData, size_t derDataLen, bool ownDerData)
		    : CryptographicKey(derData, derDataLen, ownDerData), ECPrivateKeyDataView(getRoot(), keyType)
		{}

	private:
		static constexpr const char* pemLabel = "EC PRIVATE KEY";
		static constexpr const char* keyType = "EC private key";

		using CryptographicKey::CryptographicKey;
		friend class internal::CryptographicKey<ECPrivateKey>;
		friend class internal::CryptoDataReader<ECPrivateKey>;
	};

	/// @class PKCS8PrivateKey
	/// @brief Represents a private key in PKCS#8 format
	/// This class provides methods to decode and access the components of the private key and its data.
	class PKCS8PrivateKey : public internal::CryptographicKey<PKCS8PrivateKey>,
	                        public internal::CryptoDataReader<PKCS8PrivateKey>
	{
	public:
		/// @class PrivateKeyData
		/// @brief Base class for private key data in PKCS#8 format
		/// This class serves as a base for different types of private key data
		/// that can be contained within a PKCS#8 structure.
		class PrivateKeyData
		{
		public:
			/// @brief Virtual destructor
			virtual ~PrivateKeyData() = default;

			/// @brief Casts the private key data to a specific type
			/// @tparam PrivateKeyDataType The type to cast to
			/// @return A pointer to the casted private key data
			/// @throw std::runtime_error if the cast fails
			template <class PrivateKeyDataType> PrivateKeyDataType* castAs()
			{
				auto privateKeyData = dynamic_cast<PrivateKeyDataType*>(this);
				if (privateKeyData == nullptr)
				{
					throw std::runtime_error("Trying to PKCS#8 private key data to the wrong type");
				}
				return privateKeyData;
			}

		protected:
			explicit PrivateKeyData(const std::string& rawData);

			Asn1SequenceRecord* getRoot() const
			{
				return m_Root->castAs<Asn1SequenceRecord>();
			}

			std::vector<uint8_t> m_DerData;
			std::unique_ptr<Asn1Record> m_Root;
		};

		/// @class RSAPrivateKeyData
		/// @brief Contains RSA private key data extracted from PKCS#8 format
		/// This class provides access to the components of an RSA private key
		/// that was extracted from a PKCS#8 structure.
		class RSAPrivateKeyData : public PrivateKeyData, public internal::RSAPrivateKeyDataView
		{
			friend class PKCS8PrivateKey;
			explicit RSAPrivateKeyData(const std::string& rawData);
		};

		/// @class ECPrivateKeyData
		/// @brief Contains EC private key data extracted from PKCS#8 format
		/// This class provides access to the components of an EC private key
		/// that was extracted from a PKCS#8 structure.
		class ECPrivateKeyData : public PrivateKeyData, public internal::ECPrivateKeyDataView
		{
			friend class PKCS8PrivateKey;
			explicit ECPrivateKeyData(const std::string& rawData);
		};

		/// @class Ed25519PrivateKeyData
		/// @brief Contains Ed25519 private key data extracted from PKCS#8 format
		/// This class provides access to the components of an Ed25519 private key
		/// that was extracted from a PKCS#8 structure.
		class Ed25519PrivateKeyData : public PrivateKeyData
		{
			friend class PKCS8PrivateKey;
			explicit Ed25519PrivateKeyData(const std::string& rawData);

		public:
			/// @return The Ed25519 private key
			std::string getPrivateKey() const;
		};

		/// @return The version of the PKCS#8 private key
		uint8_t getVersion() const;

		/// @return The CryptographicKeyAlgorithm enum value representing the key algorithm
		CryptographicKeyAlgorithm getPrivateKeyAlgorithm() const;

		/// @brief Gets the private key data
		/// @return A unique pointer to the PrivateKeyData containing the key material
		/// @note The actual type of the returned pointer depends on the key algorithm
		std::unique_ptr<PrivateKeyData> getPrivateKey() const;

		/// @brief Gets the private key data cast to a requested type
		/// @return A unique pointer of the requested type containing the key material. If the key algorithm doesn't
		/// match the requested type, nullptr is returned
		template <typename PrivateKeyDataType> std::unique_ptr<PrivateKeyDataType> getPrivateKeyAs() const
		{
			auto privateKey = getPrivateKey();
			if (privateKey == nullptr)
			{
				return nullptr;
			}

			if (auto* specificPrivateKey = dynamic_cast<PrivateKeyDataType*>(privateKey.get()))
			{
				privateKey.release();
				return std::unique_ptr<PrivateKeyDataType>(specificPrivateKey);
			}

			return nullptr;
		}

	private:
		static constexpr const char* pemLabel = "PRIVATE KEY";
		static constexpr const char* keyType = "PKCS#8 private key";
		static constexpr int versionOffset = 0;
		static constexpr int privateKeyAlgorithmOffset = 1;
		static constexpr int privateKeyOffset = 2;

		using CryptographicKey::CryptographicKey;
		friend class internal::CryptographicKey<PKCS8PrivateKey>;
		friend class internal::CryptoDataReader<PKCS8PrivateKey>;
	};

	/// @class RSAPublicKey
	/// @brief Represents an RSA public key in PKCS#1 format
	/// This class provides methods to decode and access the components of an RSA public key.
	class RSAPublicKey : public internal::CryptographicKey<RSAPublicKey>,
	                     public internal::CryptoDataReader<RSAPublicKey>
	{
	public:
		/// @return The modulus of the RSA public key
		std::string getModulus() const;

		/// @return The public exponent of the RSA public key
		uint64_t getPublicExponent() const;

	private:
		static constexpr const char* pemLabel = "RSA PUBLIC KEY";
		static constexpr const char* keyType = "RSA public key";
		static constexpr int modulusOffset = 0;
		static constexpr int publicExponentOffset = 1;

		using CryptographicKey::CryptographicKey;
		friend class internal::CryptographicKey<RSAPublicKey>;
		friend class internal::CryptoDataReader<RSAPublicKey>;
	};

	/// @class SubjectPublicKeyInfo
	/// @brief Represents a Subject Public Key Info (SPKI) structure
	/// This class provides methods to decode and access the components of a public key
	/// stored in the SubjectPublicKeyInfo format (RFC 5280).
	class SubjectPublicKeyInfo : public internal::CryptographicKey<SubjectPublicKeyInfo>,
	                             public internal::CryptoDataReader<SubjectPublicKeyInfo>
	{
	public:
		/// @return The CryptographicKeyAlgorithm for the public key
		CryptographicKeyAlgorithm getAlgorithm() const;

		/// @return The public key itself
		std::string getSubjectPublicKey() const;

	private:
		static constexpr const char* pemLabel = "PUBLIC KEY";
		static constexpr const char* keyType = "public key";
		static constexpr int algorithmOffset = 0;
		static constexpr int subjectPublicKeyOffset = 1;

		using CryptographicKey::CryptographicKey;
		friend class internal::CryptographicKey<SubjectPublicKeyInfo>;
		friend class internal::CryptoDataReader<SubjectPublicKeyInfo>;
	};
}  // namespace pcpp
