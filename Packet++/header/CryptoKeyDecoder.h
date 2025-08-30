#pragma once
#include "CryptoDataReader.h"
#include "Asn1Codec.h"
#include <string>
#include <memory>
#include <utility>

namespace pcpp
{
	namespace internal
	{
		class PrivateKeyData
		{
		protected:
			explicit PrivateKeyData(Asn1SequenceRecord* root, std::string decoderType)
			    : m_Root(root), m_DecoderType(std::move(decoderType))
			{}

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

		class RSAPrivateKeyData : public PrivateKeyData
		{
		public:
			uint8_t getVersion() const;
			std::string getModulus() const;
			uint64_t getPublicExponent() const;
			std::string getPrivateExponent() const;
			std::string getPrime1() const;
			std::string getPrime2() const;
			std::string getExponent1() const;
			std::string getExponent2() const;
			std::string getCoefficient() const;

		protected:
			explicit RSAPrivateKeyData(Asn1SequenceRecord* root, std::string decoderType)
			    : PrivateKeyData(root, decoderType)
			{}

		private:
			static constexpr int versionIndex = 0;
			static constexpr int modulusIndex = 1;
			static constexpr int publicExponentIndex = 2;
			static constexpr int privateExponentIndex = 3;
			static constexpr int prime1Index = 4;
			static constexpr int prime2Index = 5;
			static constexpr int exponent1Index = 6;
			static constexpr int exponent2Index = 7;
			static constexpr int coefficientIndex = 8;
		};

		class ECPrivateKeyData : public PrivateKeyData
		{
		public:
			uint8_t getVersion() const;
			std::string getPrivateKey() const;
			std::unique_ptr<Asn1ObjectIdentifier> getParameters() const;
			std::string getPublicKey() const;

		protected:
			explicit ECPrivateKeyData(Asn1SequenceRecord* root, std::string decoderType);

		private:
			static constexpr int versionIndex = 0;
			static constexpr int privateKeyIndex = 1;

			int m_ParametersIndex = -1;
			int m_PublicKeyIndex = -1;
		};

		template <typename CryptoDecoder> class CryptoKeyDecoder
		{
		public:
			/// Converts the crypto key to DER-encoded format
			/// @return A byte vector containing the DER-encoded data
			std::vector<uint8_t> toDER() const
			{
				return m_Root->encode();
			}

			/// Converts the crypto key to PEM-encoded format
			/// @return A string containing the PEM-encoded data
			std::string toPEM() const
			{
				return PemCodec::encode(m_Root->encode(), CryptoDecoder::pemLabel);
			}

		protected:
			CryptoKeyDecoder(std::unique_ptr<uint8_t[]> derData, size_t derDataLen)
			{
				m_Root = Asn1Record::decode(derData.get(), derDataLen);
				m_DerData = std::move(derData);
			}

			virtual ~CryptoKeyDecoder() = default;

			Asn1SequenceRecord* getRoot() const
			{
				return m_Root->castAs<Asn1SequenceRecord>();
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
					throw std::runtime_error("Invalid " + std::string(CryptoDecoder::keyType) + " data: " + fieldName);
				}
			}

		private:
			std::unique_ptr<uint8_t[]> m_DerData;
			std::unique_ptr<Asn1Record> m_Root;
		};
	}  // namespace internal

	class RSAPrivateKey : public internal::CryptoKeyDecoder<RSAPrivateKey>,
	                      public internal::CryptoDataReader<RSAPrivateKey>,
	                      public internal::RSAPrivateKeyData
	{
	protected:
		RSAPrivateKey(std::unique_ptr<uint8_t[]> derData, size_t derDataLen)
		    : CryptoKeyDecoder(std::move(derData), derDataLen), RSAPrivateKeyData(getRoot(), keyType)
		{}

	private:
		static constexpr const char* pemLabel = "RSA PRIVATE KEY";
		static constexpr const char* keyType = "RSA private key";

		using CryptoKeyDecoder::CryptoKeyDecoder;
		friend class internal::CryptoKeyDecoder<RSAPrivateKey>;
		friend class internal::CryptoDataReader<RSAPrivateKey>;
	};

	class ECPrivateKey : public internal::CryptoKeyDecoder<ECPrivateKey>,
	                     public internal::CryptoDataReader<ECPrivateKey>,
	                     public internal::ECPrivateKeyData
	{
	protected:
		ECPrivateKey(std::unique_ptr<uint8_t[]> derData, size_t derDataLen)
		    : CryptoKeyDecoder(std::move(derData), derDataLen), ECPrivateKeyData(getRoot(), keyType)
		{}

	private:
		static constexpr const char* pemLabel = "EC PRIVATE KEY";
		static constexpr const char* keyType = "EC private key";

		using CryptoKeyDecoder::CryptoKeyDecoder;
		friend class internal::CryptoKeyDecoder<ECPrivateKey>;
		friend class internal::CryptoDataReader<ECPrivateKey>;
	};

	class RSAPublicKey : public internal::CryptoKeyDecoder<RSAPublicKey>,
	                     public internal::CryptoDataReader<RSAPublicKey>
	{
	public:
		std::string getModulus() const;
		uint64_t getPublicExponent() const;

	private:
		static constexpr const char* pemLabel = "RSA PUBLIC KEY";
		static constexpr const char* keyType = "RSA public key";
		static constexpr int modulusIndex = 0;
		static constexpr int publicExponentIndex = 1;

		using CryptoKeyDecoder::CryptoKeyDecoder;
		friend class internal::CryptoKeyDecoder<RSAPublicKey>;
		friend class internal::CryptoDataReader<RSAPublicKey>;
	};

	/// @class PKCS8PrivateKeyAlgorithm
	/// Represents cryptographic algorithms used in PKCS#8 private keys
	/// This class encapsulates various hashing and signature algorithms that can be used
	/// in PKCS#8 private keys.
	class PKCS8PrivateKeyAlgorithm
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

		PKCS8PrivateKeyAlgorithm() = default;

		// cppcheck-suppress noExplicitConstructor
		/// Construct LdapOperationType from Value enum
		/// @param[in] value the operation type enum value
		constexpr PKCS8PrivateKeyAlgorithm(Value value) : m_Value(value)
		{}

		/// @return A string representation of the operation type
		std::string toString() const;

		/// @return The OID value of the operation type
		std::string getOidValue() const;

		/// A static method that creates LdapOperationType from an integer value
		/// @param[in] value The operation type integer value
		/// @return The operation type that corresponds to the integer value. If the integer value
		/// doesn't correspond to any operation type, LdapOperationType::Unknown is returned
		static PKCS8PrivateKeyAlgorithm fromOidValue(const Asn1ObjectIdentifier& value);

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

	class PKCS8PrivateKey : public internal::CryptoKeyDecoder<PKCS8PrivateKey>,
	                        public internal::CryptoDataReader<PKCS8PrivateKey>
	{
	public:
		/// @class X509ExtensionData
		/// A base class for X509 extension data
		class PrivateKeyData
		{
		public:
			virtual ~PrivateKeyData() = default;

			/// A templated method that accepts a class derived from X509ExtensionData as its template argument and
			/// attempts to cast the current instance to that type
			/// @tparam PrivateKeyDataType The type to cast to
			/// @return A pointer to the type after casting
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
			PrivateKeyData(const std::string& rawData);
			Asn1SequenceRecord* getRoot() const
			{
				return m_Root->castAs<Asn1SequenceRecord>();
			}

			std::vector<uint8_t> m_DerData;
			std::unique_ptr<Asn1Record> m_Root;
		};

		class RSAPrivateKeyData : public PrivateKeyData, public internal::RSAPrivateKeyData
		{
			friend class PKCS8PrivateKey;
			RSAPrivateKeyData(const std::string& rawData);
		};

		class ECPrivateKeyData : public PrivateKeyData, public internal::ECPrivateKeyData
		{
			friend class PKCS8PrivateKey;
			ECPrivateKeyData(const std::string& rawData);
		};

		class Ed25519PrivateKeyData : public PrivateKeyData
		{
			friend class PKCS8PrivateKey;
			Ed25519PrivateKeyData(const std::string& rawData);

		public:
			std::string getPrivateKey() const;
		};

		uint8_t getVersion() const;
		PKCS8PrivateKeyAlgorithm getPrivateKeyAlgorithm() const;
		std::unique_ptr<PrivateKeyData> getPrivateKey() const;

	private:
		static constexpr const char* pemLabel = "PRIVATE KEY";
		static constexpr const char* keyType = "PKCS#8 private key";
		static constexpr int versionIndex = 0;
		static constexpr int privateKeyAlgorithmIndex = 1;
		static constexpr int privateKeyIndex = 2;

		using CryptoKeyDecoder::CryptoKeyDecoder;
		friend class internal::CryptoKeyDecoder<PKCS8PrivateKey>;
		friend class internal::CryptoDataReader<PKCS8PrivateKey>;
	};
}  // namespace pcpp
