#pragma once
#include "CryptoDataReader.h"
#include "Asn1Codec.h"
#include <string>
#include <memory>

namespace pcpp
{
	namespace internal
	{
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

			Asn1SequenceRecord* CryptoKeyDecoder::getRoot() const
			{
				return m_Root->castAs<Asn1SequenceRecord>();
			}

			template <class Asn1RecordType>
			Asn1RecordType* castSubRecordAs(int index, const std::string& fieldName) const
			{
				try
				{
					return getRoot()->getSubRecords().at(index)->castAs<Asn1RecordType>();
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
	                      public internal::CryptoDataReader<RSAPrivateKey>
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

	private:
		static constexpr const char* pemLabel = "RSA PRIVATE KEY";
		static constexpr const char* keyType = "RSA private key";
		static constexpr int versionIndex = 0;
		static constexpr int modulusIndex = 1;
		static constexpr int publicExponentIndex = 2;
		static constexpr int privateExponentIndex = 3;
		static constexpr int prime1Index = 4;
		static constexpr int prime2Index = 5;
		static constexpr int exponent1Index = 6;
		static constexpr int exponent2Index = 7;
		static constexpr int coefficientIndex = 8;

		using CryptoKeyDecoder::CryptoKeyDecoder;
		friend class internal::CryptoKeyDecoder<RSAPrivateKey>;
		friend class internal::CryptoDataReader<RSAPrivateKey>;
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
}  // namespace pcpp
