#pragma once
#include "CryptoDataReader.h"
#include "Asn1Codec.h"
#include <string>
#include <memory>

namespace pcpp
{
	namespace internal
	{
		class CryptoKeyDecoder
		{
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

			virtual std::string getType() const = 0;

			template <class Asn1RecordType>
			Asn1RecordType* castSubRecordAs(int index, const std::string& fieldName) const
			{
				try
				{
					return getRoot()->getSubRecords().at(index)->castAs<Asn1RecordType>();
				}
				catch (const std::exception&)
				{
					throw std::runtime_error("Invalid " + getType() + " data: " + fieldName);
				}
			}

		private:
			std::unique_ptr<uint8_t[]> m_DerData;
			std::unique_ptr<Asn1Record> m_Root;
		};
	}

	class RSAPrivateKey : public internal::CryptoDataReader<RSAPrivateKey>, internal::CryptoKeyDecoder
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
		static constexpr int versionIndex = 0;
		static constexpr int modulusIndex = 1;
		static constexpr int publicExponentIndex = 2;
		static constexpr int privateExponentIndex = 3;
		static constexpr int prime1Index = 4;
		static constexpr int prime2Index = 5;
		static constexpr int exponent1Index = 6;
		static constexpr int exponent2Index = 7;
		static constexpr int coefficientIndex = 8;

		friend class internal::CryptoDataReader<RSAPrivateKey>;

		using CryptoKeyDecoder::CryptoKeyDecoder;

		std::string getType() const override { return "RSA private key"; }
	};

	class RSAPublicKey : public internal::CryptoDataReader<RSAPublicKey>, internal::CryptoKeyDecoder
	{
	public:
		std::string getModulus() const;
		uint64_t getPublicExponent() const;
	private:
		static constexpr const char* pemLabel = "RSA PUBLIC KEY";
		static constexpr int modulusIndex = 0;
		static constexpr int publicExponentIndex = 1;

		friend class internal::CryptoDataReader<RSAPublicKey>;

		using CryptoKeyDecoder::CryptoKeyDecoder;

		std::string getType() const override { return "RSA public key"; }
	};
}
