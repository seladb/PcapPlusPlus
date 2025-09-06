#include "CryptoKeyDecoder.h"
#include <unordered_map>

namespace pcpp
{
	namespace internal
	{
		uint8_t RSAPrivateKeyDataView::getVersion() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(versionOffset, "version")->getIntValue<uint8_t>();
		}

		std::string RSAPrivateKeyDataView::getModulus() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(modulusOffset, "modulus")->getValueAsString(true);
		}

		uint64_t RSAPrivateKeyDataView::getPublicExponent() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(publicExponentOffset, "public exponent")->getIntValue<uint64_t>();
		}

		std::string RSAPrivateKeyDataView::getPrivateExponent() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(privateExponentOffset, "private exponent")
			    ->getValueAsString(true);
		}

		std::string RSAPrivateKeyDataView::getPrime1() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(prime1Offset, "prime1")->getValueAsString(true);
		}

		std::string RSAPrivateKeyDataView::getPrime2() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(prime2Offset, "prime2")->getValueAsString(true);
		}

		std::string RSAPrivateKeyDataView::getExponent1() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(exponent1Offset, "exponent1")->getValueAsString(true);
		}

		std::string RSAPrivateKeyDataView::getExponent2() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(exponent2Offset, "exponent2")->getValueAsString(true);
		}

		std::string RSAPrivateKeyDataView::getCoefficient() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(coefficientOffset, "coefficient")->getValueAsString(true);
		}

		ECPrivateKeyDataView::ECPrivateKeyDataView(Asn1SequenceRecord* root, std::string decoderType)
		    : PrivateKeyDataView(root, decoderType)
		{
			for (size_t currOffset = 2; currOffset < root->getSubRecords().size(); currOffset++)
			{
				auto record = root->getSubRecords().at(currOffset);

				if (record->getTagClass() != Asn1TagClass::ContextSpecific)
				{
					continue;
				}

				switch (record->getTagType())
				{
				case 0:
				{
					m_ParametersOffset = currOffset;
					break;
				}
				case 1:
				{
					m_PublicKeyOffset = currOffset;
					break;
				}
				default:
				{
					break;
				}
				}
			}
		}

		uint8_t ECPrivateKeyDataView::getVersion() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(versionOffset, "version")->getIntValue<uint8_t>();
		}

		std::string ECPrivateKeyDataView::getPrivateKey() const
		{
			return castSubRecordAs<Asn1OctetStringRecord>(privateKeyOffset, "private key")->getValue();
		}

		std::unique_ptr<Asn1ObjectIdentifier> ECPrivateKeyDataView::getParameters() const
		{
			if (m_ParametersOffset == -1)
			{
				return nullptr;
			}

			auto parametersRecord = castSubRecordAs<Asn1ConstructedRecord>(m_ParametersOffset, "parameters");
			auto firstParamRecord = parametersRecord->getSubRecords().at(0);
			if (firstParamRecord->getUniversalTagType() != Asn1UniversalTagType::ObjectIdentifier)
			{
				return nullptr;
			}

			return std::make_unique<Asn1ObjectIdentifier>(
			    firstParamRecord->castAs<Asn1ObjectIdentifierRecord>()->getValue());
		}

		std::string ECPrivateKeyDataView::getPublicKey() const
		{
			if (m_PublicKeyOffset == -1)
			{
				return {};
			}

			auto publicKeyRecord = castSubRecordAs<Asn1ConstructedRecord>(m_PublicKeyOffset, "public key");
			auto firstPublicKeyRecord = publicKeyRecord->getSubRecords().at(0);
			if (firstPublicKeyRecord->getUniversalTagType() != Asn1UniversalTagType::BitString)
			{
				return {};
			}

			auto vecValue = firstPublicKeyRecord->castAs<Asn1BitStringRecord>()->getVecValue();
			return byteArrayToHexString(vecValue.data(), vecValue.size());
		}
	}  // namespace internal

	std::string RSAPublicKey::getModulus() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(modulusOffset, "modulus")->getValueAsString(true);
	}

	uint64_t RSAPublicKey::getPublicExponent() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(publicExponentOffset, "public exponent")->getIntValue<uint64_t>();
	}

	std::string CryptographicKeyAlgorithm::toString() const
	{
		switch (m_Value)
		{
		case RSA:
			return "RSA";
		case DSA:
			return "DSA";
		case ECDSA:
			return "ECDSA";
		case ED25519:
			return "Ed25519";
		case ED448:
			return "ED448";
		case DiffieHellman:
			return "DiffieHellman";
		case X448:
			return "X448";
		case Unknown:
		default:
			return "Unknown";
		}
	}

	std::string CryptographicKeyAlgorithm::getOidValue() const
	{
		switch (m_Value)
		{
		case RSA:
			return "1.2.840.113549.1.1.1";
		case DSA:
			return "1.2.840.10040.4.1";
		case ECDSA:
			return "1.2.840.10045.2.1";
		case ED25519:
			return "1.3.101.112";
		case ED448:
			return "1.3.101.113";
		case DiffieHellman:
			return "1.2.840.113549.1.3.1";
		case X448:
			return "1.3.101.111";
		case Unknown:
		default:
			return "0.0";
		}
	}

	static const std::unordered_map<std::string, CryptographicKeyAlgorithm::Value> X509AlgorithmOidMap = {
		{ "1.2.840.113549.1.1.1", CryptographicKeyAlgorithm::RSA           },
		{ "1.2.840.10040.4.1",    CryptographicKeyAlgorithm::DSA           },
		{ "1.2.840.10045.2.1",    CryptographicKeyAlgorithm::ECDSA         },
		{ "1.3.101.112",          CryptographicKeyAlgorithm::ED25519       },
		{ "1.3.101.113",          CryptographicKeyAlgorithm::ED448         },
		{ "1.2.840.113549.1.3.1", CryptographicKeyAlgorithm::DiffieHellman },
		{ "1.3.101.111",          CryptographicKeyAlgorithm::X448          },
	};

	CryptographicKeyAlgorithm CryptographicKeyAlgorithm::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStringValue = value.toString();

		auto it = X509AlgorithmOidMap.find(oidStringValue);
		if (it != X509AlgorithmOidMap.end())
		{
			return { it->second };
		}

		return { Unknown };
	}

	uint8_t PKCS8PrivateKey::getVersion() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(versionOffset, "version")->getIntValue<uint8_t>();
	}

	CryptographicKeyAlgorithm PKCS8PrivateKey::getPrivateKeyAlgorithm() const
	{
		auto oidValue = castSubRecordAs<Asn1SequenceRecord>(privateKeyAlgorithmOffset, "private key algorithm")
		                    ->getSubRecords()
		                    .at(0)
		                    ->castAs<Asn1ObjectIdentifierRecord>()
		                    ->getValue();
		return CryptographicKeyAlgorithm::fromOidValue(oidValue);
	}

	std::unique_ptr<PKCS8PrivateKey::PrivateKeyData> PKCS8PrivateKey::getPrivateKey() const
	{
		auto rawData = castSubRecordAs<Asn1OctetStringRecord>(privateKeyOffset, "private key")->getValue();

		auto privateKeyAlgorithm = CryptographicKeyAlgorithm::Unknown;
		try
		{
			privateKeyAlgorithm = getPrivateKeyAlgorithm();
		}
		catch (...)
		{
			throw std::runtime_error("Invalid " + std::string(keyType) +
			                         " data: cannot get private key because fetching the private key algorithm failed");
		}

		switch (privateKeyAlgorithm)
		{
		case CryptographicKeyAlgorithm::RSA:
		{
			return std::unique_ptr<PrivateKeyData>(new RSAPrivateKeyData(rawData));
		}
		case CryptographicKeyAlgorithm::ECDSA:
		{
			return std::unique_ptr<PrivateKeyData>(new ECPrivateKeyData(rawData));
		}
		case CryptographicKeyAlgorithm::ED25519:
		{
			return std::unique_ptr<PrivateKeyData>(new Ed25519PrivateKeyData(rawData));
		}
		default:
		{
			return nullptr;
		}
		}
	}

	PKCS8PrivateKey::PrivateKeyData::PrivateKeyData(const std::string& rawData)
	{
		m_DerData.resize(rawData.length() / 2);
		hexStringToByteArray(rawData, m_DerData.data(), m_DerData.size());
		m_Root = Asn1Record::decode(m_DerData.data(), m_DerData.size());
	}

	PKCS8PrivateKey::RSAPrivateKeyData::RSAPrivateKeyData(const std::string& rawData)
	    : PKCS8PrivateKey::PrivateKeyData(rawData), internal::RSAPrivateKeyDataView(getRoot(), "PKCS#8 RSA private key")
	{}

	PKCS8PrivateKey::ECPrivateKeyData::ECPrivateKeyData(const std::string& rawData)
	    : PKCS8PrivateKey::PrivateKeyData(rawData), internal::ECPrivateKeyDataView(getRoot(), "PKCS#8 EC private key")
	{}

	PKCS8PrivateKey::Ed25519PrivateKeyData::Ed25519PrivateKeyData(const std::string& rawData)
	    : PKCS8PrivateKey::PrivateKeyData(rawData)
	{}

	std::string PKCS8PrivateKey::Ed25519PrivateKeyData::getPrivateKey() const
	{
		try
		{
			return m_Root->castAs<Asn1OctetStringRecord>()->getValue();
		}
		catch (...)
		{
			throw std::runtime_error("Invalid PKCS#8 Ed25519 data");
		}
	}

	CryptographicKeyAlgorithm SubjectPublicKeyInfo::getAlgorithm() const
	{
		auto algorithmRecord = castSubRecordAs<Asn1SequenceRecord>(algorithmOffset, "algorithm record");
		if (algorithmRecord->getSubRecords().size() < 1)
		{
			return CryptographicKeyAlgorithm::Unknown;
		}

		try
		{
			return CryptographicKeyAlgorithm::fromOidValue(
			    algorithmRecord->getSubRecords().at(0)->castAs<Asn1ObjectIdentifierRecord>()->getValue());
		}
		catch (const std::exception&)
		{
			throw std::runtime_error("Invalid public key data: algorithm identifier");
		}
	}

	std::string SubjectPublicKeyInfo::getSubjectPublicKey() const
	{
		auto vecValue =
		    castSubRecordAs<Asn1BitStringRecord>(subjectPublicKeyOffset, "subject public key")->getVecValue();
		return byteArrayToHexString(vecValue.data(), vecValue.size());
	}
}  // namespace pcpp
