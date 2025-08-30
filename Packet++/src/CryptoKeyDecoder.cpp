#include "CryptoKeyDecoder.h"

#include <iostream>
#include <unordered_map>

namespace pcpp
{
	namespace internal
	{
		uint8_t RSAPrivateKeyData::getVersion() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(versionIndex, "version")->getIntValue<uint8_t>();
		}

		std::string RSAPrivateKeyData::getModulus() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(modulusIndex, "modulus")->getValueAsString(true);
		}

		uint64_t RSAPrivateKeyData::getPublicExponent() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(publicExponentIndex, "public exponent")->getIntValue<uint64_t>();
		}

		std::string RSAPrivateKeyData::getPrivateExponent() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(privateExponentIndex, "private exponent")->getValueAsString(true);
		}

		std::string RSAPrivateKeyData::getPrime1() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(prime1Index, "prime1")->getValueAsString(true);
		}

		std::string RSAPrivateKeyData::getPrime2() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(prime2Index, "prime2")->getValueAsString(true);
		}

		std::string RSAPrivateKeyData::getExponent1() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(exponent1Index, "exponent1")->getValueAsString(true);
		}

		std::string RSAPrivateKeyData::getExponent2() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(exponent2Index, "exponent2")->getValueAsString(true);
		}

		std::string RSAPrivateKeyData::getCoefficient() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(coefficientIndex, "coefficient")->getValueAsString(true);
		}

		ECPrivateKeyData::ECPrivateKeyData(Asn1SequenceRecord* root, std::string decoderType)
		    : PrivateKeyData(root, decoderType)
		{
			size_t currIndex = 2;
			while (root->getSubRecords().size() > currIndex)
			{
				auto record = root->getSubRecords().at(currIndex);

				if (record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 0)
				{
					m_ParametersIndex = currIndex;
				}
				else if (record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 1)
				{
					m_PublicKeyIndex = currIndex;
				}
				currIndex++;
			}
		}

		uint8_t ECPrivateKeyData::getVersion() const
		{
			return castSubRecordAs<Asn1IntegerRecord>(versionIndex, "version")->getIntValue<uint8_t>();
		}

		std::string ECPrivateKeyData::getPrivateKey() const
		{
			return castSubRecordAs<Asn1OctetStringRecord>(privateKeyIndex, "private key")->getValue();
		}

		std::unique_ptr<Asn1ObjectIdentifier> ECPrivateKeyData::getParameters() const
		{
			if (m_ParametersIndex == -1)
			{
				return nullptr;
			}

			auto parametersRecord = castSubRecordAs<Asn1ConstructedRecord>(m_ParametersIndex, "parameters");
			auto firstParamRecord = parametersRecord->getSubRecords().at(0);
			if (firstParamRecord->getUniversalTagType() != Asn1UniversalTagType::ObjectIdentifier)
			{
				return nullptr;
			}

			return std::make_unique<Asn1ObjectIdentifier>(
			    firstParamRecord->castAs<Asn1ObjectIdentifierRecord>()->getValue());
		}

		std::string ECPrivateKeyData::getPublicKey() const
		{
			if (m_PublicKeyIndex == -1)
			{
				return {};
			}

			auto publicKeyRecord = castSubRecordAs<Asn1ConstructedRecord>(m_PublicKeyIndex, "public key");
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
		return castSubRecordAs<Asn1IntegerRecord>(modulusIndex, "modulus")->getValueAsString(true);
	}

	uint64_t RSAPublicKey::getPublicExponent() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(publicExponentIndex, "public exponent")->getIntValue<uint64_t>();
	}

	std::string PKCS8PrivateKeyAlgorithm::toString() const
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
			return "ED25519";
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

	std::string PKCS8PrivateKeyAlgorithm::getOidValue() const
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

	static const std::unordered_map<std::string, PKCS8PrivateKeyAlgorithm::Value> X509AlgorithmOidMap = {
		{ "1.2.840.113549.1.1.1", PKCS8PrivateKeyAlgorithm::RSA           },
		{ "1.2.840.10040.4.1",    PKCS8PrivateKeyAlgorithm::DSA           },
		{ "1.2.840.10045.2.1",    PKCS8PrivateKeyAlgorithm::ECDSA         },
		{ "1.3.101.112",          PKCS8PrivateKeyAlgorithm::ED25519       },
		{ "1.3.101.113",          PKCS8PrivateKeyAlgorithm::ED448         },
		{ "1.2.840.113549.1.3.1", PKCS8PrivateKeyAlgorithm::DiffieHellman },
		{ "1.3.101.111",          PKCS8PrivateKeyAlgorithm::X448          },
	};

	PKCS8PrivateKeyAlgorithm PKCS8PrivateKeyAlgorithm::fromOidValue(const Asn1ObjectIdentifier& value)
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
		return castSubRecordAs<Asn1IntegerRecord>(versionIndex, "version")->getIntValue<uint8_t>();
	}

	PKCS8PrivateKeyAlgorithm PKCS8PrivateKey::getPrivateKeyAlgorithm() const
	{
		auto oidValue = castSubRecordAs<Asn1SequenceRecord>(privateKeyAlgorithmIndex, "private key algorithm")
		                    ->getSubRecords()
		                    .at(0)
		                    ->castAs<Asn1ObjectIdentifierRecord>()
		                    ->getValue();
		return PKCS8PrivateKeyAlgorithm::fromOidValue(oidValue);
	}

	std::unique_ptr<PKCS8PrivateKey::PrivateKeyData> PKCS8PrivateKey::getPrivateKey() const
	{
		auto rawData = castSubRecordAs<Asn1OctetStringRecord>(privateKeyIndex, "private key")->getValue();
		switch (getPrivateKeyAlgorithm())
		{
		case PKCS8PrivateKeyAlgorithm::RSA:
		{
			return std::unique_ptr<PrivateKeyData>(new RSAPrivateKeyData(rawData));
		}
		case PKCS8PrivateKeyAlgorithm::ECDSA:
		{
			return std::unique_ptr<PrivateKeyData>(new ECPrivateKeyData(rawData));
		}
		case PKCS8PrivateKeyAlgorithm::ED25519:
		{
			return std::unique_ptr<PrivateKeyData>(new Ed25519PrivateKeyData(rawData));
		}
		default:
		{
			return {};
		}
		}
	}

	PKCS8PrivateKey::PrivateKeyData::PrivateKeyData(const std::string& rawData)
	{
		m_DerData.resize(rawData.length() / 2);
		hexStringToByteArray(rawData, m_DerData.data(), rawData.length() / 2);
		m_Root = Asn1Record::decode(m_DerData.data(), rawData.size());
	}

	PKCS8PrivateKey::RSAPrivateKeyData::RSAPrivateKeyData(const std::string& rawData)
	    : PKCS8PrivateKey::PrivateKeyData(rawData), internal::RSAPrivateKeyData(getRoot(), "PKCS#8 RSA private key")
	{}

	PKCS8PrivateKey::ECPrivateKeyData::ECPrivateKeyData(const std::string& rawData)
	    : PKCS8PrivateKey::PrivateKeyData(rawData), internal::ECPrivateKeyData(getRoot(), "PKCS#8 EC private key")
	{}

	PKCS8PrivateKey::Ed25519PrivateKeyData::Ed25519PrivateKeyData(const std::string& rawData)
	    : PKCS8PrivateKey::PrivateKeyData(rawData)
	{}

	std::string PKCS8PrivateKey::Ed25519PrivateKeyData::getPrivateKey() const
	{
		return m_Root->castAs<Asn1OctetStringRecord>()->getValue();
	}
}  // namespace pcpp
