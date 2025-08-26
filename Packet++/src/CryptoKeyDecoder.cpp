#include "CryptoKeyDecoder.h"

namespace pcpp
{
	uint8_t RSAPrivateKey::getVersion() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(versionIndex, "version")->getIntValue<uint8_t>();
	}

	std::string RSAPrivateKey::getModulus() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(modulusIndex, "modulus")->getValueAsString(true);
	}

	uint64_t RSAPrivateKey::getPublicExponent() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(publicExponentIndex, "public exponent")->getIntValue<uint64_t>();
	}

	std::string RSAPrivateKey::getPrivateExponent() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(privateExponentIndex, "private exponent")->getValueAsString(true);
	}

	std::string RSAPrivateKey::getPrime1() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(prime1Index, "prime1")->getValueAsString(true);
	}

	std::string RSAPrivateKey::getPrime2() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(prime2Index, "prime2")->getValueAsString(true);
	}

	std::string RSAPrivateKey::getExponent1() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(exponent1Index, "exponent1")->getValueAsString(true);
	}

	std::string RSAPrivateKey::getExponent2() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(exponent2Index, "exponent2")->getValueAsString(true);
	}

	std::string RSAPrivateKey::getCoefficient() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(coefficientIndex, "coefficient")->getValueAsString(true);
	}

	std::string RSAPublicKey::getModulus() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(modulusIndex, "modulus")->getValueAsString(true);
	}

	uint64_t RSAPublicKey::getPublicExponent() const
	{
		return castSubRecordAs<Asn1IntegerRecord>(publicExponentIndex, "public exponent")->getIntValue<uint64_t>();
	}
}  // namespace pcpp
