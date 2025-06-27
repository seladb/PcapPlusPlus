#include "X509Decoder.h"
#include "Asn1Codec.h"
#include <iostream>
#include <unordered_map>

namespace pcpp
{
	std::string X509Algorithm::toString() const
	{
		switch (m_Value)
		{
		case Sha1:                     return "Sha1";
		case Sha256:                   return "Sha256";
		case Sha384:                   return "Sha384";
		case Sha512:                   return "Sha512";
		case Md5:                      return "Md5";
		case RsaEncryption:           return "RsaEncryption";
		case Sha1WithRsaEncryption:   return "Sha1WithRsaEncryption";
		case Sha256WithRsaEncryption: return "Sha256WithRsaEncryption";
		case Sha384WithRsaEncryption: return "Sha384WithRsaEncryption";
		case Sha512WithRsaEncryption: return "Sha512WithRsaEncryption";
		case Ecdsa:                   return "Ecdsa";
		case EcdsaWithSha1:           return "EcdsaWithSha1";
		case EcdsaWithSha256:         return "EcdsaWithSha256";
		case EcdsaWithSha384:         return "EcdsaWithSha384";
		case EcdsaWithSha512:         return "EcdsaWithSha512";
		case Ed25519:                 return "Ed25519";
		case Ed448:                   return "Ed448";
		case Dsa:                     return "Dsa";
		case DsaWithSha1:             return "DsaWithSha1";
		case DsaWithSha256:           return "DsaWithSha256";
		case Rsa:                     return "Rsa";
		case RsaPss:                  return "RsaPss";
		case DiffieHellman:           return "DiffieHellman";
		case Unknown:
		default:                      return "Unknown";
		}
	}

	std::string X509Algorithm::getOidValue() const
	{
		switch (m_Value)
		{
		case Sha1:                     return "1.3.14.3.2.26";
		case Sha256:                   return "2.16.840.1.101.3.4.2.1";
		case Sha384:                   return "2.16.840.1.101.3.4.2.2";
		case Sha512:                   return "2.16.840.1.101.3.4.2.3";
		case Md5:                      return "1.2.840.113549.2.5";

		case RsaEncryption:           return "1.2.840.113549.1.1.1";
		case Sha1WithRsaEncryption:   return "1.2.840.113549.1.1.5";
		case Sha256WithRsaEncryption: return "1.2.840.113549.1.1.11";
		case Sha384WithRsaEncryption: return "1.2.840.113549.1.1.12";
		case Sha512WithRsaEncryption: return "1.2.840.113549.1.1.13";

		case Ecdsa:                   return "1.2.840.10045.2.1";
		case EcdsaWithSha1:           return "1.2.840.10045.4.1";
		case EcdsaWithSha256:         return "1.2.840.10045.4.3.2";
		case EcdsaWithSha384:         return "1.2.840.10045.4.3.3";
		case EcdsaWithSha512:         return "1.2.840.10045.4.3.4";

		case Ed25519:                 return "1.3.101.112";
		case Ed448:                   return "1.3.101.113";

		case Dsa:                     return "1.2.840.10040.4.1";
		case DsaWithSha1:             return "1.2.840.10040.4.3";
		case DsaWithSha256:           return "2.16.840.1.101.3.4.3.2";

		case Rsa:                     return "1.2.840.113549.1.1.1";
		case RsaPss:                  return "1.2.840.113549.1.1.10";

		case DiffieHellman:           return "1.2.840.113549.1.3.1";

		case Unknown:
		default:                      return "0.0";
		}
	}

	X509Algorithm X509Algorithm::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStringValue = value.toString();
		static const std::unordered_map<std::string, Value> oidMap = {
			{"1.3.14.3.2.26", Sha1},
			{"2.16.840.1.101.3.4.2.1", Sha256},
			{"2.16.840.1.101.3.4.2.2", Sha384},
			{"2.16.840.1.101.3.4.2.3", Sha512},
			{"1.2.840.113549.2.5", Md5},

			{"1.2.840.113549.1.1.1", RsaEncryption},
			{"1.2.840.113549.1.1.5", Sha1WithRsaEncryption},
			{"1.2.840.113549.1.1.11", Sha256WithRsaEncryption},
			{"1.2.840.113549.1.1.12", Sha384WithRsaEncryption},
			{"1.2.840.113549.1.1.13", Sha512WithRsaEncryption},

			{"1.2.840.10045.2.1", Ecdsa},
			{"1.2.840.10045.4.1", EcdsaWithSha1},
			{"1.2.840.10045.4.3.2", EcdsaWithSha256},
			{"1.2.840.10045.4.3.3", EcdsaWithSha384},
			{"1.2.840.10045.4.3.4", EcdsaWithSha512},

			{"1.2.840.10040.4.1", Dsa},
			{"1.2.840.10040.4.3", DsaWithSha1},
			{"2.16.840.1.101.3.4.3.2", DsaWithSha256},

			{"1.3.101.112", Ed25519},
			{"1.3.101.113", Ed448},

			{"1.2.840.113549.1.1.1", Rsa},
			{"1.2.840.113549.1.1.10", RsaPss},

			{"1.2.840.113549.1.3.1", DiffieHellman}
		};

		auto it = oidMap.find(oidStringValue);
		if (it != oidMap.end())
		{
			return {it->second};
		}

		return {Unknown};
	}

	std::string X520DistinguishedName::toString() const
	{
		switch (m_Value)
		{
		case CommonName:              return "CommonName";
		case Surname:                 return "Surname";
		case SerialNumber:            return "SerialNumber";
		case CountryName:             return "CountryName";
		case LocalityName:            return "LocalityName";
		case StateOrProvinceName:     return "StateOrProvinceName";
		case OrganizationName:        return "OrganizationName";
		case OrganizationalUnitName: return "OrganizationalUnitName";
		case Title:                   return "Title";
		case GivenName:               return "GivenName";
		case Initials:                return "Initials";
		case Pseudonym:               return "Pseudonym";
		case GenerationQualifier:     return "GenerationQualifier";
		case DnQualifier:             return "DnQualifier";
		case DomainComponent:         return "DomainComponent";
		case EmailAddress:            return "EmailAddress";
		case Unknown:
		default:                      return "Unknown";
		}
	}

	std::string X520DistinguishedName::getOidValue() const
	{
		switch (m_Value)
		{
		case CommonName:              return "2.5.4.3";
		case Surname:                 return "2.5.4.4";
		case SerialNumber:            return "2.5.4.5";
		case CountryName:             return "2.5.4.6";
		case LocalityName:            return "2.5.4.7";
		case StateOrProvinceName:     return "2.5.4.8";
		case OrganizationName:        return "2.5.4.10";
		case OrganizationalUnitName: return "2.5.4.11";
		case Title:                   return "2.5.4.12";
		case GivenName:               return "2.5.4.42";
		case Initials:                return "2.5.4.43";
		case GenerationQualifier:     return "2.5.4.44";
		case DnQualifier:             return "2.5.4.46";
		case Pseudonym:               return "2.5.4.65";
		case DomainComponent:         return "0.9.2342.19200300.100.1.25"; // from pilot attributes
		case EmailAddress:            return "1.2.840.113549.1.9.1";      // pkcs9 emailAddress
		case Unknown:
		default:                      return "0.0";
		}
	}

	X520DistinguishedName X520DistinguishedName::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStringValue = value.toString();
		static const std::unordered_map<std::string, Value> oidMap = {
		    {"2.5.4.3", CommonName},
		    {"2.5.4.4", Surname},
		    {"2.5.4.5", SerialNumber},
		    {"2.5.4.6", CountryName},
		    {"2.5.4.7", LocalityName},
		    {"2.5.4.8", StateOrProvinceName},
		    {"2.5.4.10", OrganizationName},
		    {"2.5.4.11", OrganizationalUnitName},
		    {"2.5.4.12", Title},
		    {"2.5.4.42", GivenName},
		    {"2.5.4.43", Initials},
		    {"2.5.4.44", GenerationQualifier},
		    {"2.5.4.46", DnQualifier},
		    {"2.5.4.65", Pseudonym},
		    {"0.9.2342.19200300.100.1.25", DomainComponent},
		    {"1.2.840.113549.1.9.1", EmailAddress}
		};

		auto it = oidMap.find(oidStringValue);
		if (it != oidMap.end())
		{
			return {it->second};
		}

		return {Unknown};
	}

	std::string X509ExtensionType::toString() const
	{
		switch (m_Value)
		{
		case BasicConstraints:      return "BasicConstraints";
		case KeyUsage:              return "KeyUsage";
		case ExtendedKeyUsage:      return "ExtendedKeyUsage";
		case SubjectKeyIdentifier:  return "SubjectKeyIdentifier";
		case AuthorityKeyIdentifier:return "AuthorityKeyIdentifier";
		case SubjectAltName:        return "SubjectAltName";
		case IssuerAltName:         return "IssuerAltName";
		case CrlDistributionPoints: return "CRLDistributionPoints";
		case AuthorityInfoAccess:   return "AuthorityInfoAccess";
		case CertificatePolicies:   return "CertificatePolicies";
		case PolicyMappings:        return "PolicyMappings";
		case PolicyConstraints:     return "PolicyConstraints";
		case NameConstraints:       return "NameConstraints";
		case InhibitAnyPolicy:      return "InhibitAnyPolicy";
		case Unknown:
		default:                    return "Unknown";
		}
	}

	std::string X509ExtensionType::getOidValue() const
	{
		switch (m_Value)
		{
		case BasicConstraints:       return "2.5.29.19";
		case KeyUsage:               return "2.5.29.15";
		case ExtendedKeyUsage:       return "2.5.29.37";
		case SubjectKeyIdentifier:   return "2.5.29.14";
		case AuthorityKeyIdentifier: return "2.5.29.35";
		case SubjectAltName:         return "2.5.29.17";
		case IssuerAltName:          return "2.5.29.18";
		case CrlDistributionPoints:  return "2.5.29.31";
		case AuthorityInfoAccess:    return "1.3.6.1.5.5.7.1.1";
		case CertificatePolicies:    return "2.5.29.32";
		case PolicyMappings:         return "2.5.29.33";
		case PolicyConstraints:      return "2.5.29.36";
		case NameConstraints:        return "2.5.29.30";
		case InhibitAnyPolicy:       return "2.5.29.54";
		case Unknown:
		default:                     return "0.0";
		}
	}

	X509ExtensionType X509ExtensionType::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStr = value.toString();
		static const std::unordered_map<std::string, Value> oidMap = {
			{"2.5.29.19",  BasicConstraints},
			{"2.5.29.15",  KeyUsage},
			{"2.5.29.37",  ExtendedKeyUsage},
			{"2.5.29.14",  SubjectKeyIdentifier},
			{"2.5.29.35",  AuthorityKeyIdentifier},
			{"2.5.29.17",  SubjectAltName},
			{"2.5.29.18",  IssuerAltName},
			{"2.5.29.31",  CrlDistributionPoints},
			{"1.3.6.1.5.5.7.1.1", AuthorityInfoAccess},
			{"2.5.29.32",  CertificatePolicies},
			{"2.5.29.33",  PolicyMappings},
			{"2.5.29.36",  PolicyConstraints},
			{"2.5.29.30",  NameConstraints},
			{"2.5.29.54",  InhibitAnyPolicy}
		};

		auto it = oidMap.find(oidStr);
		if (it != oidMap.end())
			return {it->second};

		return {Unknown};
	}

	X509Version X509VersionRecord::getVersion() const
	{
		auto intValue = m_Root->getSubRecords().at(0)->castAs<Asn1IntegerRecord>()->getIntValue<uint8_t>();
		if (intValue > 3)
		{
			throw std::runtime_error("Invalid X509 version value: " + std::to_string(intValue));
		}

		return static_cast<X509Version>(intValue);
	}

	bool X509VersionRecord::isValidVersionRecord(const Asn1Record* record)
	{
		return (record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 0 && record->isConstructed());
	}

	Asn1Record* X509RelativeDistinguishedName::getRecord(int index) const
	{
		auto attributeTypeAndValue = m_Root->getSubRecords().at(0)->castAs<Asn1SequenceRecord>();
		return attributeTypeAndValue->getSubRecords().at(index);
	}

	X520DistinguishedName X509RelativeDistinguishedName::getType() const
	{
		auto oidRecord = getRecord(m_TypeOffset)->castAs<Asn1ObjectIdentifierRecord>();
		return X520DistinguishedName::fromOidValue(oidRecord->getValue());
	}

	std::string X509RelativeDistinguishedName::getValue() const
	{
		auto valueRecord = getRecord(m_ValueOffset);
		switch (valueRecord->getUniversalTagType())
		{
		case Asn1UniversalTagType::PrintableString:
		{
			return valueRecord->castAs<Asn1PrintableStringRecord>()->getValue();
		}
		case Asn1UniversalTagType::IA5String:
		{
			return valueRecord->castAs<Asn1IA5StringRecord>()->getValue();
		}
		case Asn1UniversalTagType::UTF8String:
		{
			return valueRecord->castAs<Asn1UTF8StringRecord>()->getValue();
		}
		default:
		{
			throw std::runtime_error("Unsupported X509RelativeDistinguishedName value: " + std::to_string(static_cast<int>(valueRecord->getUniversalTagType())));
		}
		}
	}

	std::vector<X509RelativeDistinguishedName> X509Name::getComponents() const
	{
		std::vector<X509RelativeDistinguishedName> result;
		for (auto const& subRecord: m_Root->getSubRecords())
		{
			result.push_back(X509RelativeDistinguishedName(subRecord->castAs<Asn1SetRecord>()));
		}

		return result;
	}

	X509Algorithm X509AlgorithmIdentifier::getAlgorithm() const
	{
		auto oidRecord = m_Root->getSubRecords().at(m_AlgorithmOffset)->castAs<Asn1ObjectIdentifierRecord>();
		return X509Algorithm::fromOidValue(oidRecord->getValue());
	}

	std::string X509Validity::getNotBeforeValue(const std::string& format, const std::string& timezone, bool includeMilliseconds) const
	{
		return m_Root->getSubRecords().at(m_NotBeforeOffset)->castAs<Asn1TimeRecord>()->getValueAsString(format, timezone, includeMilliseconds);
	}

	std::string X509Validity::getNotAfterValue(const std::string& format, const std::string& timezone, bool includeMilliseconds) const
	{
		return m_Root->getSubRecords().at(m_NotAfterOffset)->castAs<Asn1TimeRecord>()->getValueAsString(format, timezone, includeMilliseconds);
	}

	X509AlgorithmIdentifier X509SubjectPublicKeyInfo::getAlgorithm() const
	{
		auto root = m_Root->getSubRecords().at(m_AlgorithmOffset)->castAs<Asn1SequenceRecord>();
		return X509AlgorithmIdentifier(root);
	}

	std::string X509SubjectPublicKeyInfo::getSubjectPublicKey() const
	{
		return m_Root->getSubRecords().at(m_SubjectPublicKeyOffset)->castAs<Asn1BitStringRecord>()->getValue();
	}

	X509Extension::X509Extension(Asn1SequenceRecord* root) : X509Base(root)
	{
		if (root->getSubRecords().size() > 2)
		{
			m_CriticalOffset = 1;
			m_ExtensionValueOffset = 2;
		}
	}

	X509ExtensionType X509Extension::getType() const
	{
		auto extensionTypeRecord = m_Root->getSubRecords().at(m_ExtensionIdOffset)->castAs<Asn1ObjectIdentifierRecord>();
		return X509ExtensionType::fromOidValue(extensionTypeRecord->getValue());
	}

	bool X509Extension::getCritical() const
	{
		if (m_CriticalOffset == -1)
		{
			return false;
		}

		return m_Root->getSubRecords().at(m_CriticalOffset)->castAs<Asn1BooleanRecord>()->getValue();
	}

	std::string X509Extension::getValue() const
	{
		return m_Root->getSubRecords().at(m_ExtensionValueOffset)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	std::vector<X509Extension> X509Extensions::getExtensions() const
	{
		std::vector<X509Extension> result;
		for (const auto& extension : m_Root->getSubRecords().at(0)->castAs<Asn1SequenceRecord>()->getSubRecords())
		{
			result.push_back({extension->castAs<Asn1SequenceRecord>()});
		}

		return result;
	}

	bool X509Extensions::isValidExtensionsRecord(const Asn1Record* record)
	{
		return (record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 3 && record->isConstructed());
	}

	std::string X509TBSCertificate::getSerialNumber() const
	{
		return m_Root->getSubRecords().at(getIndex(m_SerialNumberOffset))->castAs<Asn1IntegerRecord>()->getValueAsString();
	}

	X509AlgorithmIdentifier X509TBSCertificate::getSignature() const
	{
		auto root = m_Root->getSubRecords().at(getIndex(m_SignatureOffset))->castAs<Asn1SequenceRecord>();
		return X509AlgorithmIdentifier(root);
	}

	X509TBSCertificate::X509TBSCertificate(Asn1SequenceRecord* root) : X509Base(root)
	{
		int currIndex = 0;
		auto record = root->getSubRecords().at(currIndex);
		if (X509VersionRecord::isValidVersionRecord(record))
		{
			m_VersionOffset = currIndex++;
		}

		m_SerialNumberOffset = currIndex++;
		m_SignatureOffset = currIndex++;
		m_IssuerOffset = currIndex++;
		m_ValidityOffset = currIndex++;
		m_SubjectOffset = currIndex++;
		m_SubjectPublicKeyInfoOffset = currIndex++;

		record = root->getSubRecords().at(currIndex);

		if (record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 1)
		{
			m_IssuerUniqueID = currIndex++;
			record = root->getSubRecords().at(currIndex);
		}

		if (record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 2)
		{
			m_SubjectUniqueID = currIndex++;
			record = root->getSubRecords().at(currIndex);
		}

		if (X509Extensions::isValidExtensionsRecord(record))
		{
			m_ExtensionsOffset = currIndex++;
		}
	}

	X509Version X509TBSCertificate::getVersion() const
	{
		if (m_VersionOffset == -1)
		{
			return X509Version::V1;
		}

		auto root = m_Root->getSubRecords().at(m_VersionOffset);
		auto versionRecord = X509VersionRecord(root->castAs<Asn1ConstructedRecord>());
		return versionRecord.getVersion();
	}

	X509Name X509TBSCertificate::getIssuer() const
	{
		auto root = m_Root->getSubRecords().at(getIndex(m_IssuerOffset))->castAs<Asn1SequenceRecord>();
		return X509Name(root);
	}

	X509Validity X509TBSCertificate::getValidity() const
	{
		auto root = m_Root->getSubRecords().at(getIndex(m_ValidityOffset))->castAs<Asn1SequenceRecord>();
		return X509Validity(root);
	}

	X509Name X509TBSCertificate::getSubject() const
	{
		auto root = m_Root->getSubRecords().at(getIndex(m_SubjectOffset))->castAs<Asn1SequenceRecord>();
		return X509Name(root);
	}

	X509SubjectPublicKeyInfo X509TBSCertificate::getSubjectPublicKeyInfo() const
	{
		auto root = m_Root->getSubRecords().at(getIndex(m_SubjectPublicKeyInfoOffset))->castAs<Asn1SequenceRecord>();
		return X509SubjectPublicKeyInfo(root);
	}

	std::unique_ptr<X509Extensions> X509TBSCertificate::getExtensions() const
	{
		if (m_ExtensionsOffset == -1)
		{
			return nullptr;
		}

		auto root = m_Root->getSubRecords().at(getIndex(m_ExtensionsOffset))->castAs<Asn1ConstructedRecord>();
		return std::unique_ptr<X509Extensions>(new X509Extensions(root));
	}

	std::unique_ptr<X509Certificate> X509Certificate::decode(const uint8_t* data, size_t dataLen)
	{
		return std::unique_ptr<X509Certificate>(new X509Certificate(Asn1Record::decode(data, dataLen)));
	}

	Asn1SequenceRecord* X509Certificate::getRoot() const
	{
		return m_Root->castAs<Asn1SequenceRecord>();
	}

	X509TBSCertificate X509Certificate::getTbsCertificate() const
	{
		auto root = getRoot()->getSubRecords().at(m_TBSCertificateOffset)->castAs<Asn1SequenceRecord>();
		return X509TBSCertificate(root);
	}

	X509AlgorithmIdentifier X509Certificate::getSignatureAlgorithm() const
	{
		auto root = getRoot()->getSubRecords().at(m_SignatureAlgorithmOffset)->castAs<Asn1SequenceRecord>();
		return X509AlgorithmIdentifier(root);
	}

	std::string X509Certificate::getSignature() const
	{
		return getRoot()->getSubRecords().at(m_SignatureOffset)->castAs<Asn1BitStringRecord>()->getValue();
	}
}