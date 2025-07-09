#include "X509Decoder.h"
#include "Asn1Codec.h"
#include "GeneralUtils.h"
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <unordered_map>

namespace pcpp
{
	std::string X509Algorithm::toString() const
	{
		switch (m_Value)
		{
		case SHA1:             return "SHA1";
		case SHA256:           return "SHA256";
		case SHA384:           return "SHA384";
		case SHA512:           return "SHA512";
		case MD5:              return "MD5";
		case RSA:              return "RSA";
		case RSAWithSHA1:      return "RSAWithSHA1";
		case RSAWithSHA256:    return "RSAWithSHA256";
		case RSAWithSHA384:    return "RSAWithSHA384";
		case RSAWithSHA512:    return "RSAWithSHA512";
		case RSAPSS:           return "RSAPSS";
		case ECDSA:            return "ECDSA";
		case ECDSAWithSHA1:    return "ECDSAWithSHA1";
		case ECDSAWithSHA256:  return "ECDSAWithSHA256";
		case ECDSAWithSHA384:  return "ECDSAWithSHA384";
		case ECDSAWithSHA512:  return "ECDSAWithSHA512";
		case ED25519:          return "ED25519";
		case ED448:            return "ED448";
		case DSA:              return "DSA";
		case DSAWithSHA1:      return "DSAWithSHA1";
		case DSAWithSHA256:    return "DSAWithSHA256";
		case DiffieHellman:    return "DiffieHellman";
		case Unknown:
		default:               return "Unknown";
		}
	}

	std::string X509Algorithm::getOidValue() const
	{
		switch (m_Value)
		{
		case SHA1:             return "1.3.14.3.2.26";
		case SHA256:           return "2.16.840.1.101.3.4.2.1";
		case SHA384:           return "2.16.840.1.101.3.4.2.2";
		case SHA512:           return "2.16.840.1.101.3.4.2.3";
		case MD5:              return "1.2.840.113549.2.5";

		case RSA:              return "1.2.840.113549.1.1.1";
		case RSAWithSHA1:      return "1.2.840.113549.1.1.5";
		case RSAWithSHA256:    return "1.2.840.113549.1.1.11";
		case RSAWithSHA384:    return "1.2.840.113549.1.1.12";
		case RSAWithSHA512:    return "1.2.840.113549.1.1.13";
		case RSAPSS:           return "1.2.840.113549.1.1.10";

		case ECDSA:            return "1.2.840.10045.2.1";
		case ECDSAWithSHA1:    return "1.2.840.10045.4.1";
		case ECDSAWithSHA256:  return "1.2.840.10045.4.3.2";
		case ECDSAWithSHA384:  return "1.2.840.10045.4.3.3";
		case ECDSAWithSHA512:  return "1.2.840.10045.4.3.4";

		case ED25519:          return "1.3.101.112";
		case ED448:            return "1.3.101.113";

		case DSA:              return "1.2.840.10040.4.1";
		case DSAWithSHA1:      return "1.2.840.10040.4.3";
		case DSAWithSHA256:    return "2.16.840.1.101.3.4.3.2";

		case DiffieHellman:    return "1.2.840.113549.1.3.1";

		case Unknown:
		default:               return "0.0";
		}
	}

	X509Algorithm X509Algorithm::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStringValue = value.toString();
		static const std::unordered_map<std::string, Value> oidMap = {
			{"1.3.14.3.2.26", SHA1},
			{"2.16.840.1.101.3.4.2.1", SHA256},
			{"2.16.840.1.101.3.4.2.2", SHA384},
			{"2.16.840.1.101.3.4.2.3", SHA512},
			{"1.2.840.113549.2.5", MD5},

			{"1.2.840.113549.1.1.1", RSA},
			{"1.2.840.113549.1.1.5", RSAWithSHA1},
			{"1.2.840.113549.1.1.11", RSAWithSHA256},
			{"1.2.840.113549.1.1.12", RSAWithSHA384},
			{"1.2.840.113549.1.1.13", RSAWithSHA512},
			{"1.2.840.113549.1.1.10", RSAPSS},

			{"1.2.840.10045.2.1", ECDSA},
			{"1.2.840.10045.4.1", ECDSAWithSHA1},
			{"1.2.840.10045.4.3.2", ECDSAWithSHA256},
			{"1.2.840.10045.4.3.3", ECDSAWithSHA384},
			{"1.2.840.10045.4.3.4", ECDSAWithSHA512},

			{"1.2.840.10040.4.1", DSA},
			{"1.2.840.10040.4.3", DSAWithSHA1},
			{"2.16.840.1.101.3.4.3.2", DSAWithSHA256},

			{"1.3.101.112", ED25519},
			{"1.3.101.113", ED448},

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
		case CommonName:          return "CommonName";
		case Surname:             return "Surname";
		case SerialNumber:        return "SerialNumber";
		case Country:             return "Country";
		case Locality:            return "Locality";
		case StateOrProvince:     return "StateOrProvinceName";
		case Organization:        return "Organization";
		case OrganizationalUnit:  return "OrganizationalUnit";
		case Title:               return "Title";
		case GivenName:           return "GivenName";
		case Initials:            return "Initials";
		case Pseudonym:           return "Pseudonym";
		case GenerationQualifier: return "GenerationQualifier";
		case DnQualifier:         return "DnQualifier";
		case DomainComponent:     return "DomainComponent";
		case EmailAddress:        return "EmailAddress";
		case PostalCode:          return "PostalCode";
		case StreetAddress:       return  "StreetAddress";
		case BusinessCategory:    return "BusinessCategory";
		case Unknown:
		default:                  return "Unknown";
		}
	}

	std::string X520DistinguishedName::getShortName() const
	{
		switch (m_Value)
		{
		case CommonName:          return "CN";
		case Surname:             return "SN";
		case SerialNumber:        return "SERIALNUMBER";
		case Country:             return "C";
		case Locality:            return "L";
		case StateOrProvince:     return "ST";
		case Organization:        return "O";
		case OrganizationalUnit:  return "OU";
		case Title:               return "T";
		case GivenName:           return "G";
		case Initials:            return "Initials";
		case Pseudonym:           return "Pseudonym";
		case GenerationQualifier: return "GENERATION";
		case DnQualifier:         return "dnQualifier";
		case DomainComponent:     return "DC";
		case EmailAddress:        return "E";
		case PostalCode:          return "postalCode";
		case StreetAddress:       return  "STREET";
		case BusinessCategory:    return "businessCategory";
		case Unknown:
		default:                  return "Unknown";
		}
	}

	std::string X520DistinguishedName::getOidValue() const
	{
		switch (m_Value)
		{
		case CommonName:          return "2.5.4.3";
		case Surname:             return "2.5.4.4";
		case SerialNumber:        return "2.5.4.5";
		case Country:             return "2.5.4.6";
		case Locality:            return "2.5.4.7";
		case StateOrProvince:     return "2.5.4.8";
		case Organization:        return "2.5.4.10";
		case OrganizationalUnit:  return "2.5.4.11";
		case Title:               return "2.5.4.12";
		case GivenName:           return "2.5.4.42";
		case Initials:            return "2.5.4.43";
		case GenerationQualifier: return "2.5.4.44";
		case DnQualifier:         return "2.5.4.46";
		case Pseudonym:           return "2.5.4.65";
		case DomainComponent:     return "0.9.2342.19200300.100.1.25";
		case EmailAddress:        return "1.2.840.113549.1.9.1";
		case PostalCode:          return "2.5.4.17";
		case StreetAddress:       return  "2.5.4.9";
		case BusinessCategory:    return "2.5.4.15";
		case Unknown:
		default:                  return "0.0";
		}
	}

	X520DistinguishedName X520DistinguishedName::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStringValue = value.toString();
		static const std::unordered_map<std::string, Value> oidMap = {
		    {"2.5.4.3", CommonName},
		    {"2.5.4.4", Surname},
		    {"2.5.4.5", SerialNumber},
		    {"2.5.4.6", Country},
		    {"2.5.4.7", Locality},
		    {"2.5.4.8", StateOrProvince},
		    {"2.5.4.10", Organization},
		    {"2.5.4.11", OrganizationalUnit},
		    {"2.5.4.12", Title},
		    {"2.5.4.42", GivenName},
		    {"2.5.4.43", Initials},
		    {"2.5.4.44", GenerationQualifier},
		    {"2.5.4.46", DnQualifier},
		    {"2.5.4.65", Pseudonym},
		    {"0.9.2342.19200300.100.1.25", DomainComponent},
		    {"1.2.840.113549.1.9.1", EmailAddress},
			{"2.5.4.17", PostalCode},
			{"2.5.4.9", StreetAddress},
			{"2.5.4.15", BusinessCategory}
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
		case BasicConstraints:            return "BasicConstraints";
		case KeyUsage:                    return "KeyUsage";
		case ExtendedKeyUsage:            return "ExtendedKeyUsage";
		case SubjectKeyIdentifier:        return "SubjectKeyIdentifier";
		case AuthorityKeyIdentifier:      return "AuthorityKeyIdentifier";
		case SubjectAltName:              return "SubjectAltName";
		case IssuerAltName:               return "IssuerAltName";
		case CrlDistributionPoints:       return "CRLDistributionPoints";
		case AuthorityInfoAccess:         return "AuthorityInfoAccess";
		case CertificatePolicies:         return "CertificatePolicies";
		case PolicyMappings:              return "PolicyMappings";
		case PolicyConstraints:           return "PolicyConstraints";
		case NameConstraints:             return "NameConstraints";
		case InhibitAnyPolicy:            return "InhibitAnyPolicy";
		case CTPrecertificateSCTs:        return "CTPrecertificateSCTs";
		case SubjectInfoAccess:           return "SubjectInfoAccess";
		case FreshestCRL:                 return "FreshestCRL";
		case TLSFeature:                  return "TLSFeature";
		case OcspNoCheck:                 return "OcspNoCheck";
		case SubjectDirectoryAttributes:  return "SubjectDirectoryAttributes";
		case Unknown:
		default:                    return "Unknown";
		}
	}

	std::string X509ExtensionType::getOidValue() const
	{
		switch (m_Value)
		{
		case BasicConstraints:            return "2.5.29.19";
		case KeyUsage:                    return "2.5.29.15";
		case ExtendedKeyUsage:            return "2.5.29.37";
		case SubjectKeyIdentifier:        return "2.5.29.14";
		case AuthorityKeyIdentifier:      return "2.5.29.35";
		case SubjectAltName:              return "2.5.29.17";
		case IssuerAltName:               return "2.5.29.18";
		case CrlDistributionPoints:       return "2.5.29.31";
		case AuthorityInfoAccess:         return "1.3.6.1.5.5.7.1.1";
		case CertificatePolicies:         return "2.5.29.32";
		case PolicyMappings:              return "2.5.29.33";
		case PolicyConstraints:           return "2.5.29.36";
		case NameConstraints:             return "2.5.29.30";
		case InhibitAnyPolicy:            return "2.5.29.54";
		case CTPrecertificateSCTs:        return "1.3.6.1.4.1.11129.2.4.2";
		case SubjectInfoAccess:           return "1.3.6.1.5.5.7.1.11";
		case FreshestCRL:                 return "2.5.29.46";
		case TLSFeature:                  return "1.3.6.1.5.5.7.1.24";
		case OcspNoCheck:                 return "1.3.6.1.5.5.7.48.1.5";
		case SubjectDirectoryAttributes:  return "2.5.29.9";
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
			{"2.5.29.54",  InhibitAnyPolicy},
			{"1.3.6.1.4.1.11129.2.4.2", CTPrecertificateSCTs},
			{"1.3.6.1.5.5.7.1.11", SubjectInfoAccess},
			{"2.5.29.46", FreshestCRL},
			{"1.3.6.1.5.5.7.1.24", TLSFeature},
			{"1.3.6.1.5.5.7.48.1.5", OcspNoCheck},
			{"2.5.29.9", SubjectDirectoryAttributes},
		};

		auto it = oidMap.find(oidStr);
		if (it != oidMap.end())
			return {it->second};

		return {Unknown};
	}

	std::string X509SerialNumber::toString(const std::string& delimiter) const
	{
		// Remove leading zeros
		auto firstNonZero = m_SerialNumber.find_first_not_of('0');
		if (firstNonZero == std::string::npos)
		{
			return "0";
		}

		auto tempResult = m_SerialNumber.substr(firstNonZero);
		if (delimiter.empty())
		{
			return tempResult;
		}

		// Add delimiter
		std::string result;
		result.reserve(tempResult.length() + delimiter.size() * ((tempResult.length() / 2) - 1));

		for (auto i = 0; i < tempResult.length(); ++i)
		{
			result += tempResult[i];
			// Add a delimiter after every two characters, except for the very last pair
			if ((i + 1) % 2 == 0 && (i + 1) < tempResult.length())
			{
				result += delimiter;
			}
		}
		return result;
	}

	std::string X509Timestamp::toString(const std::string& format, const std::string& timezone, bool includeMilliseconds) const
	{
		return m_Record->getValueAsString(format, timezone, includeMilliseconds);
	}

	std::chrono::system_clock::time_point X509Timestamp::getTimestamp(const std::string& timezone) const
	{
		return m_Record->getValue(timezone);
	}

	std::string X509Key::toString(const std::string& delimiter) const
	{
		std::ostringstream result;
		bool first = true;

		for (const auto& byte : m_Key)
		{
			if (!first)
			{
				result << delimiter;
			}
			result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			first = false;
		}

		return result.str();
	}

	const std::vector<uint8_t>& X509Key::getBytes() const
	{
		return m_Key;
	}

	namespace X509Internal
	{
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

		std::vector<X509RelativeDistinguishedName> X509Name::getRDNs() const
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

		X509Timestamp X509Validity::getNotBefore() const
		{
			return { m_Root->getSubRecords().at(m_NotBeforeOffset)->castAs<Asn1TimeRecord>() };
		}

		X509Timestamp X509Validity::getNotAfter() const
		{
			return { m_Root->getSubRecords().at(m_NotAfterOffset)->castAs<Asn1TimeRecord>() };
		}

		X509AlgorithmIdentifier X509SubjectPublicKeyInfo::getAlgorithm() const
		{
			auto root = m_Root->getSubRecords().at(m_AlgorithmOffset)->castAs<Asn1SequenceRecord>();
			return X509AlgorithmIdentifier(root);
		}

		X509Key X509SubjectPublicKeyInfo::getSubjectPublicKey() const
		{
			return {m_Root->getSubRecords().at(m_SubjectPublicKeyOffset)->castAs<Asn1BitStringRecord>()->getVecValue()};
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

		X509SerialNumber X509TBSCertificate::getSerialNumber() const
		{
			auto serialNumber = m_Root->getSubRecords().at(getIndex(m_SerialNumberOffset))->castAs<Asn1IntegerRecord>()->getValueAsString();
			return X509SerialNumber(serialNumber);
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

		Asn1SequenceRecord* X509Certificate::getAsn1Root() const
		{
			return m_Root->castAs<Asn1SequenceRecord>();
		}

		X509TBSCertificate X509Certificate::getTbsCertificate() const
		{
			auto root = getAsn1Root()->getSubRecords().at(m_TBSCertificateOffset)->castAs<Asn1SequenceRecord>();
			return X509TBSCertificate(root);
		}

		X509AlgorithmIdentifier X509Certificate::getSignatureAlgorithm() const
		{
			auto root = getAsn1Root()->getSubRecords().at(m_SignatureAlgorithmOffset)->castAs<Asn1SequenceRecord>();
			return X509AlgorithmIdentifier(root);
		}

		X509Key X509Certificate::getSignature() const
		{
			return {getAsn1Root()->getSubRecords().at(m_SignatureOffset)->castAs<Asn1BitStringRecord>()->getVecValue()};
		}

		std::vector<uint8_t> X509Certificate::encode()
		{
			return m_Root->encode();
		}
	}

	X509Name::X509Name(const X509Internal::X509Name& internalName)
	{
		for (const auto& rdn : internalName.getRDNs())
		{
			m_RDNs.push_back({rdn.getType(), rdn.getValue()});
		}
	}

	std::string X509Name::toString(const std::string& delimiter) const
	{
		std::ostringstream result;
		bool first = true;

		for (const auto& rdn : m_RDNs)
		{
			if (!first)
			{
				result << delimiter;
			}
			result << rdn.type.getShortName() << "=" << rdn.value;
			first = false;
		}

		return result.str();
	}

	X509Certificate::X509Certificate(uint8_t* derData, size_t derDataLen, bool ownDerData) : m_X509Internal(X509Internal::X509Certificate::decode(derData, derDataLen)), m_TBSCertificate(m_X509Internal->getTbsCertificate())
	{
		if (ownDerData)
		{
			m_DerData.reset(derData);
		}
	}

	std::unique_ptr<X509Certificate> X509Certificate::fromDER(const uint8_t* derData, size_t derDataLen, bool ownDerData)
	{
		return std::unique_ptr<X509Certificate>(new X509Certificate(const_cast<uint8_t*>(derData), derDataLen, ownDerData));
	}

	std::unique_ptr<X509Certificate> X509Certificate::fromDER(const std::string& derData)
	{
		size_t derDataBufferLen = derData.length() / 2;
		auto derDataBuffer = new uint8_t[derDataBufferLen];
		hexStringToByteArray(derData, derDataBuffer, derDataBufferLen);
		return std::unique_ptr<X509Certificate>(new X509Certificate(derDataBuffer, derDataBufferLen, true));
	}

	std::unique_ptr<X509Certificate> X509Certificate::fromDERFile(const std::string& derFileName)
	{
		std::ifstream derFile(derFileName, std::ios::binary);
		if (!derFile)
		{
			throw std::runtime_error("Failed to open DER file");
		}

		derFile.seekg(0, std::ios::end);
		std::streamsize derDataLen = derFile.tellg();
		if (derDataLen < 0)
		{
			throw std::runtime_error("Failed to determine DER file size");
		}
		derFile.seekg(0, std::ios::beg);

		auto derData = new char[derDataLen];

		if (!derFile.read(derData, derDataLen))
		{
			throw std::runtime_error("Failed to read DER file");
		}

		return std::unique_ptr<X509Certificate>(new X509Certificate(reinterpret_cast<uint8_t*>(derData), derDataLen, true));
	}

	X509Version X509Certificate::getVersion() const
	{
		return m_TBSCertificate.getVersion();
	}
	bool X509Certificate::hasExtension(const X509ExtensionType& extensionType) const
	{
		auto extensions = m_TBSCertificate.getExtensions()->getExtensions();
		return std::any_of(extensions.begin(), extensions.end(), [extensionType](const auto& ext) {
			return ext.getType() == extensionType;
		});
	}

	size_t X509Certificate::getExtensionCount() const
	{
		return m_TBSCertificate.getExtensions()->getExtensions().size();
	}

	X509Name X509Certificate::getSubject() const
	{
		return {m_TBSCertificate.getSubject()};
	}

	X509Name X509Certificate::getIssuer() const
	{
		return {m_TBSCertificate.getIssuer()};
	}

	X509SerialNumber X509Certificate::getSerialNumber() const
	{
		return m_TBSCertificate.getSerialNumber();
	}

	X509Timestamp X509Certificate::getNotBefore() const
	{
		return m_TBSCertificate.getValidity().getNotBefore();
	}

	X509Timestamp X509Certificate::getNotAfter() const
	{
		return m_TBSCertificate.getValidity().getNotAfter();
	}

	X509Algorithm X509Certificate::getPublicKeyAlgorithm() const
	{
		return m_TBSCertificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm();
	}

	X509Key X509Certificate::getPublicKey() const
	{
		return m_TBSCertificate.getSubjectPublicKeyInfo().getSubjectPublicKey();
	}

	X509Algorithm X509Certificate::getSignatureAlgorithm() const
	{
		return m_X509Internal->getSignatureAlgorithm().getAlgorithm();
	}

	X509Key X509Certificate::getSignature() const
	{
		return m_X509Internal->getSignature();
	}

	const X509Internal::X509Certificate* X509Certificate::getRawCertificate() const
	{
		return m_X509Internal.get();
	}

	std::vector<uint8_t> X509Certificate::toDER() const
	{
		return m_X509Internal->encode();
	}

	std::string X509Certificate::toJson(int indent) const
	{
		nlohmann::ordered_json certificateJson = {
			{"version", static_cast<int>(getVersion()) + 1},
			{"serialNumber", getSerialNumber().toString()},
			{"issuer", getIssuer().toString()},
			{"validity", {
				{"notBefore", getNotBefore().toString()},
				{"notAfter", getNotAfter().toString()},
			}},
			{"subject", getSubject().toString()},
			{"subjectPublicKeyInfo", {
				{"subjectPublicKeyAlgorithm", getPublicKeyAlgorithm().toString()},
				{"subjectPublicKey", getPublicKey().toString()}
			}},
			{"extensions", getExtensionCount()},
			{"signatureAlgorithm", getSignatureAlgorithm().toString()},
			{"signature", getSignature().toString()}
		};

		return certificateJson.dump(indent);
	}
}