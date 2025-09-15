#include "X509Decoder.h"
#include "Asn1Codec.h"
#include "GeneralUtils.h"
#include "PemCodec.h"
#include "json.hpp"
#include <fstream>
#include <unordered_map>

namespace pcpp
{
	std::string X509Algorithm::toString() const
	{
		switch (m_Value)
		{
		case SHA1:
			return "SHA1";
		case SHA256:
			return "SHA256";
		case SHA384:
			return "SHA384";
		case SHA512:
			return "SHA512";
		case MD5:
			return "MD5";
		case RSA:
			return "RSA";
		case RSAWithSHA1:
			return "RSAWithSHA1";
		case RSAWithSHA256:
			return "RSAWithSHA256";
		case RSAWithSHA384:
			return "RSAWithSHA384";
		case RSAWithSHA512:
			return "RSAWithSHA512";
		case RSAPSS:
			return "RSAPSS";
		case ECDSA:
			return "ECDSA";
		case ECDSAWithSHA1:
			return "ECDSAWithSHA1";
		case ECDSAWithSHA256:
			return "ECDSAWithSHA256";
		case ECDSAWithSHA384:
			return "ECDSAWithSHA384";
		case ECDSAWithSHA512:
			return "ECDSAWithSHA512";
		case ED25519:
			return "ED25519";
		case ED448:
			return "ED448";
		case DSA:
			return "DSA";
		case DSAWithSHA1:
			return "DSAWithSHA1";
		case DSAWithSHA256:
			return "DSAWithSHA256";
		case DiffieHellman:
			return "DiffieHellman";
		case Unknown:
		default:
			return "Unknown";
		}
	}

	std::string X509Algorithm::getOidValue() const
	{
		switch (m_Value)
		{
		case SHA1:
			return "1.3.14.3.2.26";
		case SHA256:
			return "2.16.840.1.101.3.4.2.1";
		case SHA384:
			return "2.16.840.1.101.3.4.2.2";
		case SHA512:
			return "2.16.840.1.101.3.4.2.3";
		case MD5:
			return "1.2.840.113549.2.5";

		case RSA:
			return "1.2.840.113549.1.1.1";
		case RSAWithSHA1:
			return "1.2.840.113549.1.1.5";
		case RSAWithSHA256:
			return "1.2.840.113549.1.1.11";
		case RSAWithSHA384:
			return "1.2.840.113549.1.1.12";
		case RSAWithSHA512:
			return "1.2.840.113549.1.1.13";
		case RSAPSS:
			return "1.2.840.113549.1.1.10";

		case ECDSA:
			return "1.2.840.10045.2.1";
		case ECDSAWithSHA1:
			return "1.2.840.10045.4.1";
		case ECDSAWithSHA256:
			return "1.2.840.10045.4.3.2";
		case ECDSAWithSHA384:
			return "1.2.840.10045.4.3.3";
		case ECDSAWithSHA512:
			return "1.2.840.10045.4.3.4";

		case ED25519:
			return "1.3.101.112";
		case ED448:
			return "1.3.101.113";

		case DSA:
			return "1.2.840.10040.4.1";
		case DSAWithSHA1:
			return "1.2.840.10040.4.3";
		case DSAWithSHA256:
			return "2.16.840.1.101.3.4.3.2";

		case DiffieHellman:
			return "1.2.840.113549.1.3.1";

		case Unknown:
		default:
			return "0.0";
		}
	}

	static const std::unordered_map<std::string, X509Algorithm::Value> X509AlgorithmOidMap = {
		{ "1.3.14.3.2.26",          X509Algorithm::SHA1            },
		{ "2.16.840.1.101.3.4.2.1", X509Algorithm::SHA256          },
		{ "2.16.840.1.101.3.4.2.2", X509Algorithm::SHA384          },
		{ "2.16.840.1.101.3.4.2.3", X509Algorithm::SHA512          },
		{ "1.2.840.113549.2.5",     X509Algorithm::MD5             },
		{ "1.2.840.113549.1.1.1",   X509Algorithm::RSA             },
		{ "1.2.840.113549.1.1.5",   X509Algorithm::RSAWithSHA1     },
		{ "1.2.840.113549.1.1.11",  X509Algorithm::RSAWithSHA256   },
		{ "1.2.840.113549.1.1.12",  X509Algorithm::RSAWithSHA384   },
		{ "1.2.840.113549.1.1.13",  X509Algorithm::RSAWithSHA512   },
		{ "1.2.840.113549.1.1.10",  X509Algorithm::RSAPSS          },
		{ "1.2.840.10045.2.1",      X509Algorithm::ECDSA           },
		{ "1.2.840.10045.4.1",      X509Algorithm::ECDSAWithSHA1   },
		{ "1.2.840.10045.4.3.2",    X509Algorithm::ECDSAWithSHA256 },
		{ "1.2.840.10045.4.3.3",    X509Algorithm::ECDSAWithSHA384 },
		{ "1.2.840.10045.4.3.4",    X509Algorithm::ECDSAWithSHA512 },
		{ "1.2.840.10040.4.1",      X509Algorithm::DSA             },
		{ "1.2.840.10040.4.3",      X509Algorithm::DSAWithSHA1     },
		{ "2.16.840.1.101.3.4.3.2", X509Algorithm::DSAWithSHA256   },
		{ "1.3.101.112",            X509Algorithm::ED25519         },
		{ "1.3.101.113",            X509Algorithm::ED448           },
		{ "1.2.840.113549.1.3.1",   X509Algorithm::DiffieHellman   }
	};

	X509Algorithm X509Algorithm::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStringValue = value.toString();

		auto it = X509AlgorithmOidMap.find(oidStringValue);
		if (it != X509AlgorithmOidMap.end())
		{
			return { it->second };
		}

		return { Unknown };
	}

	std::string X520DistinguishedName::toString() const
	{
		switch (m_Value)
		{
		case CommonName:
			return "CommonName";
		case Surname:
			return "Surname";
		case SerialNumber:
			return "SerialNumber";
		case Country:
			return "Country";
		case Locality:
			return "Locality";
		case StateOrProvince:
			return "StateOrProvinceName";
		case Organization:
			return "Organization";
		case OrganizationalUnit:
			return "OrganizationalUnit";
		case Title:
			return "Title";
		case GivenName:
			return "GivenName";
		case Initials:
			return "Initials";
		case Pseudonym:
			return "Pseudonym";
		case GenerationQualifier:
			return "GenerationQualifier";
		case DnQualifier:
			return "DnQualifier";
		case DomainComponent:
			return "DomainComponent";
		case EmailAddress:
			return "EmailAddress";
		case PostalCode:
			return "PostalCode";
		case StreetAddress:
			return "StreetAddress";
		case BusinessCategory:
			return "BusinessCategory";
		case Unknown:
		default:
			return "Unknown";
		}
	}

	std::string X520DistinguishedName::getShortName() const
	{
		switch (m_Value)
		{
		case CommonName:
			return "CN";
		case Surname:
			return "SN";
		case SerialNumber:
			return "SERIALNUMBER";
		case Country:
			return "C";
		case Locality:
			return "L";
		case StateOrProvince:
			return "ST";
		case Organization:
			return "O";
		case OrganizationalUnit:
			return "OU";
		case Title:
			return "T";
		case GivenName:
			return "G";
		case Initials:
			return "Initials";
		case Pseudonym:
			return "Pseudonym";
		case GenerationQualifier:
			return "GENERATION";
		case DnQualifier:
			return "dnQualifier";
		case DomainComponent:
			return "DC";
		case EmailAddress:
			return "E";
		case PostalCode:
			return "postalCode";
		case StreetAddress:
			return "STREET";
		case BusinessCategory:
			return "businessCategory";
		case Unknown:
		default:
			return "Unknown";
		}
	}

	std::string X520DistinguishedName::getOidValue() const
	{
		switch (m_Value)
		{
		case CommonName:
			return "2.5.4.3";
		case Surname:
			return "2.5.4.4";
		case SerialNumber:
			return "2.5.4.5";
		case Country:
			return "2.5.4.6";
		case Locality:
			return "2.5.4.7";
		case StateOrProvince:
			return "2.5.4.8";
		case Organization:
			return "2.5.4.10";
		case OrganizationalUnit:
			return "2.5.4.11";
		case Title:
			return "2.5.4.12";
		case GivenName:
			return "2.5.4.42";
		case Initials:
			return "2.5.4.43";
		case GenerationQualifier:
			return "2.5.4.44";
		case DnQualifier:
			return "2.5.4.46";
		case Pseudonym:
			return "2.5.4.65";
		case DomainComponent:
			return "0.9.2342.19200300.100.1.25";
		case EmailAddress:
			return "1.2.840.113549.1.9.1";
		case PostalCode:
			return "2.5.4.17";
		case StreetAddress:
			return "2.5.4.9";
		case BusinessCategory:
			return "2.5.4.15";
		case Unknown:
		default:
			return "0.0";
		}
	}

	static const std::unordered_map<std::string, X520DistinguishedName::Value> X520DistinguishedNameOidMap = {
		{ "2.5.4.3",                    X520DistinguishedName::CommonName          },
		{ "2.5.4.4",                    X520DistinguishedName::Surname             },
		{ "2.5.4.5",                    X520DistinguishedName::SerialNumber        },
		{ "2.5.4.6",                    X520DistinguishedName::Country             },
		{ "2.5.4.7",                    X520DistinguishedName::Locality            },
		{ "2.5.4.8",                    X520DistinguishedName::StateOrProvince     },
		{ "2.5.4.10",                   X520DistinguishedName::Organization        },
		{ "2.5.4.11",                   X520DistinguishedName::OrganizationalUnit  },
		{ "2.5.4.12",                   X520DistinguishedName::Title               },
		{ "2.5.4.42",                   X520DistinguishedName::GivenName           },
		{ "2.5.4.43",                   X520DistinguishedName::Initials            },
		{ "2.5.4.44",                   X520DistinguishedName::GenerationQualifier },
		{ "2.5.4.46",                   X520DistinguishedName::DnQualifier         },
		{ "2.5.4.65",                   X520DistinguishedName::Pseudonym           },
		{ "0.9.2342.19200300.100.1.25", X520DistinguishedName::DomainComponent     },
		{ "1.2.840.113549.1.9.1",       X520DistinguishedName::EmailAddress        },
		{ "2.5.4.17",                   X520DistinguishedName::PostalCode          },
		{ "2.5.4.9",                    X520DistinguishedName::StreetAddress       },
		{ "2.5.4.15",                   X520DistinguishedName::BusinessCategory    }
	};

	X520DistinguishedName X520DistinguishedName::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStringValue = value.toString();

		auto it = X520DistinguishedNameOidMap.find(oidStringValue);
		if (it != X520DistinguishedNameOidMap.end())
		{
			return { it->second };
		}

		return { Unknown };
	}

	std::string X509ExtensionType::toString() const
	{
		switch (m_Value)
		{
		case BasicConstraints:
			return "BasicConstraints";
		case KeyUsage:
			return "KeyUsage";
		case ExtendedKeyUsage:
			return "ExtendedKeyUsage";
		case SubjectKeyIdentifier:
			return "SubjectKeyIdentifier";
		case AuthorityKeyIdentifier:
			return "AuthorityKeyIdentifier";
		case SubjectAltName:
			return "SubjectAltName";
		case IssuerAltName:
			return "IssuerAltName";
		case CrlDistributionPoints:
			return "CRLDistributionPoints";
		case AuthorityInfoAccess:
			return "AuthorityInfoAccess";
		case CertificatePolicies:
			return "CertificatePolicies";
		case PolicyMappings:
			return "PolicyMappings";
		case PolicyConstraints:
			return "PolicyConstraints";
		case NameConstraints:
			return "NameConstraints";
		case InhibitAnyPolicy:
			return "InhibitAnyPolicy";
		case CTPrecertificateSCTs:
			return "CTPrecertificateSCTs";
		case SubjectInfoAccess:
			return "SubjectInfoAccess";
		case FreshestCRL:
			return "FreshestCRL";
		case TLSFeature:
			return "TLSFeature";
		case OcspNoCheck:
			return "OcspNoCheck";
		case SubjectDirectoryAttributes:
			return "SubjectDirectoryAttributes";
		case Unknown:
		default:
			return "Unknown";
		}
	}

	std::string X509ExtensionType::getOidValue() const
	{
		switch (m_Value)
		{
		case BasicConstraints:
			return "2.5.29.19";
		case KeyUsage:
			return "2.5.29.15";
		case ExtendedKeyUsage:
			return "2.5.29.37";
		case SubjectKeyIdentifier:
			return "2.5.29.14";
		case AuthorityKeyIdentifier:
			return "2.5.29.35";
		case SubjectAltName:
			return "2.5.29.17";
		case IssuerAltName:
			return "2.5.29.18";
		case CrlDistributionPoints:
			return "2.5.29.31";
		case AuthorityInfoAccess:
			return "1.3.6.1.5.5.7.1.1";
		case CertificatePolicies:
			return "2.5.29.32";
		case PolicyMappings:
			return "2.5.29.33";
		case PolicyConstraints:
			return "2.5.29.36";
		case NameConstraints:
			return "2.5.29.30";
		case InhibitAnyPolicy:
			return "2.5.29.54";
		case CTPrecertificateSCTs:
			return "1.3.6.1.4.1.11129.2.4.2";
		case SubjectInfoAccess:
			return "1.3.6.1.5.5.7.1.11";
		case FreshestCRL:
			return "2.5.29.46";
		case TLSFeature:
			return "1.3.6.1.5.5.7.1.24";
		case OcspNoCheck:
			return "1.3.6.1.5.5.7.48.1.5";
		case SubjectDirectoryAttributes:
			return "2.5.29.9";
		case Unknown:
		default:
			return "0.0";
		}
	}

	static const std::unordered_map<std::string, X509ExtensionType::Value> X509ExtensionTypeOidMap = {
		{ "2.5.29.19",               X509ExtensionType::BasicConstraints           },
		{ "2.5.29.15",               X509ExtensionType::KeyUsage                   },
		{ "2.5.29.37",               X509ExtensionType::ExtendedKeyUsage           },
		{ "2.5.29.14",               X509ExtensionType::SubjectKeyIdentifier       },
		{ "2.5.29.35",               X509ExtensionType::AuthorityKeyIdentifier     },
		{ "2.5.29.17",               X509ExtensionType::SubjectAltName             },
		{ "2.5.29.18",               X509ExtensionType::IssuerAltName              },
		{ "2.5.29.31",               X509ExtensionType::CrlDistributionPoints      },
		{ "1.3.6.1.5.5.7.1.1",       X509ExtensionType::AuthorityInfoAccess        },
		{ "2.5.29.32",               X509ExtensionType::CertificatePolicies        },
		{ "2.5.29.33",               X509ExtensionType::PolicyMappings             },
		{ "2.5.29.36",               X509ExtensionType::PolicyConstraints          },
		{ "2.5.29.30",               X509ExtensionType::NameConstraints            },
		{ "2.5.29.54",               X509ExtensionType::InhibitAnyPolicy           },
		{ "1.3.6.1.4.1.11129.2.4.2", X509ExtensionType::CTPrecertificateSCTs       },
		{ "1.3.6.1.5.5.7.1.11",      X509ExtensionType::SubjectInfoAccess          },
		{ "2.5.29.46",               X509ExtensionType::FreshestCRL                },
		{ "1.3.6.1.5.5.7.1.24",      X509ExtensionType::TLSFeature                 },
		{ "1.3.6.1.5.5.7.48.1.5",    X509ExtensionType::OcspNoCheck                },
		{ "2.5.29.9",                X509ExtensionType::SubjectDirectoryAttributes },
	};

	X509ExtensionType X509ExtensionType::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		std::string oidStr = value.toString();

		auto it = X509ExtensionTypeOidMap.find(oidStr);
		if (it != X509ExtensionTypeOidMap.end())
			return { it->second };

		return { Unknown };
	}

	template <class Asn1RecordType>
	static Asn1RecordType* castRecordAs(Asn1Record* record, const std::string& fieldName)
	{
		try
		{
			return record->castAs<Asn1RecordType>();
		}
		catch (const std::bad_cast&)
		{
			throw std::runtime_error("Invalid X509 certificate data: " + fieldName);
		}
	}

	template <class Asn1RecordType>
	static Asn1RecordType* getSubRecordAndCast(Asn1ConstructedRecord* record, int index, const std::string& fieldName)
	{
		try
		{
			return castRecordAs<Asn1RecordType>(record->getSubRecords().at(index), fieldName);
		}
		catch (const std::out_of_range&)
		{
			throw std::runtime_error("Invalid X509 certificate data: " + fieldName);
		}
	}

	std::string X509SerialNumber::toString(const std::string& delimiter) const
	{
		if (delimiter.empty())
		{
			return m_SerialNumber;
		}

		// Add delimiter
		std::string result;
		result.reserve(m_SerialNumber.length() + delimiter.size() * (m_SerialNumber.length() / 2 - 1));

		for (size_t i = 0; i < m_SerialNumber.length(); ++i)
		{
			result += m_SerialNumber[i];
			// Add a delimiter after every two characters, except for the very last pair
			if ((i + 1) % 2 == 0 && i + 1 < m_SerialNumber.length())
			{
				result += delimiter;
			}
		}
		return result;
	}

	std::string X509Timestamp::toString(const std::string& format, const std::string& timezone,
	                                    bool includeMilliseconds) const
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
			auto intValue = getSubRecordAndCast<Asn1IntegerRecord>(m_Root, 0, "Version")->getIntValue<uint8_t>();
			if (intValue > 3)
			{
				throw std::runtime_error("Invalid X509 version value: " + std::to_string(intValue));
			}

			return static_cast<X509Version>(intValue);
		}

		bool X509VersionRecord::isValidVersionRecord(const Asn1Record* record)
		{
			return record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 0 &&
			       record->isConstructed();
		}

		Asn1Record* X509RelativeDistinguishedName::getRecord(int index) const
		{
			auto attributeTypeAndValue = getSubRecordAndCast<Asn1SequenceRecord>(m_Root, 0, "RDN");
			try
			{
				return attributeTypeAndValue->getSubRecords().at(index);
			}
			catch (const std::out_of_range&)
			{
				throw std::runtime_error("Invalid X509 certificate data: RDN");
			}
		}

		X520DistinguishedName X509RelativeDistinguishedName::getType() const
		{
			auto oidRecord = castRecordAs<Asn1ObjectIdentifierRecord>(getRecord(typeOffset), "RDN Type");
			return X520DistinguishedName::fromOidValue(oidRecord->getValue());
		}

		std::string X509RelativeDistinguishedName::getValue() const
		{
			auto valueRecord = getRecord(valueOffset);
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
				throw std::runtime_error("Invalid X509 certificate data: unsupported RDN value ASN.1 type: " +
				                         std::to_string(static_cast<int>(valueRecord->getUniversalTagType())));
			}
			}
		}

		std::vector<X509RelativeDistinguishedName> X509Name::getRDNs() const
		{
			std::vector<X509RelativeDistinguishedName> result;
			for (auto const& subRecord : m_Root->getSubRecords())
			{
				result.push_back(X509RelativeDistinguishedName(castRecordAs<Asn1SetRecord>(subRecord, "RDN")));
			}

			return result;
		}

		X509Algorithm X509AlgorithmIdentifier::getAlgorithm() const
		{
			auto oidRecord = getSubRecordAndCast<Asn1ObjectIdentifierRecord>(m_Root, algorithmOffset, "Algorithm");
			return X509Algorithm::fromOidValue(oidRecord->getValue());
		}

		X509Timestamp X509Validity::getNotBefore() const
		{
			return X509Timestamp(getSubRecordAndCast<Asn1TimeRecord>(m_Root, notBeforeOffset, "Not Before"));
		}

		X509Timestamp X509Validity::getNotAfter() const
		{
			return X509Timestamp(getSubRecordAndCast<Asn1TimeRecord>(m_Root, notAfterOffset, "Not After"));
		}

		X509AlgorithmIdentifier X509SubjectPublicKeyInfo::getAlgorithm() const
		{
			auto root =
			    getSubRecordAndCast<Asn1SequenceRecord>(m_Root, algorithmOffset, "Subject Public Key Algorithm");
			return X509AlgorithmIdentifier(root);
		}

		X509Key X509SubjectPublicKeyInfo::getSubjectPublicKey() const
		{
			return X509Key(
			    getSubRecordAndCast<Asn1BitStringRecord>(m_Root, subjectPublicKeyOffset, "Subject Public Key")
			        ->getVecValue());
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
			auto extensionTypeRecord =
			    getSubRecordAndCast<Asn1ObjectIdentifierRecord>(m_Root, extensionIdOffset, "Extension Type");
			return X509ExtensionType::fromOidValue(extensionTypeRecord->getValue());
		}

		bool X509Extension::isCritical() const
		{
			if (m_CriticalOffset == -1)
			{
				return false;
			}

			return getSubRecordAndCast<Asn1BooleanRecord>(m_Root, m_CriticalOffset, "Extension Critical")->getValue();
		}

		std::string X509Extension::getValue() const
		{
			return getSubRecordAndCast<Asn1OctetStringRecord>(m_Root, m_ExtensionValueOffset, "Extension Value")
			    ->getValue();
		}

		std::vector<X509Extension> X509Extensions::getExtensions() const
		{
			std::vector<X509Extension> result;
			auto extensionsRecord = getSubRecordAndCast<Asn1SequenceRecord>(m_Root, 0, "Extensions");
			for (const auto& extension : extensionsRecord->getSubRecords())
			{
				result.push_back(X509Extension(castRecordAs<Asn1SequenceRecord>(extension, "Extension")));
			}

			return result;
		}

		bool X509Extensions::isValidExtensionsRecord(const Asn1Record* record)
		{
			return (record->getTagClass() == Asn1TagClass::ContextSpecific && record->getTagType() == 3 &&
			        record->isConstructed());
		}

		X509SerialNumber X509TBSCertificate::getSerialNumber() const
		{
			auto serialNumber = getSubRecordAndCast<Asn1IntegerRecord>(m_Root, m_SerialNumberOffset, "Serial Number")
			                        ->getValueAsString(true);
			return X509SerialNumber(serialNumber);
		}

		X509AlgorithmIdentifier X509TBSCertificate::getSignature() const
		{
			auto root = getSubRecordAndCast<Asn1SequenceRecord>(m_Root, m_SignatureOffset, "Signature Algorithm");
			return X509AlgorithmIdentifier(root);
		}

		X509TBSCertificate::X509TBSCertificate(Asn1SequenceRecord* root) : X509Base(root)
		{
			try
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

				if (root->getSubRecords().size() > static_cast<size_t>(currIndex))
				{
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
			}
			catch (const std::out_of_range&)
			{
				throw std::runtime_error("Invalid X509 certificate data: TBS Certificate");
			}
		}

		X509Version X509TBSCertificate::getVersion() const
		{
			if (m_VersionOffset == -1)
			{
				return X509Version::V1;
			}

			auto versionAsn1Record = getSubRecordAndCast<Asn1ConstructedRecord>(m_Root, m_VersionOffset, "Version");
			auto versionRecord = X509VersionRecord(versionAsn1Record);
			return versionRecord.getVersion();
		}

		X509Name X509TBSCertificate::getIssuer() const
		{
			auto root = getSubRecordAndCast<Asn1SequenceRecord>(m_Root, m_IssuerOffset, "Issuer");
			return X509Name(root);
		}

		X509Validity X509TBSCertificate::getValidity() const
		{
			auto root = getSubRecordAndCast<Asn1SequenceRecord>(m_Root, m_ValidityOffset, "Validity");
			return X509Validity(root);
		}

		X509Name X509TBSCertificate::getSubject() const
		{
			auto root = getSubRecordAndCast<Asn1SequenceRecord>(m_Root, m_SubjectOffset, "Subject");
			return X509Name(root);
		}

		X509SubjectPublicKeyInfo X509TBSCertificate::getSubjectPublicKeyInfo() const
		{
			auto root = getSubRecordAndCast<Asn1SequenceRecord>(m_Root, m_SubjectPublicKeyInfoOffset,
			                                                    "Subject Public Key Info");
			return X509SubjectPublicKeyInfo(root);
		}

		std::unique_ptr<X509Extensions> X509TBSCertificate::getExtensions() const
		{
			if (m_ExtensionsOffset == -1)
			{
				return nullptr;
			}

			auto root = getSubRecordAndCast<Asn1ConstructedRecord>(m_Root, m_ExtensionsOffset, "Extensions");
			return std::unique_ptr<X509Extensions>(new X509Extensions(root));
		}

		std::unique_ptr<X509Certificate> X509Certificate::decode(const uint8_t* data, size_t dataLen)
		{
			return std::unique_ptr<X509Certificate>(new X509Certificate(Asn1Record::decode(data, dataLen)));
		}

		Asn1SequenceRecord* X509Certificate::getAsn1Root() const
		{
			return castRecordAs<Asn1SequenceRecord>(m_Root.get(), "Root");
		}

		X509TBSCertificate X509Certificate::getTbsCertificate() const
		{
			auto root = getSubRecordAndCast<Asn1SequenceRecord>(getAsn1Root(), tbsCertificateOffset, "TBS Certificate");
			return X509TBSCertificate(root);
		}

		X509AlgorithmIdentifier X509Certificate::getSignatureAlgorithm() const
		{
			auto root =
			    getSubRecordAndCast<Asn1SequenceRecord>(getAsn1Root(), signatureAlgorithmOffset, "Signature Algorithm");
			return X509AlgorithmIdentifier(root);
		}

		X509Key X509Certificate::getSignature() const
		{
			return X509Key(
			    getSubRecordAndCast<Asn1BitStringRecord>(getAsn1Root(), signatureOffset, "Signature")->getVecValue());
		}

		std::vector<uint8_t> X509Certificate::encode()
		{
			return m_Root->encode();
		}
	}  // namespace X509Internal

	X509Name::X509Name(const X509Internal::X509Name& internalName)
	{
		for (const auto& rdn : internalName.getRDNs())
		{
			m_RDNs.emplace_back(RDN{ rdn.getType(), rdn.getValue() });
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

	X509Extension::X509Extension(const X509Internal::X509Extension& internalExtension)
	    : m_IsCritical(internalExtension.isCritical()), m_Type(internalExtension.getType()),
	      m_Data(internalExtension.getValue())
	{}

	std::unique_ptr<X509ExtensionData> X509Extension::getData() const
	{
		switch (m_Type)
		{
		case X509ExtensionType::BasicConstraints:
		{
			return std::unique_ptr<X509ExtensionData>(new X509BasicConstraintsExtension(m_Data));
		}
		case X509ExtensionType::SubjectKeyIdentifier:
		{
			return std::unique_ptr<X509ExtensionData>(new X509SubjectKeyIdentifierExtension(m_Data));
		}
		case X509ExtensionType::KeyUsage:
		{
			return std::unique_ptr<X509ExtensionData>(new X509KeyUsageExtension(m_Data));
		}
		case X509ExtensionType::ExtendedKeyUsage:
		{
			return std::unique_ptr<X509ExtensionData>(new X509ExtendedKeyUsageExtension(m_Data));
		}
		default:
		{
			return {};
		}
		}
	}

	X509Certificate::X509Certificate(uint8_t* derData, size_t derDataLen, bool ownDerData)
	    : m_X509Internal(X509Internal::X509Certificate::decode(derData, derDataLen)),
	      m_TBSCertificate(m_X509Internal->getTbsCertificate())
	{
		if (ownDerData)
		{
			m_DerData.reset(derData);
		}
	}

	X509Certificate::X509Certificate(std::unique_ptr<uint8_t[]> derData, size_t derDataLen)
	    : m_X509Internal(X509Internal::X509Certificate::decode(derData.get(), derDataLen)),
	      m_TBSCertificate(m_X509Internal->getTbsCertificate())
	{
		m_DerData = std::move(derData);
	}

	X509Version X509Certificate::getVersion() const
	{
		return m_TBSCertificate.getVersion();
	}

	const std::vector<X509Extension>& X509Certificate::getExtensions() const
	{
		if (!m_ExtensionsParsed)
		{
			auto extensions = m_TBSCertificate.getExtensions();
			if (extensions != nullptr)
			{
				for (const auto& extension : extensions->getExtensions())
				{
					m_Extensions.emplace_back(X509Extension(extension));
				}
			}
			m_ExtensionsParsed = true;
		}

		return m_Extensions;
	}

	bool X509Certificate::hasExtension(const X509ExtensionType& extensionType) const
	{
		auto extensions = m_TBSCertificate.getExtensions()->getExtensions();
		return std::any_of(extensions.begin(), extensions.end(),
		                   [extensionType](const auto& ext) { return ext.getType() == extensionType; });
	}

	const X509Extension* X509Certificate::getExtension(X509ExtensionType extensionType) const
	{
		const auto& extensions = getExtensions();
		auto matchExtension =
		    std::find_if(extensions.begin(), extensions.end(), [&extensionType](const X509Extension& extension) {
			    return extension.getType() == extensionType;
		    });

		if (matchExtension != extensions.end())
		{
			return &(*matchExtension);
		}

		return nullptr;
	}

	X509Name X509Certificate::getSubject() const
	{
		return X509Name(m_TBSCertificate.getSubject());
	}

	X509Name X509Certificate::getIssuer() const
	{
		return X509Name(m_TBSCertificate.getIssuer());
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

	std::string X509Certificate::toPEM() const
	{
		return PemCodec::encode(m_X509Internal->encode(), pemLabel);
	}

	std::string X509Certificate::toJson(int indent) const
	{
		auto extensions = nlohmann::ordered_json::array();
		for (const auto& extension : getExtensions())
		{
			extensions.push_back({
			    { "type",       extension.getType().toString() },
			    { "isCritical", extension.isCritical()         },
			});
		}

		nlohmann::ordered_json certificateJson = {
			{ "version",              static_cast<int>(getVersion()) + 1 },
			{ "serialNumber",         getSerialNumber().toString()       },
			{ "issuer",               getIssuer().toString()             },
			{ "validity",
             {
			      { "notBefore", getNotBefore().toString() },
			      { "notAfter", getNotAfter().toString() },
			  }			                                              },
			{ "subject",              getSubject().toString()            },
			{ "subjectPublicKeyInfo",
             { { "subjectPublicKeyAlgorithm", getPublicKeyAlgorithm().toString() },
			    { "subjectPublicKey", getPublicKey().toString() } }      },
			{ "extensions",           extensions                         },
			{ "signatureAlgorithm",   getSignatureAlgorithm().toString() },
			{ "signature",            getSignature().toString()          }
		};

		return certificateJson.dump(indent);
	}
}  // namespace pcpp
