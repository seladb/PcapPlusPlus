#include "X509ExtensionDataDecoder.h"
#include "GeneralUtils.h"
#include <unordered_map>

namespace pcpp
{
	std::string X509ExtendedKeyUsagePurpose::toString() const
	{
		switch (m_Value)
		{
		case ServerAuth:
			return "ServerAuth";
		case ClientAuth:
			return "ClientAuth";
		case CodeSigning:
			return "CodeSigning";
		case EmailProtection:
			return "EmailProtection";
		case TimeStamping:
			return "TimeStamping";
		case OCSPSigning:
			return "OCSPSigning";
		case IPSecEndSystem:
			return "IPSecEndSystem";
		case IPSecTunnel:
			return "IPSecTunnel";
		case IPSecUser:
			return "IPSecUser";
		case AnyExtendedKeyUsage:
			return "AnyExtendedKeyUsage";
		case SmartCardLogon:
			return "SmartCardLogon";
		case EncryptedFileSystem:
			return "EncryptedFileSystem";
		case DocumentSigning:
			return "DocumentSigning";
		default:
			return "Unknown";
		}
	}

	std::string X509ExtendedKeyUsagePurpose::getOidValue() const
	{
		switch (m_Value)
		{
		case ServerAuth:
			return "1.3.6.1.5.5.7.3.1";
		case ClientAuth:
			return "1.3.6.1.5.5.7.3.2";
		case CodeSigning:
			return "1.3.6.1.5.5.7.3.3";
		case EmailProtection:
			return "1.3.6.1.5.5.7.3.4";
		case TimeStamping:
			return "1.3.6.1.5.5.7.3.8";
		case OCSPSigning:
			return "1.3.6.1.5.5.7.3.9";
		case IPSecEndSystem:
			return "1.3.6.1.5.5.7.3.5";
		case IPSecTunnel:
			return "1.3.6.1.5.5.7.3.6";
		case IPSecUser:
			return "1.3.6.1.5.5.7.3.7";
		case AnyExtendedKeyUsage:
			return "2.5.29.37.0";
		case SmartCardLogon:
			return "1.3.6.1.4.1.311.20.2.2";
		case EncryptedFileSystem:
			return "1.3.6.1.4.1.311.10.3.4";
		case DocumentSigning:
			return "1.3.6.1.4.1.311.10.3.12";
		default:
			return "0.0";
		}
	}

	static const std::unordered_map<std::string, X509ExtendedKeyUsagePurpose::Value>
	    X509ExtendedKeyUsagePurposeOidMap = {
		    { "1.3.6.1.5.5.7.3.1",       X509ExtendedKeyUsagePurpose::ServerAuth          },
		    { "1.3.6.1.5.5.7.3.2",       X509ExtendedKeyUsagePurpose::ClientAuth          },
		    { "1.3.6.1.5.5.7.3.3",       X509ExtendedKeyUsagePurpose::CodeSigning         },
		    { "1.3.6.1.5.5.7.3.4",       X509ExtendedKeyUsagePurpose::EmailProtection     },
		    { "1.3.6.1.5.5.7.3.8",       X509ExtendedKeyUsagePurpose::TimeStamping        },
		    { "1.3.6.1.5.5.7.3.9",       X509ExtendedKeyUsagePurpose::OCSPSigning         },
		    { "1.3.6.1.5.5.7.3.5",       X509ExtendedKeyUsagePurpose::IPSecEndSystem      },
		    { "1.3.6.1.5.5.7.3.6",       X509ExtendedKeyUsagePurpose::IPSecTunnel         },
		    { "1.3.6.1.5.5.7.3.7",       X509ExtendedKeyUsagePurpose::IPSecUser           },
		    { "2.5.29.37.0",             X509ExtendedKeyUsagePurpose::AnyExtendedKeyUsage },
		    { "1.3.6.1.4.1.311.20.2.2",  X509ExtendedKeyUsagePurpose::SmartCardLogon      },
		    { "1.3.6.1.4.1.311.10.3.4",  X509ExtendedKeyUsagePurpose::EncryptedFileSystem },
		    { "1.3.6.1.4.1.311.10.3.12", X509ExtendedKeyUsagePurpose::DocumentSigning     },
		    { "0.0",		             X509ExtendedKeyUsagePurpose::Unknown             },
    };

	X509ExtendedKeyUsagePurpose X509ExtendedKeyUsagePurpose::fromOidValue(const Asn1ObjectIdentifier& value)
	{
		auto it = X509ExtendedKeyUsagePurposeOidMap.find(value.toString());
		if (it != X509ExtendedKeyUsagePurposeOidMap.end())
		{
			return { it->second };
		}

		return { Unknown };
	}

	template <class Asn1RecordType>
	static Asn1RecordType* castRecordAs(Asn1Record* record, const std::string& extensionName,
	                                    const std::string& fieldName)
	{
		try
		{
			return record->castAs<Asn1RecordType>();
		}
		catch (const std::bad_cast&)
		{
			throw std::runtime_error("Invalid X509 certificate " + extensionName + " extension data: " + fieldName);
		}
	}

	template <class Asn1RecordType>
	static Asn1RecordType* getSubRecordAndCast(Asn1ConstructedRecord* record, int index,
	                                           const std::string& extensionName, const std::string& fieldName)
	{
		try
		{
			return castRecordAs<Asn1RecordType>(record->getSubRecords().at(index), extensionName, fieldName);
		}
		catch (const std::out_of_range&)
		{
			throw std::runtime_error("Invalid X509 certificate " + extensionName + " extension data: " + fieldName);
		}
	}

	namespace X509Internal
	{
		std::unique_ptr<Asn1Record> X509ExtensionDataDecoder::decodeAsn1Data(const std::string& rawData,
		                                                                     std::vector<uint8_t>& rawDataBytes)
		{
			rawDataBytes.resize(rawData.length() / 2);
			hexStringToByteArray(rawData, rawDataBytes.data(), rawData.length() / 2);
			return Asn1Record::decode(rawDataBytes.data(), rawData.size());
		}

		std::unique_ptr<X509BasicConstraintsDataDecoder> X509BasicConstraintsDataDecoder::create(
		    const std::string& rawData)
		{
			std::vector<uint8_t> rawDataBytes;
			auto record = decodeAsn1Data(rawData, rawDataBytes);
			auto basicConstraintsRecord = castRecordAs<Asn1SequenceRecord>(record.get(), "Basic Constraints", "Value");
			bool isCA = false;
			uint8_t pathLenConstraint = 0;
			if (basicConstraintsRecord->getSubRecords().size() > isCAOffset)
			{
				isCA = getSubRecordAndCast<Asn1BooleanRecord>(basicConstraintsRecord, isCAOffset, "Basic Constraints",
				                                              "Is CA")
				           ->getValue();
			}
			if (basicConstraintsRecord->getSubRecords().size() > pathLenConstraintOffset)
			{
				pathLenConstraint =
				    getSubRecordAndCast<Asn1IntegerRecord>(basicConstraintsRecord, pathLenConstraintOffset,
				                                           "Basic Constraints", "Path Length Constraint")
				        ->getIntValue<uint8_t>();
			}

			return std::unique_ptr<X509BasicConstraintsDataDecoder>(
			    new X509BasicConstraintsDataDecoder(isCA, pathLenConstraint));
		}

		std::unique_ptr<X509SubjectKeyIdentifierDataDecoder> X509SubjectKeyIdentifierDataDecoder::create(
		    const std::string& rawData)
		{
			std::vector<uint8_t> rawDataBytes;
			auto record = decodeAsn1Data(rawData, rawDataBytes);
			auto keyIdentifier =
			    castRecordAs<Asn1OctetStringRecord>(record.get(), "Subject Key Identifier", "Key Identifier")
			        ->getValue();
			return std::unique_ptr<X509SubjectKeyIdentifierDataDecoder>(
			    new X509SubjectKeyIdentifierDataDecoder(keyIdentifier));
		}

		std::unique_ptr<X509KeyUsageDataDecoder> X509KeyUsageDataDecoder::create(const std::string& rawData)
		{
			std::vector<uint8_t> rawDataBytes;
			auto record = decodeAsn1Data(rawData, rawDataBytes);
			auto keyUsage = castRecordAs<Asn1BitStringRecord>(record.get(), "Key Usage", "Key Usage")->getValue();
			return std::unique_ptr<X509KeyUsageDataDecoder>(new X509KeyUsageDataDecoder(keyUsage));
		}

		std::unique_ptr<X509ExtendedKeyUsageDataDecoder> X509ExtendedKeyUsageDataDecoder::create(
		    const std::string& rawData)
		{
			std::vector<uint8_t> rawDataBytes;
			auto record = decodeAsn1Data(rawData, rawDataBytes);
			auto extendedKeyUsageRecord =
			    castRecordAs<Asn1SequenceRecord>(record.get(), "Extended Key Usage", "Purposes List");
			auto result = std::unique_ptr<X509ExtendedKeyUsageDataDecoder>(new X509ExtendedKeyUsageDataDecoder());
			for (const auto& subRecord : extendedKeyUsageRecord->getSubRecords())
			{
				result->m_ExtendedKeyUsagePurposes.push_back(
				    subRecord->castAs<Asn1ObjectIdentifierRecord>()->getValue());
			}

			return result;
		}
	}  // namespace X509Internal

	X509BasicConstraintsExtension::X509BasicConstraintsExtension(const std::string& rawExtensionData)
	{
		auto dataDecoder = X509Internal::X509BasicConstraintsDataDecoder::create(rawExtensionData);
		m_IsCA = dataDecoder->isCA();
		m_PathLenConstraint = dataDecoder->getPathLenConstraint();
	}

	X509SubjectKeyIdentifierExtension::X509SubjectKeyIdentifierExtension(const std::string& rawExtensionData)
	{
		auto dataDecoder = X509Internal::X509SubjectKeyIdentifierDataDecoder::create(rawExtensionData);
		m_KeyIdentifier = dataDecoder->getKeyIdentifier();
	}

	X509KeyUsageExtension::X509KeyUsageExtension(const std::string& rawExtensionData)
	{
		auto dataDecoder = X509Internal::X509KeyUsageDataDecoder::create(rawExtensionData);
		m_BitString = dataDecoder->getKeyUsage();
	}

	bool X509KeyUsageExtension::isBitSet(size_t location) const
	{
		if (m_BitString.size() < location + 1)
		{
			return false;
		}

		return m_BitString[m_BitString.size() - 1 - location] == '1';
	}

	bool X509KeyUsageExtension::isDigitalSignature() const
	{
		return isBitSet(digitalSignatureLocation);
	}

	bool X509KeyUsageExtension::isNonRepudiation() const
	{
		return isBitSet(nonRepudiationLocation);
	}

	bool X509KeyUsageExtension::isKeyEncipherment() const
	{
		return isBitSet(keyEnciphermentLocation);
	}

	bool X509KeyUsageExtension::isDataEncipherment() const
	{
		return isBitSet(dataEnciphermentLocation);
	}

	bool X509KeyUsageExtension::isKeyAgreement() const
	{
		return isBitSet(keyAgreementLocation);
	}

	bool X509KeyUsageExtension::isKeyCertSign() const
	{
		return isBitSet(keyCertSignLocation);
	}

	bool X509KeyUsageExtension::isCRLSign() const
	{
		return isBitSet(crlSignLocation);
	}

	bool X509KeyUsageExtension::isEncipherOnly() const
	{
		return isBitSet(encipherOnlyLocation);
	}

	bool X509KeyUsageExtension::isDecipherOnly() const
	{
		return isBitSet(decipherOnlyLocation);
	}

	X509ExtendedKeyUsageExtension::X509ExtendedKeyUsageExtension(const std::string& rawExtensionData)
	{
		auto dataDecoder = X509Internal::X509ExtendedKeyUsageDataDecoder::create(rawExtensionData);
		for (const auto& purpose : dataDecoder->getExtendedKeyUsagePurposes())
		{
			m_Purposes.push_back(X509ExtendedKeyUsagePurpose::fromOidValue(purpose));
		}
	}
}  // namespace pcpp
