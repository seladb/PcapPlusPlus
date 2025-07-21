#include "../TestDefinition.h"
#include "GeneralUtils.h"
#include "X509Decoder.h"
#include <tuple>
#include <algorithm>

PTF_TEST_CASE(X509ParsingTest)
{
	auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_chatgpt.der");

	PTF_ASSERT_EQUAL(x509Certificate->getVersion(), pcpp::X509Version::V3, enumclass);
	PTF_ASSERT_EQUAL(x509Certificate->getSerialNumber().toString(), "8f:7c:fe:10:9e:fa:98:7f:11:68:12:e1:98:00:84:97");
	PTF_ASSERT_EQUAL(x509Certificate->getSerialNumber().toString(""), "8f7cfe109efa987f116812e198008497");
	PTF_ASSERT_EQUAL(x509Certificate->getSerialNumber().toString(", "),
	                 "8f, 7c, fe, 10, 9e, fa, 98, 7f, 11, 68, 12, e1, 98, 00, 84, 97");

	auto issuer = x509Certificate->getIssuer();
	PTF_ASSERT_EQUAL(issuer.toString(), "C=US, O=Google Trust Services, CN=WE1");
	PTF_ASSERT_EQUAL(issuer.toString("\n"), "C=US\nO=Google Trust Services\nCN=WE1");
	std::vector<pcpp::X509Name::RDN> expectedIssuerRDNs = {
		{ pcpp::X520DistinguishedName::Country,      "US"                    },
		{ pcpp::X520DistinguishedName::Organization, "Google Trust Services" },
		{ pcpp::X520DistinguishedName::CommonName,   "WE1"                   }
	};
	PTF_ASSERT_VECTORS_EQUAL(issuer.getRDNs(), expectedIssuerRDNs);

	PTF_ASSERT_EQUAL(x509Certificate->getNotBefore().toString(), "2025-06-01 00:45:43");
	PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
	                     x509Certificate->getNotBefore().getTimestamp().time_since_epoch())
	                     .count(),
	                 1748738743000000);
	PTF_ASSERT_EQUAL(x509Certificate->getNotAfter().toString(), "2025-08-30 01:45:39");
	PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
	                     x509Certificate->getNotAfter().getTimestamp().time_since_epoch())
	                     .count(),
	                 1756518339000000);

	auto subject = x509Certificate->getSubject();
	PTF_ASSERT_EQUAL(subject.toString(), "CN=chatgpt.com");
	std::vector<pcpp::X509Name::RDN> expectedSubjectRDNs = {
		{ pcpp::X520DistinguishedName::CommonName, "chatgpt.com" }
	};
	PTF_ASSERT_VECTORS_EQUAL(subject.getRDNs(), expectedSubjectRDNs);

	PTF_ASSERT_EQUAL(x509Certificate->getPublicKeyAlgorithm(), pcpp::X509Algorithm::ECDSA, enum);
	PTF_ASSERT_EQUAL(
	    x509Certificate->getPublicKey().toString(),
	    "04:1b:6f:da:7f:7d:ec:43:96:ae:83:17:01:f7:92:ce:0a:18:50:18:73:9f:e4:27:5b:4b:d4:b6:42:b8:9c:01:32:94:31:d3:69:f4:2d:ca:9e:b9:86:35:53:20:6a:d9:45:e6:03:13:0c:fd:94:51:55:21:84:06:6f:df:5b:b9:99");

	PTF_ASSERT_EQUAL(x509Certificate->getSignatureAlgorithm(), pcpp::X509Algorithm::ECDSAWithSHA256, enum);
	PTF_ASSERT_EQUAL(
	    x509Certificate->getSignature().toString(),
	    "30:46:02:21:00:df:06:da:82:75:83:9e:65:db:92:d8:a1:7b:5e:3c:8d:e8:d6:61:e9:39:ce:2e:e5:59:92:f3:8f:0a:4f:43:f5:02:21:00:8f:df:13:b1:a5:e0:10:f5:e1:7b:86:96:50:7d:a8:63:dd:18:67:d4:7e:94:f2:1b:a6:40:c6:e9:60:76:11:60");

	std::vector<std::tuple<pcpp::X509ExtensionType, bool, std::string>> expectedExtensions = {
		{ pcpp::X509ExtensionType::KeyUsage,               true,  "03020780"		                                                                                                                                                                                                                                                                                                                                                                                                                                    },
		{ pcpp::X509ExtensionType::ExtendedKeyUsage,       false, "300a06082b06010505070301"		                                                                                                                                                                                                                                                                                                                                                                                                                    },
		{ pcpp::X509ExtensionType::BasicConstraints,       true,  "3000"		                                                                                                                                                                                                                                                                                                                                                                                                                                        },
		{ pcpp::X509ExtensionType::SubjectKeyIdentifier,   false, "04149b9dcac58952129eff05e58637f09d6ace2d0a96"		                                                                                                                                                                                                                                                                                                                                                                                                },
		{ pcpp::X509ExtensionType::AuthorityKeyIdentifier, false, "301680149077923567c4ffa8cca9e67bd980797bcc93f938"		                                                                                                                                                                                                                                                                                                                                                                                            },
		{ pcpp::X509ExtensionType::AuthorityInfoAccess,    false,
         "3050302706082b06010505073001861b687474703a2f2f6f2e706b692e676f6f672f732f7765312f6a3377302506082b060105050730028619687474703a2f2f692e706b692e676f6f672f7765312e637274"		                                                                                                                                                                                                                                                                                                                                 },
		{ pcpp::X509ExtensionType::SubjectAltName,         false,
         "301c820b636861746770742e636f6d820d2a2e636861746770742e636f6d"		                                                                                                                                                                                                                                                                                                                                                                                                                                         },
		{ pcpp::X509ExtensionType::CertificatePolicies,    false, "300a3008060667810c010201"		                                                                                                                                                                                                                                                                                                                                                                                                                    },
		{ pcpp::X509ExtensionType::CrlDistributionPoints,  false,
         "302d302ba029a0278625687474703a2f2f632e706b692e676f6f672f7765312f4450325053387a516e56732e63726c"		                                                                                                                                                                                                                                                                                                                                                                                                       },
		{ pcpp::X509ExtensionType::CTPrecertificateSCTs,   false,
         "0481f300f100760012f14e34bd53724c840619c38f3f7a13f8e7b56287889c6d300584ebe586263a00000197292a8d190000040300473045022100c6d289a41c9d63e7c549c444d724d5c78286fcb753b71ca0d070377c74526e3c022043f3a4548f4530b0041cd07a37f05e53f7960db800b9dc34472b55a2bb85e39a0077000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e421eb47e4eaa3400000197292a8d260000040300483046022100b71d1b1f0b0dd4506acafa8fdd3dff65b0e362b47ed5edca98c79bfc1ea49c210221009eda8fcdbb2a985adb2f8d038dfa4e60ebbab3daf027efa236e273fc4120218e" }
	};

	PTF_ASSERT_EQUAL(x509Certificate->getExtensions().size(), 10);
	int i = 0;
	for (auto const& extension : x509Certificate->getExtensions())
	{
		PTF_ASSERT_EQUAL(extension.getType(), std::get<0>(expectedExtensions[i]));
		PTF_ASSERT_EQUAL(extension.isCritical(), std::get<1>(expectedExtensions[i]));
		PTF_ASSERT_EQUAL(extension.getRawDataAsHexString(), std::get<2>(expectedExtensions[i]));
		i++;
	}

	for (auto const& expectedExtension : expectedExtensions)
	{
		PTF_ASSERT_TRUE(x509Certificate->hasExtension(std::get<0>(expectedExtension)));
		PTF_ASSERT_NOT_NULL(x509Certificate->getExtension(std::get<0>(expectedExtension)));
	}

	std::vector<pcpp::X509ExtensionType> missingExtensionTypes = { pcpp::X509ExtensionType::IssuerAltName,
		                                                           pcpp::X509ExtensionType::PolicyMappings,
		                                                           pcpp::X509ExtensionType::PolicyConstraints };
	for (const auto& extensionType : missingExtensionTypes)
	{
		PTF_ASSERT_FALSE(x509Certificate->hasExtension(extensionType));
		PTF_ASSERT_NULL(x509Certificate->getExtension(extensionType));
	}

	std::string expectedJson =
	    "{\"version\":3,\"serialNumber\":\"8f:7c:fe:10:9e:fa:98:7f:11:68:12:e1:98:00:84:97\",\"issuer\":\"C=US, O=Google Trust Services, CN=WE1\",\"validity\":{\"notBefore\":\"2025-06-01 00:45:43\",\"notAfter\":\"2025-08-30 01:45:39\"},\"subject\":\"CN=chatgpt.com\",\"subjectPublicKeyInfo\":{\"subjectPublicKeyAlgorithm\":\"ECDSA\",\"subjectPublicKey\":\"04:1b:6f:da:7f:7d:ec:43:96:ae:83:17:01:f7:92:ce:0a:18:50:18:73:9f:e4:27:5b:4b:d4:b6:42:b8:9c:01:32:94:31:d3:69:f4:2d:ca:9e:b9:86:35:53:20:6a:d9:45:e6:03:13:0c:fd:94:51:55:21:84:06:6f:df:5b:b9:99\"},\"extensions\":[{\"type\":\"KeyUsage\",\"isCritical\":true},{\"type\":\"ExtendedKeyUsage\",\"isCritical\":false},{\"type\":\"BasicConstraints\",\"isCritical\":true},{\"type\":\"SubjectKeyIdentifier\",\"isCritical\":false},{\"type\":\"AuthorityKeyIdentifier\",\"isCritical\":false},{\"type\":\"AuthorityInfoAccess\",\"isCritical\":false},{\"type\":\"SubjectAltName\",\"isCritical\":false},{\"type\":\"CertificatePolicies\",\"isCritical\":false},{\"type\":\"CRLDistributionPoints\",\"isCritical\":false},{\"type\":\"CTPrecertificateSCTs\",\"isCritical\":false}],\"signatureAlgorithm\":\"ECDSAWithSHA256\",\"signature\":\"30:46:02:21:00:df:06:da:82:75:83:9e:65:db:92:d8:a1:7b:5e:3c:8d:e8:d6:61:e9:39:ce:2e:e5:59:92:f3:8f:0a:4f:43:f5:02:21:00:8f:df:13:b1:a5:e0:10:f5:e1:7b:86:96:50:7d:a8:63:dd:18:67:d4:7e:94:f2:1b:a6:40:c6:e9:60:76:11:60\"}";
	PTF_ASSERT_EQUAL(x509Certificate->toJson(), expectedJson);

	std::string expectedAsn1String = R"(Sequence (constructed), Length: 4+935
  Sequence (constructed), Length: 4+844
    ContextSpecific (0) (constructed), Length: 2+3
      Integer, Length: 2+1, Value: 2
    Integer, Length: 2+17, Value: 0x008f7cfe109efa987f116812e198008497
    Sequence (constructed), Length: 2+10
      ObjectIdentifier, Length: 2+8, Value: 1.2.840.10045.4.3.2
    Sequence (constructed), Length: 2+59
      Set (constructed), Length: 2+11
        Sequence (constructed), Length: 2+9
          ObjectIdentifier, Length: 2+3, Value: 2.5.4.6
          PrintableString, Length: 2+2, Value: US
      Set (constructed), Length: 2+30
        Sequence (constructed), Length: 2+28
          ObjectIdentifier, Length: 2+3, Value: 2.5.4.10
          PrintableString, Length: 2+21, Value: Google Trust Services
      Set (constructed), Length: 2+12
        Sequence (constructed), Length: 2+10
          ObjectIdentifier, Length: 2+3, Value: 2.5.4.3
          PrintableString, Length: 2+3, Value: WE1
    Sequence (constructed), Length: 2+30
      UTCTime, Length: 2+13, Value: 2025-06-01 00:45:43
      UTCTime, Length: 2+13, Value: 2025-08-30 01:45:39
    Sequence (constructed), Length: 2+22
      Set (constructed), Length: 2+20
        Sequence (constructed), Length: 2+18
          ObjectIdentifier, Length: 2+3, Value: 2.5.4.3
          PrintableString, Length: 2+11, Value: chatgpt.com
    Sequence (constructed), Length: 2+89
      Sequence (constructed), Length: 2+19
        ObjectIdentifier, Length: 2+7, Value: 1.2.840.10045.2.1
        ObjectIdentifier, Length: 2+8, Value: 1.2.840.10045.3.1.7
      BitString, Length: 2+66, Value: 0000010000011011011011111101101001111111011111011110110001000011100101101010111010000011000101110000000111110111100100101100111000001010000110000101000000011000011100111001111111100100001001110101101101001011110101001011011001000010101110001001110000000001001100101001010000110001110100110110100111110100001011011100101010011110101110011000011000110101010100110010000001101010110110010100010111100110000000110001001100001100111111011001010001010001010101010010000110000100000001100110111111011111010110111011100110011001
    ContextSpecific (3) (constructed), Length: 4+596
      Sequence (constructed), Length: 4+592
        Sequence (constructed), Length: 2+14
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.15
          Boolean, Length: 2+1, Value: true
          OctetString, Length: 2+4, Value: 03020780
        Sequence (constructed), Length: 2+19
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.37
          OctetString, Length: 2+12, Value: 300a06082b06010505070301
        Sequence (constructed), Length: 2+12
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.19
          Boolean, Length: 2+1, Value: true
          OctetString, Length: 2+2, Value: 3000
        Sequence (constructed), Length: 2+29
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.14
          OctetString, Length: 2+22, Value: 04149b9dcac58952129eff05e58637f09d6ace2d0a96
        Sequence (constructed), Length: 2+31
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.35
          OctetString, Length: 2+24, Value: 301680149077923567c4ffa8cca9e67bd980797bcc93f938
        Sequence (constructed), Length: 2+94
          ObjectIdentifier, Length: 2+8, Value: 1.3.6.1.5.5.7.1.1
          OctetString, Length: 2+82, Value: 3050302706082b06010505073001861b687474703a2f2f6f2e706b692e676f6f672f732f7765312f6a3377302506082b060105050730028619687474703a2f2f692e706b692e676f6f672f7765312e637274
        Sequence (constructed), Length: 2+37
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.17
          OctetString, Length: 2+30, Value: 301c820b636861746770742e636f6d820d2a2e636861746770742e636f6d
        Sequence (constructed), Length: 2+19
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.32
          OctetString, Length: 2+12, Value: 300a3008060667810c010201
        Sequence (constructed), Length: 2+54
          ObjectIdentifier, Length: 2+3, Value: 2.5.29.31
          OctetString, Length: 2+47, Value: 302d302ba029a0278625687474703a2f2f632e706b692e676f6f672f7765312f4450325053387a516e56732e63726c
        Sequence (constructed), Length: 4+261
          ObjectIdentifier, Length: 2+10, Value: 1.3.6.1.4.1.11129.2.4.2
          OctetString, Length: 3+246, Value: 0481f300f100760012f14e34bd53724c840619c38f3f7a13f8e7b56287889c6d300584ebe586263a00000197292a8d190000040300473045022100c6d289a41c9d63e7c549c444d724d5c78286fcb753b71ca0d070377c74526e3c022043f3a4548f4530b0041cd07a37f05e53f7960db800b9dc34472b55a2bb85e39a0077000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e421eb47e4eaa3400000197292a8d260000040300483046022100b71d1b1f0b0dd4506acafa8fdd3dff65b0e362b47ed5edca98c79bfc1ea49c210221009eda8fcdbb2a985adb2f8d038dfa4e60ebbab3daf027efa236e273fc4120218e
  Sequence (constructed), Length: 2+10
    ObjectIdentifier, Length: 2+8, Value: 1.2.840.10045.4.3.2
  BitString, Length: 2+73, Value: 001100000100011000000010001000010000000011011111000001101101101010000010011101011000001110011110011001011101101110010010110110001010000101111011010111100011110010001101111010001101011001100001111010010011100111001110001011101110010101011001100100101111001110001111000010100100111101000011111101010000001000100001000000001000111111011111000100111011000110100101111000000001000011110101111000010111101110000110100101100101000001111101101010000110001111011101000110000110011111010100011111101001010011110010000110111010011001000000110001101110100101100000011101100001000101100000)";

	PTF_ASSERT_EQUAL(x509Certificate->getRawCertificate()->getAsn1Root()->toString(), expectedAsn1String);

	std::string derDataString =
	    "308203a73082034ca0030201020211008f7cfe109efa987f116812e198008497300a06082a8648ce3d040302303b310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531301e170d3235303630313030343534335a170d3235303833303031343533395a3016311430120603550403130b636861746770742e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200041b6fda7f7dec4396ae831701f792ce0a185018739fe4275b4bd4b642b89c01329431d369f42dca9eb9863553206ad945e603130cfd9451552184066fdf5bb999a382025430820250300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e041604149b9dcac58952129eff05e58637f09d6ace2d0a96301f0603551d230418301680149077923567c4ffa8cca9e67bd980797bcc93f938305e06082b0601050507010104523050302706082b06010505073001861b687474703a2f2f6f2e706b692e676f6f672f732f7765312f6a3377302506082b060105050730028619687474703a2f2f692e706b692e676f6f672f7765312e63727430250603551d11041e301c820b636861746770742e636f6d820d2a2e636861746770742e636f6d30130603551d20040c300a3008060667810c01020130360603551d1f042f302d302ba029a0278625687474703a2f2f632e706b692e676f6f672f7765312f4450325053387a516e56732e63726c30820105060a2b06010401d6790204020481f60481f300f100760012f14e34bd53724c840619c38f3f7a13f8e7b56287889c6d300584ebe586263a00000197292a8d190000040300473045022100c6d289a41c9d63e7c549c444d724d5c78286fcb753b71ca0d070377c74526e3c022043f3a4548f4530b0041cd07a37f05e53f7960db800b9dc34472b55a2bb85e39a0077000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e421eb47e4eaa3400000197292a8d260000040300483046022100b71d1b1f0b0dd4506acafa8fdd3dff65b0e362b47ed5edca98c79bfc1ea49c210221009eda8fcdbb2a985adb2f8d038dfa4e60ebbab3daf027efa236e273fc4120218e300a06082a8648ce3d0403020349003046022100df06da8275839e65db92d8a17b5e3c8de8d661e939ce2ee55992f38f0a4f43f50221008fdf13b1a5e010f5e17b8696507da863dd1867d47e94f21ba640c6e960761160";
	uint8_t derData[5000];
	auto derDataLen = pcpp::hexStringToByteArray(derDataString, derData, 5000);

	auto x509CertFromString = pcpp::X509Certificate::fromDER(derDataString);
	auto x509CertFromDerData = pcpp::X509Certificate::fromDER(derData, derDataLen);

	PTF_ASSERT_EQUAL(x509CertFromString->toJson(), expectedJson);
	PTF_ASSERT_EQUAL(x509CertFromDerData->toJson(), expectedJson);

	auto certDerData = x509Certificate->toDER();
	PTF_ASSERT_EQUAL(certDerData.size(), derDataLen)
	PTF_ASSERT_BUF_COMPARE(certDerData.data(), derData, derDataLen);
}

PTF_TEST_CASE(X509VariantsParsingTest)
{
	// Multiple RDNs
	{
		auto x509Cert = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_all_rdns.der");
		std::vector<pcpp::X509Name::RDN> expectedRDNs = {
			{ pcpp::X520DistinguishedName::Country,             "US"                  },
			{ pcpp::X520DistinguishedName::StateOrProvince,     "California"          },
			{ pcpp::X520DistinguishedName::Locality,            "San Francisco"       },
			{ pcpp::X520DistinguishedName::Organization,        "ExampleOrg"          },
			{ pcpp::X520DistinguishedName::OrganizationalUnit,  "DevOps"              },
			{ pcpp::X520DistinguishedName::CommonName,          "example.com"         },
			{ pcpp::X520DistinguishedName::EmailAddress,        "admin@example.com"   },
			{ pcpp::X520DistinguishedName::SerialNumber,        "123456789"           },
			{ pcpp::X520DistinguishedName::Title,               "Engineer"            },
			{ pcpp::X520DistinguishedName::GivenName,           "John"                },
			{ pcpp::X520DistinguishedName::Surname,             "Doe"                 },
			{ pcpp::X520DistinguishedName::Initials,            "JD"                  },
			{ pcpp::X520DistinguishedName::Pseudonym,           "jdoe"                },
			{ pcpp::X520DistinguishedName::GenerationQualifier, "Jr"                  },
			{ pcpp::X520DistinguishedName::DnQualifier,         "qualifier"           },
			{ pcpp::X520DistinguishedName::PostalCode,          "94105"               },
			{ pcpp::X520DistinguishedName::StreetAddress,       "1234 Example Street" },
			{ pcpp::X520DistinguishedName::BusinessCategory,    "IT"                  },
			{ pcpp::X520DistinguishedName::Unknown,             "UID12345"            },
			{ pcpp::X520DistinguishedName::DomainComponent,     "example.com"         },
		};
		std::string rdnsAsString =
		    "C=US, ST=California, L=San Francisco, O=ExampleOrg, OU=DevOps, CN=example.com, E=admin@example.com, SERIALNUMBER=123456789, T=Engineer, G=John, SN=Doe, Initials=JD, Pseudonym=jdoe, GENERATION=Jr, dnQualifier=qualifier, postalCode=94105, STREET=1234 Example Street, businessCategory=IT, Unknown=UID12345, DC=example.com";

		auto issuer = x509Cert->getIssuer();
		PTF_ASSERT_VECTORS_EQUAL(issuer.getRDNs(), expectedRDNs);
		PTF_ASSERT_EQUAL(issuer.toString(), rdnsAsString);

		auto subject = x509Cert->getSubject();
		PTF_ASSERT_VECTORS_EQUAL(subject.getRDNs(), expectedRDNs);
		PTF_ASSERT_EQUAL(subject.toString(), rdnsAsString);
	}

	// Different algorithms
	{
		std::vector<std::tuple<std::string, pcpp::X509Algorithm, pcpp::X509Algorithm>> derFilesAndExpectedAlgs = {
			{ "x509_cert_dsa.der",     pcpp::X509Algorithm::DSAWithSHA256,   pcpp::X509Algorithm::DSA     },
			{ "x509_cert_ecdsa.der",   pcpp::X509Algorithm::ECDSAWithSHA256, pcpp::X509Algorithm::ECDSA   },
			{ "x509_cert_ed25519.der", pcpp::X509Algorithm::ED25519,         pcpp::X509Algorithm::ED25519 },
			{ "x509_cert_rsa.der",     pcpp::X509Algorithm::RSAWithSHA256,   pcpp::X509Algorithm::RSA     },
		};
		for (const auto& derFileAndExpectedAlgs : derFilesAndExpectedAlgs)
		{
			auto x509Cert = pcpp::X509Certificate::fromDERFile("PacketExamples/" + std::get<0>(derFileAndExpectedAlgs));
			PTF_ASSERT_EQUAL(x509Cert->getSignatureAlgorithm(), std::get<1>(derFileAndExpectedAlgs), enum);
			PTF_ASSERT_EQUAL(x509Cert->getPublicKeyAlgorithm(), std::get<2>(derFileAndExpectedAlgs), enum);
		}
	}

	// Doesn't work on 32-bit systems because max time is 2038
#ifndef __MINGW32__
	// Long expiration
	{
		auto x509Cert = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_long_expiration.der");
		PTF_ASSERT_EQUAL(x509Cert->getNotBefore().toString(), "2025-07-08 07:00:24");
		PTF_ASSERT_EQUAL(x509Cert->getNotAfter().toString(), "2051-01-01 07:00:24");
	}
#endif

	// Multiple extensions
	{
		auto x509Cert = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_many_extensions.der");
		PTF_ASSERT_EQUAL(x509Cert->getExtensions().size(), 18);
		std::vector<pcpp::X509ExtensionType> extensionTypes = {
			pcpp::X509ExtensionType::BasicConstraints,
			pcpp::X509ExtensionType::KeyUsage,
			pcpp::X509ExtensionType::ExtendedKeyUsage,
			pcpp::X509ExtensionType::SubjectAltName,
			pcpp::X509ExtensionType::SubjectKeyIdentifier,
			pcpp::X509ExtensionType::CertificatePolicies,
			pcpp::X509ExtensionType::PolicyConstraints,
			pcpp::X509ExtensionType::InhibitAnyPolicy,
			pcpp::X509ExtensionType::NameConstraints,
			pcpp::X509ExtensionType::CrlDistributionPoints,
			pcpp::X509ExtensionType::AuthorityInfoAccess,
			pcpp::X509ExtensionType::SubjectInfoAccess,
			pcpp::X509ExtensionType::FreshestCRL,
			pcpp::X509ExtensionType::TLSFeature,
			pcpp::X509ExtensionType::OcspNoCheck,
			pcpp::X509ExtensionType::CTPrecertificateSCTs,
			pcpp::X509ExtensionType::SubjectDirectoryAttributes,
			pcpp::X509ExtensionType::Unknown,
		};

		for (const auto& extensionType : extensionTypes)
		{
			PTF_ASSERT_TRUE(x509Cert->hasExtension(extensionType));
		}
	}

	// Multiple languages
	{
		auto x509Cert = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_multilang.der");
		auto issuerRDNs = x509Cert->getIssuer().getRDNs();
		auto ouRDN = std::find_if(issuerRDNs.begin(), issuerRDNs.end(), [](pcpp::X509Name::RDN value) {
			return value.type == pcpp::X520DistinguishedName::OrganizationalUnit;
		});

		PTF_ASSERT_EQUAL(ouRDN->value, "שלום 你好 こんにちは 안녕하세요 नमस्ते สวัสดี 🌍🚀");
	}

	// Serial number with leading zeros
	{
		auto x509Cert = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_serial_lead_zeros.der");
		PTF_ASSERT_EQUAL(x509Cert->getSerialNumber().toString(), "80");
	}
}

PTF_TEST_CASE(X509InvalidDataTest)
{
	// Partial data - invalid ASN.1 root record
	{
		std::string partialData = "3082010e3081c1a0030201";
		PTF_ASSERT_RAISES(pcpp::X509Certificate::fromDER(partialData), std::invalid_argument,
		                  "Cannot decode ASN.1 record, data doesn't contain the entire record");
	}

	// Partial data - missing ASN.1 records
	{
		std::string partialData = "300ba0030201020204075bcd15";
		PTF_ASSERT_RAISES(pcpp::X509Certificate::fromDER(partialData), std::runtime_error,
		                  "Invalid X509 certificate data: TBS Certificate");
	}

	// Invalid version
	{
		std::string dataWithInvalidVersion =
		    "3082010e3081c1a0030201040214294861014feb660ccfea3232e4352f7d34df2f7c300506032b657030163114301206035504030c0b6578616d706c652e636f6d301e170d3235303730383039353234365a170d3236303730383039353234365a30163114301206035504030c0b6578616d706c652e636f6d302a300506032b6570032100d20266ed1c28501e0b0dbd0aee37aaff4326b1167fea1381f3da303643bba8d3a321301f301d0603551d0e0416041484b078c94e3e9ee4ecebcc9fcd6ef75ed0815887300506032b6570034100bd3cbb731c6aa2d54528b14315d0c44b173d11be0bbff8458d6298e06f63e6f1fa400a78d962d8e49350192582e624042fcce4fb158b9fbd1c85faa1c3b7340a";
		auto x509Certificate = pcpp::X509Certificate::fromDER(dataWithInvalidVersion);
		PTF_ASSERT_RAISES(x509Certificate->getVersion(), std::runtime_error, "Invalid X509 version value: 4");
	}

	// Invalid NotBefore field
	{
		std::string dataWithInvalidNotBefore =
		    "3082010e3081c1a0030201040214294861014feb660ccfea3232e4352f7d34df2f7c300506032b657030163114301206035504030c0b6578616d706c652e636f6d301e120d3235303730383039353234365a170d3236303730383039353234365a30163114301206035504030c0b6578616d706c652e636f6d302a300506032b6570032100d20266ed1c28501e0b0dbd0aee37aaff4326b1167fea1381f3da303643bba8d3a321301f301d0603551d0e0416041484b078c94e3e9ee4ecebcc9fcd6ef75ed0815887300506032b6570034100bd3cbb731c6aa2d54528b14315d0c44b173d11be0bbff8458d6298e06f63e6f1fa400a78d962d8e49350192582e624042fcce4fb158b9fbd1c85faa1c3b7340a";
		auto x509Certificate = pcpp::X509Certificate::fromDER(dataWithInvalidNotBefore);
		PTF_ASSERT_RAISES(x509Certificate->getNotBefore().toString(), std::runtime_error,
		                  "Invalid X509 certificate data: Not Before");
	}

	// Invalid RDN value
	{
		std::string dataWithInvalidRDNValue =
		    "3082010e3081c1a0030201020214294861014feb660ccfea3232e4352f7d34df2f7c300506032b657030163114301206035504030c0b6578616d706c652e636f6d301e170d3235303730383039353234365a170d3236303730383039353234365a30163114301206035504030a0b6578616d706c652e636f6d302a300506032b6570032100d20266ed1c28501e0b0dbd0aee37aaff4326b1167fea1381f3da303643bba8d3a321301f301d0603551d0e0416041484b078c94e3e9ee4ecebcc9fcd6ef75ed0815887300506032b6570034100bd3cbb731c6aa2d54528b14315d0c44b173d11be0bbff8458d6298e06f63e6f1fa400a78d962d8e49350192582e624042fcce4fb158b9fbd1c85faa1c3b7340a";
		auto x509Certificate = pcpp::X509Certificate::fromDER(dataWithInvalidRDNValue);
		PTF_ASSERT_RAISES(x509Certificate->getSubject().toString(), std::runtime_error,
		                  "Invalid X509 certificate data: unsupported RDN value ASN.1 type: 10");
	}

	// DER file doesn't exist
	{
		PTF_ASSERT_RAISES(pcpp::X509Certificate::fromDERFile("PacketExamples/missing_file.der"), std::runtime_error,
		                  "DER file doesn't exist or cannot be opened");
	}
}

PTF_TEST_CASE(X509ExtensionDataTest)
{
	// BasicConstraints - with data
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_many_extensions.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::BasicConstraints);
		PTF_ASSERT_NOT_NULL(extension);
		auto extensionDataPtr = extension->getData();
		PTF_ASSERT_TRUE(extensionDataPtr->castAs<pcpp::X509BasicConstraintsExtension>()->isCA());
		PTF_ASSERT_EQUAL(extensionDataPtr->castAs<pcpp::X509BasicConstraintsExtension>()->getPathLenConstraint(), 12);
	}

	// BasicConstraints - no data
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_chatgpt.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::BasicConstraints);
		PTF_ASSERT_NOT_NULL(extension);
		auto extensionDataPtr = extension->getData();
		PTF_ASSERT_FALSE(extensionDataPtr->castAs<pcpp::X509BasicConstraintsExtension>()->isCA());
		PTF_ASSERT_EQUAL(extensionDataPtr->castAs<pcpp::X509BasicConstraintsExtension>()->getPathLenConstraint(), 0);
	}

	// SubjectKeyIdentifier
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_chatgpt.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::SubjectKeyIdentifier);
		PTF_ASSERT_NOT_NULL(extension);
		auto extensionDataPtr = extension->getData();
		PTF_ASSERT_EQUAL(extensionDataPtr->castAs<pcpp::X509SubjectKeyIdentifierExtension>()->getKeyIdentifier(),
		                 "9b9dcac58952129eff05e58637f09d6ace2d0a96");
	}

	// KeyUsage - 1 bit exists
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_chatgpt.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::KeyUsage);
		PTF_ASSERT_NOT_NULL(extension);
		auto extensionDataPtr = extension->getData();
		auto extensionData = extensionDataPtr->castAs<pcpp::X509KeyUsageExtension>();
		PTF_ASSERT_TRUE(extensionData->isDigitalSignature());
		PTF_ASSERT_FALSE(extensionData->isKeyEncipherment());
		PTF_ASSERT_FALSE(extensionData->isNonRepudiation());
		PTF_ASSERT_FALSE(extensionData->isDataEncipherment());
		PTF_ASSERT_FALSE(extensionData->isKeyAgreement());
		PTF_ASSERT_FALSE(extensionData->isKeyCertSign());
		PTF_ASSERT_FALSE(extensionData->isCRLSign());
		PTF_ASSERT_FALSE(extensionData->isEncipherOnly());
		PTF_ASSERT_FALSE(extensionData->isDecipherOnly());
	}

	// KeyUsage - 5 bits exist
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_many_extensions.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::KeyUsage);
		PTF_ASSERT_NOT_NULL(extension);
		auto extensionDataPtr = extension->getData();
		auto extensionData = extensionDataPtr->castAs<pcpp::X509KeyUsageExtension>();
		PTF_ASSERT_TRUE(extensionData->isDigitalSignature());
		PTF_ASSERT_TRUE(extensionData->isKeyEncipherment());
		PTF_ASSERT_TRUE(extensionData->isNonRepudiation());
		PTF_ASSERT_FALSE(extensionData->isDataEncipherment());
		PTF_ASSERT_TRUE(extensionData->isKeyAgreement());
		PTF_ASSERT_FALSE(extensionData->isKeyCertSign());
		PTF_ASSERT_FALSE(extensionData->isCRLSign());
		PTF_ASSERT_FALSE(extensionData->isEncipherOnly());
		PTF_ASSERT_FALSE(extensionData->isDecipherOnly());
	}

	// ExtendedKeyUsage
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_many_extensions.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::ExtendedKeyUsage);
		PTF_ASSERT_NOT_NULL(extension);
		auto extensionDataPtr = extension->getData();

		std::vector<pcpp::X509ExtendedKeyUsagePurpose> expectedPurposes = {
			pcpp::X509ExtendedKeyUsagePurpose::ServerAuth,   pcpp::X509ExtendedKeyUsagePurpose::ClientAuth,
			pcpp::X509ExtendedKeyUsagePurpose::CodeSigning,  pcpp::X509ExtendedKeyUsagePurpose::EmailProtection,
			pcpp::X509ExtendedKeyUsagePurpose::TimeStamping, pcpp::X509ExtendedKeyUsagePurpose::OCSPSigning,
		};

		PTF_ASSERT_VECTORS_EQUAL(extensionDataPtr->castAs<pcpp::X509ExtendedKeyUsageExtension>()->getPurposes(),
		                         expectedPurposes);
	}

	// Extension data doesn't exist
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_chatgpt.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::CertificatePolicies);
		PTF_ASSERT_NOT_NULL(extension);
		PTF_ASSERT_NULL(extension->getData());
	}

	// Cast to invalid type
	{
		auto x509Certificate = pcpp::X509Certificate::fromDERFile("PacketExamples/x509_cert_many_extensions.der");
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::ExtendedKeyUsage);
		PTF_ASSERT_NOT_NULL(extension);
		auto extensionDataPtr = extension->getData();
		PTF_ASSERT_RAISES(extensionDataPtr->castAs<pcpp::X509KeyUsageExtension>(), std::runtime_error,
		                  "Trying to cast X509 extension data to the wrong type");
	}

	// Invalid extension - wrong ASN.1 type
	{
		std::string dataWithInvalidSubjectKeyIdentifierData =
		    "3082010e3081c1a0030201020214283c4642303a207d3252acc93fde28a3be53d2c1300506032b657030163114301206035504030c0b6578616d706c652e636f6d301e170d3235303731363036353735345a170d3236303731363036353735345a30163114301206035504030c0b6578616d706c652e636f6d302a300506032b6570032100929aa980b434df25d72a989042b527f7ad34a40f221be06c6adb1c19c5950b7ca321301f301d0603551d0e041603146af318be2f8cc3a402d01b9802208dd9bf071f27300506032b6570034100ec2612468af716fae16cefaa2c42ce1f544c535f5b0033cbdcbbf7e0bdae213c53c027be9a63c59bd53003cd78174ece077b3f69fcbe5d34f64471dc25a54f08";
		auto x509Certificate = pcpp::X509Certificate::fromDER(dataWithInvalidSubjectKeyIdentifierData);
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::SubjectKeyIdentifier);
		PTF_ASSERT_NOT_NULL(extension);
		PTF_ASSERT_RAISES(extension->getData(), std::runtime_error,
		                  "Invalid X509 certificate Subject Key Identifier extension data: Key Identifier");
	}

	// Invalid extension - wrong ASN.1 type in a sequence
	{
		std::string dataWithInvalidBasicConstraintsData =
		    "3082068a30820572a0030201020214727a3a165c5f9d570b038308253b73f4573ec969300d06092a864886f70d01010b05003081a1310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d53616e204672616e636973636f31153013060355040a0c0c4578616d706c6520436f727031163014060355040b0c0d4954204465706172746d656e743114301206035504030c0b6578616d706c652e636f6d3120301e06092a864886f70d010901161161646d696e406578616d706c652e636f6d301e170d3235303731363036353735355a170d3236303731363036353735355a3081a1310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d53616e204672616e636973636f31153013060355040a0c0c4578616d706c6520436f727031163014060355040b0c0d4954204465706172746d656e743114301206035504030c0b6578616d706c652e636f6d3120301e06092a864886f70d010901161161646d696e406578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100c1df5863dcaa9083479b8b597239da32bf1cf074d4235d25a3baad8c8fb50f5a701851663f2e5394209e4d5dc908de5654000a677d2282ca2ab91c2b464732ada47bdda20297e840456ca174842fe3031d37539c8188d968b924aaa2a0138c3d082c47c32dbb01e840e5b0262b641e0bad80b446d4fc9fd28e8e4091c2a6badb30608698057f5744fd7902471a83321b746748482e74e9b392844b8849ebaac6a514448d58e60780ffd03c774a65513bf9650eed3c6ba75be3389cd47f4a5e935878712721a3f06ecbbdc4ccfe1932a568ee856d5844b9db9d48439bd18364cfd5dfeb92199c0677a9d9d6c901e65cc2afdc612b8105acf307f44ca62e148efd0203010001a38202b6308202b230120603551d130101ff040830060201ff02010c300e0603551d0f0101ff0404030203b830450603551d25043e303c06082b0601050507030106082b0601050507030206082b0601050507030306082b0601050507030406082b0601050507030806082b0601050507030930400603551d1104393037820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d8704c0a8010a811161646d696e406578616d706c652e636f6d301d0603551d0e0416041415147d240141ac94de2329a3bfdbb8d7fdde535730180603551d200411300f300d060b2b06010401868d1f010101300c0603551d2404053003800100300a0603551d360403020101301b0603551d1e04143012a010300e820c2e6578616d706c652e636f6d302b0603551d1f042430223020a01ea01c861a687474703a2f2f6578616d706c652e636f6d2f63726c2e70656d305b06082b06010505070101044f304d302406082b060105050730018618687474703a2f2f6f6373702e6578616d706c652e636f6d2f302506082b060105050730028619687474703a2f2f6578616d706c652e636f6d2f63612e70656d303906082b0601050507010b042d302b302906082b06010505070308861d687474703a2f2f74696d657374616d702e6578616d706c652e636f6d2f30310603551d2e042a30283026a024a0228620687474703a2f2f6578616d706c652e636f6d2f64656c74612d63726c2e70656d301c06082b0601050507011804100c0e7374617475735f72657175657374300f06092b0601050507300105040205003012060a2b06010401d679020402040404030201302c0603551d0904250c234578616d706c65207375626a656374206469726563746f727920617474726962757465302a06082a03040506070801041e0c1c437573746f6d20436572746966696361746520457874656e73696f6e300d06092a864886f70d01010b05000382010100a48337e50cfcfe4e0cd422b18ead3f7997910a1d2cf08d7caf505743648ec4a4314bc6ad5b337a5974f2b6e04b16d191a99b65eeff7723e102b74f856935d43b39e841c39941cb1e2265f1cefb96fb8edc662dc8990996762dd2647d2c150f9b3b487cab9727385b2e07e42b51feb64a163c51909b412232c5c41d3341fe00765e4bdae9066cd347ddfcbb0fe2db332bf6dfb3bcc1c01b54f244b8aeee99f4a6fabc57c3583471d7cf7d3ae5cf96cb0d39eaae1e6da2f2ce1c38079363d9c706dc7145f04413986ce21bcd7f5c3b95ceb97e7a467c3b80acff4b03ec0d577c8d83c56297d347bb0834b98b50360b65a1d67acbe4d4dfd5d45b8331b3c2483d51";
		auto x509Certificate = pcpp::X509Certificate::fromDER(dataWithInvalidBasicConstraintsData);
		auto extension = x509Certificate->getExtension(pcpp::X509ExtensionType::BasicConstraints);
		PTF_ASSERT_NOT_NULL(extension);
		PTF_ASSERT_RAISES(extension->getData(), std::runtime_error,
		                  "Invalid X509 certificate Basic Constraints extension data: Is CA");
	}
}
