#include <cstdint>
#include <memory>
#include <vector>

#include <X509Decoder.h>
#include <X509ExtensionDataDecoder.h>
#include <Logger.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (size == 0)
		return 0;

	pcpp::Logger::getInstance().suppressLogs();

	// fromDER needs a mutable buffer that outlives the parse
	std::vector<uint8_t> buf(data, data + size);

	try
	{
		auto cert = pcpp::X509Certificate::fromDER(buf.data(), buf.size());
		if (!cert)
			return 0;

		cert->getVersion();
		cert->getSerialNumber();
		cert->getIssuer();
		cert->getSubject();
		cert->getNotBefore();
		cert->getNotAfter();
		cert->getPublicKeyAlgorithm();
		cert->getPublicKey();
		cert->getSignatureAlgorithm();
		cert->getSignature();
		cert->toJson();

		for (const auto& ext : cert->getExtensions())
		{
			ext.getType();
			ext.isCritical();

			auto extData = ext.getData();
			if (!extData)
				continue;

			switch (ext.getType())
			{
			case pcpp::X509ExtensionType::BasicConstraints:
			{
				auto* bc = extData->castAs<pcpp::X509BasicConstraintsExtension>();
				bc->isCA();
				bc->getPathLenConstraint();
				break;
			}
			case pcpp::X509ExtensionType::KeyUsage:
			{
				auto* ku = extData->castAs<pcpp::X509KeyUsageExtension>();
				ku->isDigitalSignature();
				ku->isNonRepudiation();
				ku->isKeyEncipherment();
				ku->isDataEncipherment();
				ku->isKeyAgreement();
				ku->isKeyCertSign();
				ku->isCRLSign();
				ku->isEncipherOnly();
				ku->isDecipherOnly();
				break;
			}
			case pcpp::X509ExtensionType::ExtendedKeyUsage:
				extData->castAs<pcpp::X509ExtendedKeyUsageExtension>()->getPurposes();
				break;
			case pcpp::X509ExtensionType::SubjectKeyIdentifier:
				extData->castAs<pcpp::X509SubjectKeyIdentifierExtension>()->getKeyIdentifier();
				break;
			default:
				break;
			}
		}
	}
	catch (...)
	{}

	return 0;
}
