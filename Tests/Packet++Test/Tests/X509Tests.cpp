#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GeneralUtils.h"
#include "X509Decoder.h"


std::vector<uint8_t> base64_decode_scratch(const std::string& encoded_string)
{
    // The Base64 character set
    const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Build the reverse lookup table only once
    static std::vector<int> decoding_table(256, -1);
    if (decoding_table[0] == -1) { // Simple check to see if it's uninitialized
        for (int i = 0; i < 64; i++) {
            decoding_table[static_cast<unsigned char>(BASE64_CHARS[i])] = i;
        }
    }

    int in_len = encoded_string.size();
    if (in_len % 4 != 0) {
        throw std::runtime_error("Input data size is not a multiple of 4.");
    }

    std::vector<uint8_t> decoded_bytes;
    // Reserve memory to avoid reallocations
    decoded_bytes.reserve((in_len / 4) * 3);

    int char_idx = 0;
    uint32_t sextet_a, sextet_b, sextet_c, sextet_d;
    uint32_t triple;

    while (char_idx < in_len && encoded_string[char_idx] != '=') {
        // Read 4 characters (24 bits) from the encoded string
        sextet_a = decoding_table[static_cast<unsigned char>(encoded_string[char_idx++])];
        sextet_b = decoding_table[static_cast<unsigned char>(encoded_string[char_idx++])];
        sextet_c = decoding_table[static_cast<unsigned char>(encoded_string[char_idx++])];
        sextet_d = decoding_table[static_cast<unsigned char>(encoded_string[char_idx++])];

        // Combine the 4 sextets into a 24-bit triple
        triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        // Extract 3 bytes (8 bits each) from the 24-bit triple and push to vector
        decoded_bytes.push_back((triple >> 16) & 0xFF); // First byte
        decoded_bytes.push_back((triple >> 8) & 0xFF);  // Second byte
        decoded_bytes.push_back(triple & 0xFF);         // Third byte
    }

    // Handle padding
    if (char_idx < in_len && encoded_string[char_idx] == '=') {
        // Two padding characters ('==') mean the last group had only one original byte.
        // We have already written the first byte, so we just need to remove the last two.
        if (char_idx + 1 < in_len && encoded_string[char_idx + 1] == '=') {
            decoded_bytes.pop_back();
            decoded_bytes.pop_back();
        }
        // One padding character ('=') means the last group had two original bytes.
        // We only need to remove the last one.
        else {
             decoded_bytes.pop_back();
        }
    }

    return decoded_bytes;
}

PTF_TEST_CASE(X509ParsingTest)
{
	// std::string rawDataString = "308204a130820448a003020102021100ab6686b5627be80596821330128649f5300a06082a8648ce3d04030230818f310b3009060355040613024742311b30190603550408131247726561746572204d616e636865737465723110300e0603550407130753616c666f726431183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f2045434320446f6d61696e2056616c69646174696f6e2053656375726520536572766572204341301e170d3235303230353030303030305a170d3236303230353233353935395a3015311330110603550403130a6769746875622e636f6d3059301306072a8648ce3d020106082a8648ce3d0301070342000420345c46ff2ccbf8249aaef0bb2f77a91f97213671bac22618c51e43fd9d49e0cc469c85fc29b4f97c280ba32cc75cbf6fe746dd048abacb802d37880dee06d6a38202fc308202f8301f0603551d23041830168014f6850a3b1186e1047d0eaa0b2cd2eecc647b7bae301d0603551d0e0416041453c87fde9e984ec74dd6bcdeab953e303d3dd1c8300e0603551d0f0101ff040403020780300c0603551d130101ff04023000301d0603551d250416301406082b0601050507030106082b0601050507030230490603551d20044230403034060b2b06010401b231010202073025302306082b06010505070201161768747470733a2f2f7365637469676f2e636f6d2f4350533008060667810c01020130818406082b0601050507010104783076304f06082b060105050730028643687474703a2f2f6372742e7365637469676f2e636f6d2f5365637469676f454343446f6d61696e56616c69646174696f6e53656375726553657276657243412e637274302306082b060105050730018617687474703a2f2f6f6373702e7365637469676f2e636f6d3082017e060a2b06010401d6790204020482016e0482016a0168007500969764bf555897adf743876837084277e9f03ad5f6a4f3366e46a43f0fcaa9c600000194d36b944b000004030046304402203b8baa3e2e9423b7a01e12396d1e1b3f4e21029c7774c5379eaffdef0f5c60b002206251b0468b7e4aa1010acfff7ebc7f6074cfc28c7d40b772ec68d32d61df70c00077001986d4c728aa6ffeba036f782a4d0191aace2d72310faece5d70412d254cc7d400000194d36b93ed0000040300483046022100e5ac89f1ec9fb731faa0c41dbe16fab774c964d6a8f87213b0ffe1e46157c6d0022100c4fe24a0107d4b887411b17ebcab1abc2c383de946cd6dc80cb291d3c6460b13007600cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e700000194d36b94250000040300473045022100d46296f766a00c5349218acc1f781a25d5ec74856951c64e7f11f5164b1bb8b1022052427ec948361739dd0d1320c24775c14e5b6b601b8b4103574bf3cd6d5db32730250603551d11041e301c820a6769746875622e636f6d820e7777772e6769746875622e636f6d300a06082a8648ce3d04030203470030440220718ca76ec1041275df9ea509ed96632cd8229fdf00e350337024784fdfca6d2c02206d55f377620219fa778711fc1c461873e2e0e973c17eb4a9ad71e5894a270c90";
	std::string rawDataString = "308203a73082034ca0030201020211008f7cfe109efa987f116812e198008497300a06082a8648ce3d040302303b310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531301e170d3235303630313030343534335a170d3235303833303031343533395a3016311430120603550403130b636861746770742e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200041b6fda7f7dec4396ae831701f792ce0a185018739fe4275b4bd4b642b89c01329431d369f42dca9eb9863553206ad945e603130cfd9451552184066fdf5bb999a382025430820250300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e041604149b9dcac58952129eff05e58637f09d6ace2d0a96301f0603551d230418301680149077923567c4ffa8cca9e67bd980797bcc93f938305e06082b0601050507010104523050302706082b06010505073001861b687474703a2f2f6f2e706b692e676f6f672f732f7765312f6a3377302506082b060105050730028619687474703a2f2f692e706b692e676f6f672f7765312e63727430250603551d11041e301c820b636861746770742e636f6d820d2a2e636861746770742e636f6d30130603551d20040c300a3008060667810c01020130360603551d1f042f302d302ba029a0278625687474703a2f2f632e706b692e676f6f672f7765312f4450325053387a516e56732e63726c30820105060a2b06010401d6790204020481f60481f300f100760012f14e34bd53724c840619c38f3f7a13f8e7b56287889c6d300584ebe586263a00000197292a8d190000040300473045022100c6d289a41c9d63e7c549c444d724d5c78286fcb753b71ca0d070377c74526e3c022043f3a4548f4530b0041cd07a37f05e53f7960db800b9dc34472b55a2bb85e39a0077000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e421eb47e4eaa3400000197292a8d260000040300483046022100b71d1b1f0b0dd4506acafa8fdd3dff65b0e362b47ed5edca98c79bfc1ea49c210221009eda8fcdbb2a985adb2f8d038dfa4e60ebbab3daf027efa236e273fc4120218e300a06082a8648ce3d0403020349003046022100df06da8275839e65db92d8a17b5e3c8de8d661e939ce2ee55992f38f0a4f43f50221008fdf13b1a5e010f5e17b8696507da863dd1867d47e94f21ba640c6e960761160";

	uint8_t data[5000];
	auto dataLen = pcpp::hexStringToByteArray(rawDataString, data, 5000);

	// auto x509Cert = pcpp::X509Certificate::fromDER(data, dataLen);
	// auto x509Cert = pcpp::X509Certificate::fromDER(rawDataString);
	auto x509Cert = pcpp::X509Certificate::fromDERFile("/Users/seladb/Downloads/cert.der");
	auto cert = x509Cert->getRawCertificate();
	// auto cert = pcpp::X509Decoder::X509Certificate::decode(data, dataLen);
	std::cout << "Version: " << static_cast<int>(cert->getTbsCertificate().getVersion()) << std::endl;
	std::cout << "Serial number: " << cert->getTbsCertificate().getSerialNumber() << std::endl;
	std::cout << "Signature: " << cert->getTbsCertificate().getSignature().getAlgorithm().toString() << std::endl;
	std::cout << "Issuer: " << std::endl;
	for (const auto& component : cert->getTbsCertificate().getIssuer().getRDNs())
	{
		std::cout << "  Type: " << component.getType().toString() << ", Value: " << component.getValue() << std::endl;
	}
	std::cout << "Issuer: " << x509Cert->getIssuer().toString() << std::endl;
	std::cout << "Validity: " << std::endl;
	std::cout << "  Not Before: " << cert->getTbsCertificate().getValidity().getNotBefore() << std::endl;
	std::cout << "  Not After: " << cert->getTbsCertificate().getValidity().getNotAfter() << std::endl;
	std::cout << "Subject: " << std::endl;
	for (const auto& component : cert->getTbsCertificate().getSubject().getRDNs())
	{
		std::cout << "  Type: " << component.getType().toString() << ", Value: " << component.getValue() << std::endl;
	}
	std::cout << "Subject: " << x509Cert->getSubject().toString() << std::endl;
	std::cout << "Subject public key info: " << std::endl;
	auto subjectPublicKeyInfo = cert->getTbsCertificate().getSubjectPublicKeyInfo();
	std::cout << "  Algorithm: " << subjectPublicKeyInfo.getAlgorithm().getAlgorithm().toString() << std::endl;
	auto publicKey = pcpp::byteArrayToHexString(subjectPublicKeyInfo.getSubjectPublicKey().data(), subjectPublicKeyInfo.getSubjectPublicKey().size());
	std::cout << "  Subject Public Key: " << publicKey << std::endl;
	std::cout << "Public Key Algorithm: " << x509Cert->getPublicKeyAlgorithm().toString() << std::endl;
	auto extensions = cert->getTbsCertificate().getExtensions();
	if (extensions != nullptr)
	{
		std::cout << "Extensions: " << std::endl;
		for (const auto& extension : extensions->getExtensions())
		{
			std::cout << "  Type: " << extension.getType().toString() << ", Value: " << extension.getValue() << std::endl;
		}
	}

	std::cout << "Has extension AuthorityKeyIdentifier? " << (x509Cert->hasExtension(pcpp::X509ExtensionType::AuthorityKeyIdentifier) ? "true" : "false") << std::endl;
	std::cout << "Has extension CrlDistributionPoints? " << (x509Cert->hasExtension(pcpp::X509ExtensionType::CrlDistributionPoints) ? "true" : "false") << std::endl;

	std::cout << "Signature Algorithm: " << cert->getSignatureAlgorithm().getAlgorithm().toString() << std::endl;
	std::cout << "Signature Algorithm: " << x509Cert->getSignatureAlgorithm().toString() << std::endl;
	auto signature = pcpp::byteArrayToHexString(cert->getSignature().data(), cert->getSignature().size());
	std::cout << "Signature: " << signature << std::endl;
}
