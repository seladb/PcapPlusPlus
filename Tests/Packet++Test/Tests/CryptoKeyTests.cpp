#include "../TestDefinition.h"
#include "CryptoKeyDecoder.h"
#include <array>

namespace
{
	bool compareStringToFile(const std::string& text, const std::string& filePath)
	{
		std::ifstream file(filePath);
		if (!file)
		{
			return false;
		}

		std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

		return text == fileContent;
	}

	bool compareVectorToBinaryFile(const std::vector<uint8_t>& data, const std::string& filePath)
	{
		std::ifstream file(filePath, std::ios::binary);
		if (!file)
		{
			return false;
		}

		// Read file into vector
		std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

		return data == fileData;
	}
}  // namespace

PTF_TEST_CASE(CryptoKeyDecodingTest)
{
	// RSA private key
	{
		auto rsaPrivateKeyPem = pcpp::RSAPrivateKey::fromPEMFile("PacketExamples/RSAPrivateKey.pem");
		auto rsaPrivateKeyDer = pcpp::RSAPrivateKey::fromDERFile("PacketExamples/RSAPrivateKey.der");

		PTF_ASSERT_TRUE(compareStringToFile(rsaPrivateKeyPem->toPEM(), "PacketExamples/RSAPrivateKey.pem"));
		PTF_ASSERT_TRUE(compareVectorToBinaryFile(rsaPrivateKeyDer->toDER(), "PacketExamples/RSAPrivateKey.der"));

		std::array<std::unique_ptr<pcpp::RSAPrivateKey>, 2> rsaPrivateKeys;
		rsaPrivateKeys[0] = std::move(rsaPrivateKeyPem);
		rsaPrivateKeys[1] = std::move(rsaPrivateKeyDer);

		for (const auto& rsaPrivateKey : rsaPrivateKeys)
		{
			PTF_ASSERT_EQUAL(rsaPrivateKey->getVersion(), 0);
			PTF_ASSERT_EQUAL(
			    rsaPrivateKey->getModulus(),
			    "a2775755304e015b7eba1cac8717652b2f3684b5010ab4e9181f1fc93ae8674b629607a91a519b4668dbd34fadf521a81b8a36484cf4efe62ef5b2101d3309726744f6fd88d9dce4d65c7136e77c8d3042f70bd87d54b1ebb9f42309419b6e9a77139eb4b53da34210eeec5bd4817df4a6fbd9ff353fa90b155d35724d86af7b69c127acf37c3a9affeb8988e614233f17a75ed3eb63d2cae1578420cc39677ba6ed53b513073459e82094e12a5907137d99796908f669457a64f2ab55c6211f6bf782033118acaa5052f01758ad9786fff17b97da6b7f1bd9fcc386efa60036fe96d40af09e4fe1eee84126890fae459241abbcb91dad93689a339da8f713d7");
			PTF_ASSERT_EQUAL(rsaPrivateKey->getPublicExponent(), 65537);
			PTF_ASSERT_EQUAL(
			    rsaPrivateKey->getPrivateExponent(),
			    "3d47e6992b6f40f3d2094167924d30cbe933173b6ef92ae401453c281b202e563109863a32c3355e898ee155dcb7e9ca0f1943006286c13681e00b1a28e96756cfbd23acde41cf2041fafc794937a1c9e2786cef6bd6d685a3ce82a8ab2685c19dc8b8c450d8bf0bdc77429020c7f74aa0f1be78950d3e260018f85ff4fe28923a9b09c9a088a8ef3a990c772ea258809fb786c3e1f14c509cf3b617269af1c3ec3d4fccb5104c43912c2f1b463b3d7d0ec0ac44bc796d19c683158a86df1fdea568c092f60d07b8c626f1ebe45012b2f0b581b5f5adf77aec20063f45911c9fb45aab302fd37f9479172ac91d28fced992f9db8a351866a4750ca7826625c81");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKey->getPrime1(),
			    "d136117ee9dd44e28ed9722372e22ff39e8c6a7c15c7ab68cfca6b086e2488017c666544aa50a3c1a4307b8873c12e75c39d860a92f69f78df5476a4924bf0b369617f2a3b9afacf97548ec9f2e00188cb7dd04750abec666dfe8a12682dbe92ac4fc5d4d292697c8891bcd603e7c28e42c0ba24db00830207f8ebee3b789abb");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKey->getPrime2(),
			    "c6ccfcf21d50a743c158efa07d09c7306129231dea99855013d37cbb47db4a3270c4f1515fa181f93955ffc08c9aca47c4f1903a154079e69521c1f98b89b1da797a9bfeab42661240b3915321e8da64e6a72cef878dba6234898cceb606bb6b7a44bd9221527e17446a5c3696dd1665b993ed5d882da293393ed69690833f95");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKey->getExponent1(),
			    "c63c78598c99e892d08ec43348c18074545072f9fedd42d33ec96ba00255c535bb3d7f49902476f69e707e2d6e99a73f594ae2df1420723d6348b25f006ccab805eba7464a5270c3d17e030ae2835590dc58ebc9176cc0c4d206f5a7b9655705be169cbb2b882642255a0ad7b3bda0419288f218c817750bb0a8324e7bb5accf");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKey->getExponent2(),
			    "5f15d8be2d0b509575bb06122afc2c4b958d49809b9f064680d51cc9aedad228420bd0a86d2720b58598fe94a82bb9288ea843a5a4588c759f4ae02e6d7154a1fc8c8a644aa19d948961d9d67b57966dc06ca16f87d4601b6ca985b1b11a93361aeb1a08f4eb31e80b0f1c3ff7f4932be091426d041f5fad2f2a41150ed5d7e9");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKey->getCoefficient(),
			    "240c1e596df91b3ee4db2c15a514922160992be394497bf21bb4a6dffca117b017426183e5c56e88d7e1e9fbd60c723a0edd6ef723789b4f4d1b01907be9d796ba2c7b092a39e8847cdb4ded38345913b18c18bb17e77e96e853350637f825da3cfd61fefe7e6b1570c9af244e3e9ffb6f6890d5c18e232e2df852b53a0f9a");
		}
	}

	// EC private key
	{
		auto ecPrivateKeyPem = pcpp::ECPrivateKey::fromPEMFile("PacketExamples/ECPrivateKey.pem");
		auto ecPrivateKeyDer = pcpp::ECPrivateKey::fromDERFile("PacketExamples/ECPrivateKey.der");

		PTF_ASSERT_TRUE(compareStringToFile(ecPrivateKeyPem->toPEM(), "PacketExamples/ECPrivateKey.pem"));
		PTF_ASSERT_TRUE(compareVectorToBinaryFile(ecPrivateKeyDer->toDER(), "PacketExamples/ECPrivateKey.der"));

		std::array<std::unique_ptr<pcpp::ECPrivateKey>, 2> ecPrivateKeys;
		ecPrivateKeys[0] = std::move(ecPrivateKeyPem);
		ecPrivateKeys[1] = std::move(ecPrivateKeyDer);

		for (const auto& ecPrivateKey : ecPrivateKeys)
		{
			PTF_ASSERT_EQUAL(ecPrivateKey->getVersion(), 1);
			PTF_ASSERT_EQUAL(ecPrivateKey->getPrivateKey(),
			                 "1c2a46c7f70c5f4a2e8da0d5c3be388a2f85ef69323a7f1c6b09c56874b654c9");
			PTF_ASSERT_NOT_NULL(ecPrivateKey->getParameters());
			PTF_ASSERT_EQUAL(ecPrivateKey->getParameters()->toString(), "1.2.840.10045.3.1.7");
			PTF_ASSERT_EQUAL(
			    ecPrivateKey->getPublicKey(),
			    "04d107f8d8c53033d3cb7f852c00e40b086229b0b8ce480b9bb337e1fe8a0992ae0306710da0d6360519e9e67a01cbbf3df3020b570ca0225b76d076b7db38a320");
		}
	}

	// EC private key without parameters and data
	{
		std::string pemData =
		    "-----BEGIN EC PRIVATE KEY-----\nMCUCAQEEIAzqjXRl3z+3MinjwcLi0LAUZHGtDhuDWce9QNNO9u7y\n-----END EC PRIVATE KEY-----";
		auto ecPrivateKeyPem = pcpp::ECPrivateKey::fromPEM(pemData);
		PTF_ASSERT_EQUAL(ecPrivateKeyPem->getVersion(), 1);
		PTF_ASSERT_EQUAL(ecPrivateKeyPem->getPrivateKey(),
		                 "0cea8d7465df3fb73229e3c1c2e2d0b0146471ad0e1b8359c7bd40d34ef6eef2");
		PTF_ASSERT_NULL(ecPrivateKeyPem->getParameters());
		PTF_ASSERT_EQUAL(ecPrivateKeyPem->getPublicKey(), "");
	}

	// PKCS#8 RSA private key
	{
		auto pkcs8PrivateKeyPem = pcpp::PKCS8PrivateKey::fromPEMFile("PacketExamples/RSAPrivateKeyPKCS8.pem");
		auto pkcs8PrivateKeyDer = pcpp::PKCS8PrivateKey::fromDERFile("PacketExamples/RSAPrivateKeyPKCS8.der");

		PTF_ASSERT_TRUE(compareStringToFile(pkcs8PrivateKeyPem->toPEM(), "PacketExamples/RSAPrivateKeyPKCS8.pem"));
		PTF_ASSERT_TRUE(
		    compareVectorToBinaryFile(pkcs8PrivateKeyDer->toDER(), "PacketExamples/RSAPrivateKeyPKCS8.der"));

		std::array<std::unique_ptr<pcpp::PKCS8PrivateKey>, 2> pkcs8PrivateKeys;
		pkcs8PrivateKeys[0] = std::move(pkcs8PrivateKeyPem);
		pkcs8PrivateKeys[1] = std::move(pkcs8PrivateKeyDer);

		for (const auto& pkcs8PrivateKey : pkcs8PrivateKeys)
		{
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getVersion(), 0);
			auto privateKeyAlgorithm = pkcs8PrivateKey->getPrivateKeyAlgorithm();
			PTF_ASSERT_EQUAL(privateKeyAlgorithm, pcpp::CryptographicKeyAlgorithm::RSA);
			PTF_ASSERT_EQUAL(privateKeyAlgorithm.toString(), "RSA");
			PTF_ASSERT_EQUAL(privateKeyAlgorithm.getOidValue(), "1.2.840.113549.1.1.1");

			auto privateKeyData = pkcs8PrivateKey->getPrivateKey();
			PTF_ASSERT_NOT_NULL(privateKeyData);
			auto rsaPrivateKeyData = privateKeyData->castAs<pcpp::PKCS8PrivateKey::RSAPrivateKeyData>();
			PTF_ASSERT_EQUAL(rsaPrivateKeyData->getVersion(), 0);
			PTF_ASSERT_EQUAL(
			    rsaPrivateKeyData->getModulus(),
			    "b84f1d24c5c139ea5a0111cd2474e8186099ff2618546be98110c56afe0b1d3b5b2a747267204fdb3ec136a631423f11e536ea6eb9b3286953fd7fcdabaa4f1e39c95b5d6b8d088fb2c2dcec2e0366ac1bb72a4764bc1ef4abc706cd369a5d00a78e4859c2446884b55f6711fc473272963d8798f9071ee019fe1f6ae4870e0eef9954bab0258904ec98b50f5d108fffa16e47c8ae946fb96f280ecfd69a9e7702d56abba492e847fa10180c1f7e4ed537f47c73960c8ff18d2e32b998639fcff79cfbe392663e1f40056b22c31c7bf0bcd6b72ed4b3cfe7285eec839ae0daa56e45b0ebd843e8bd64609791fd2ac090de1890b99af9d29442f09ecffcfd2647");
			PTF_ASSERT_EQUAL(rsaPrivateKeyData->getPublicExponent(), 65537);
			PTF_ASSERT_EQUAL(
			    rsaPrivateKeyData->getPrivateExponent(),
			    "193bd654f730e749ab4798dfa9ed74ec06d32403068863108b227804ed57298a10dc9528d1ef089539d84b85217007cbdec2a5576cdbec87cf2a012f7020ac730a47ae81f1d1a8a9be8dbdf57aaf433003c8bb64743eeaa0bba14f7b152363e1a2647134be20e38bc27beca94d0d95089482996806359ab28ff1ccecb39bbca96edbe44ce40aea9566c44eefa5d0c1e98c0e31d70b0a5f79aafcfcc976db5afa38c0140dce6cbf402e16ec43942516b0d1151e8864aa623a082af0e597a825fc80f4261ff5c5bb189e2de889fb66730bd9ea90bb7fbec378db9a05668351adbbcce4e7bbcbb973aef573fcb75ff0f7a7724b8824f37272e45d68f058fe5364e1");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKeyData->getPrime1(),
			    "f72966c5c82e190c8e56788ce3b7c1b2f532804939952774cedba46e50d815358602bdefb1f53d3419038bd91106040f13bef6a30e4a95d6fbcee379c9968d9d2d58bfd96fe4696da8da135b9a99f9fc723792556c208ea097fd01c32085041045bfb9c2caea6b55fd09910d6e68b7390616342d33176707ca7627105ff1e24f");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKeyData->getPrime2(),
			    "bee656a997e031f8f9f3a1d59798e9da12e550648e3c3f7f93c39ff7edf859bc2dd71f35ab9880ff11fa1663c6a5c8ec13437016792f485cbacf4ad23b8cca8c37c0111671b3033f1b3bf72cbfebe8642e979cbc2dd4eaf86a4c03bad8a876335117e9a2b964feca4c4db3520034f3c7e5778e01f250bfeba448b28b2293d689");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKeyData->getExponent1(),
			    "5f7f65b041ba5dff55f7df3840bc3d615210233527c493ac3448f56d925b0b46d4f2b644a8f3e2a4008e3838b4b5285852fed3f9088a94feade8b047dc36099d9369d926c06ef6b5622a70945255f01b345e7871fd074f5489a53e4b108394a05cf2c9699451a30b646b8fda2ab0d72a774998fb65e442f0e5af6544946db74d");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKeyData->getExponent2(),
			    "47ac77d149029600a2e804550b8c10111e9316720aad3832102a9cbf1b8be9352c08dee0e9c2627c6225818e88a0ea2528be63312ce2c1ca7f21213879bf4cb504a18a48e0fb93367865355289e46ae6624fee3b0102360e7aea7b6405c08a508e1bea4e7c491d189b3979204a8f970ff069c8d9963f172fc408bf7059d523f1");
			PTF_ASSERT_EQUAL(
			    rsaPrivateKeyData->getCoefficient(),
			    "85007f83f620922732265d61c551d192157c8bf7085ee0143faf35b08c71a432eb9133bbc8971e02b1636bb10a5abff4b5956c28f01c1a188215980daa34e52c564eb64ddbb841cfd4723cb4c79189b226eee37d42d83eed34c3ca33043e971440bba0a936e4dea56b28625500b2f17d0b938b447c48d29d0e82109aea8918b");
		}
	}

	// PKCS#8 EC private key
	{
		auto pkcs8PrivateKeyPem = pcpp::PKCS8PrivateKey::fromPEMFile("PacketExamples/ECPrivateKeyPKCS8.pem");
		auto pkcs8PrivateKeyDer = pcpp::PKCS8PrivateKey::fromDERFile("PacketExamples/ECPrivateKeyPKCS8.der");

		PTF_ASSERT_TRUE(compareStringToFile(pkcs8PrivateKeyPem->toPEM(), "PacketExamples/ECPrivateKeyPKCS8.pem"));
		PTF_ASSERT_TRUE(compareVectorToBinaryFile(pkcs8PrivateKeyDer->toDER(), "PacketExamples/ECPrivateKeyPKCS8.der"));

		std::array<std::unique_ptr<pcpp::PKCS8PrivateKey>, 2> pkcs8PrivateKeys;
		pkcs8PrivateKeys[0] = std::move(pkcs8PrivateKeyPem);
		pkcs8PrivateKeys[1] = std::move(pkcs8PrivateKeyDer);

		for (const auto& pkcs8PrivateKey : pkcs8PrivateKeys)
		{
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getVersion(), 0);
			auto privateKeyAlgorithm = pkcs8PrivateKey->getPrivateKeyAlgorithm();
			PTF_ASSERT_EQUAL(privateKeyAlgorithm, pcpp::CryptographicKeyAlgorithm::ECDSA);
			PTF_ASSERT_EQUAL(privateKeyAlgorithm.toString(), "ECDSA");
			PTF_ASSERT_EQUAL(privateKeyAlgorithm.getOidValue(), "1.2.840.10045.2.1");

			auto privateKeyData = pkcs8PrivateKey->getPrivateKey();
			PTF_ASSERT_NOT_NULL(privateKeyData);
			auto ecPrivateKeyData = privateKeyData->castAs<pcpp::PKCS8PrivateKey::ECPrivateKeyData>();
			PTF_ASSERT_EQUAL(ecPrivateKeyData->getVersion(), 1);
			PTF_ASSERT_EQUAL(ecPrivateKeyData->getPrivateKey(),
			                 "a00a20ed4c8e1453172ce494b400646e10b7a28a027af33ac5378918085aa0c2");
			PTF_ASSERT_NULL(ecPrivateKeyData->getParameters());
			PTF_ASSERT_EQUAL(
			    ecPrivateKeyData->getPublicKey(),
			    "04f43a5190b322cfc716de98df40106121ab6b4523aa20ba43efd15a3d90edfa83dd98afdaf774542b6592d8f3d6cd9d5b0be361cf9164f2a88ce7b0710e74f2fb");
		}
	}

	// PKCS#8 Ed25519 private key
	{
		auto pkcs8PrivateKeyPem = pcpp::PKCS8PrivateKey::fromPEMFile("PacketExamples/Ed25519PrivateKeyPKCS8.pem");
		auto pkcs8PrivateKeyDer = pcpp::PKCS8PrivateKey::fromDERFile("PacketExamples/Ed25519PrivateKeyPKCS8.der");

		PTF_ASSERT_TRUE(compareStringToFile(pkcs8PrivateKeyPem->toPEM(), "PacketExamples/Ed25519PrivateKeyPKCS8.pem"));
		PTF_ASSERT_TRUE(
		    compareVectorToBinaryFile(pkcs8PrivateKeyDer->toDER(), "PacketExamples/Ed25519PrivateKeyPKCS8.der"));

		std::array<std::unique_ptr<pcpp::PKCS8PrivateKey>, 2> pkcs8PrivateKeys;
		pkcs8PrivateKeys[0] = std::move(pkcs8PrivateKeyPem);
		pkcs8PrivateKeys[1] = std::move(pkcs8PrivateKeyDer);

		for (const auto& pkcs8PrivateKey : pkcs8PrivateKeys)
		{
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getVersion(), 0);
			auto privateKeyAlgorithm = pkcs8PrivateKey->getPrivateKeyAlgorithm();
			PTF_ASSERT_EQUAL(privateKeyAlgorithm, pcpp::CryptographicKeyAlgorithm::ED25519);
			PTF_ASSERT_EQUAL(privateKeyAlgorithm.toString(), "Ed25519");
			PTF_ASSERT_EQUAL(privateKeyAlgorithm.getOidValue(), "1.3.101.112");

			auto privateKeyData = pkcs8PrivateKey->getPrivateKey();
			PTF_ASSERT_NOT_NULL(privateKeyData);
			auto ed25519PrivateKeyData = privateKeyData->castAs<pcpp::PKCS8PrivateKey::Ed25519PrivateKeyData>();
			PTF_ASSERT_EQUAL(ed25519PrivateKeyData->getPrivateKey(),
			                 "ca0f1d19e149dbc05941d19fd5369d054e7a3660793bc372eec68c0acca595bd");
			PTF_ASSERT_RAISES(privateKeyData->castAs<pcpp::PKCS8PrivateKey::RSAPrivateKeyData>(), std::runtime_error,
			                  "Trying to PKCS#8 private key data to the wrong type");
		}
	}

	// PKCS#8 unsupported private key
	{
		std::vector<uint8_t> privateKeyBytes = {
			0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x04, 0x22, 0x04, 0x20,
			0xca, 0x0f, 0x1d, 0x19, 0xe1, 0x49, 0xdb, 0xc0, 0x59, 0x41, 0xd1, 0x9f, 0xd5, 0x36, 0x9d, 0x05,
			0x4e, 0x7a, 0x36, 0x60, 0x79, 0x3b, 0xc3, 0x72, 0xee, 0xc6, 0x8c, 0x0a, 0xcc, 0xa5, 0x95, 0xbd
		};
		auto privateKey = pcpp::PKCS8PrivateKey::fromDER(privateKeyBytes.data(), privateKeyBytes.size());
		auto privateKeyAlgorithm = privateKey->getPrivateKeyAlgorithm();
		PTF_ASSERT_EQUAL(privateKeyAlgorithm, pcpp::CryptographicKeyAlgorithm::X448);
		PTF_ASSERT_EQUAL(privateKeyAlgorithm.toString(), "X448");
		PTF_ASSERT_EQUAL(privateKeyAlgorithm.getOidValue(), "1.3.101.111");
		PTF_ASSERT_NULL(privateKey->getPrivateKey());
	}

	// PKCS#8 get private key as
	{
		auto pkcs8PrivateKeyPem = pcpp::PKCS8PrivateKey::fromPEMFile("PacketExamples/RSAPrivateKeyPKCS8.pem");
		auto rsaPrivateKeyData = pkcs8PrivateKeyPem->getPrivateKeyAs<pcpp::PKCS8PrivateKey::RSAPrivateKeyData>();
		PTF_ASSERT_NOT_NULL(rsaPrivateKeyData);
		PTF_ASSERT_EQUAL(
		    rsaPrivateKeyData->getCoefficient(),
		    "85007f83f620922732265d61c551d192157c8bf7085ee0143faf35b08c71a432eb9133bbc8971e02b1636bb10a5abff4b5956c28f01c1a188215980daa34e52c564eb64ddbb841cfd4723cb4c79189b226eee37d42d83eed34c3ca33043e971440bba0a936e4dea56b28625500b2f17d0b938b447c48d29d0e82109aea8918b");

		PTF_ASSERT_NULL(pkcs8PrivateKeyPem->getPrivateKeyAs<pcpp::PKCS8PrivateKey::ECPrivateKeyData>());

		std::vector<uint8_t> x448PrivateKeyBytes = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
			                                         0x65, 0x6f, 0x04, 0x22, 0x04, 0x20, 0xca, 0x0f, 0x1d, 0x19,
			                                         0xe1, 0x49, 0xdb, 0xc0, 0x59, 0x41, 0xd1, 0x9f, 0xd5, 0x36,
			                                         0x9d, 0x05, 0x4e, 0x7a, 0x36, 0x60, 0x79, 0x3b, 0xc3, 0x72,
			                                         0xee, 0xc6, 0x8c, 0x0a, 0xcc, 0xa5, 0x95, 0xbd };
		pkcs8PrivateKeyPem = pcpp::PKCS8PrivateKey::fromDER(x448PrivateKeyBytes.data(), x448PrivateKeyBytes.size());
		PTF_ASSERT_NULL(pkcs8PrivateKeyPem->getPrivateKeyAs<pcpp::PKCS8PrivateKey::RSAPrivateKeyData>());
	}

	// RSA public key
	{
		auto rsaPublicKeyPem = pcpp::RSAPublicKey::fromPEMFile("PacketExamples/RSAPublicKey.pem");
		auto rsaPublicKeyDer = pcpp::RSAPublicKey::fromDERFile("PacketExamples/RSAPublicKey.der");

		PTF_ASSERT_TRUE(compareStringToFile(rsaPublicKeyPem->toPEM(), "PacketExamples/RSAPublicKey.pem"));
		PTF_ASSERT_TRUE(compareVectorToBinaryFile(rsaPublicKeyDer->toDER(), "PacketExamples/RSAPublicKey.der"));

		std::array<std::unique_ptr<pcpp::RSAPublicKey>, 2> rsaPublicKeys;
		rsaPublicKeys[0] = std::move(rsaPublicKeyDer);
		rsaPublicKeys[1] = std::move(rsaPublicKeyPem);

		for (const auto& rsaPublicKey : rsaPublicKeys)
		{
			PTF_ASSERT_EQUAL(
			    rsaPublicKey->getModulus(),
			    "a2775755304e015b7eba1cac8717652b2f3684b5010ab4e9181f1fc93ae8674b629607a91a519b4668dbd34fadf521a81b8a36484cf4efe62ef5b2101d3309726744f6fd88d9dce4d65c7136e77c8d3042f70bd87d54b1ebb9f42309419b6e9a77139eb4b53da34210eeec5bd4817df4a6fbd9ff353fa90b155d35724d86af7b69c127acf37c3a9affeb8988e614233f17a75ed3eb63d2cae1578420cc39677ba6ed53b513073459e82094e12a5907137d99796908f669457a64f2ab55c6211f6bf782033118acaa5052f01758ad9786fff17b97da6b7f1bd9fcc386efa60036fe96d40af09e4fe1eee84126890fae459241abbcb91dad93689a339da8f713d7");
			PTF_ASSERT_EQUAL(rsaPublicKey->getPublicExponent(), 65537);
		}
	}

	// Subject Public Key Info 1
	{
		auto publicKey = pcpp::SubjectPublicKeyInfo::fromPEMFile("PacketExamples/PublicKey.pem");
		PTF_ASSERT_EQUAL(publicKey->getAlgorithm(), pcpp::CryptographicKeyAlgorithm::ECDSA);
		PTF_ASSERT_EQUAL(
		    publicKey->getSubjectPublicKey(),
		    "04d107f8d8c53033d3cb7f852c00e40b086229b0b8ce480b9bb337e1fe8a0992ae0306710da0d6360519e9e67a01cbbf3df3020b570ca0225b76d076b7db38a320");
	}

	// Subject Public Key Info 2
	{
		auto publicKey = pcpp::SubjectPublicKeyInfo::fromPEMFile("PacketExamples/PublicKey2.pem");
		PTF_ASSERT_EQUAL(publicKey->getAlgorithm(), pcpp::CryptographicKeyAlgorithm::RSA);
		PTF_ASSERT_EQUAL(
		    publicKey->getSubjectPublicKey(),
		    "3082010a0282010100b84f1d24c5c139ea5a0111cd2474e8186099ff2618546be98110c56afe0b1d3b5b2a747267204fdb3ec136a631423f11e536ea6eb9b3286953fd7fcdabaa4f1e39c95b5d6b8d088fb2c2dcec2e0366ac1bb72a4764bc1ef4abc706cd369a5d00a78e4859c2446884b55f6711fc473272963d8798f9071ee019fe1f6ae4870e0eef9954bab0258904ec98b50f5d108fffa16e47c8ae946fb96f280ecfd69a9e7702d56abba492e847fa10180c1f7e4ed537f47c73960c8ff18d2e32b998639fcff79cfbe392663e1f40056b22c31c7bf0bcd6b72ed4b3cfe7285eec839ae0daa56e45b0ebd843e8bd64609791fd2ac090de1890b99af9d29442f09ecffcfd26470203010001");
	}
}

PTF_TEST_CASE(CryptoKeyInvalidDataTest)
{
	// Trying to read the wrong type of PEM file
	{
		PTF_ASSERT_RAISES(pcpp::RSAPrivateKey::fromPEMFile("PacketExamples/RSAPublicKey.pem"), std::invalid_argument,
		                  "Unexpected BEGIN label in PEM - expected 'RSA PRIVATE KEY' but got 'RSA PUBLIC KEY'");
	}

	// Invalid ASN.1 root
	{
		std::vector<uint8_t> malformedData = { 0x02, 0x01, 0x00 };
		PTF_ASSERT_RAISES(pcpp::RSAPrivateKey::fromDER(malformedData.data(), malformedData.size()), std::runtime_error,
		                  "Invalid RSA private key data");
	}

	// Unexpected type of ASN.1 field
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			                                   0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
		auto ecPrivateKey = pcpp::ECPrivateKey::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_RAISES(ecPrivateKey->getVersion(), std::runtime_error, "Invalid EC private key data: version");
	}

	// EC private key - Invalid parameters value
	{
		std::vector<uint8_t> malformedData = {
			0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x1c, 0x2a, 0x46, 0xc7, 0xf7, 0x0c, 0x5f, 0x4a, 0x2e, 0x8d, 0xa0,
			0xd5, 0xc3, 0xbe, 0x38, 0x8a, 0x2f, 0x85, 0xef, 0x69, 0x32, 0x3a, 0x7f, 0x1c, 0x6b, 0x09, 0xc5, 0x68, 0x74,
			0xb6, 0x54, 0xc9, 0xa0, 0x0a, 0x04, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03,
			0x42, 0x00, 0x04, 0xd1, 0x07, 0xf8, 0xd8, 0xc5, 0x30, 0x33, 0xd3, 0xcb, 0x7f, 0x85, 0x2c, 0x00, 0xe4, 0x0b,
			0x08, 0x62, 0x29, 0xb0, 0xb8, 0xce, 0x48, 0x0b, 0x9b, 0xb3, 0x37, 0xe1, 0xfe, 0x8a, 0x09, 0x92, 0xae, 0x03,
			0x06, 0x71, 0x0d, 0xa0, 0xd6, 0x36, 0x05, 0x19, 0xe9, 0xe6, 0x7a, 0x01, 0xcb, 0xbf, 0x3d, 0xf3, 0x02, 0x0b,
			0x57, 0x0c, 0xa0, 0x22, 0x5b, 0x76, 0xd0, 0x76, 0xb7, 0xdb, 0x38, 0xa3, 0x20
		};
		auto ecPrivateKey = pcpp::ECPrivateKey::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_NULL(ecPrivateKey->getParameters());
	}

	// EC private key - Invalid public key value
	{
		std::vector<uint8_t> malformedData = {
			0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x1c, 0x2a, 0x46, 0xc7, 0xf7, 0x0c, 0x5f, 0x4a, 0x2e, 0x8d, 0xa0,
			0xd5, 0xc3, 0xbe, 0x38, 0x8a, 0x2f, 0x85, 0xef, 0x69, 0x32, 0x3a, 0x7f, 0x1c, 0x6b, 0x09, 0xc5, 0x68, 0x74,
			0xb6, 0x54, 0xc9, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x04,
			0x42, 0x00, 0x04, 0xd1, 0x07, 0xf8, 0xd8, 0xc5, 0x30, 0x33, 0xd3, 0xcb, 0x7f, 0x85, 0x2c, 0x00, 0xe4, 0x0b,
			0x08, 0x62, 0x29, 0xb0, 0xb8, 0xce, 0x48, 0x0b, 0x9b, 0xb3, 0x37, 0xe1, 0xfe, 0x8a, 0x09, 0x92, 0xae, 0x03,
			0x06, 0x71, 0x0d, 0xa0, 0xd6, 0x36, 0x05, 0x19, 0xe9, 0xe6, 0x7a, 0x01, 0xcb, 0xbf, 0x3d, 0xf3, 0x02, 0x0b,
			0x57, 0x0c, 0xa0, 0x22, 0x5b, 0x76, 0xd0, 0x76, 0xb7, 0xdb, 0x38, 0xa3, 0x20
		};
		auto ecPrivateKey = pcpp::ECPrivateKey::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_EQUAL(ecPrivateKey->getPublicKey(), "");
	}

	// Malformed PKCS#8 algorithm field
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x24, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
			                                   0x04, 0x22, 0x04, 0x20, 0xca, 0x0f, 0x1d, 0x19, 0xe1, 0x49, 0xdb, 0xc0,
			                                   0x59, 0x41, 0xd1, 0x9f, 0xd5, 0x36, 0x9d, 0x05, 0x4e, 0x7a, 0x36, 0x60,
			                                   0x79, 0x3b, 0xc3, 0x72, 0xee, 0xc6, 0x8c, 0x0a, 0xcc, 0xa5, 0x95, 0xbd };
		auto privateKey = pcpp::PKCS8PrivateKey::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_RAISES(privateKey->getPrivateKeyAlgorithm(), std::runtime_error,
		                  "Invalid PKCS#8 private key data: private key algorithm");
		PTF_ASSERT_NULL(privateKey->getPrivateKey());
	}

	// Unknown PKCS#8 algorithm
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x75,
			                                   0x04, 0x22, 0x04, 0x20, 0xca, 0x0f, 0x1d, 0x19, 0xe1, 0x49, 0xdb, 0xc0,
			                                   0x59, 0x41, 0xd1, 0x9f, 0xd5, 0x36, 0x9d, 0x05, 0x4e, 0x7a, 0x36, 0x60,
			                                   0x79, 0x3b, 0xc3, 0x72, 0xee, 0xc6, 0x8c, 0x0a, 0xcc, 0xa5, 0x95, 0xbd };
		auto privateKey = pcpp::PKCS8PrivateKey::fromDER(malformedData.data(), malformedData.size());
		auto privateKeyAlgorithm = privateKey->getPrivateKeyAlgorithm();
		PTF_ASSERT_EQUAL(privateKeyAlgorithm, pcpp::CryptographicKeyAlgorithm::Unknown);
		PTF_ASSERT_EQUAL(privateKeyAlgorithm.toString(), "Unknown");
		PTF_ASSERT_EQUAL(privateKeyAlgorithm.getOidValue(), "0.0");
		PTF_ASSERT_NULL(privateKey->getPrivateKey());
	}

	// Malformed PKCS#8 private key
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
			                                   0x03, 0x22, 0x04, 0x20, 0xca, 0x0f, 0x1d, 0x19, 0xe1, 0x49, 0xdb, 0xc0,
			                                   0x59, 0x41, 0xd1, 0x9f, 0xd5, 0x36, 0x9d, 0x05, 0x4e, 0x7a, 0x36, 0x60,
			                                   0x79, 0x3b, 0xc3, 0x72, 0xee, 0xc6, 0x8c, 0x0a, 0xcc, 0xa5, 0x95, 0xbd };
		auto privateKey = pcpp::PKCS8PrivateKey::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_RAISES(privateKey->getPrivateKey(), std::runtime_error,
		                  "Invalid PKCS#8 private key data: private key");
	}

	// Malformed PKCS#8 EC private key data
	{
		std::vector<uint8_t> malformedData = {
			0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
			0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x03, 0x01, 0x01, 0x04, 0x20,
			0xa0, 0x0a, 0x20, 0xed, 0x4c, 0x8e, 0x14, 0x53, 0x17, 0x2c, 0xe4, 0x94, 0xb4, 0x00, 0x64, 0x6e, 0x10, 0xb7,
			0xa2, 0x8a, 0x02, 0x7a, 0xf3, 0x3a, 0xc5, 0x37, 0x89, 0x18, 0x08, 0x5a, 0xa0, 0xc2, 0xa1, 0x44, 0x03, 0x42,
			0x00, 0x04, 0xf4, 0x3a, 0x51, 0x90, 0xb3, 0x22, 0xcf, 0xc7, 0x16, 0xde, 0x98, 0xdf, 0x40, 0x10, 0x61, 0x21,
			0xab, 0x6b, 0x45, 0x23, 0xaa, 0x20, 0xba, 0x43, 0xef, 0xd1, 0x5a, 0x3d, 0x90, 0xed, 0xfa, 0x83, 0xdd, 0x98,
			0xaf, 0xda, 0xf7, 0x74, 0x54, 0x2b, 0x65, 0x92, 0xd8, 0xf3, 0xd6, 0xcd, 0x9d, 0x5b, 0x0b, 0xe3, 0x61, 0xcf,
			0x91, 0x64, 0xf2, 0xa8, 0x8c, 0xe7, 0xb0, 0x71, 0x0e, 0x74, 0xf2, 0xfb
		};
		auto privateKey = pcpp::PKCS8PrivateKey::fromDER(malformedData.data(), malformedData.size());
		auto privateKeyData = privateKey->getPrivateKey();
		PTF_ASSERT_NOT_NULL(privateKeyData);
		auto ecPrivateKeyData = privateKeyData->castAs<pcpp::PKCS8PrivateKey::ECPrivateKeyData>();
		PTF_ASSERT_RAISES(ecPrivateKeyData->getVersion(), std::runtime_error,
		                  "Invalid PKCS#8 EC private key data: version");
	}

	// Malformed PKCS#8 Ed25519 private key data
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
			                                   0x04, 0x22, 0x02, 0x20, 0xca, 0x0f, 0x1d, 0x19, 0xe1, 0x49, 0xdb, 0xc0,
			                                   0x59, 0x41, 0xd1, 0x9f, 0xd5, 0x36, 0x9d, 0x05, 0x4e, 0x7a, 0x36, 0x60,
			                                   0x79, 0x3b, 0xc3, 0x72, 0xee, 0xc6, 0x8c, 0x0a, 0xcc, 0xa5, 0x95, 0xbd };
		auto privateKey = pcpp::PKCS8PrivateKey::fromDER(malformedData.data(), malformedData.size());
		auto privateKeyData = privateKey->getPrivateKey();
		PTF_ASSERT_NOT_NULL(privateKeyData);
		auto ed25519PrivateKeyData = privateKeyData->castAs<pcpp::PKCS8PrivateKey::Ed25519PrivateKeyData>();
		PTF_ASSERT_RAISES(ed25519PrivateKeyData->getPrivateKey(), std::runtime_error, "Invalid PKCS#8 Ed25519 data");
	}

	// Public key unknown algorithm
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
			                                   0x15, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
			                                   0x42, 0x00, 0x04, 0xd1, 0x07, 0xf8, 0xd8, 0xc5, 0x30, 0x33, 0xd3, 0xcb,
			                                   0x7f, 0x85, 0x2c, 0x00, 0xe4, 0x0b, 0x08, 0x62, 0x29, 0xb0, 0xb8, 0xce,
			                                   0x48, 0x0b, 0x9b, 0xb3, 0x37, 0xe1, 0xfe, 0x8a, 0x09, 0x92, 0xae, 0x03,
			                                   0x06, 0x71, 0x0d, 0xa0, 0xd6, 0x36, 0x05, 0x19, 0xe9, 0xe6, 0x7a, 0x01,
			                                   0xcb, 0xbf, 0x3d, 0xf3, 0x02, 0x0b, 0x57, 0x0c, 0xa0, 0x22, 0x5b, 0x76,
			                                   0xd0, 0x76, 0xb7, 0xdb, 0x38, 0xa3, 0x20 };
		auto publicKey = pcpp::SubjectPublicKeyInfo::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_EQUAL(publicKey->getAlgorithm(), pcpp::CryptographicKeyAlgorithm::Unknown);
	}

	// Malformed public key algorithm field - sequence not found
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x59, 0x03, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
			                                   0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
			                                   0x42, 0x00, 0x04, 0xd1, 0x07, 0xf8, 0xd8, 0xc5, 0x30, 0x33, 0xd3, 0xcb,
			                                   0x7f, 0x85, 0x2c, 0x00, 0xe4, 0x0b, 0x08, 0x62, 0x29, 0xb0, 0xb8, 0xce,
			                                   0x48, 0x0b, 0x9b, 0xb3, 0x37, 0xe1, 0xfe, 0x8a, 0x09, 0x92, 0xae, 0x03,
			                                   0x06, 0x71, 0x0d, 0xa0, 0xd6, 0x36, 0x05, 0x19, 0xe9, 0xe6, 0x7a, 0x01,
			                                   0xcb, 0xbf, 0x3d, 0xf3, 0x02, 0x0b, 0x57, 0x0c, 0xa0, 0x22, 0x5b, 0x76,
			                                   0xd0, 0x76, 0xb7, 0xdb, 0x38, 0xa3, 0x20 };
		auto publicKey = pcpp::SubjectPublicKeyInfo::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_RAISES(publicKey->getAlgorithm(), std::runtime_error, "Invalid public key data: algorithm record");
	}

	// Malformed public key algorithm field - no elements in sequence
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x03, 0x90 };
		auto publicKey = pcpp::SubjectPublicKeyInfo::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_EQUAL(publicKey->getAlgorithm(), pcpp::CryptographicKeyAlgorithm::Unknown);
	}

	// Malformed public key algorithm field - cannot read OID value
	{
		std::vector<uint8_t> malformedData = { 0x30, 0x59, 0x30, 0x13, 0x04, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
			                                   0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
			                                   0x42, 0x00, 0x04, 0xd1, 0x07, 0xf8, 0xd8, 0xc5, 0x30, 0x33, 0xd3, 0xcb,
			                                   0x7f, 0x85, 0x2c, 0x00, 0xe4, 0x0b, 0x08, 0x62, 0x29, 0xb0, 0xb8, 0xce,
			                                   0x48, 0x0b, 0x9b, 0xb3, 0x37, 0xe1, 0xfe, 0x8a, 0x09, 0x92, 0xae, 0x03,
			                                   0x06, 0x71, 0x0d, 0xa0, 0xd6, 0x36, 0x05, 0x19, 0xe9, 0xe6, 0x7a, 0x01,
			                                   0xcb, 0xbf, 0x3d, 0xf3, 0x02, 0x0b, 0x57, 0x0c, 0xa0, 0x22, 0x5b, 0x76,
			                                   0xd0, 0x76, 0xb7, 0xdb, 0x38, 0xa3, 0x20 };
		auto publicKey = pcpp::SubjectPublicKeyInfo::fromDER(malformedData.data(), malformedData.size());
		PTF_ASSERT_RAISES(publicKey->getAlgorithm(), std::runtime_error,
		                  "Invalid public key data: algorithm identifier");
	}
}
