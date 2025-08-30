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

		compareStringToFile(rsaPrivateKeyPem->toPEM(), "PacketExamples/RSAPrivateKey.pem");
		compareVectorToBinaryFile(rsaPrivateKeyDer->toDER(), "PacketExamples/RSAPrivateKey.der");

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

	// RSA public key
	{
		auto rsaPublicKeyPem = pcpp::RSAPublicKey::fromPEMFile("PacketExamples/RSAPublicKey.pem");
		auto rsaPublicKeyDer = pcpp::RSAPublicKey::fromDERFile("PacketExamples/RSAPublicKey.der");

		compareStringToFile(rsaPublicKeyPem->toPEM(), "PacketExamples/RSAPublicKey.pem");
		compareVectorToBinaryFile(rsaPublicKeyDer->toDER(), "PacketExamples/RSAPublicKey.der");

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

	// EC private key
	{
		auto ecPrivateKeyPem = pcpp::ECPrivateKey::fromPEMFile("PacketExamples/ECPrivateKey.pem");
		auto ecPrivateKeyDer = pcpp::ECPrivateKey::fromDERFile("PacketExamples/ECPrivateKey.der");

		compareStringToFile(ecPrivateKeyPem->toPEM(), "PacketExamples/ECPrivateKey.pem");
		compareVectorToBinaryFile(ecPrivateKeyDer->toDER(), "PacketExamples/ECPrivateKey.der");

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

	// PKCS#8 RSA private key
	{
		auto pkcs8PrivateKeyPem = pcpp::PKCS8PrivateKey::fromPEMFile("PacketExamples/RSAPrivateKeyPKCS8.pem");
		auto pkcs8PrivateKeyDer = pcpp::PKCS8PrivateKey::fromDERFile("PacketExamples/RSAPrivateKeyPKCS8.der");

		compareStringToFile(pkcs8PrivateKeyPem->toPEM(), "PacketExamples/RSAPrivateKeyPKCS8.pem");
		compareVectorToBinaryFile(pkcs8PrivateKeyDer->toDER(), "PacketExamples/RSAPrivateKeyPKCS8.der");

		std::array<std::unique_ptr<pcpp::PKCS8PrivateKey>, 2> pkcs8PrivateKeys;
		pkcs8PrivateKeys[0] = std::move(pkcs8PrivateKeyPem);
		pkcs8PrivateKeys[1] = std::move(pkcs8PrivateKeyDer);

		for (const auto& pkcs8PrivateKey : pkcs8PrivateKeys)
		{
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getVersion(), 0);
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getPrivateKeyAlgorithm(), pcpp::PKCS8PrivateKeyAlgorithm::RSA);

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

		compareStringToFile(pkcs8PrivateKeyPem->toPEM(), "PacketExamples/ECPrivateKeyPKCS8.pem");
		compareVectorToBinaryFile(pkcs8PrivateKeyDer->toDER(), "PacketExamples/ECPrivateKeyPKCS8.der");

		std::array<std::unique_ptr<pcpp::PKCS8PrivateKey>, 2> pkcs8PrivateKeys;
		pkcs8PrivateKeys[0] = std::move(pkcs8PrivateKeyPem);
		pkcs8PrivateKeys[1] = std::move(pkcs8PrivateKeyDer);

		for (const auto& pkcs8PrivateKey : pkcs8PrivateKeys)
		{
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getVersion(), 0);
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getPrivateKeyAlgorithm(), pcpp::PKCS8PrivateKeyAlgorithm::ECDSA);

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

		compareStringToFile(pkcs8PrivateKeyPem->toPEM(), "PacketExamples/Ed25519PrivateKeyPKCS8.pem");
		compareVectorToBinaryFile(pkcs8PrivateKeyDer->toDER(), "PacketExamples/Ed25519PrivateKeyPKCS8.der");

		std::array<std::unique_ptr<pcpp::PKCS8PrivateKey>, 2> pkcs8PrivateKeys;
		pkcs8PrivateKeys[0] = std::move(pkcs8PrivateKeyPem);
		pkcs8PrivateKeys[1] = std::move(pkcs8PrivateKeyDer);

		for (const auto& pkcs8PrivateKey : pkcs8PrivateKeys)
		{
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getVersion(), 0);
			PTF_ASSERT_EQUAL(pkcs8PrivateKey->getPrivateKeyAlgorithm(), pcpp::PKCS8PrivateKeyAlgorithm::ED25519);

			auto privateKeyData = pkcs8PrivateKey->getPrivateKey();
			PTF_ASSERT_NOT_NULL(privateKeyData);
			auto ed25519PrivateKeyData = privateKeyData->castAs<pcpp::PKCS8PrivateKey::Ed25519PrivateKeyData>();
			PTF_ASSERT_EQUAL(ed25519PrivateKeyData->getPrivateKey(),
			                 "ca0f1d19e149dbc05941d19fd5369d054e7a3660793bc372eec68c0acca595bd");
		}
	}
}
