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
}

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

		for (const auto& resPublicKey : rsaPublicKeys)
		{
			PTF_ASSERT_EQUAL(
			    resPublicKey->getModulus(),
			    "a2775755304e015b7eba1cac8717652b2f3684b5010ab4e9181f1fc93ae8674b629607a91a519b4668dbd34fadf521a81b8a36484cf4efe62ef5b2101d3309726744f6fd88d9dce4d65c7136e77c8d3042f70bd87d54b1ebb9f42309419b6e9a77139eb4b53da34210eeec5bd4817df4a6fbd9ff353fa90b155d35724d86af7b69c127acf37c3a9affeb8988e614233f17a75ed3eb63d2cae1578420cc39677ba6ed53b513073459e82094e12a5907137d99796908f669457a64f2ab55c6211f6bf782033118acaa5052f01758ad9786fff17b97da6b7f1bd9fcc386efa60036fe96d40af09e4fe1eee84126890fae459241abbcb91dad93689a339da8f713d7");
			PTF_ASSERT_EQUAL(resPublicKey->getPublicExponent(), 65537);
		}
	}
}
