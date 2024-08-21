#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "SSLLayer.h"
#include "SystemUtils.h"
#include <fstream>
#include <sstream>

PTF_TEST_CASE(SSLClientHelloParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-ClientHello1.dat");

	pcpp::Packet clientHelloPacket(&rawPacket1);

	PTF_ASSERT_TRUE(clientHelloPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLHandshakeLayer* handshakeLayer = clientHelloPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLClientHelloMessage* clientHelloMessage =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessageAt(0), clientHelloMessage, ptr);
	PTF_ASSERT_NOT_NULL(clientHelloMessage);
	PTF_ASSERT_EQUAL(handshakeLayer->getRecordType(), pcpp::SSL_HANDSHAKE, enum);
	PTF_ASSERT_EQUAL(handshakeLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_0, enum);
	PTF_ASSERT_EQUAL(clientHelloMessage->getHandshakeType(), pcpp::SSL_CLIENT_HELLO, enum);
	PTF_ASSERT_EQUAL(clientHelloMessage->getHandshakeVersion().asEnum(), pcpp::SSLVersion::TLS1_2, enum);
	uint8_t* random = clientHelloMessage->getClientHelloHeader()->random;
	PTF_ASSERT_EQUAL(random[0], 0x3e, hex);
	PTF_ASSERT_EQUAL(random[8], 0x78, hex);
	PTF_ASSERT_EQUAL(random[27], 0xe5, hex);
	PTF_ASSERT_EQUAL(clientHelloMessage->getSessionIDLength(), 0);
	PTF_ASSERT_NULL(clientHelloMessage->getSessionID());
	PTF_ASSERT_EQUAL(clientHelloMessage->getCipherSuiteCount(), 11);

	uint16_t cipherSuiteIDs[11] = { 0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014,
		                            0x0033, 0x0039, 0x002f, 0x0035, 0x000a };
	std::string cipherSuiteNames[11] = { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		                                 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		                                 "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		                                 "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		                                 "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		                                 "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		                                 "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		                                 "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		                                 "TLS_RSA_WITH_AES_128_CBC_SHA",
		                                 "TLS_RSA_WITH_AES_256_CBC_SHA",
		                                 "TLS_RSA_WITH_3DES_EDE_CBC_SHA" };
	pcpp::SSLKeyExchangeAlgorithm cipherSuiteKey[11] = {
		pcpp::SSL_KEYX_ECDHE, pcpp::SSL_KEYX_ECDHE, pcpp::SSL_KEYX_ECDHE, pcpp::SSL_KEYX_ECDHE,
		pcpp::SSL_KEYX_ECDHE, pcpp::SSL_KEYX_ECDHE, pcpp::SSL_KEYX_DHE,   pcpp::SSL_KEYX_DHE,
		pcpp::SSL_KEYX_RSA,   pcpp::SSL_KEYX_RSA,   pcpp::SSL_KEYX_RSA
	};

	pcpp::SSLAuthenticationAlgorithm cipherSuiteAuth[11] = {
		pcpp::SSL_AUTH_ECDSA, pcpp::SSL_AUTH_RSA, pcpp::SSL_AUTH_ECDSA, pcpp::SSL_AUTH_ECDSA,
		pcpp::SSL_AUTH_RSA,   pcpp::SSL_AUTH_RSA, pcpp::SSL_AUTH_RSA,   pcpp::SSL_AUTH_RSA,
		pcpp::SSL_AUTH_RSA,   pcpp::SSL_AUTH_RSA, pcpp::SSL_AUTH_RSA
	};

	pcpp::SSLSymetricEncryptionAlgorithm cipherSuiteSym[11] = {
		pcpp::SSL_SYM_AES_128_GCM, pcpp::SSL_SYM_AES_128_GCM, pcpp::SSL_SYM_AES_256_CBC, pcpp::SSL_SYM_AES_128_CBC,
		pcpp::SSL_SYM_AES_128_CBC, pcpp::SSL_SYM_AES_256_CBC, pcpp::SSL_SYM_AES_128_CBC, pcpp::SSL_SYM_AES_256_CBC,
		pcpp::SSL_SYM_AES_128_CBC, pcpp::SSL_SYM_AES_256_CBC, pcpp::SSL_SYM_3DES_EDE_CBC
	};

	pcpp::SSLHashingAlgorithm cipherSuiteHash[11] = { pcpp::SSL_HASH_SHA256, pcpp::SSL_HASH_SHA256, pcpp::SSL_HASH_SHA,
		                                              pcpp::SSL_HASH_SHA,    pcpp::SSL_HASH_SHA,    pcpp::SSL_HASH_SHA,
		                                              pcpp::SSL_HASH_SHA,    pcpp::SSL_HASH_SHA,    pcpp::SSL_HASH_SHA,
		                                              pcpp::SSL_HASH_SHA,    pcpp::SSL_HASH_SHA };

	PTF_PRINT_VERBOSE("Iterating over cipher suites");
	for (int i = 0; i < clientHelloMessage->getCipherSuiteCount(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		pcpp::SSLCipherSuite* curCipherSuite = clientHelloMessage->getCipherSuite(i);
		PTF_ASSERT_NOT_NULL(curCipherSuite);
		PTF_ASSERT_EQUAL(curCipherSuite->asString(), cipherSuiteNames[i]);
		PTF_ASSERT_EQUAL(curCipherSuite->getID(), cipherSuiteIDs[i]);
		PTF_ASSERT_EQUAL(curCipherSuite->getKeyExchangeAlg(), cipherSuiteKey[i], enum);
		PTF_ASSERT_EQUAL(curCipherSuite->getAuthAlg(), cipherSuiteAuth[i], enum);
		PTF_ASSERT_EQUAL(curCipherSuite->getSymKeyAlg(), cipherSuiteSym[i], enum);
		PTF_ASSERT_EQUAL(curCipherSuite->getMACAlg(), cipherSuiteHash[i], enum);
	}

	PTF_ASSERT_EQUAL(clientHelloMessage->getCompressionMethodsValue(), 0);
	PTF_ASSERT_EQUAL(handshakeLayer->getHeaderLen(), 188);

	int extCount = clientHelloMessage->getExtensionCount();
	PTF_ASSERT_EQUAL(extCount, 9);
	PTF_ASSERT_EQUAL(clientHelloMessage->getExtensionsLength(), 116);

	pcpp::SSLExtension* ext = clientHelloMessage->getExtension(0);
	PTF_ASSERT_EQUAL(ext->getType(), pcpp::SSL_EXT_SERVER_NAME, enum);
	pcpp::SSLServerNameIndicationExtension* serverNameExt =
	    clientHelloMessage->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
	PTF_ASSERT_NOT_NULL(serverNameExt);
	PTF_ASSERT_EQUAL(serverNameExt->getHostName(), "www.google.com");

	pcpp::TLSECPointFormatExtension* ecPointFormatExt =
	    clientHelloMessage->getExtensionOfType<pcpp::TLSECPointFormatExtension>();
	PTF_ASSERT_NOT_NULL(ecPointFormatExt);
	std::vector<uint8_t> ecPointFormatList = ecPointFormatExt->getECPointFormatList();
	PTF_ASSERT_EQUAL(ecPointFormatList.size(), 1);
	PTF_ASSERT_EQUAL(ecPointFormatList.at(0), 0);

	pcpp::TLSSupportedGroupsExtension* supportedGroupsExt =
	    clientHelloMessage->getExtensionOfType<pcpp::TLSSupportedGroupsExtension>();
	PTF_ASSERT_NOT_NULL(supportedGroupsExt);
	std::vector<uint16_t> supportedGroups = supportedGroupsExt->getSupportedGroups();
	PTF_ASSERT_EQUAL(supportedGroups.size(), 3);
	PTF_ASSERT_EQUAL(supportedGroups.at(0), 23);
	PTF_ASSERT_EQUAL(supportedGroups.at(1), 24);
	PTF_ASSERT_EQUAL(supportedGroups.at(2), 25);

	pcpp::SSLExtensionType extTypes[9] = { pcpp::SSL_EXT_SERVER_NAME,
		                                   pcpp::SSL_EXT_RENEGOTIATION_INFO,
		                                   pcpp::SSL_EXT_SUPPORTED_GROUPS,
		                                   pcpp::SSL_EXT_EC_POINT_FORMATS,
		                                   pcpp::SSL_EXT_SESSIONTICKET_TLS,
		                                   pcpp::SSL_EXT_Unknown,
		                                   pcpp::SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
		                                   pcpp::SSL_EXT_STATUS_REQUEST,
		                                   pcpp::SSL_EXT_SIGNATURE_ALGORITHMS };

	uint16_t extLength[9] = { 19, 1, 8, 2, 0, 0, 23, 5, 22 };

	PTF_PRINT_VERBOSE("Iterating over extensions");
	for (int i = 0; i < extCount; i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		pcpp::SSLExtension* curExt = clientHelloMessage->getExtension(i);
		PTF_ASSERT_EQUAL(curExt->getType(), extTypes[i], enum);
		PTF_ASSERT_EQUAL(curExt->getLength(), extLength[i]);
		PTF_ASSERT_EQUAL(clientHelloMessage->getExtensionOfType(extTypes[i]), curExt, ptr);
	}
}  // SSLClientHelloParsingTest

PTF_TEST_CASE(SSLExtensionWithZeroSizeTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tls_zero_size_ext.dat");

	pcpp::Packet clientHelloPacket(&rawPacket1);

	pcpp::SSLHandshakeLayer* handshakeLayer = clientHelloPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	pcpp::SSLClientHelloMessage* clientHelloMessage =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
	PTF_ASSERT_NOT_NULL(clientHelloMessage);

	PTF_ASSERT_EQUAL(clientHelloMessage->getExtensionCount(), 7);
	pcpp::SSLExtension* zeroSizeExt = clientHelloMessage->getExtension(6);
	PTF_ASSERT_NOT_NULL(zeroSizeExt);
	PTF_ASSERT_EQUAL(zeroSizeExt->getType(), pcpp::SSL_EXT_SIGNED_CERTIFICATE_TIMESTAMP, enum);
	PTF_ASSERT_EQUAL(zeroSizeExt->getLength(), 0);
	PTF_ASSERT_EQUAL(zeroSizeExt->getTotalLength(), 4);
	PTF_ASSERT_NULL(zeroSizeExt->getData());

}  // SSLExtensionWithZeroSizeTest

PTF_TEST_CASE(SSLAppDataParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-MultipleAppData.dat");

	pcpp::Packet appDataPacket(&rawPacket1);

	PTF_ASSERT_TRUE(appDataPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLApplicationDataLayer* appDataLayer = appDataPacket.getLayerOfType<pcpp::SSLApplicationDataLayer>();
	PTF_ASSERT_NOT_NULL(appDataLayer);

	PTF_ASSERT_EQUAL(appDataLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_2, enum);
	PTF_ASSERT_EQUAL(appDataLayer->getRecordType(), pcpp::SSL_APPLICATION_DATA, enum);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedDataLen(), 880);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[0], 0, hex);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[16], 0xd9, hex);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[77], 0x19, hex);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[869], 0xbc, hex);

	PTF_ASSERT_NOT_NULL(appDataLayer->getNextLayer());
	PTF_ASSERT_EQUAL(appDataLayer->getNextLayer()->getProtocol(), pcpp::SSL, enum);
	appDataLayer = dynamic_cast<pcpp::SSLApplicationDataLayer*>(appDataLayer->getNextLayer());
	PTF_ASSERT_NOT_NULL(appDataLayer);

	PTF_ASSERT_EQUAL(appDataLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_2, enum);
	PTF_ASSERT_EQUAL(appDataLayer->getRecordType(), pcpp::SSL_APPLICATION_DATA, enum);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedDataLen(), 41);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[0], 0, hex);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[19], 0x7d, hex);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[40], 0xec, hex);

	PTF_ASSERT_NULL(appDataLayer->getNextLayer());
}  // SSLAppDataParsingTest

PTF_TEST_CASE(SSLAlertParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-AlertClear.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/SSL-AlertEnc.dat");

	pcpp::Packet clearAlertPacket(&rawPacket1);
	pcpp::Packet encAlertPacket(&rawPacket2);

	PTF_ASSERT_TRUE(clearAlertPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLAlertLayer* clearAlertLayer = clearAlertPacket.getLayerOfType<pcpp::SSLAlertLayer>();
	PTF_ASSERT_NOT_NULL(clearAlertLayer);
	PTF_ASSERT_EQUAL(clearAlertLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_0, enum);
	PTF_ASSERT_EQUAL(clearAlertLayer->getRecordType(), pcpp::SSL_ALERT, enum);
	PTF_ASSERT_EQUAL(clearAlertLayer->getAlertLevel(), pcpp::SSL_ALERT_LEVEL_FATAL, enum);
	PTF_ASSERT_EQUAL(clearAlertLayer->getAlertDescription(), pcpp::SSL_ALERT_PROTOCOL_VERSION, enum);
	PTF_ASSERT_EQUAL(clearAlertLayer->getRecordLayer()->length, be16toh(2));
	PTF_ASSERT_NULL(clearAlertLayer->getNextLayer());

	PTF_ASSERT_TRUE(encAlertPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLAlertLayer* encAlertLayer = encAlertPacket.getLayerOfType<pcpp::SSLAlertLayer>();
	PTF_ASSERT_NOT_NULL(encAlertLayer);
	PTF_ASSERT_EQUAL(encAlertLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_2, enum);
	PTF_ASSERT_EQUAL(encAlertLayer->getRecordType(), pcpp::SSL_ALERT, enum);
	PTF_ASSERT_EQUAL(encAlertLayer->getAlertLevel(), pcpp::SSL_ALERT_LEVEL_ENCRYPTED, enum);
	PTF_ASSERT_EQUAL(encAlertLayer->getAlertDescription(), pcpp::SSL_ALERT_ENCRYPTED, enum);
	PTF_ASSERT_EQUAL(encAlertLayer->getRecordLayer()->length, be16toh(26));
	PTF_ASSERT_EQUAL(encAlertLayer->getHeaderLen(), 31);
}  // SSLAlertParsingTest

/**
 * Testing: server-hello, change-cipher-spec, encrypted handshake message
 */
PTF_TEST_CASE(SSLMultipleRecordParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-MultipleRecords1.dat");

	pcpp::Packet multipleRecordsPacket(&rawPacket1);

	PTF_ASSERT_TRUE(multipleRecordsPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLServerHelloMessage* serverHelloMessage =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();
	PTF_ASSERT_NOT_NULL(serverHelloMessage);
	PTF_ASSERT_EQUAL(serverHelloMessage->getSessionIDLength(), 32);
	PTF_ASSERT_EQUAL(serverHelloMessage->getSessionID()[0], 0xbf, hex);
	PTF_ASSERT_EQUAL(serverHelloMessage->getSessionID()[31], 0x44, hex);
	PTF_ASSERT_EQUAL(serverHelloMessage->getCipherSuite()->asString(), "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
	PTF_ASSERT_EQUAL(serverHelloMessage->getCipherSuite()->getSymKeyAlg(), pcpp::SSL_SYM_AES_128_GCM, enum);
	PTF_ASSERT_EQUAL(serverHelloMessage->getExtensionsLength(), 20);
	PTF_ASSERT_EQUAL(serverHelloMessage->getExtensionCount(), 3);
	uint16_t extensionsLength[3] = { 1, 5, 2 };
	uint16_t totalExtensionsLength[3] = { 5, 9, 6 };
	pcpp::SSLExtensionType extensionTypes[3] = { pcpp::SSL_EXT_RENEGOTIATION_INFO,
		                                         pcpp::SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
		                                         pcpp::SSL_EXT_EC_POINT_FORMATS };
	uint8_t extensionDataFirstByte[3] = { 0, 0, 1 };
	PTF_PRINT_VERBOSE("iterating over SSL extensions");
	for (int i = 0; i < 3; i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		pcpp::SSLExtension* curExt = serverHelloMessage->getExtension(i);
		PTF_ASSERT_EQUAL(curExt->getLength(), extensionsLength[i]);
		PTF_ASSERT_EQUAL(curExt->getTotalLength(), totalExtensionsLength[i]);
		PTF_ASSERT_EQUAL(curExt->getType(), extensionTypes[i], enum);
		PTF_ASSERT_EQUAL(curExt->getData()[0], extensionDataFirstByte[i]);
	}
	pcpp::TLSECPointFormatExtension* ecPointFormatExt =
	    serverHelloMessage->getExtensionOfType<pcpp::TLSECPointFormatExtension>();
	PTF_ASSERT_NOT_NULL(ecPointFormatExt);
	std::vector<uint8_t> ecPointFormatList = ecPointFormatExt->getECPointFormatList();
	PTF_ASSERT_EQUAL(ecPointFormatList.size(), 1);
	PTF_ASSERT_EQUAL(ecPointFormatList.at(0), 0);

	pcpp::SSLChangeCipherSpecLayer* ccsLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLChangeCipherSpecLayer>();
	PTF_ASSERT_NOT_NULL(ccsLayer);
	PTF_ASSERT_EQUAL(ccsLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_2, enum);
	PTF_ASSERT_EQUAL(ccsLayer->getRecordType(), pcpp::SSL_CHANGE_CIPHER_SPEC, enum);
	PTF_ASSERT_EQUAL(ccsLayer->getHeaderLen(), 6);

	handshakeLayer = multipleRecordsPacket.getNextLayerOfType<pcpp::SSLHandshakeLayer>(handshakeLayer);
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLUnknownMessage* unknownMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLUnknownMessage>();
	PTF_ASSERT_NOT_NULL(unknownMessage);
	PTF_ASSERT_EQUAL(unknownMessage->getHandshakeType(), pcpp::SSL_HANDSHAKE_UNKNOWN, enum);
	PTF_ASSERT_EQUAL(unknownMessage->getMessageLength(), 40);
}  // SSLMultipleRecordParsingTest

/**
 * Testing: client-key-exchange
 */
PTF_TEST_CASE(SSLMultipleRecordParsing2Test)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-MultipleRecords2.dat");

	pcpp::Packet multipleRecordsPacket(&rawPacket1);

	PTF_ASSERT_TRUE(multipleRecordsPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);

	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLClientKeyExchangeMessage* clientKeyExMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientKeyExchangeMessage>();
	PTF_ASSERT_NOT_NULL(clientKeyExMsg);
	PTF_ASSERT_EQUAL(clientKeyExMsg->getHandshakeType(), pcpp::SSL_CLIENT_KEY_EXCHANGE, enum);
	PTF_ASSERT_EQUAL(clientKeyExMsg->getMessageLength(), 70);
	PTF_ASSERT_EQUAL(clientKeyExMsg->getClientKeyExchangeParamsLength(), 66);
	PTF_ASSERT_EQUAL(clientKeyExMsg->getClientKeyExchangeParams()[0], 0x41, hex);
	PTF_ASSERT_EQUAL(clientKeyExMsg->getClientKeyExchangeParams()[10], 0xf2, hex);
	PTF_ASSERT_EQUAL(clientKeyExMsg->getClientKeyExchangeParams()[65], 0xdc, hex);
}  // SSLMultipleRecordParsing2Test

/**
 * Testing - certificate, certificate-request
 */
PTF_TEST_CASE(SSLMultipleRecordParsing3Test)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-MultipleRecords3.dat");

	pcpp::Packet multipleRecordsPacket(&rawPacket1);

	PTF_ASSERT_TRUE(multipleRecordsPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);

	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 5);

	pcpp::SSLCertificateMessage* certMsg = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLCertificateMessage>();
	PTF_ASSERT_NOT_NULL(certMsg);
	PTF_ASSERT_EQUAL(certMsg->getHandshakeType(), pcpp::SSL_CERTIFICATE, enum);
	PTF_ASSERT_EQUAL(certMsg->getMessageLength(), 4966);
	PTF_ASSERT_EQUAL(certMsg->getNumOfCertificates(), 3);
	PTF_ASSERT_NULL(certMsg->getCertificate(1000));

	pcpp::SSLx509Certificate* cert = certMsg->getCertificate(0);
	PTF_ASSERT_NOT_NULL(cert);
	PTF_ASSERT_TRUE(cert->allDataExists());
	PTF_ASSERT_EQUAL(cert->getDataLength(), 1509);
	std::string certBuffer(cert->getData(), cert->getData() + cert->getDataLength());
	std::size_t pos = certBuffer.find("LDAP Intermediate CA");
	PTF_ASSERT_TRUE(pos != std::string::npos);
	pos = certBuffer.find("Internal Development CA");
	PTF_ASSERT_EQUAL(pos, std::string::npos, ptr);
	auto asn1Record = cert->getRootAsn1Record();
	PTF_ASSERT_NOT_NULL(asn1Record);
	PTF_ASSERT_EQUAL(asn1Record->getSubRecords().size(), 3);

	cert = certMsg->getCertificate(1);
	PTF_ASSERT_NOT_NULL(cert);
	PTF_ASSERT_TRUE(cert->allDataExists());
	PTF_ASSERT_EQUAL(cert->getDataLength(), 1728);
	certBuffer = std::string(cert->getData(), cert->getData() + cert->getDataLength());
	pos = certBuffer.find("Internal Development CA");
	PTF_ASSERT_TRUE(pos != std::string::npos);

	cert = certMsg->getCertificate(2);
	PTF_ASSERT_NOT_NULL(cert);
	PTF_ASSERT_TRUE(cert->allDataExists());
	PTF_ASSERT_EQUAL(cert->getDataLength(), 1713);
	certBuffer = std::string(cert->getData(), cert->getData() + cert->getDataLength());
	pos = certBuffer.find("Internal Development CA");
	PTF_ASSERT_TRUE(pos != std::string::npos);

	pcpp::SSLCertificateRequestMessage* certReqMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLCertificateRequestMessage>();
	PTF_ASSERT_TRUE(certReqMsg->isMessageComplete());
	PTF_ASSERT_EQUAL(certReqMsg->getHandshakeType(), pcpp::SSL_CERTIFICATE_REQUEST, enum);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateTypes().size(), 2);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateTypes().at(0), pcpp::SSL_CCT_RSA_SIGN, enum);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateTypes().at(1), pcpp::SSL_CCT_DSS_SIGN, enum);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateAuthorityLength(), 110);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateAuthorityData()[0], 0x0, hex);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateAuthorityData()[1], 0x6c, hex);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateAuthorityData()[14], 0x2, hex);
	PTF_ASSERT_EQUAL(certReqMsg->getCertificateAuthorityData()[47], 0x13, hex);
}  // SSLMultipleRecordParsing3Test

/**
 * Testing: server-key-exchange, server-hello-done
 */
PTF_TEST_CASE(SSLMultipleRecordParsing4Test)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-MultipleRecords4.dat");

	pcpp::Packet multipleRecordsPacket(&rawPacket1);

	PTF_ASSERT_TRUE(multipleRecordsPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);

	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLServerKeyExchangeMessage* serverKeyExMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerKeyExchangeMessage>();
	PTF_ASSERT_NOT_NULL(serverKeyExMsg);
	PTF_ASSERT_EQUAL(serverKeyExMsg->getHandshakeType(), pcpp::SSL_SERVER_KEY_EXCHANGE, enum);
	PTF_ASSERT_EQUAL(serverKeyExMsg->getMessageLength(), 333);
	PTF_ASSERT_EQUAL(serverKeyExMsg->getServerKeyExchangeParamsLength(), 329);
	PTF_ASSERT_EQUAL(serverKeyExMsg->getServerKeyExchangeParams()[0], 0x03, hex);
	PTF_ASSERT_EQUAL(serverKeyExMsg->getServerKeyExchangeParams()[10], 0x7a, hex);
	PTF_ASSERT_EQUAL(serverKeyExMsg->getServerKeyExchangeParams()[328], 0x33, hex);

	handshakeLayer = multipleRecordsPacket.getNextLayerOfType<pcpp::SSLHandshakeLayer>(handshakeLayer);
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLServerHelloDoneMessage* serverHelloDoneMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloDoneMessage>();
	PTF_ASSERT_NOT_NULL(serverHelloDoneMsg);
	PTF_ASSERT_EQUAL(serverHelloDoneMsg->getHandshakeType(), pcpp::SSL_SERVER_DONE, enum);
	PTF_ASSERT_EQUAL(serverHelloDoneMsg->getMessageLength(), 4);
	PTF_ASSERT_EQUAL(serverHelloDoneMsg, handshakeLayer->getHandshakeMessageAt(0), ptr);
}  // SSLMultipleRecordParsing4Test

/**
 * Testing: change-cipher-spec, encrypted-handshake-message, application-data
 */
PTF_TEST_CASE(SSLMultipleRecordParsing5Test)
{
	timeval time;
	gettimeofday(&time, nullptr);
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-MultipleRecords5.dat");

	pcpp::Packet multipleRecordsPacket(&rawPacket1);

	pcpp::SSLChangeCipherSpecLayer* ccsLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLChangeCipherSpecLayer>();
	PTF_ASSERT_NOT_NULL(ccsLayer);
	PTF_ASSERT_EQUAL(ccsLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_2, enum);
	PTF_ASSERT_EQUAL(ccsLayer->getRecordType(), pcpp::SSL_CHANGE_CIPHER_SPEC, enum);
	PTF_ASSERT_EQUAL(ccsLayer->getHeaderLen(), 6);

	pcpp::SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLUnknownMessage* unknownMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLUnknownMessage>();
	PTF_ASSERT_NOT_NULL(unknownMessage);
	PTF_ASSERT_EQUAL(unknownMessage->getHandshakeType(), pcpp::SSL_HANDSHAKE_UNKNOWN, enum);
	PTF_ASSERT_EQUAL(unknownMessage->getMessageLength(), 40);

	pcpp::SSLApplicationDataLayer* appDataLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLApplicationDataLayer>();
	PTF_ASSERT_NOT_NULL(appDataLayer);
	PTF_ASSERT_EQUAL(appDataLayer->getRecordVersion().asEnum(), pcpp::SSLVersion::TLS1_2, enum);
	PTF_ASSERT_EQUAL(appDataLayer->getRecordType(), pcpp::SSL_APPLICATION_DATA, enum);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedDataLen(), 64);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[0], 0, hex);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[16], 0x07, hex);
	PTF_ASSERT_EQUAL(appDataLayer->getEncryptedData()[61], 0x92, hex);
	PTF_ASSERT_NULL(appDataLayer->getNextLayer());
}  // SSLMultipleRecordParsing5Test

PTF_TEST_CASE(SSLPartialCertificateParseTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-PartialCertificate1.dat");

	pcpp::Packet partialCertPacket(&rawPacket1);

	PTF_ASSERT_TRUE(partialCertPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLHandshakeLayer* handshakeLayer = partialCertPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	handshakeLayer = partialCertPacket.getNextLayerOfType<pcpp::SSLHandshakeLayer>(handshakeLayer);
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	pcpp::SSLCertificateMessage* certMsg = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLCertificateMessage>();
	PTF_ASSERT_NOT_NULL(certMsg);
	PTF_ASSERT_FALSE(certMsg->isMessageComplete());
	PTF_ASSERT_EQUAL(certMsg->getNumOfCertificates(), 1);
	pcpp::SSLx509Certificate* cert = certMsg->getCertificate(0);
	PTF_ASSERT_FALSE(cert->allDataExists());
	PTF_ASSERT_EQUAL(cert->getDataLength(), 1266);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/SSL-PartialCertificate2.dat");

	pcpp::Packet partialCertPacket2(&rawPacket2);

	PTF_ASSERT_TRUE(partialCertPacket2.isPacketOfType(pcpp::SSL));
	handshakeLayer = partialCertPacket2.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	handshakeLayer = partialCertPacket2.getNextLayerOfType<pcpp::SSLHandshakeLayer>(handshakeLayer);
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	certMsg = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLCertificateMessage>();
	PTF_ASSERT_NOT_NULL(certMsg);
	PTF_ASSERT_FALSE(certMsg->isMessageComplete());
	PTF_ASSERT_EQUAL(certMsg->getNumOfCertificates(), 1);
	cert = certMsg->getCertificate(0);
	PTF_ASSERT_FALSE(cert->allDataExists());
	PTF_ASSERT_EQUAL(cert->getDataLength(), 1268);
}  // SSLPartialCertificateParseTest

PTF_TEST_CASE(SSLNewSessionTicketParseTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-NewSessionTicket.dat");

	pcpp::Packet sslPacket(&rawPacket1);

	PTF_ASSERT_TRUE(sslPacket.isPacketOfType(pcpp::SSL));
	pcpp::SSLHandshakeLayer* handshakeLayer = sslPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);

	PTF_ASSERT_EQUAL(handshakeLayer->getHandshakeMessagesCount(), 1);
	pcpp::SSLNewSessionTicketMessage* newSessionTicketMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLNewSessionTicketMessage>();
	PTF_ASSERT_NOT_NULL(newSessionTicketMsg);
	PTF_ASSERT_TRUE(newSessionTicketMsg->isMessageComplete());
	PTF_ASSERT_EQUAL(newSessionTicketMsg->getHandshakeType(), pcpp::SSL_NEW_SESSION_TICKET, enum);
	PTF_ASSERT_EQUAL(newSessionTicketMsg->getSessionTicketDataLength(), 214);
	PTF_ASSERT_EQUAL(newSessionTicketMsg->getSessionTicketData()[0], 0, hex);
	PTF_ASSERT_EQUAL(newSessionTicketMsg->getSessionTicketData()[16], 0xf9, hex);
	PTF_ASSERT_EQUAL(newSessionTicketMsg->getSessionTicketData()[213], 0x75, hex);
}  // SSLNewSessionTicketParseTest

PTF_TEST_CASE(SSLMalformedPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ssl-malformed1.dat");

	pcpp::Packet badSSLPacket(&rawPacket1);

	pcpp::SSLHandshakeLayer* handshakeLayer = badSSLPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	pcpp::SSLClientHelloMessage* clientHelloMessage =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
	PTF_ASSERT_NOT_NULL(clientHelloMessage);
	PTF_ASSERT_EQUAL(clientHelloMessage->getExtensionCount(), 1);
}  // SSLMalformedPacketParsing

PTF_TEST_CASE(TLS1_3ParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tls1_3_client_hello1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/tls1_3_client_hello2.dat");

	pcpp::Packet tls13ClientHello1(&rawPacket1);
	pcpp::Packet tls13ClientHello2(&rawPacket2);

	uint16_t cipherSuiteIDs[3] = { 0x1302, 0x1303, 0x1301 };
	std::string cipherSuiteNames[3] = { "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
		                                "TLS_AES_128_GCM_SHA256" };
	pcpp::SSLSymetricEncryptionAlgorithm cipherSuiteSym[3] = { pcpp::SSL_SYM_AES_256_GCM,
		                                                       pcpp::SSL_SYM_CHACHA20_POLY1305,
		                                                       pcpp::SSL_SYM_AES_128_GCM };

	pcpp::SSLHashingAlgorithm cipherSuiteHash[3] = { pcpp::SSL_HASH_SHA384, pcpp::SSL_HASH_SHA256,
		                                             pcpp::SSL_HASH_SHA256 };

	pcpp::SSLHandshakeLayer* handshakeLayer = tls13ClientHello1.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	pcpp::SSLClientHelloMessage* clientHelloMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
	PTF_ASSERT_NOT_NULL(clientHelloMsg);
	PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuiteCount(), 4);
	for (int i = 0; i < 3; i++)
	{
		PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(i)->asString(), cipherSuiteNames[i]);
		PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(i)->getID(), cipherSuiteIDs[i]);
		PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(i)->getSymKeyAlg(), cipherSuiteSym[i], enum);
		PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(i)->getMACAlg(), cipherSuiteHash[i], enum);
		PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(i)->getKeyExchangeAlg(), pcpp::SSL_KEYX_NULL, enum);
		PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(i)->getAuthAlg(), pcpp::SSL_AUTH_NULL, enum);
	}

	pcpp::SSLSupportedVersionsExtension* supportedVersionsExt =
	    clientHelloMsg->getExtensionOfType<pcpp::SSLSupportedVersionsExtension>();
	PTF_ASSERT_NOT_NULL(supportedVersionsExt);
	std::vector<pcpp::SSLVersion> versionVec = supportedVersionsExt->getSupportedVersions();
	PTF_ASSERT_EQUAL(versionVec.size(), 3);
	PTF_ASSERT_EQUAL(versionVec[0].asEnum(), pcpp::SSLVersion::TLS1_3_D28, enum);
	PTF_ASSERT_EQUAL(versionVec[1].asEnum(), pcpp::SSLVersion::TLS1_3_D27, enum);
	PTF_ASSERT_EQUAL(versionVec[2].asEnum(), pcpp::SSLVersion::TLS1_3_D26, enum);
	PTF_ASSERT_EQUAL(versionVec[0].asEnum(true), pcpp::SSLVersion::TLS1_3, enum);

	pcpp::TLSECPointFormatExtension* ecPointFormatExt =
	    clientHelloMsg->getExtensionOfType<pcpp::TLSECPointFormatExtension>();
	PTF_ASSERT_NOT_NULL(ecPointFormatExt);
	std::vector<uint8_t> ecPointFormatList = ecPointFormatExt->getECPointFormatList();
	PTF_ASSERT_EQUAL(ecPointFormatList.size(), 3);
	PTF_ASSERT_EQUAL(ecPointFormatList.at(0), 0);
	PTF_ASSERT_EQUAL(ecPointFormatList.at(1), 1);
	PTF_ASSERT_EQUAL(ecPointFormatList.at(2), 2);

	pcpp::TLSSupportedGroupsExtension* supportedGroupsExt =
	    clientHelloMsg->getExtensionOfType<pcpp::TLSSupportedGroupsExtension>();
	PTF_ASSERT_NOT_NULL(supportedGroupsExt);
	std::vector<uint16_t> supportedGroups = supportedGroupsExt->getSupportedGroups();
	PTF_ASSERT_EQUAL(supportedGroups.size(), 5);
	PTF_ASSERT_EQUAL(supportedGroups.at(0), 29);
	PTF_ASSERT_EQUAL(supportedGroups.at(1), 23);
	PTF_ASSERT_EQUAL(supportedGroups.at(2), 30);
	PTF_ASSERT_EQUAL(supportedGroups.at(3), 25);
	PTF_ASSERT_EQUAL(supportedGroups.at(4), 24);

	handshakeLayer = tls13ClientHello2.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	clientHelloMsg = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
	PTF_ASSERT_NOT_NULL(clientHelloMsg);
	PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuiteCount(), 18);
	PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(0)->asString(), cipherSuiteNames[2]);
	PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(1)->asString(), cipherSuiteNames[1]);
	PTF_ASSERT_EQUAL(clientHelloMsg->getCipherSuite(2)->asString(), cipherSuiteNames[0]);

	supportedVersionsExt = clientHelloMsg->getExtensionOfType<pcpp::SSLSupportedVersionsExtension>();
	PTF_ASSERT_NOT_NULL(supportedVersionsExt);
	versionVec.clear();
	versionVec = supportedVersionsExt->getSupportedVersions();
	PTF_ASSERT_EQUAL(versionVec.size(), 2);
	PTF_ASSERT_EQUAL(versionVec[0].asEnum(), pcpp::SSLVersion::TLS1_3, enum);
	PTF_ASSERT_EQUAL(versionVec[1].asEnum(), pcpp::SSLVersion::TLS1_2, enum);

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/tls1_3_server_hello1.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/tls1_3_server_hello2.dat");

	pcpp::Packet tls13ServerHello1(&rawPacket3);
	pcpp::Packet tls13ServerHello2(&rawPacket4);

	handshakeLayer = tls13ServerHello1.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	pcpp::SSLServerHelloMessage* serverHelloMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();
	PTF_ASSERT_NOT_NULL(serverHelloMsg);
	PTF_ASSERT_EQUAL(serverHelloMsg->getCipherSuite()->asString(), cipherSuiteNames[0]);

	supportedVersionsExt = serverHelloMsg->getExtensionOfType<pcpp::SSLSupportedVersionsExtension>();
	PTF_ASSERT_NOT_NULL(supportedVersionsExt);
	versionVec.clear();
	versionVec = supportedVersionsExt->getSupportedVersions();
	PTF_ASSERT_EQUAL(versionVec.size(), 1);
	PTF_ASSERT_EQUAL(versionVec[0].asEnum(), pcpp::SSLVersion::TLS1_3_D28, enum);
	PTF_ASSERT_EQUAL(serverHelloMsg->getHandshakeVersion().asEnum(true), pcpp::SSLVersion::TLS1_3, enum);

	handshakeLayer = tls13ServerHello2.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	serverHelloMsg = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();
	PTF_ASSERT_NOT_NULL(serverHelloMsg);
	PTF_ASSERT_EQUAL(serverHelloMsg->getCipherSuite()->asString(), cipherSuiteNames[2]);

	supportedVersionsExt = serverHelloMsg->getExtensionOfType<pcpp::SSLSupportedVersionsExtension>();
	PTF_ASSERT_NOT_NULL(supportedVersionsExt);
	versionVec.clear();
	versionVec = supportedVersionsExt->getSupportedVersions();
	PTF_ASSERT_EQUAL(versionVec.size(), 1);
	PTF_ASSERT_EQUAL(versionVec[0].asEnum(), pcpp::SSLVersion::TLS1_3, enum);
	PTF_ASSERT_EQUAL(serverHelloMsg->getHandshakeVersion().asEnum(true), pcpp::SSLVersion::TLS1_3, enum);
}  // TLS1_3ParsingTest

PTF_TEST_CASE(TLSCipherSuiteTest)
{
	std::ifstream cipherNamesFile("PacketExamples/CipherSuiteNames.txt");
	std::ifstream cipherIDsFile("PacketExamples/CipherSuiteIDs.txt");
	std::string cipherSuiteName;
	std::string cipherSuiteIDStr;
	while (std::getline(cipherNamesFile, cipherSuiteName))
	{
		std::getline(cipherIDsFile, cipherSuiteIDStr);
		std::stringstream iss;
		iss << std::hex << cipherSuiteIDStr;
		uint16_t cipherSuiteID;
		iss >> cipherSuiteID;
		pcpp::SSLCipherSuite* cipherSuiteByName = pcpp::SSLCipherSuite::getCipherSuiteByName(cipherSuiteName);
		pcpp::SSLCipherSuite* cipherSuiteByID = pcpp::SSLCipherSuite::getCipherSuiteByID(cipherSuiteID);
		PTF_ASSERT_NOT_NULL(cipherSuiteByName);
		PTF_ASSERT_NOT_NULL(cipherSuiteByID);
		PTF_ASSERT_EQUAL(cipherSuiteByName->asString(), cipherSuiteName);
		PTF_ASSERT_EQUAL(cipherSuiteByID->getID(), cipherSuiteID);
		PTF_ASSERT_EQUAL(cipherSuiteByName, cipherSuiteByID, ptr);
	}
}  // TLSCipherSuiteTest

PTF_TEST_CASE(ClientHelloTLSFingerprintTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tls1_3_client_hello1.dat");
	pcpp::Packet tls13ClientHello1(&rawPacket1);

	pcpp::SSLHandshakeLayer* handshakeLayer = tls13ClientHello1.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	pcpp::SSLClientHelloMessage* clientHelloMsg =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
	PTF_ASSERT_NOT_NULL(clientHelloMsg);

	pcpp::SSLClientHelloMessage::ClientHelloTLSFingerprint tlsFingerprint = clientHelloMsg->generateTLSFingerprint();
	PTF_ASSERT_EQUAL(tlsFingerprint.toString(),
	                 "771,4866-4867-4865-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2");
	PTF_ASSERT_EQUAL(tlsFingerprint.toMD5(), "a66e498c488aa0523759691248cdfb01");

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/tls_grease.dat");
	pcpp::Packet tlsGreaseClientHello(&rawPacket2);

	handshakeLayer = tlsGreaseClientHello.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	clientHelloMsg = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
	PTF_ASSERT_NOT_NULL(clientHelloMsg);

	tlsFingerprint = clientHelloMsg->generateTLSFingerprint();
	PTF_ASSERT_EQUAL(tlsFingerprint.toString(),
	                 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-"
	                 "11-35-16-5-13-18-51-45-43-27-21,29-23-24,0");
	PTF_ASSERT_EQUAL(tlsFingerprint.toMD5(), "b32309a26951912be7dba376398abc3b");
}  // ClientHelloTLSFingerprintTest

PTF_TEST_CASE(ServerHelloTLSFingerprintTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-MultipleRecords1.dat");

	pcpp::Packet multipleRecordsPacket(&rawPacket1);

	pcpp::SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	pcpp::SSLServerHelloMessage* serverHelloMessage =
	    handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();
	PTF_ASSERT_NOT_NULL(serverHelloMessage);

	pcpp::SSLServerHelloMessage::ServerHelloTLSFingerprint tlsFingerprint =
	    serverHelloMessage->generateTLSFingerprint();
	PTF_ASSERT_EQUAL(tlsFingerprint.toString(), "771,49195,65281-16-11");
	PTF_ASSERT_EQUAL(tlsFingerprint.toMD5(), "554786d4c84f8a7953b7e453c6371067");

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/tls_server_hello.dat");

	pcpp::Packet serverHelloPacket(&rawPacket2);

	handshakeLayer = serverHelloPacket.getLayerOfType<pcpp::SSLHandshakeLayer>();
	PTF_ASSERT_NOT_NULL(handshakeLayer);
	serverHelloMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();
	PTF_ASSERT_NOT_NULL(serverHelloMessage);

	tlsFingerprint = serverHelloMessage->generateTLSFingerprint();
	PTF_ASSERT_EQUAL(tlsFingerprint.toString(), "771,49195,23-65281-11-35-16");
	PTF_ASSERT_EQUAL(tlsFingerprint.toMD5(), "eca9b8f0f3eae50309eaf901cb822d9b");
}  // ServerHelloTLSFingerprintTest
