#define LOG_MODULE PacketLogModuleSSLLayer

#include "Logger.h"
#include "SSLLayer.h"
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif
#include <sstream>
#include <map>


namespace pcpp
{

static std::map<uint16_t, bool> createSSLPortMap()
{
	std::map<uint16_t, bool> result;

	result[0]   = true; //default
	result[443] = true; //HTTPS
	result[465] = true; //SMTPS
	result[636] = true; //LDAPS
	result[989] = true; //FTPS - data
	result[990] = true; //FTPS - control
	result[992] = true; //Telnet over TLS/SSL
	result[993] = true; //IMAPS
	result[995] = true; //POP3S

	return result;
}

static const std::map<uint16_t, bool> SSLPortMap = createSSLPortMap();


// ----------------
// SSLLayer methods
// ----------------

bool SSLLayer::IsSSLMessage(uint16_t srcPort, uint16_t dstPort, uint8_t* data, size_t dataLen)
{
	// check the port map first
	if (SSLPortMap.find(srcPort) == SSLPortMap.end() && SSLPortMap.find(dstPort) == SSLPortMap.end())
		return false;

	if (dataLen < sizeof(ssl_tls_record_layer))
		return false;

	ssl_tls_record_layer* recordLayer = (ssl_tls_record_layer*)data;

	// there is no SSL message with length 0
	if (recordLayer->length == 0)
		return false;

	if (recordLayer->recordType < 20 || recordLayer->recordType > 23)
		return false;

	uint16_t recordVersion = ntohs(recordLayer->recordVersion);

	if (recordVersion != SSL3 &&
			recordVersion != TLS1_0 &&
			recordVersion != TLS1_1 &&
			recordVersion != TLS1_2)
		return false;

	return true;
}

SSLLayer* SSLLayer::createSSLMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
{
	ssl_tls_record_layer* recordLayer = (ssl_tls_record_layer*)data;
	switch (recordLayer->recordType)
	{
		case SSL_HANDSHAKE:
		{
			return new SSLHandshakeLayer(data, dataLen, prevLayer, packet);
		}

		case SSL_ALERT:
		{
			return new SSLAlertLayer(data, dataLen, prevLayer, packet);
		}

		case SSL_CHANGE_CIPHER_SPEC:
		{
			return new SSLChangeCipherSpecLayer(data, dataLen, prevLayer, packet);
		}

		case SSL_APPLICATION_DATA:
		{
			return new SSLApplicationDataLayer(data, dataLen, prevLayer, packet);
		}

		default:
			return NULL;
	}
}

std::string SSLLayer::sslVersionToString(SSLVersion ver)
{
	switch (ver)
	{
	case SSL2:
		return "SSLv2";
	case SSL3:
		return "SSLv3";
	case TLS1_0:
		return "TLSv1.0";
	case TLS1_1:
		return "TLSv1.1";
	case TLS1_2:
		return "TLSv1.2";
	default:
		return "SSL/TLS unknown";
	}
}

const std::map<uint16_t, bool>* SSLLayer::getSSLPortMap()
{
	return &SSLPortMap;
}

SSLVersion SSLLayer::getRecordVersion()
{
	uint16_t recordVersion = ntohs(getRecordLayer()->recordVersion);
	return (SSLVersion)recordVersion;
}

SSLRecordType SSLLayer::getRecordType()
{
	return (SSLRecordType)(getRecordLayer()->recordType);
}

size_t SSLLayer::getHeaderLen()
{
	size_t len = sizeof(ssl_tls_record_layer) + ntohs(getRecordLayer()->length);
	if (len > m_DataLen)
		return m_DataLen;
	return len;
}

void SSLLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	if (SSLLayer::IsSSLMessage(0, 0, m_Data + headerLen, m_DataLen - headerLen))
		m_NextLayer = SSLLayer::createSSLMessage(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
}


// -------------------------
// SSLHandshakeLayer methods
// -------------------------

std::string SSLHandshakeLayer::toString()
{
	std::stringstream result;
	result << sslVersionToString(getRecordVersion()) << " Layer, Handshake:";
    for(size_t i = 0; i < m_MessageList.size(); i++)
    {
    	if (i == 0)
    		result << " " << m_MessageList.at(i)->toString();
    	else
    		result << ", " << m_MessageList.at(i)->toString();
    }
	return  result.str();
}

SSLHandshakeLayer::SSLHandshakeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	: SSLLayer(data, dataLen, prevLayer, packet)
{
	uint8_t* curPos = m_Data + sizeof(ssl_tls_record_layer);
	size_t recordDataLen = ntohs(getRecordLayer()->length);
	if (recordDataLen > m_DataLen - sizeof(ssl_tls_record_layer))
		recordDataLen = m_DataLen - sizeof(ssl_tls_record_layer);

	size_t curPosIndex = 0;
	while (true)
	{
		SSLHandshakeMessage* message = SSLHandshakeMessage::createHandhakeMessage(curPos, recordDataLen-curPosIndex, this);
		if (message == NULL)
			break;

		m_MessageList.pushBack(message);
		curPos += message->getMessageLength();
		curPosIndex += message->getMessageLength();
	}
}

size_t SSLHandshakeLayer::getHandshakeMessagesCount()
{
	return m_MessageList.size();
}

SSLHandshakeMessage* SSLHandshakeLayer::getHandshakeMessageAt(int index)
{
	if (index < 0 || index >= (int)(m_MessageList.size()))
		return NULL;

	return m_MessageList.at(index);
}


// --------------------------------
// SSLChangeCipherSpecLayer methods
// --------------------------------

std::string SSLChangeCipherSpecLayer::toString()
{
	std::stringstream result;
	result << sslVersionToString(getRecordVersion()) << " Layer, Change Cipher Spec";
	return  result.str();
}

// ---------------------
// SSLAlertLayer methods
// ---------------------

SSLAlertLevel SSLAlertLayer::getAlertLevel()
{
	uint8_t* pos = m_Data + sizeof(ssl_tls_record_layer);
	uint8_t alertLevel = *pos;
	if (alertLevel == SSL_ALERT_LEVEL_WARNING || alertLevel == SSL_ALERT_LEVEL_FATAL)
		return (SSLAlertLevel)alertLevel;
	else
		return SSL_ALERT_LEVEL_ENCRYPTED;

}

SSLAlertDescription SSLAlertLayer::getAlertDescription()
{
	if (getAlertLevel() == SSL_ALERT_LEVEL_ENCRYPTED)
		return SSL_ALERT_ENCRYPRED;

	uint8_t* pos = m_Data + sizeof(ssl_tls_record_layer) + sizeof(uint8_t);
	uint8_t alertDesc = *pos;

	switch (alertDesc)
	{
	case SSL_ALERT_CLOSE_NOTIFY:
	case SSL_ALERT_UNEXPECTED_MESSAGE:
	case SSL_ALERT_BAD_RECORD_MAC:
	case SSL_ALERT_DECRYPTION_FAILED:
	case SSL_ALERT_RECORD_OVERFLOW:
	case SSL_ALERT_DECOMPRESSION_FAILURE:
	case SSL_ALERT_HANDSHAKE_FAILURE:
	case SSL_ALERT_NO_CERTIFICATE:
	case SSL_ALERT_BAD_CERTIFICATE:
	case SSL_ALERT_UNSUPPORTED_CERTIFICATE:
	case SSL_ALERT_CERTIFICATE_REVOKED:
	case SSL_ALERT_CERTIFICATE_EXPIRED:
	case SSL_ALERT_CERTIFICATE_UNKNOWN:
	case SSL_ALERT_ILLEGAL_PARAMETER:
	case SSL_ALERT_UNKNOWN_CA:
	case SSL_ALERT_ACCESS_DENIED:
	case SSL_ALERT_DECODE_ERROR:
	case SSL_ALERT_DECRYPT_ERROR:
	case SSL_ALERT_EXPORT_RESTRICTION:
	case SSL_ALERT_PROTOCOL_VERSION:
	case SSL_ALERT_INSUFFICIENT_SECURITY:
	case SSL_ALERT_INTERNAL_ERROR:
	case SSL_ALERT_USER_CANCELLED:
	case SSL_ALERT_NO_RENEGOTIATION:
		return (SSLAlertDescription)alertDesc;
		break;
	default:
		return SSL_ALERT_ENCRYPRED;
	}
}

std::string SSLAlertLayer::toString()
{
	std::stringstream result;
	result << sslVersionToString(getRecordVersion()) << " Layer, ";
	if (getAlertLevel() == SSL_ALERT_LEVEL_ENCRYPTED)
		result << "Encrypted Alert";
	else
		//TODO: add alert level and description here
		result << "Alert";
	return  result.str();
}

// -------------------------------
// SSLApplicationDataLayer methods
// -------------------------------

uint8_t* SSLApplicationDataLayer::getEncrpytedData()
{
	if (getHeaderLen() <= sizeof(ssl_tls_record_layer))
		return NULL;

	return m_Data + sizeof(ssl_tls_record_layer);
}

size_t SSLApplicationDataLayer::getEncrpytedDataLen()
{
	int result = (int)getHeaderLen() - (int)sizeof(ssl_tls_record_layer);
	if (result < 0)
		return 0;

	return (size_t)result;
}

std::string SSLApplicationDataLayer::toString()
{
	return sslVersionToString(getRecordVersion()) + " Layer, Application Data";
}

} // namespace pcpp
