#define LOG_MODULE PacketLogModuleSdpLayer


#include "SdpLayer.h"
#include "Logger.h"
#include <stdlib.h>
#include <string>
#include <sstream>

namespace pcpp
{

std::vector<std::string> splitByWhiteSpaces(std::string str)
{
    std::string buf;
    std::stringstream stream(str);
    std::vector<std::string> result;
    while (stream >> buf)
        result.push_back(buf);

    return result;
}


SdpLayer::SdpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : TextBasedProtocolMessage(data, dataLen, prevLayer, packet)
{
	m_Protocol = SDP;
	m_FieldsOffset = 0;
	parseFields();
}

SdpLayer::SdpLayer()
{
	m_Protocol = SDP;
	m_FieldsOffset = 0;
}

SdpLayer::SdpLayer(std::string username, long sessionID, long sessionVersion, IPv4Address ipAddress, std::string sessionName, long startTime, long stopTime)
{
	m_Protocol = SDP;
	m_FieldsOffset = 0;

	// must initialize m_Data otherwise addField() will fail while trying to extend the layer
	// initializing in length of 1 but keeping m_DataLen with value of 0.
	// when extending the field m_Data is purged so there isn't a memory leak here
	m_Data = new uint8_t[1];
	m_DataLen = 0;

	addField(PCPP_SDP_PROTOCOL_VERSION_FIELD, "0");

	std::stringstream sessionIDStream;
	sessionIDStream << sessionID;
	std::stringstream sessionVersionStream;
	sessionVersionStream << sessionVersion;
	std::string networkInfo = "IN IP4 " + ipAddress.toString();
	std::string originatorFieldValue = username + " " + sessionIDStream.str() + " " + sessionVersionStream.str() + " " + networkInfo;
	addField(PCPP_SDP_ORIGINATOR_FIELD, originatorFieldValue);

	addField(PCPP_SDP_SESSION_NAME_FIELD, sessionName);

	addField(PCPP_SDP_CONNECTION_INFO_FIELD, networkInfo);

	std::stringstream startTimeStream;
	startTimeStream << startTime;
	std::stringstream stopTimeStream;
	stopTimeStream << stopTime;
	addField(PCPP_SDP_TIME_FIELD, startTimeStream.str() + " " + stopTimeStream.str());
}

std::string SdpLayer::toString()
{
	return "SDP Layer";
}

IPv4Address SdpLayer::getOwnerIPv4Address()
{
	HeaderField* originator = getFieldByName(PCPP_SDP_ORIGINATOR_FIELD);
	if (originator == NULL)
		return IPv4Address::Zero;

	std::vector<std::string> tokens = splitByWhiteSpaces(originator->getFieldValue());
	if (tokens.size() < 6)
		return IPv4Address::Zero;

	if (tokens[3] != "IN" || tokens[4] != "IP4")
		return IPv4Address::Zero;

	return IPv4Address(tokens[5]);
}

uint16_t SdpLayer::getMediaPort(std::string mediaType)
{
	int mediaFieldIndex = 0;
	HeaderField* mediaDesc = getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD, mediaFieldIndex);

	while (mediaDesc != NULL)
	{
		std::vector<std::string> tokens = splitByWhiteSpaces(mediaDesc->getFieldValue());

		if (tokens.size() >= 2 && tokens[0] == mediaType)
			return atoi(tokens[1].c_str());

		mediaFieldIndex++;
		mediaDesc = getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD, mediaFieldIndex);
	}

	return 0;
}

bool SdpLayer::addMediaDescription(std::string mediaType, uint16_t mediaPort, std::string mediaProtocol, std::string mediaFormat, std::vector<std::string> mediaAttributes)
{
	std::stringstream portStream;
	portStream << mediaPort;

	std::string mediaFieldValue = mediaType + " " + portStream.str() + " " + mediaProtocol + " " + mediaFormat;
	if (addField(PCPP_SDP_MEDIA_NAME_FIELD, mediaFieldValue) == NULL)
	{
		LOG_ERROR("Failed to add media description field");
		return false;
	}


	for (std::vector<std::string>::iterator iter = mediaAttributes.begin(); iter != mediaAttributes.end(); iter++)
	{
		if (addField(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, *iter) == NULL)
		{
			LOG_ERROR("Faild to add media attribute '%s'", iter->c_str());
			return false;
		}
	}

	return true;
}


}
