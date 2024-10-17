#define LOG_MODULE PacketLogModuleSdpLayer

#include "SdpLayer.h"
#include "Logger.h"
#include <sstream>

namespace pcpp
{

	std::vector<std::string> splitByWhiteSpaces(const std::string& str)
	{
		std::string buf;
		std::stringstream stream(str);
		std::vector<std::string> result;
		while (stream >> buf)
			result.push_back(buf);

		return result;
	}

	SdpLayer::SdpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : TextBasedProtocolMessage(data, dataLen, prevLayer, packet, SDP)
	{
		m_FieldsOffset = 0;
		parseFields();
	}

	SdpLayer::SdpLayer()
	{
		m_Protocol = SDP;
		m_FieldsOffset = 0;
	}

	SdpLayer::SdpLayer(const std::string& username, long sessionID, long sessionVersion, IPv4Address ipAddress,
	                   const std::string& sessionName, long startTime, long stopTime)
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
		std::string originatorFieldValue =
		    username + " " + sessionIDStream.str() + " " + sessionVersionStream.str() + " " + networkInfo;
		addField(PCPP_SDP_ORIGINATOR_FIELD, originatorFieldValue);

		addField(PCPP_SDP_SESSION_NAME_FIELD, sessionName);

		addField(PCPP_SDP_CONNECTION_INFO_FIELD, networkInfo);

		std::stringstream startTimeStream;
		startTimeStream << startTime;
		std::stringstream stopTimeStream;
		stopTimeStream << stopTime;
		addField(PCPP_SDP_TIME_FIELD, startTimeStream.str() + " " + stopTimeStream.str());
	}

	std::string SdpLayer::toString() const
	{
		return "SDP Layer";
	}

	IPv4Address SdpLayer::getOwnerIPv4Address() const
	{
		HeaderField* originator = getFieldByName(PCPP_SDP_ORIGINATOR_FIELD);
		if (originator == nullptr)
			return IPv4Address::Zero;

		std::vector<std::string> tokens = splitByWhiteSpaces(originator->getFieldValue());
		if (tokens.size() < 6)
			return IPv4Address::Zero;

		if (tokens[3] != "IN" || tokens[4] != "IP4")
			return IPv4Address::Zero;

		try
		{
			return IPv4Address(tokens[5]);
		}
		catch (const std::exception&)
		{
			return IPv4Address::Zero;
		}
	}

	uint16_t SdpLayer::getMediaPort(const std::string& mediaType) const
	{
		int mediaFieldIndex = 0;
		HeaderField* mediaDesc = getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD, mediaFieldIndex);

		while (mediaDesc != nullptr)
		{
			std::vector<std::string> tokens = splitByWhiteSpaces(mediaDesc->getFieldValue());

			if (tokens.size() >= 2 && tokens[0] == mediaType)
				return atoi(tokens[1].c_str());

			mediaFieldIndex++;
			mediaDesc = getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD, mediaFieldIndex);
		}

		return 0;
	}

	bool SdpLayer::addMediaDescription(const std::string& mediaType, uint16_t mediaPort,
	                                   const std::string& mediaProtocol, const std::string& mediaFormat,
	                                   const std::vector<std::string>& mediaAttributes)
	{
		std::stringstream portStream;
		portStream << mediaPort;

		std::string mediaFieldValue = mediaType + " " + portStream.str() + " " + mediaProtocol + " " + mediaFormat;
		if (addField(PCPP_SDP_MEDIA_NAME_FIELD, mediaFieldValue) == nullptr)
		{
			PCPP_LOG_ERROR("Failed to add media description field");
			return false;
		}

		for (const auto& iter : mediaAttributes)
		{
			if (addField(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, iter) == nullptr)
			{
				PCPP_LOG_ERROR("Failed to add media attribute '" << iter << "'");
				return false;
			}
		}

		return true;
	}

}  // namespace pcpp
