#include "LineBasedProtocol.h"
#include "Logger.h"

#include <string.h>

#define ASCII_HYPHEN 0x2d
#define ASCII_SPACE 0x20

namespace pcpp
{

	size_t LineBasedProtocolMessage::getOptionOffset() const
	{
		size_t maxLen;
		if (m_DataLen < 5)
			maxLen = m_DataLen;
		else
			maxLen = 5;

		// Find <SP> if exists
		uint8_t *pos = (uint8_t *)memchr(m_Data, ASCII_SPACE, maxLen);
		if (pos)
			return pos - m_Data;

		// Find Hyphen "-" if exists
		pos = (uint8_t *)memchr(m_Data, ASCII_HYPHEN, maxLen);
		if (pos)
			return pos - m_Data;

		return m_DataLen;
	}

	void LineBasedProtocolMessage::setDelimiter(bool hyphen)
	{
		if (hyphen)
			memset(&m_Data[getOptionOffset()], ASCII_HYPHEN, 1);
		else
			memset(&m_Data[getOptionOffset()], ASCII_SPACE, 1);
	}

	bool LineBasedProtocolMessage::hyphenRequired(std::string value)
	{
		size_t firstPos = value.find_first_of("\r\n");
		size_t lastPos = value.find_last_of("\r\n");

		if ((firstPos != std::string::npos) && (lastPos != std::string::npos))
		{
			if (firstPos == lastPos - 1)
				return false;
			return true;
		}

		PCPP_LOG_ERROR("There should be at least one delimiter");
		return false;
	}

	void LineBasedProtocolMessage::setCommandField(std::string value)
	{
		size_t currentOffset = getOptionOffset();
		if (!currentOffset)
			value += " \r\n";

		if (value.size() < currentOffset)
			shortenLayer(0, currentOffset - value.size());
		else if (m_Data && value.size() > currentOffset)
			extendLayer(0, value.size() - currentOffset);
		else if (!m_Data)
		{
			m_Data = new uint8_t[value.size()];
			m_DataLen = value.size();
		}

		memcpy(m_Data, value.c_str(), value.size());
	}

	void LineBasedProtocolMessage::setOptionField(std::string value)
	{
		size_t lastPos = value.find_last_of("\r\n");
		if (lastPos == std::string::npos || lastPos != value.size() - 2)
			value += "\r\n";

		size_t currentOffset = getOptionOffset() + 1;

		if (value.size() < (m_DataLen - currentOffset))
			shortenLayer(currentOffset, (m_DataLen - currentOffset) - value.size());
		else if (m_Data && value.size() > (m_DataLen - currentOffset))
			extendLayer(currentOffset, value.size() - (m_DataLen - currentOffset));
		else if (!m_Data)
		{
			m_Data = new uint8_t[value.size()];
			m_DataLen = value.size();
		}

		memcpy(&m_Data[currentOffset], value.c_str(), value.size());

		if (hyphenRequired(value))
			setDelimiter(true);
		else
			setDelimiter(false);
	}

	std::string LineBasedProtocolMessage::getCommandField() const
	{
		size_t offset = getOptionOffset();

		// If there is no option remove trailing newline characters
		if (offset == m_DataLen && offset > 1)
			return std::string((char *)m_Data, offset - 2);
		return std::string((char *)m_Data, offset);
	}

	std::string LineBasedProtocolMessage::getOptionField() const
	{
		if (getOptionOffset() != m_DataLen)
			return std::string((char *)&m_Data[getOptionOffset() + 1], m_DataLen - getOptionOffset() - 3);
		return "";
	}

	bool LineBasedProtocolMessage::isMultiLine() const
	{
		if (m_Data[getOptionOffset()] == ASCII_HYPHEN)
			return true;
		return false;
	}

	bool LineBasedProtocolMessage::isDataValid(const uint8_t *data, size_t dataSize)
	{
		std::string payload = std::string((char *)data, dataSize);
		if (payload.find_last_of("\r\n") == dataSize - 1)
			return true;
		return false;
	}

} // namespace pcpp
