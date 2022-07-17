#include "SingleCommandTextProtocol.h"
#include "Logger.h"

#include <string.h>

#define ASCII_HYPHEN 0x2d
#define ASCII_SPACE 0x20

namespace pcpp
{

	size_t SingleCommandTextProtocol::getArgumentFieldOffset() const
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

		return m_DataLen - 1;
	}

	void SingleCommandTextProtocol::setDelimiter(bool hyphen)
	{
		if (hyphen)
			memset(&m_Data[getArgumentFieldOffset()], ASCII_HYPHEN, 1);
		else
			memset(&m_Data[getArgumentFieldOffset()], ASCII_SPACE, 1);
	}

	bool SingleCommandTextProtocol::hyphenRequired(std::string value)
	{
		size_t firstPos = value.find_first_of("\r\n");
		size_t lastPos = value.find_last_of("\r\n");
		return (firstPos != std::string::npos) && (lastPos != std::string::npos) && (firstPos != lastPos - 1);
	}

	SingleCommandTextProtocol::SingleCommandTextProtocol(std::string &command, std::string &option)
	{
		m_Data = new uint8_t[6];
		m_DataLen = 6;
		if (!command.empty())
			setCommandInternal(command);
		if (!option.empty())
			setCommandOptionInternal(option);
	}

	bool SingleCommandTextProtocol::setCommandInternal(std::string value)
	{
		size_t currentOffset = getArgumentFieldOffset();
		if (currentOffset == m_DataLen - 1)
			currentOffset = 0;
		if (!currentOffset)
			value += " \r\n";

		if (value.size() < currentOffset)
		{
			if (!shortenLayer(0, currentOffset - value.size()))
				return false;
		}
		else if (m_Data && value.size() > currentOffset)
		{
			if (!extendLayer(0, value.size() - currentOffset))
				return false;
		}

		memcpy(m_Data, value.c_str(), value.size());
		return true;
	}

	bool SingleCommandTextProtocol::setCommandOptionInternal(std::string value)
	{
		size_t lastPos = value.find_last_of("\r\n");
		if (lastPos == std::string::npos || lastPos != value.size() - 2)
			value += "\r\n";

		size_t currentOffset = getArgumentFieldOffset() + 1;

		if (value.size() < (m_DataLen - currentOffset))
		{
			if (!shortenLayer(currentOffset, (m_DataLen - currentOffset) - value.size()))
				return false;
		}
		else if (m_Data && value.size() > (m_DataLen - currentOffset))
		{
			if (!extendLayer(currentOffset, value.size() - (m_DataLen - currentOffset)))
				return false;
		}

		memcpy(&m_Data[currentOffset], value.c_str(), value.size());

		if (hyphenRequired(value))
			setDelimiter(true);
		else
			setDelimiter(false);
		return true;
	}

	std::string SingleCommandTextProtocol::getCommandInternal() const
	{
		size_t offset = getArgumentFieldOffset();

		// If there is no option remove trailing newline characters
		if (offset == (m_DataLen - 1) && offset > 1)
			return std::string((char *)m_Data, offset - 1);
		return std::string((char *)m_Data, offset);
	}

	std::string SingleCommandTextProtocol::getCommandOptionInternal() const
	{
		if (getArgumentFieldOffset() != (m_DataLen - 1))
			return std::string((char *)&m_Data[getArgumentFieldOffset() + 1], m_DataLen - getArgumentFieldOffset() - 2);
		return "";
	}

	bool SingleCommandTextProtocol::isMultiLine() const
	{
		return m_Data[getArgumentFieldOffset()] == ASCII_HYPHEN;
	}

	bool SingleCommandTextProtocol::isDataValid(const uint8_t *data, size_t dataSize)
	{
		if (data == nullptr || dataSize < 6)
			return false;

		std::string payload = std::string((char *)data, dataSize);
		return payload.find_last_of("\r\n") == dataSize - 1;
	}

} // namespace pcpp
