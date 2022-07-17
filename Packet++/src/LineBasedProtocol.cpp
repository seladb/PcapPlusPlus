#include "LineBasedProtocol.h"
#include "Logger.h"

#include <string.h>

#define ASCII_HYPHEN 0x2d
#define ASCII_SPACE 0x20

namespace pcpp
{

	size_t LineBasedProtocolMessage::getArgumentFieldOffset() const
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

	void LineBasedProtocolMessage::setDelimiter(bool hyphen)
	{
		if (hyphen)
			memset(&m_Data[getArgumentFieldOffset()], ASCII_HYPHEN, 1);
		else
			memset(&m_Data[getArgumentFieldOffset()], ASCII_SPACE, 1);
	}

	bool LineBasedProtocolMessage::hyphenRequired(std::string value)
	{
		size_t firstPos = value.find_first_of("\r\n");
		size_t lastPos = value.find_last_of("\r\n");

		return (firstPos != std::string::npos) && (lastPos != std::string::npos) && (firstPos != lastPos - 1);
	}

	void LineBasedProtocolMessage::setCommandInternal(std::string value)
	{
		size_t currentOffset = getArgumentFieldOffset();
		if (currentOffset == SIZE_MAX)
			currentOffset = 0;
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

	void LineBasedProtocolMessage::setCommandOptionInternal(std::string value)
	{
		size_t lastPos = value.find_last_of("\r\n");
		if (lastPos == std::string::npos || lastPos != value.size() - 2)
			value += "\r\n";

		size_t currentOffset = getArgumentFieldOffset() + 1;

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

	std::string LineBasedProtocolMessage::getCommandInternal() const
	{
		size_t offset = getArgumentFieldOffset();

		// If there is no option remove trailing newline characters
		if (offset == (m_DataLen - 1) && offset > 1)
			return std::string((char *)m_Data, offset - 1);
		return std::string((char *)m_Data, offset);
	}

	std::string LineBasedProtocolMessage::getCommandOptionInternal() const
	{
		if (getArgumentFieldOffset() != (m_DataLen - 1))
			return std::string((char *)&m_Data[getArgumentFieldOffset() + 1], m_DataLen - getArgumentFieldOffset() - 2);
		return "";
	}

	bool LineBasedProtocolMessage::isMultiLine() const
	{
		return m_Data[getArgumentFieldOffset()] == ASCII_HYPHEN;
	}

	bool LineBasedProtocolMessage::isDataValid(const uint8_t *data, size_t dataSize)
	{
		if (data == nullptr || dataSize < 6)
			return false;

		std::string payload = std::string((char *)data, dataSize);
		if (payload.find_last_of("\r\n") == dataSize - 1)
			return true;
		return false;
	}

} // namespace pcpp
