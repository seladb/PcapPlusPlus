#include "SingleCommandTextProtocol.h"
#include <cstring>
#include <algorithm>
#include <vector>

enum
{
	ASCII_HYPHEN = 0x2d,
	ASCII_SPACE = 0x20,
	MAX_COMMAND_LENGTH = 9,  // From SMTP command "STARTTLS" + 1 byte hyphen or space
	MIN_PACKET_LENGTH = 2    // CRLF
};

namespace pcpp
{

	size_t SingleCommandTextProtocol::getArgumentFieldOffset() const
	{
		size_t maxLen = 0;
		if (m_DataLen < MAX_COMMAND_LENGTH)
		{
			maxLen = m_DataLen;
		}
		else
		{
			maxLen = MAX_COMMAND_LENGTH;
		}

		// To correctly detect multi-line packets with the option containing a space in
		// the first MAX_CONTENT_LENGTH bytes, search the both of hyphen and space to take
		// correct command delimiter

		std::string const field(reinterpret_cast<char*>(m_Data), maxLen);

		size_t const posHyphen = field.find_first_of(ASCII_HYPHEN);
		size_t const posSpace = field.find_first_of(ASCII_SPACE);
		size_t const posCRLF = field.rfind("\r\n");

		// No delimiter or packet end
		if (posHyphen == std::string::npos && posSpace == std::string::npos && posCRLF == std::string::npos)
		{
			return 0;
			// Both hyphen and space found
		}
		if (posHyphen != std::string::npos || posSpace != std::string::npos)
		{
			return std::min(posSpace, posHyphen);
			// If nothing found but there is a CRLF it is a only command packet
		}
		if (posCRLF != std::string::npos)
		{
			return posCRLF;
		}

		return 0;
	}

	void SingleCommandTextProtocol::setDelimiter(bool hyphen)
	{
		if (hyphen)
		{
			memset(&m_Data[getArgumentFieldOffset()], ASCII_HYPHEN, 1);
		}
		else
		{
			memset(&m_Data[getArgumentFieldOffset()], ASCII_SPACE, 1);
		}
	}

	bool SingleCommandTextProtocol::hyphenRequired(const std::string& value)
	{
		size_t const firstPos = value.find("\r\n");
		size_t const lastPos = value.rfind("\r\n");
		return (firstPos != std::string::npos) && (lastPos != std::string::npos) && (firstPos != lastPos);
	}

	SingleCommandTextProtocol::SingleCommandTextProtocol(const std::string& command, const std::string& option,
	                                                     ProtocolType protocol)
	{
		m_Protocol = protocol;
		m_Data = new uint8_t[MIN_PACKET_LENGTH];
		m_DataLen = MIN_PACKET_LENGTH;
		if (!command.empty())
		{
			setCommandInternal(command);
		}
		if (!option.empty())
		{
			setCommandOptionInternal(option);
		}
	}

	bool SingleCommandTextProtocol::setCommandInternal(std::string value)
	{
		size_t currentOffset = getArgumentFieldOffset();
		if (currentOffset == m_DataLen - 1)
		{
			currentOffset = 0;
		}
		if (currentOffset == 0U)
		{
			value += " \r\n";
		}

		if (value.size() < currentOffset)
		{
			if (!shortenLayer(0, currentOffset - value.size()))
			{
				return false;
			}
		}
		else if ((m_Data != nullptr) && value.size() > currentOffset)
		{
			if (!extendLayer(0, value.size() - currentOffset))
			{
				return false;
			}
		}

		memcpy(m_Data, value.c_str(), value.size());
		return true;
	}

	bool SingleCommandTextProtocol::setCommandOptionInternal(std::string value)
	{
		size_t const lastPos = value.rfind("\r\n");
		if (lastPos == std::string::npos || lastPos != value.size() - 2)
		{
			value += "\r\n";
		}

		size_t const currentOffset = getArgumentFieldOffset() + 1;

		if (value.size() < (m_DataLen - currentOffset))
		{
			if (!shortenLayer(currentOffset, (m_DataLen - currentOffset) - value.size()))
			{
				return false;
			}
		}
		else if ((m_Data != nullptr) && value.size() > (m_DataLen - currentOffset))
		{
			if (!extendLayer(currentOffset, value.size() - (m_DataLen - currentOffset)))
			{
				return false;
			}
		}

		memcpy(&m_Data[currentOffset], value.c_str(), value.size());

		if (hyphenRequired(value))
		{
			setDelimiter(true);
		}
		else
		{
			setDelimiter(false);
		}
		return true;
	}

	std::string SingleCommandTextProtocol::getCommandInternal() const
	{
		size_t const offset = getArgumentFieldOffset();

		// If there is no option remove trailing newline characters
		if (offset == (m_DataLen - 1) && offset > 1)
		{
			return std::string((char*)m_Data, offset - 1);
		}
		return std::string((char*)m_Data, offset);
	}

	std::string SingleCommandTextProtocol::getCommandOptionInternal() const
	{
		size_t const offset = getArgumentFieldOffset();

		// We don't want to get delimiter so add 1 for start unless there is no command,
		// and we don't want to trailing newline characters so remove 2 and remove addition from start point
		int const addition = offset != 0U ? 1 : 0;
		if (offset != (m_DataLen - 1))
		{
			auto option = std::string((char*)&m_Data[offset + addition], m_DataLen - (offset + 2 + addition));

			// Remove XXX- and XXX<SP> since they are delimiters of the protocol where XXX is the usually status code
			// Check RFC821 (SMTP) Section 3.3 and RFC959 (FTP) Section 4.2
			auto code = getCommandInternal();
			auto vDelim = std::vector<std::string>{ code + " ", code + "-" };

			for (const auto& delim : vDelim)
			{
				size_t pos = 0;
				while ((pos = option.find(delim, pos)) != std::string::npos)
				{
					option.replace(pos, delim.length(), "");
				}
			}
			return option;
		}
		return "";
	}

	bool SingleCommandTextProtocol::isMultiLine() const
	{
		return m_Data[getArgumentFieldOffset()] == ASCII_HYPHEN;
	}

	bool SingleCommandTextProtocol::isDataValid(const uint8_t* data, size_t dataSize)
	{
		if (data == nullptr || dataSize < MIN_PACKET_LENGTH)
		{
			return false;
		}

		std::string const payload = std::string((char*)data, dataSize);
		return payload.rfind("\r\n") == dataSize - 2;
	}

}  // namespace pcpp
