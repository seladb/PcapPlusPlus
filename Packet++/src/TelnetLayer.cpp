#define LOG_MODULE PacketLogModuleTelnetLayer

#include "TelnetLayer.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include <cstring>

namespace pcpp
{

	bool TelnetLayer::isDataField(uint8_t* pos) const
	{
		// "FF FF" means data
		return pos[0] != static_cast<int>(TelnetCommand::InterpretAsCommand) ||
		       pos[1] == static_cast<int>(TelnetCommand::InterpretAsCommand);
	}

	bool TelnetLayer::isCommandField(uint8_t* pos) const
	{
		return !isDataField(pos);
	}

	size_t TelnetLayer::distanceToNextIAC(uint8_t* startPos, size_t maxLength)
	{
		uint8_t* pos = nullptr;
		size_t addition = 0;
		size_t currentOffset = 0;
		do
		{
			// If it is second turn position should be adjusted to after second FF
			if (addition)
				addition += 2;

			pos = (uint8_t*)memchr(startPos + currentOffset + 1, static_cast<int>(TelnetCommand::InterpretAsCommand),
			                       maxLength - currentOffset);
			if (pos)
				addition += pos - (startPos + currentOffset);
			else
				addition += maxLength - currentOffset;
			currentOffset = currentOffset + addition;
			// "FF FF" means data continue
		} while (pos && ((pos + 1) < (startPos + maxLength)) &&
		         (pos[1] == static_cast<int>(TelnetCommand::InterpretAsCommand)) && (currentOffset < maxLength));

		return addition;
	}

	size_t TelnetLayer::getFieldLen(uint8_t* startPos, size_t maxLength)
	{
		// Check first byte is IAC
		if (startPos && (startPos[0] == static_cast<int>(TelnetCommand::InterpretAsCommand)) && (maxLength >= 2))
		{
			// If subnegotiation parse until next IAC
			if (startPos[1] == static_cast<int>(TelnetCommand::Subnegotiation))
				return distanceToNextIAC(startPos, maxLength);
			// Only WILL, WONT, DO, DONT have option. Ref http://pcmicro.com/netfoss/telnet.html
			else if (startPos[1] >= static_cast<int>(TelnetCommand::WillPerform) &&
			         startPos[1] <= static_cast<int>(TelnetCommand::DontPerform))
				return 3;
			return 2;
		}
		return distanceToNextIAC(startPos, maxLength);
	}

	uint8_t* TelnetLayer::getNextDataField(uint8_t* pos, size_t len)
	{
		size_t offset = 0;
		while (offset < len)
		{
			// Move to next field
			size_t length = getFieldLen(pos, len - offset);
			pos += length;
			offset += length;

			if (isDataField(pos))
				return pos;
		}

		return nullptr;
	}

	uint8_t* TelnetLayer::getNextCommandField(uint8_t* pos, size_t len)
	{
		size_t offset = 0;
		while (offset < len)
		{
			// Move to next field
			size_t length = getFieldLen(pos, len - offset);
			pos += length;
			offset += length;

			if ((static_cast<size_t>(pos - m_Data) <= (m_DataLen - 2)) &&
			    isCommandField(pos))  // Need at least 2 bytes for command
				return pos;
		}

		return nullptr;
	}

	int16_t TelnetLayer::getSubCommand(uint8_t* pos, size_t len)
	{
		if (len < 3 || pos[1] < static_cast<int>(TelnetCommand::Subnegotiation))
			return static_cast<int>(TelnetOption::TelnetOptionNoOption);
		return pos[2];
	}

	uint8_t* TelnetLayer::getCommandData(uint8_t* pos, size_t& len)
	{
		if (pos[1] == static_cast<int>(TelnetCommand::Subnegotiation) && len > 3)
		{
			len -= 3;
			return &pos[3];
		}
		len = 0;
		return nullptr;
	}

	std::string TelnetLayer::getDataAsString(bool removeEscapeCharacters)
	{
		uint8_t* dataPos = nullptr;
		if (isDataField(m_Data))
			dataPos = m_Data;
		else
			dataPos = getNextDataField(m_Data, m_DataLen);

		if (!dataPos)
		{
			PCPP_LOG_DEBUG("Packet does not have a data field");
			return std::string();
		}

		// Convert to string
		if (removeEscapeCharacters)
		{
			std::stringstream ss;
			for (size_t idx = 0; idx < m_DataLen - (dataPos - m_Data) + 1; ++idx)
			{
				if (int(dataPos[idx]) < 127 && int(dataPos[idx]) > 31)  // From SPACE to ~
					ss << dataPos[idx];
			}
			return ss.str();
		}
		return std::string((char*)m_Data, m_DataLen);
	}

	size_t TelnetLayer::getTotalNumberOfCommands()
	{
		size_t ctr = 0;
		if (isCommandField(m_Data))
			++ctr;

		uint8_t* pos = m_Data;
		while (pos != nullptr)
		{
			size_t offset = pos - m_Data;
			pos = getNextCommandField(pos, m_DataLen - offset);
			if (pos)
				++ctr;
		}

		return ctr;
	}

	size_t TelnetLayer::getNumberOfCommands(TelnetCommand command)
	{
		if (static_cast<int>(command) < 0)
			return 0;

		size_t ctr = 0;
		if (isCommandField(m_Data) && m_Data[1] == static_cast<int>(command))
			++ctr;

		uint8_t* pos = m_Data;
		while (pos != nullptr)
		{
			size_t offset = pos - m_Data;
			pos = getNextCommandField(pos, m_DataLen - offset);
			if (pos && pos[1] == static_cast<int>(command))
				++ctr;
		}

		return ctr;
	}

	TelnetLayer::TelnetCommand TelnetLayer::getFirstCommand()
	{
		// If starts with command
		if (isCommandField(m_Data))
			return static_cast<TelnetCommand>(m_Data[1]);

		// Check is there any command
		uint8_t* pos = getNextCommandField(m_Data, m_DataLen);
		if (pos)
			return static_cast<TelnetCommand>(pos[1]);
		return TelnetCommand::TelnetCommandEndOfPacket;
	}

	TelnetLayer::TelnetCommand TelnetLayer::getNextCommand()
	{
		if (lastPositionOffset == SIZE_MAX)
		{
			lastPositionOffset = 0;
			if (isCommandField(m_Data))
				return static_cast<TelnetLayer::TelnetCommand>(m_Data[1]);
		}

		uint8_t* pos = getNextCommandField(&m_Data[lastPositionOffset], m_DataLen - lastPositionOffset);
		if (pos)
		{
			lastPositionOffset = pos - m_Data;
			return static_cast<TelnetLayer::TelnetCommand>(pos[1]);
		}
		lastPositionOffset = SIZE_MAX;
		return TelnetCommand::TelnetCommandEndOfPacket;
	}

	TelnetLayer::TelnetOption TelnetLayer::getOption()
	{
		if (lastPositionOffset < m_DataLen)
			return static_cast<TelnetOption>(getSubCommand(
			    &m_Data[lastPositionOffset], getFieldLen(&m_Data[lastPositionOffset], m_DataLen - lastPositionOffset)));
		return TelnetOption::TelnetOptionNoOption;
	}

	TelnetLayer::TelnetOption TelnetLayer::getOption(TelnetCommand command)
	{
		// Check input
		if (static_cast<int>(command) < 0)
		{
			PCPP_LOG_ERROR("Command type can't be negative");
			return TelnetOption::TelnetOptionNoOption;
		}

		if (isCommandField(m_Data) && m_Data[1] == static_cast<int>(command))
			return static_cast<TelnetOption>(getSubCommand(m_Data, getFieldLen(m_Data, m_DataLen)));

		uint8_t* pos = m_Data;
		while (pos != nullptr)
		{
			size_t offset = pos - m_Data;
			pos = getNextCommandField(pos, m_DataLen - offset);

			if (pos && pos[1] == static_cast<int>(command))
				return static_cast<TelnetOption>(getSubCommand(pos, getFieldLen(pos, m_DataLen - offset)));
		}

		PCPP_LOG_DEBUG("Can't find requested command");
		return TelnetOption::TelnetOptionNoOption;
	}

	uint8_t* TelnetLayer::getOptionData(size_t& length)
	{
		if (lastPositionOffset < m_DataLen)
		{
			size_t lenBuffer = getFieldLen(&m_Data[lastPositionOffset], m_DataLen - lastPositionOffset);
			uint8_t* posBuffer = getCommandData(&m_Data[lastPositionOffset], lenBuffer);

			length = lenBuffer;
			return posBuffer;
		}
		return nullptr;
	}

	uint8_t* TelnetLayer::getOptionData(TelnetCommand command, size_t& length)
	{
		// Check input
		if (static_cast<int>(command) < 0)
		{
			PCPP_LOG_ERROR("Command type can't be negative");
			length = 0;
			return nullptr;
		}

		if (isCommandField(m_Data) && m_Data[1] == static_cast<int>(command))
		{
			size_t lenBuffer = getFieldLen(m_Data, m_DataLen);
			uint8_t* posBuffer = getCommandData(m_Data, lenBuffer);

			length = lenBuffer;
			return posBuffer;
		}

		uint8_t* pos = m_Data;
		while (pos != nullptr)
		{
			size_t offset = pos - m_Data;
			pos = getNextCommandField(pos, m_DataLen - offset);

			if (pos && pos[1] == static_cast<int>(command))
			{
				size_t lenBuffer = getFieldLen(m_Data, m_DataLen);
				uint8_t* posBuffer = getCommandData(m_Data, lenBuffer);

				length = lenBuffer;
				return posBuffer;
			}
		}

		PCPP_LOG_DEBUG("Can't find requested command");
		length = 0;
		return nullptr;
	}

	std::string TelnetLayer::getTelnetCommandAsString(TelnetCommand val)
	{
		switch (val)
		{
		case TelnetCommand::TelnetCommandEndOfPacket:
			return "Reached end of packet while parsing";
		case TelnetCommand::EndOfFile:
			return "End of File";
		case TelnetCommand::Suspend:
			return "Suspend current process";
		case TelnetCommand::Abort:
			return "Abort Process";
		case TelnetCommand::EndOfRecordCommand:
			return "End of Record";
		case TelnetCommand::SubnegotiationEnd:
			return "Subnegotiation End";
		case TelnetCommand::NoOperation:
			return "No Operation";
		case TelnetCommand::DataMark:
			return "Data Mark";
		case TelnetCommand::Break:
			return "Break";
		case TelnetCommand::InterruptProcess:
			return "Interrupt Process";
		case TelnetCommand::AbortOutput:
			return "Abort Output";
		case TelnetCommand::AreYouThere:
			return "Are You There";
		case TelnetCommand::EraseCharacter:
			return "Erase Character";
		case TelnetCommand::EraseLine:
			return "Erase Line";
		case TelnetCommand::GoAhead:
			return "Go Ahead";
		case TelnetCommand::Subnegotiation:
			return "Subnegotiation";
		case TelnetCommand::WillPerform:
			return "Will Perform";
		case TelnetCommand::WontPerform:
			return "Wont Perform";
		case TelnetCommand::DoPerform:
			return "Do Perform";
		case TelnetCommand::DontPerform:
			return "Dont Perform";
		case TelnetCommand::InterpretAsCommand:
			return "Interpret As Command";
		default:
			return "Unknown Command";
		}
	}

	std::string TelnetLayer::getTelnetOptionAsString(TelnetOption val)
	{
		switch (val)
		{
		case TelnetOption::TelnetOptionNoOption:
			return "No option for this command";
		case TelnetOption::TransmitBinary:
			return "Binary Transmission";
		case TelnetOption::Echo:
			return "Echo";
		case TelnetOption::Reconnection:
			return "Reconnection";
		case TelnetOption::SuppressGoAhead:
			return "Suppress Go Ahead";
		case TelnetOption::ApproxMsgSizeNegotiation:
			return "Negotiate approximate message size";
		case TelnetOption::Status:
			return "Status";
		case TelnetOption::TimingMark:
			return "Timing Mark";
		case TelnetOption::RemoteControlledTransAndEcho:
			return "Remote Controlled Transmission and Echo";
		case TelnetOption::OutputLineWidth:
			return "Output Line Width";
		case TelnetOption::OutputPageSize:
			return "Output Page Size";
		case TelnetOption::OutputCarriageReturnDisposition:
			return "Negotiate About Output Carriage-Return Disposition";
		case TelnetOption::OutputHorizontalTabStops:
			return "Negotiate About Output Horizontal Tabstops";
		case TelnetOption::OutputHorizontalTabDisposition:
			return "Negotiate About Output Horizontal Tab Disposition";
		case TelnetOption::OutputFormfeedDisposition:
			return "Negotiate About Output Formfeed Disposition";
		case TelnetOption::OutputVerticalTabStops:
			return "Negotiate About Vertical Tabstops";
		case TelnetOption::OutputVerticalTabDisposition:
			return "Negotiate About Output Vertcial Tab Disposition";
		case TelnetOption::OutputLinefeedDisposition:
			return "Negotiate About Output Linefeed Disposition";
		case TelnetOption::ExtendedASCII:
			return "Extended ASCII";
		case TelnetOption::Logout:
			return "Logout";
		case TelnetOption::ByteMacro:
			return "Byte Macro";
		case TelnetOption::DataEntryTerminal:
			return "Data Entry Terminal";
		case TelnetOption::SUPDUP:
			return "SUPDUP";
		case TelnetOption::SUPDUPOutput:
			return "SUPDUP Output";
		case TelnetOption::SendLocation:
			return "Send Location";
		case TelnetOption::TerminalType:
			return "Terminal Type";
		case TelnetOption::EndOfRecordOption:
			return "End Of Record";
		case TelnetOption::TACACSUserIdentification:
			return "TACACS User Identification";
		case TelnetOption::OutputMarking:
			return "Output Marking";
		case TelnetOption::TerminalLocationNumber:
			return "Terminal Location Number";
		case TelnetOption::Telnet3270Regime:
			return "Telnet 3270 Regime";
		case TelnetOption::X3Pad:
			return "X3 Pad";
		case TelnetOption::NegotiateAboutWindowSize:
			return "Negotiate About Window Size";
		case TelnetOption::TerminalSpeed:
			return "Terminal Speed";
		case TelnetOption::RemoteFlowControl:
			return "Remote Flow Control";
		case TelnetOption::Linemode:
			return "Line mode";
		case TelnetOption::XDisplayLocation:
			return "X Display Location";
		case TelnetOption::EnvironmentOption:
			return "Environment Option";
		case TelnetOption::AuthenticationOption:
			return "Authentication Option";
		case TelnetOption::EncryptionOption:
			return "Encryption Option";
		case TelnetOption::NewEnvironmentOption:
			return "New Environment Option";
		case TelnetOption::TN3270E:
			return "TN3270E";
		case TelnetOption::XAuth:
			return "X Server Authentication";
		case TelnetOption::Charset:
			return "Charset";
		case TelnetOption::TelnetRemoteSerialPort:
			return "Telnet Remote Serial Port";
		case TelnetOption::ComPortControlOption:
			return "Com Port Control Option";
		case TelnetOption::TelnetSuppressLocalEcho:
			return "Telnet Suppress Local Echo";
		case TelnetOption::TelnetStartTLS:
			return "Telnet Start TLS";
		case TelnetOption::Kermit:
			return "Kermit";
		case TelnetOption::SendURL:
			return "Send URL";
		case TelnetOption::ForwardX:
			return "Forward X Server";
		case TelnetOption::TelOptPragmaLogon:
			return "Telnet Option Pragma Logon";
		case TelnetOption::TelOptSSPILogon:
			return "Telnet Option SSPI Logon";
		case TelnetOption::TelOptPragmaHeartbeat:
			return "Telnet Option Pragma Heartbeat";
		case TelnetOption::ExtendedOptions:
			return "Extended option list";
		default:
			return "Unknown Option";
		}
	}

	std::string TelnetLayer::toString() const
	{
		if (isDataField(m_Data))
			return "Telnet Data";
		return "Telnet Control";
	}

}  // namespace pcpp
