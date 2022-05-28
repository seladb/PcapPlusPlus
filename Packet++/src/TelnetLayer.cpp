#define LOG_MODULE PacketLogModuleTelnetLayer

#include "TelnetLayer.h"
#include "Logger.h"

#include "GeneralUtils.h"
#include "SystemUtils.h"

#include <string.h>

namespace pcpp
{

bool TelnetLayer::isDataField(uint8_t *pos)
{
	// "FF FF" means data
	return pos[0] != InterpretAsCommand || (pos[0] == InterpretAsCommand && pos[1] == InterpretAsCommand);
}

bool TelnetLayer::isCommandField(uint8_t *pos)
{
	return pos[0] == InterpretAsCommand && pos[1] != InterpretAsCommand;
}

size_t TelnetLayer::distanceToNextIAC(uint8_t *startPos, size_t maxLength)
{
	uint8_t *pos = NULL;
	size_t addition = 0;
	size_t currentOffset = 0;
	do
	{
		// If it is second turn position should be adjusted to after second FF
		if (addition)
			addition += 2;

		pos = (uint8_t *)memchr(startPos + currentOffset + 1, InterpretAsCommand, maxLength - currentOffset);
		if (pos)
			addition += pos - (startPos + currentOffset);
		else
			addition += maxLength - currentOffset;
		currentOffset = currentOffset + addition;
		// "FF FF" means data continue
	} while (pos && (pos[1] == InterpretAsCommand) && (currentOffset < maxLength));

	return addition;
}

size_t TelnetLayer::getFieldLen(uint8_t *startPos, size_t maxLength)
{
	// Check first byte is IAC
	if (startPos && (startPos[0] == InterpretAsCommand) && (maxLength >= 2))
	{
		// If subnegotiation parse until next IAC
		if (startPos[1] == Subnegotiation)
			return distanceToNextIAC(startPos, maxLength);
		// Only WILL, WONT, DO, DONT have option. Ref http://pcmicro.com/netfoss/telnet.html
		else if (startPos[1] >= WillPerform && startPos[1] <= DontPerform)
			return 3;
		return 2;
	}
	return distanceToNextIAC(startPos, maxLength);
}

uint8_t *TelnetLayer::getNextDataField(uint8_t *pos, size_t len)
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

	return NULL;
}

uint8_t *TelnetLayer::getNextCommandField(uint8_t *pos, size_t len)
{
	size_t offset = 0;
	while (offset < len)
	{
		// Move to next field
		size_t length = getFieldLen(pos, len - offset);
		pos += length;
		offset += length;

		if (isCommandField(pos))
			return pos;
	}

	return NULL;
}

int16_t TelnetLayer::getSubCommand(uint8_t *pos, size_t len)
{
	if (len < 3 || pos[1] < Subnegotiation)
		return TelnetOptionNoOption;
	return pos[2];
}

uint8_t *TelnetLayer::getCommandData(uint8_t *pos, size_t &len)
{
	if (pos[1] == Subnegotiation && len > 3)
	{
		len -= 3;
		return &pos[3];
	}
	len = 0;
	return NULL;
}

std::string TelnetLayer::getDataAsString(bool removeEscapeCharacters)
{
	uint8_t *dataPos = NULL;
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
			if (int(dataPos[idx]) < 127 && int(dataPos[idx]) > 31) // From SPACE to ~
				ss << dataPos[idx];
		}
		return ss.str();
	}
	return std::string((char *)m_Data, m_DataLen);
}

size_t TelnetLayer::getTotalNumberOfCommands()
{
	size_t ctr = 0;
	if (isCommandField(m_Data))
		++ctr;

	size_t offset = 0;
	uint8_t *pos = m_Data;
	while (pos != NULL)
	{
		offset = pos - m_Data;
		pos = getNextCommandField(pos, m_DataLen - offset);
		if (pos)
			++ctr;
	}

	return ctr;
}

size_t TelnetLayer::getNumberOfCommands(TelnetCommand command)
{
	if (command < 0)
		return 0;

	size_t ctr = 0;
	if (isCommandField(m_Data) && m_Data[1] == command)
		++ctr;

	size_t offset = 0;
	uint8_t *pos = m_Data;
	while (pos != NULL)
	{
		offset = pos - m_Data;
		pos = getNextCommandField(pos, m_DataLen - offset);
		if (pos && pos[1] == command)
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
	uint8_t *pos = getNextCommandField(m_Data, m_DataLen);
	if (pos)
		return static_cast<TelnetCommand>(pos[1]);
	return TelnetCommandEndOfPacket;
}

TelnetLayer::TelnetCommand TelnetLayer::getNextCommand()
{
	if (lastPositionOffset == SIZE_MAX)
	{
		lastPositionOffset = 0;
		if (isCommandField(m_Data))
			return static_cast<TelnetLayer::TelnetCommand>(m_Data[1]);
	}

	uint8_t *pos = getNextCommandField(&m_Data[lastPositionOffset], m_DataLen - lastPositionOffset);
	if (pos)
	{
		lastPositionOffset = pos - m_Data;
		return static_cast<TelnetLayer::TelnetCommand>(pos[1]);
	}
	lastPositionOffset = SIZE_MAX;
	return TelnetCommandEndOfPacket;
}

TelnetLayer::TelnetOption TelnetLayer::getOption()
{
	if (lastPositionOffset < m_DataLen)
		return static_cast<TelnetOption>(getSubCommand(
			&m_Data[lastPositionOffset], getFieldLen(&m_Data[lastPositionOffset], m_DataLen - lastPositionOffset)));
	return TelnetOptionNoOption;
}

TelnetLayer::TelnetOption TelnetLayer::getOption(TelnetCommand command)
{
	// Check input
	if (command < 0)
	{
		PCPP_LOG_ERROR("Command type can't be negative");
		return TelnetOptionNoOption;
	}

	if (isCommandField(m_Data) && m_Data[1] == command)
		return static_cast<TelnetOption>(getSubCommand(m_Data, getFieldLen(m_Data, m_DataLen)));

	uint8_t *pos = m_Data;
	size_t offset = 0;
	while (pos != NULL)
	{
		offset = pos - m_Data;
		pos = getNextCommandField(pos, m_DataLen - offset);

		if (pos && pos[1] == command)
			return static_cast<TelnetOption>(getSubCommand(pos, getFieldLen(pos, m_DataLen - offset)));
	}

	PCPP_LOG_DEBUG("Can't find requested command");
	return TelnetOptionNoOption;
}

uint8_t *TelnetLayer::getOptionData(size_t &length)
{
	if (lastPositionOffset < m_DataLen)
	{
		size_t lenBuffer = getFieldLen(&m_Data[lastPositionOffset], m_DataLen - lastPositionOffset);
		uint8_t *posBuffer = getCommandData(&m_Data[lastPositionOffset], lenBuffer);

		length = lenBuffer;
		return posBuffer;
	}
	return NULL;
}

uint8_t *TelnetLayer::getOptionData(TelnetCommand command, size_t &length)
{
	// Check input
	if (command < 0)
	{
		PCPP_LOG_ERROR("Command type can't be negative");
		length = 0;
		return NULL;
	}

	if (isCommandField(m_Data) && m_Data[1] == command)
	{
		size_t lenBuffer = getFieldLen(m_Data, m_DataLen);
		uint8_t *posBuffer = getCommandData(m_Data, lenBuffer);

		length = lenBuffer;
		return posBuffer;
	}

	uint8_t *pos = m_Data;
	size_t offset = 0;
	while (pos != NULL)
	{
		offset = pos - m_Data;
		pos = getNextCommandField(pos, m_DataLen - offset);

		if (pos && pos[1] == command)
		{
			size_t lenBuffer = getFieldLen(m_Data, m_DataLen);
			uint8_t *posBuffer = getCommandData(m_Data, lenBuffer);

			length = lenBuffer;
			return posBuffer;
		}
	}

	PCPP_LOG_DEBUG("Can't find requested command");
	length = 0;
	return NULL;
}

std::string TelnetLayer::getTelnetCommandAsString(TelnetCommand val)
{
	switch (val)
	{
	case TelnetCommandEndOfPacket:
		return "Reached end of packet while parsing";
	case EndOfFile:
		return "End of File";
	case Suspend:
		return "Suspend current process";
	case Abort:
		return "Abort Process";
	case EndOfRecordCommand:
		return "End of Record";
	case SubnegotiationEnd:
		return "Subnegotiation End";
	case NoOperation:
		return "No Operation";
	case DataMark:
		return "Data Mark";
	case Break:
		return "Break";
	case InterruptProcess:
		return "Interrupt Process";
	case AbortOutput:
		return "Abort Output";
	case AreYouThere:
		return "Are You There";
	case EraseCharacter:
		return "Erase Character";
	case EraseLine:
		return "Erase Line";
	case GoAhead:
		return "Go Ahead";
	case Subnegotiation:
		return "Subnegotiation";
	case WillPerform:
		return "Will Perform";
	case WontPerform:
		return "Wont Perform";
	case DoPerform:
		return "Do Perform";
	case DontPerform:
		return "Dont Perform";
	case InterpretAsCommand:
		return "Interpret As Command";
	default:
		return "Unknown Command";
	}
}

std::string TelnetLayer::getTelnetOptionAsString(TelnetOption val)
{
	switch (val)
	{
	case TelnetOptionNoOption:
		return "No option for this command";
	case TransmitBinary:
		return "Binary Transmission";
	case Echo:
		return "Echo";
	case Reconnection:
		return "Reconnection";
	case SuppressGoAhead:
		return "Suppress Go Ahead";
	case ApproxMsgSizeNegotiation:
		return "Negotiate approximate message size";
	case Status:
		return "Status";
	case TimingMark:
		return "Timing Mark";
	case RemoteControlledTransAndEcho:
		return "Remote Controlled Transmission and Echo";
	case OutputLineWidth:
		return "Output Line Width";
	case OutputPageSize:
		return "Output Page Size";
	case OutputCarriageReturnDisposition:
		return "Negotiate About Output Carriage-Return Disposition";
	case OutputHorizontalTabStops:
		return "Negotiate About Output Horizontal Tabstops";
	case OutputHorizontalTabDisposition:
		return "Negotiate About Output Horizontal Tab Disposition";
	case OutputFormfeedDisposition:
		return "Negotiate About Output Formfeed Disposition";
	case OutputVerticalTabStops:
		return "Negotiate About Vertical Tabstops";
	case OutputVerticalTabDisposition:
		return "Negotiate About Output Vertcial Tab Disposition";
	case OutputLinefeedDisposition:
		return "Negotiate About Output Linefeed Disposition";
	case ExtendedASCII:
		return "Extended ASCII";
	case Logout:
		return "Logout";
	case ByteMacro:
		return "Byte Macro";
	case DataEntryTerminal:
		return "Data Entry Terminal";
	case SUPDUP:
		return "SUPDUP";
	case SUPDUPOutput:
		return "SUPDUP Output";
	case SendLocation:
		return "Send Location";
	case TerminalType:
		return "Terminal Type";
	case EndOfRecordOption:
		return "End Of Record";
	case TACACSUserIdentification:
		return "TACACS User Identification";
	case OutputMarking:
		return "Output Marking";
	case TerminalLocationNumber:
		return "Terminal Location Number";
	case Telnet3270Regime:
		return "Telnet 3270 Regime";
	case X3Pad:
		return "X3 Pad";
	case NegotiateAboutWindowSize:
		return "Negotiate About Window Size";
	case TerminalSpeed:
		return "Terminal Speed";
	case RemoteFlowControl:
		return "Remote Flow Control";
	case Linemode:
		return "Line mode";
	case XDisplayLocation:
		return "X Display Location";
	case EnvironmentOption:
		return "Environment Option";
	case AuthenticationOption:
		return "Authentication Option";
	case EncryptionOption:
		return "Encryption Option";
	case NewEnvironmentOption:
		return "New Environment Option";
	case TN3270E:
		return "TN3270E";
	case XAuth:
		return "X Server Authentication";
	case Charset:
		return "Charset";
	case TelnetRemoteSerialPort:
		return "Telnet Remote Serial Port";
	case ComPortControlOption:
		return "Com Port Control Option";
	case TelnetSuppressLocalEcho:
		return "Telnet Suppress Local Echo";
	case TelnetStartTLS:
		return "Telnet Start TLS";
	case Kermit:
		return "Kermit";
	case SendURL:
		return "Send URL";
	case ForwardX:
		return "Forward X Server";
	case TelOptPragmaLogon:
		return "Telnet Option Pragma Logon";
	case TelOptSSPILogon:
		return "Telnet Option SSPI Logon";
	case TelOptPragmaHeartbeat:
		return "Telnet Option Pragma Heartbeat";
	case ExtendedOptions:
		return "Extended option list";
	default:
		return "Unknown Option";
	}
}

std::string TelnetLayer::toString() const
{
	if (m_Data[0] != InterpretAsCommand || (m_Data[0] == InterpretAsCommand && m_Data[1] == InterpretAsCommand))
		return "Telnet Data";
	return "Telnet Control";
}

} // namespace pcpp
