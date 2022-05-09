#define LOG_MODULE PacketLogModuleTelnetLayer

#include "TelnetLayer.h"
#include "Logger.h"

#include "GeneralUtils.h"
#include "SystemUtils.h"

#include <string.h>

namespace pcpp
{

    bool TelnetLayer::isDataField(const uint8_t *pos)
    {
        // "FF FF" means data
        if (pos[0] != InterpretAsCommand || (pos[0] == InterpretAsCommand && pos[1] == InterpretAsCommand))
            return true;
        return false;
    }

    bool TelnetLayer::isCommandField(const uint8_t *pos)
    {
        if (pos[0] == InterpretAsCommand && pos[1] != InterpretAsCommand)
            return true;
        return false;
    }

    size_t TelnetLayer::getFieldLen(const uint8_t *startPos, const size_t maxLength)
    {
        size_t ctr = 0;
        uint8_t *pos = NULL;
        size_t addition = 0;
        size_t currentOffset = 0;
        do
        {
            // If it is second turn position should be adjusted to after second FF
            if (addition)
                addition += 2;
            // If infinite loop is detected break
            if (ctr > UINT16_MAX)
            {
                PCPP_LOG_ERROR("Infinite loop detected while parsing fields");
                return 0;
            }

            pos = (uint8_t *)memchr(startPos + currentOffset + 1, InterpretAsCommand, maxLength - currentOffset);
            if (pos)
                addition += pos - (startPos + currentOffset);
            else
                addition += maxLength - currentOffset;
            currentOffset = currentOffset + addition;
            ++ctr;
            // "FF FF" means data continue
        } while (pos && (pos[1] == InterpretAsCommand) && (currentOffset < maxLength));

        return addition;
    }

    uint8_t *TelnetLayer::getNextDataField(uint8_t *pos, const size_t len)
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

    uint8_t *TelnetLayer::getNextCommandField(uint8_t *pos, const size_t len)
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

    int16_t TelnetLayer::getSubCommand(const uint8_t *pos, const size_t len)
    {
        if (len < 3 || pos[1] < Subnegotiation)
            return TelnetOptionNoOption;
        return pos[2];
    }

    const uint8_t *TelnetLayer::getCommandData(const uint8_t *pos, size_t &len)
    {
        if (pos[1] < Subnegotiation)
        {
            len -=2;
            return &pos[2];
        }
        if (len > 3)
        {
            len -= 3;
            return &pos[3];
        }
        len=0;
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
        size_t offset = dataPos - m_Data;
        if (removeEscapeCharacters)
        {
            std::stringstream ss;
            for (size_t idx = 0; idx < m_DataLen; idx++)
                if (dataPos[idx] < 127 && dataPos[idx] > 31) // From SPACE to ~
                    ss << m_Data[idx];
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

    size_t TelnetLayer::getNumberOfCommands(TelnetCommands command)
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

    TelnetLayer::TelnetCommands TelnetLayer::getFirstCommand()
    {
        // If starts with command
        if (isCommandField(m_Data))
            return static_cast<TelnetCommands>(m_Data[1]);

        // Check is there any command
        uint8_t *pos = getNextCommandField(m_Data, m_DataLen);
        if (pos)
            return static_cast<TelnetCommands>(pos[1]);
        return TelnetCommandEndOfPacket;
    }

    TelnetLayer::TelnetCommands TelnetLayer::getNextCommand()
    {
        uint8_t *pos = getNextCommandField(lastPosition, m_DataLen - lastPositionOffset);
        if (pos)
        {
            lastPosition = pos;
            lastPositionOffset = pos - m_Data;
            return static_cast<TelnetLayer::TelnetCommands>(pos[1]);
        }
        lastPosition = m_Data;
        lastPositionOffset = 0;
        return TelnetCommandEndOfPacket;
    }

    TelnetLayer::TelnetOptions TelnetLayer::getOption()
    {
        return static_cast<TelnetOptions>(getSubCommand(lastPosition, getFieldLen(lastPosition, m_DataLen - lastPositionOffset)));
    }

    TelnetLayer::TelnetOptions TelnetLayer::getOption(TelnetCommands command)
    {
        if (command < 0)
        {
            PCPP_LOG_ERROR("Command type can't be negative");
            return TelnetOptionNoOption;
        }

        if (isCommandField(m_Data) && m_Data[1] == command)
            return static_cast<TelnetOptions>(getSubCommand(m_Data, getFieldLen(m_Data, m_DataLen)));

        uint8_t *pos = m_Data;
        size_t offset = 0;
        while (pos != NULL)
        {
            offset = pos - m_Data;
            pos = getNextCommandField(pos, m_DataLen - offset);

            if (pos && pos[1] == command)
                return static_cast<TelnetOptions>(getSubCommand(pos, getFieldLen(pos, m_DataLen - offset)));
        }

        PCPP_LOG_DEBUG("Cant find requested command");
        return TelnetOptionNoOption;
    }

    const uint8_t *TelnetLayer::getOptionData(size_t &length)
    {
        size_t lenBuffer = getFieldLen(lastPosition, m_DataLen - lastPositionOffset);
        const uint8_t *posBuffer = getCommandData(lastPosition, lenBuffer);

        length = lenBuffer;
        return posBuffer;
    }

    const uint8_t *TelnetLayer::getOptionData(TelnetCommands command, size_t &length)
    {
        // <--------------------------------------------------------------------------------
    }

    std::string TelnetLayer::getTelnetCommandAsString(TelnetCommands val)
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

    std::string TelnetLayer::getTelnetOptionAsString(TelnetOptions val)
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

    std::string TelnetLayer::toString()
    {
        if (isDataField(m_Data))
            return "Telnet Data";
        return "Telnet Control";
    }

} // namespace pcpp
