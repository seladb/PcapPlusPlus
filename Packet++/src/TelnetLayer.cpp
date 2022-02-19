#define LOG_MODULE PacketLogModuleTelnetLayer

#include "Logger.h"
#include "TelnetLayer.h"

#include "GeneralUtils.h"
#include "SystemUtils.h"

#include <string.h>

namespace pcpp
{

    void TelnetLayer::parseTelnetFields()
    {
        // Since only contains data return immediately
        if ((m_Data[0] != 255) || (m_Data[0] == 255 && m_Data[1] == 255))
        {
            isData = true;
            return;
        }

        uint8_t *pos = NULL;
        size_t currentOffset = 0;
        do
        {
            telnet_field_data buff;
            buff.hdr = (telnet_header *)(m_Data + currentOffset);
            buff.currentOffset = currentOffset;
            buff.hdrSize = 0;

            uint16_t addition = 0;
            do
            {
                // If it is second turn position should be adjusted to after second FF
                if (addition)
                    addition += 2;

                pos = (uint8_t *)memchr(m_Data + currentOffset + 1, InterpretAsCommand, m_DataLen - currentOffset);
                if (pos)
                    addition += pos - (m_Data + currentOffset);
                else
                    addition += m_DataLen - currentOffset;
                currentOffset = buff.currentOffset + addition;
                // "FF FF" means data continue
            } while (pos && (pos[1] == InterpretAsCommand) && (currentOffset < m_DataLen));
            buff.hdrSize = addition;
            telnetCommandData.push_back(buff);
        } while (currentOffset < m_DataLen && pos);
    }

    std::string TelnetLayer::getDataAsString(bool removeEscapeCharacters)
    {
        // If not data return immediately
        if (!isData)
            return "";

        if (removeEscapeCharacters)
        {
            std::stringstream ss;
            for (size_t idx = 0; idx < m_DataLen; idx++)
                if (m_Data[idx] < 127 && m_Data[idx] > 31) // From SPACE to ~
                    ss << m_Data[idx];
            return ss.str();
        }
        return std::string((char *)m_Data, m_DataLen);
    }

    uint16_t TelnetLayer::getNumberOfCommands()
    {
        return telnetCommandData.size();
    }

    TelnetLayer::TelnetCommands TelnetLayer::getCommand(size_t index)
    {
        if (index < telnetCommandData.size())
            return static_cast<TelnetCommands>(telnetCommandData[index].hdr->command);

        PCPP_LOG_ERROR("Requested command index does not exist");
        return TelnetCommandInternalError;
    }

    std::string TelnetLayer::getTelnetCommandAsString(size_t index)
    {
        return getTelnetCommandAsString(getCommand(index));
    }

    TelnetLayer::TelnetOptions TelnetLayer::getOption(size_t index)
    {
        if (index >= telnetCommandData.size())
        {
            PCPP_LOG_ERROR("Requested option index does not exist");
            return TelnetOptionInternalError;
        }
        else if (telnetCommandData[index].hdr->command < Subnegotiation || telnetCommandData[index].hdrSize < 3)
            return TelnetOptionNoOption;
        else
            return static_cast<TelnetOptions>(telnetCommandData[index].hdr->subcommand);
    }

    std::string TelnetLayer::getTelnetOptionAsString(size_t index)
    {
        return getTelnetOptionAsString(getOption(index));
    }

    const uint8_t *TelnetLayer::getOptionData(size_t index, size_t &length)
    {
        if (isData)
            return NULL;
        if (index < telnetCommandData.size())
        {
            // This means there is no subcommand data pointer should be adjusted
            if (telnetCommandData[index].hdr->command < Subnegotiation)
            {
                length = telnetCommandData[index].hdrSize - 2;
                return &(telnetCommandData[index].hdr->subcommand);
            }
            else if (telnetCommandData[index].hdrSize > 3)
            {
                length = telnetCommandData[index].hdrSize - 3;
                return telnetCommandData[index].hdr->data;
            }

            PCPP_LOG_DEBUG("No data at requested index");
            return NULL;
        }

        PCPP_LOG_ERROR("Requested option index does not exist");
        return NULL;
    }

    std::string TelnetLayer::getTelnetCommandAsString(TelnetCommands val)
    {
        switch (val)
        {
        case TelnetCommandInternalError:
            return "Internal Error";
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
        case TelnetOptionInternalError:
            return "Internal Error";
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

    void TelnetLayer::computeCalculateFields()
    {
    }

    std::string TelnetLayer::toString() const
    {
        if (isData)
            return "Telnet Data";
        return "Telnet Control";
    }

} // namespace pcpp