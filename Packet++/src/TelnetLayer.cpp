#define LOG_MODULE PacketLogModuleTelnetLayer

#include "TelnetLayer.h"
#include "Logger.h"

namespace pcpp
{
    std::string TelnetLayer::getTelnetCommandAsString(TelnetCommands val)
    {
        switch(val)
        {
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
            case EndOfRecord:
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
        if (isData)
            return "Telnet Data";
        return "Telnet Control";
    }

} // namespace pcpp