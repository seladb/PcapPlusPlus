#ifndef PACKETPP_TELNET_LAYER
#define PACKETPP_TELNET_LAYER

#include "Logger.h"
#include "Layer.h"

#include "GeneralUtils.h"
#include "SystemUtils.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

#pragma pack(push, 1)
    struct telnet_header
    {
        /// "Interpret as Command" escape character
        uint8_t interpretaion,
        /// Command
        command,
        /// Option of the command
        subcommand;
    };
#pragma pack(pop)

    enum TelnetCommands
    {
        /// Marks the end of a Telnet option subnegotiation, used with the SB code to specify more specific option parameters.
        SubnegotiationEnd = 240,
        /// Null command; does nothing.
        NoOperation,
        /// Used to mark the end of a sequence of data that the recipient should scan for urgent Telnet commands.
        DataMark,
        /// Represents the pressing of the “break” or “attention” key on the terminal.
        Break,
        /// Tells the recipient to interrupt, abort, suspend or terminate the process currently in use.
        InterruptProcess,
        /// Instructs the remote host to continue running the current process, but discard all remaining output from it. This may be needed if a program starts to send unexpectedly large amounts of data to the user.
        AbortOutput,
        /// May be used to check that the remote host is still “alive”. When this character is sent the remote host returns some type of output to indicate that it is still functioning.
        AreYouThere,
        /// Instructs the recipient to delete the last undeleted character from the data stream. Used to “undo” the sending of a character.
        EraseCharacter,
        /// Tells the recipient to delete all characters from the data stream back to (but not including) the last end of line (CR+LF) sequence.
        EraseLine,
        /// Used in Telnet half-duplex mode to signal the other device that it may transmit.
        GoAhead,
        /// Marks the beginning of a Telnet option subnegotiation, used when an option requires the client and server to exchange parameters.
        Subnegotiation,
        /// Indicates that the device sending this code is willing to perform or continue performing a particular option.
        WillPerform,
        /// Indicates that the device sending this code is either not willing to perform a particular option, or is now refusing to continue to perform it.
        WontPerform,
        /// Requests that the other device perform a particular option or confirms the expectation that the other device will perform that option.
        DoPerform,
        /// Specifies that the other party not perform an option, or confirms a device’s expectation that the other party not perform an option.
        DontPerform,
        /// Precedes command values 240 through 254 as described above. A pair of IAC bytes in a row represents the data value 255.
        InterpretAsCommand
    };

    enum TelnetOptions
    {
        /// RFC856 https://www.iana.org/go/rfc856
        BinaryTransmission = 0,
        /// RFC857 https://www.iana.org/go/rfc857
        Echo,
        Reconnection,
        /// RFC858 https://www.iana.org/go/rfc858
        SuppressGoAhead,
        ApproxMsgSizeNegotiation,
        /// RFC859 https://www.iana.org/go/rfc859
        Status,
        /// RFC860 https://www.iana.org/go/rfc860
        TimingMark,
        /// RFC726 https://www.iana.org/go/rfc726
        RemoteControlledTransAndEcho,
        OutputLineWidth,
        OutputPageSize,
        /// RFC652 https://www.iana.org/go/rfc652
        OutputCarriageReturnDisposition,
        /// RFC653 https://www.iana.org/go/rfc653
        OutputHorizontalTabStops,
        /// RFC654 https://www.iana.org/go/rfc654
        OutputHorizontalTabDisposition,
        /// RFC655 https://www.iana.org/go/rfc655
        OutputFormfeedDisposition,
        /// RFC656 https://www.iana.org/go/rfc656
        OutputVerticalTabStops,
        /// RFC657 https://www.iana.org/go/rfc657
        OutputVerticalTabDisposition,
        /// RFC658 https://www.iana.org/go/rfc658
        OutputLinefeedDisposition,
        /// RFC698 https://www.iana.org/go/rfc698
        ExtendedASCII,
        /// RFC727 https://www.iana.org/go/rfc727
        Logout,
        /// RFC735 https://www.iana.org/go/rfc735
        ByteMacro,
        /// RFC1043 - RFC732 https://www.iana.org/go/rfc1043 https://www.iana.org/go/rfc732
        DataEntryTerminal,
        /// RFC736 - RFC734 https://www.iana.org/go/rfc736 https://www.iana.org/go/rfc734
        SUPDUP,
        /// RFC749 https://www.iana.org/go/rfc749
        SUPDUPOutput,
        /// RFC779 https://www.iana.org/go/rfc779
        SendLocation,
        /// RFC1091 https://www.iana.org/go/rfc1091
        TerminalType,
        /// RFC885 https://www.iana.org/go/rfc885
        EndOfRecord,
        /// RFC927 https://www.iana.org/go/rfc927
        TACACSUserIdentification,
        /// RFC933 https://www.iana.org/go/rfc933
        OutputMarking,
        /// RFC946 https://www.iana.org/go/rfc946
        TerminalLocationNumber,
        /// RFC1041 https://www.iana.org/go/rfc1041
        Telnet3270Regime,
        /// RFC1053 https://www.iana.org/go/rfc1053
        X3Pad,
        /// RFC1073 https://www.iana.org/go/rfc1073
        NegotiateAboutWindowSize,
        /// RFC1079 https://www.iana.org/go/rfc1079
        TerminalSpeed,
        /// RFC1372 https://www.iana.org/go/rfc1372
        RemoteFlowControl,
        /// RFC1184 https://www.iana.org/go/rfc1184
        Linemode,
        /// RFC1096 https://www.iana.org/go/rfc1096
        XDisplayLocation,
        /// RFC1408 https://www.iana.org/go/rfc1408
        EnvironmentOption,
        /// RFC2941 https://www.iana.org/go/rfc2941
        AuthenticationOption,
        /// RFC2946 https://www.iana.org/go/rfc2946
        EncryptionOption,
        /// RFC1572 https://www.iana.org/go/rfc1572
        NewEnvironmentOption,
        /// RFC2355 https://www.iana.org/go/rfc2355
        TN3270E,
        XAuth,
        /// RFC2066 https://www.iana.org/go/rfc2066
        Charset,
        TelnetRemoteSerialPort,
        /// RFC2217 https://www.iana.org/go/rfc2217
        ComPortControlOption,
        TelnetSuppressLocalEcho,
        TelnetStartTLS,
        /// RFC2840 https://www.iana.org/go/rfc2840
        Kermit,
        SendURL,
        ForwardX,

        TelOptPragmaLogon = 138,
        TelOptSSPILogon,
        TelOptPragmaHeartbeat,

        ExtendedOptions = 255

    };

    class TelnetLayer : public Layer
    {
    private:
        bool isData;
        telnet_header *getTelnetHeader() const { return (telnet_header *)m_Data; }

    public:
        /**
		 * A static method that checks whether the port is considered as Telnet
		 * @param[in] port The port number to be checked
		 */
        static bool isTelnetPort(uint16_t port) { return port == 23; }

        // overridden methods

        void parseNextLayer() {}

        size_t getHeaderLen() const { return m_DataLen; }

        void computeCalculateFields() {}

        OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

        std::string toString() const;
    }

} // namespace pcpp

#endif /* PACKETPP_TELNET_LAYER */