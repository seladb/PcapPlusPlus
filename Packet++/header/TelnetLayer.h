#ifndef PACKETPP_TELNET_LAYER
#define PACKETPP_TELNET_LAYER

#include "Layer.h"

#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

    /**
     * Class for representing the Telnet Layer
     */
    class TelnetLayer : public Layer
    {
    private:
#pragma pack(push, 1)
        struct telnet_header
        {
            // "Interpret as Command" escape character (FF)
            uint8_t interpretation,
                // Command
                command,
                // Option of the command
                subcommand,
                // Data (Variable length)
                data[];
        };
#pragma pack(pop)

        struct telnet_field_data
        {
            // Header
            struct telnet_header *hdr;
            // Size of the header including data payload
            uint16_t hdrSize;
            // Offset of the current header
            uint16_t currentOffset;
        };

        bool isData;
        std::vector<telnet_field_data> telnetCommandData;

    public:
        /**
         * Telnet Command Indicator
         */
        enum TelnetCommands
        {
            /// Internal error indicator for PcapPlusPlus
            TelnetCommandInternalError = -1,

            /// End of file
            EndOfFile = 236,
            /// Suspend current process
            Suspend,
            /// Abort Process
            Abort,
            /// End of Record
            EndOfRecordCommand,
            /// Marks the end of a Telnet option subnegotiation, used with the SB code to specify more specific option parameters.
            SubnegotiationEnd,
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

        /**
         * Telnet Options
         */
        enum TelnetOptions
        {
            /// Internal return for no option detected
            TelnetOptionNoOption = -2,
            /// Internal error indicator for PcapPlusPlus
            TelnetOptionInternalError,

            /// Binary Transmission RFC856 https://www.iana.org/go/rfc856
            TransmitBinary = 0,
            /// Echo RFC857 https://www.iana.org/go/rfc857
            Echo,
            /// Reconnection
            Reconnection,
            /// Suppress Go Ahead RFC858 https://www.iana.org/go/rfc858
            SuppressGoAhead,
            /// Negotiate approximate message size
            ApproxMsgSizeNegotiation,
            /// Status RFC859 https://www.iana.org/go/rfc859
            Status,
            /// Timing Mark RFC860 https://www.iana.org/go/rfc860
            TimingMark,
            /// RCTE, Remote Controlled Transmission and Echo RFC726 https://www.iana.org/go/rfc726
            RemoteControlledTransAndEcho,
            /// Output Line Width
            OutputLineWidth,
            /// Output Page Size
            OutputPageSize,
            /// NAOCRD, Negotiate About Output Carriage-Return Disposition RFC652 https://www.iana.org/go/rfc652
            OutputCarriageReturnDisposition,
            /// NAOHTS, Negotiate About Output Horizontal Tabstops RFC653 https://www.iana.org/go/rfc653
            OutputHorizontalTabStops,
            /// NAOHTD, Negotiate About Output Horizontal Tab Disposition RFC654 https://www.iana.org/go/rfc654
            OutputHorizontalTabDisposition,
            /// NAOFFD, Negotiate About Output Formfeed Disposition RFC655 https://www.iana.org/go/rfc655
            OutputFormfeedDisposition,
            /// NAOVTS, Negotiate About Vertical Tabstops RFC656 https://www.iana.org/go/rfc656
            OutputVerticalTabStops,
            /// NAOVTD, Negotiate About Output Vertcial Tab Disposition RFC657 https://www.iana.org/go/rfc657
            OutputVerticalTabDisposition,
            /// NAOLFD, Negotiate About Output Linefeed Disposition RFC658 https://www.iana.org/go/rfc658
            OutputLinefeedDisposition,
            /// Extended ASCII RFC698 https://www.iana.org/go/rfc698
            ExtendedASCII,
            /// Logout RFC727 https://www.iana.org/go/rfc727
            Logout,
            /// BM, Byte Macro RFC735 https://www.iana.org/go/rfc735
            ByteMacro,
            /// Data Entry Terminal RFC1043 - RFC732 https://www.iana.org/go/rfc1043 https://www.iana.org/go/rfc732
            DataEntryTerminal,
            /// SUPDUP RFC736 - RFC734 https://www.iana.org/go/rfc736 https://www.iana.org/go/rfc734
            SUPDUP,
            /// SUPDUP Output RFC749 https://www.iana.org/go/rfc749
            SUPDUPOutput,
            /// Send Location RFC779 https://www.iana.org/go/rfc779
            SendLocation,
            /// Terminal Type RFC1091 https://www.iana.org/go/rfc1091
            TerminalType,
            /// End of record RFC885 https://www.iana.org/go/rfc885
            EndOfRecordOption,
            /// TUID, TACACS User Identification RFC927 https://www.iana.org/go/rfc927
            TACACSUserIdentification,
            /// OUTMRK, Output Marking RFC933 https://www.iana.org/go/rfc933
            OutputMarking,
            /// TTYLOC, Terminal Location Number RFC946 https://www.iana.org/go/rfc946
            TerminalLocationNumber,
            /// Telnet 3270 Regime RFC1041 https://www.iana.org/go/rfc1041
            Telnet3270Regime,
            /// X.3 PAD RFC1053 https://www.iana.org/go/rfc1053
            X3Pad,
            /// NAWS, Negotiate About Window Size RFC1073 https://www.iana.org/go/rfc1073
            NegotiateAboutWindowSize,
            /// Terminal Speed RFC1079 https://www.iana.org/go/rfc1079
            TerminalSpeed,
            /// Remote Flow Control RFC1372 https://www.iana.org/go/rfc1372
            RemoteFlowControl,
            /// Line Mode RFC1184 https://www.iana.org/go/rfc1184
            Linemode,
            /// X Display Location RFC1096 https://www.iana.org/go/rfc1096
            XDisplayLocation,
            /// Environment Option RFC1408 https://www.iana.org/go/rfc1408
            EnvironmentOption,
            /// Authentication Option RFC2941 https://www.iana.org/go/rfc2941
            AuthenticationOption,
            /// Encryption Option RFC2946 https://www.iana.org/go/rfc2946
            EncryptionOption,
            /// New Environment Option RFC1572 https://www.iana.org/go/rfc1572
            NewEnvironmentOption,
            /// TN3270E RFC2355 https://www.iana.org/go/rfc2355
            TN3270E,
            /// X Server Authentication
            XAuth,
            /// Charset RFC2066 https://www.iana.org/go/rfc2066
            Charset,
            /// RSP, Telnet Remote Serial Port
            TelnetRemoteSerialPort,
            /// Com Port Control Option RFC2217 https://www.iana.org/go/rfc2217
            ComPortControlOption,
            /// Telnet Suppress Local Echo
            TelnetSuppressLocalEcho,
            /// Telnet Start TLS
            TelnetStartTLS,
            /// Kermit RFC2840 https://www.iana.org/go/rfc2840
            Kermit,
            /// Send URL
            SendURL,
            /// Forward X Server
            ForwardX,

            /// Telnet Option Pragma Logon
            TelOptPragmaLogon = 138,
            /// Telnet Option SSPI Logon
            TelOptSSPILogon,
            /// Telnet Option Pragma Heartbeat
            TelOptPragmaHeartbeat,

            /// Extended option list
            ExtendedOptions = 255

        };

        /**
         * A constructor that creates the layer from an existing packet raw data
         * @param[in] data A pointer to the raw data
         * @param[in] dataLen Size of the data in bytes
         * @param[in] prevLayer A pointer to the previous layer
         * @param[in] packet A pointer to the Packet instance where layer will be stored in
         */
        TelnetLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet)
        {
            isData = false;
            m_Protocol = Telnet;
            computeCalculateFields();
        };

        /**
         * Get the Telnet data as readable string
         * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
         * @return Full payload as readable string, empty if Telnet packet contains control commands/options.
         */
        std::string getDataAsString(bool removeEscapeCharacters = true);

        /// Return the number of detected Telnet Commands
        uint16_t getNumberOfCommands();

        /**
         * Get the command of the given index
         * @param[in] index Index to requested value
         * @return Command of the given index, TelnetCommandInternalError if the requested index is larger than number of commands
         */
        TelnetCommands getCommand(size_t index);

        /**
         * Convert the Telnet Command to readable string
         * @param[in] index Index to requested value
         * @return The Telnet Command as readable string
         */
        std::string getTelnetCommandAsString(size_t index);

        /**
         * Get the command option of the given index
         * @param[in] index Index to requested value
         * @return Option of the given index, TelnetOptionInternalError if the requested index is larger than number of commands
         */
        TelnetOptions getOption(size_t index);

        /**
         * Convert the Telnet option to readable string
         * @param[in] index Index to requested value
         * @return The Telnet Option as readable string
         */
        std::string getTelnetOptionAsString(size_t index);

        /**
         * Convert the Telnet Command to readable string
         * @param[in] val Value of the command
         * @return The Telnet Command as readable string
         */
        static std::string getTelnetCommandAsString(TelnetCommands val);

        /**
         * Convert the Telnet option to readable string
         * @param[in] val Value of the option
         * @return The Telnet Option as readable string
         */
        static std::string getTelnetOptionAsString(TelnetOptions val);

        /**
         * A static method that checks whether the port is considered as Telnet
         * @param[in] port The port number to be checked
         */
        static bool isTelnetPort(uint16_t port) { return port == 23; }

        /**
         * A static method that takes a byte array and detects whether it is a Telnet message
         * @param[in] data A byte array
         * @param[in] dataSize The byte array size (in bytes)
         * @return True if the data is identified as Telnet message
         */
        static bool isDataValid(const uint8_t *data, size_t dataSize) { return data && dataSize; }

        // overridden methods

        /// Parses the next layer. Telnet is the always last so does nothing for this layer
        void parseNextLayer() {}

        /**
         * @return Get the size of the layer
         */
        size_t getHeaderLen() const { return m_DataLen; }

        /**
         * Parse Telnet fields of the packet
         */
        void computeCalculateFields();

        /**
         * @return The OSI layer level of Telnet (Application Layer).
         */
        OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

        /**
         * @return Returns the protocol info as readable string
         */
        std::string toString() const;
    };

} // namespace pcpp

#endif /* PACKETPP_TELNET_LAYER */