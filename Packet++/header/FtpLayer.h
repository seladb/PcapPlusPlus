#ifndef PACKETPP_FTP_LAYER
#define PACKETPP_FTP_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

    /**
     * Class for representing the request messages of FTP Layer
     */
    class FtpRequestLayer : public Layer
    {
    private:
    public:

        /**
         * Enum for FTP command codes
         */
        enum FtpCommand
        {
            /// Abort an active file transfer.
            ABOR,
            /// Account information.
            ACCT,
            /// Authentication/Security Data
            ADAT,
            /// Allocate sufficient disk space to receive a file.
            ALLO,
            /// Append (with create)
            APPE,
            /// Authentication/Security Mechanism
            AUTH,
            /// Get the available space
            AVBL,
            /// Clear Command Channel
            CCC,
            /// Change to Parent Directory.
            CDUP,
            /// Confidentiality Protection Command
            CONF,
            /// Client / Server Identification
            CSID,
            /// Change working directory.
            CWD,
            /// Delete file.
            DELE,
            /// Get the directory size
            DSIZ,
            /// Privacy Protected Channel
            ENC,
            /// Specifies an extended address and port to which the server should connect.
            EPRT,
            /// Enter extended passive mode.
            EPSV,
            /// Get the feature list implemented by the server.
            FEAT,
            /// Returns usage documentation on a command if specified, else a general help document is returned.
            HELP,
            /// Identify desired virtual host on server, by name.
            HOST,
            /// Language Negotiation
            LANG,
            /// Returns information of a file or directory if specified, else information of the current working directory is returned.
            LIST,
            /// Specifies a long address and port to which the server should connect.
            LPRT,
            /// Enter long passive mode.
            LPSV,
            /// Return the last-modified time of a specified file.
            MDTM,
            /// Modify the creation time of a file.
            MFCT,
            /// Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).
            MFF,
            /// Modify the last modification time of a file.
            MFMT,
            /// Integrity Protected Command
            MIC,
            /// Make directory.
            MKD,
            /// Lists the contents of a directory in a standardized machine-readable format.
            MLSD,
            /// Provides data about exactly the object named on its command line in a standardized machine-readable format.
            MLST,
            /// Sets the transfer mode (Stream, Block, or Compressed).
            MODE,
            /// Returns a list of file names in a specified directory.
            NLST,
            /// No operation (dummy packet; used mostly on keepalives).
            NOOP,
            /// Select options for a feature (for example OPTS UTF8 ON).
            OPTS,
            /// Authentication password.
            PASS,
            /// Enter passive mode.
            PASV,
            /// Protection Buffer Size
            PBSZ,
            /// Specifies an address and port to which the server should connect.
            PORT,
            /// Data Channel Protection Level.
            PROT,
            /// Print working directory. Returns the current directory of the host.
            PWD,
            /// Disconnect.
            QUIT,
            /// Re initializes the connection.
            REIN,
            /// Restart transfer from the specified point.
            REST,
            /// Retrieve a copy of the file
            RETR,
            /// Remove a directory.
            RMD,
            /// Remove a directory tree
            RMDA,
            /// Rename from.
            RNFR,
            /// Rename to.
            RNTO,
            /// Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands.
            SITE,
            /// Return the size of a file.
            SIZE,
            /// Mount file structure.
            SMNT,
            /// Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections)
            SPSV,
            /// Returns information on the server status, including the status of the current connection
            STAT,
            /// Accept the data and to store the data as a file at the server site
            STOR,
            /// Store file uniquely.
            STOU,
            /// Set file transfer structure.
            STRU,
            /// Return system type.
            SYST,
            /// Get a thumbnail of a remote image file
            THMB,
            /// Sets the transfer mode (ASCII/Binary).
            TYPE,
            /// Authentication username.
            USER,
            /// Change to the parent of the current working directory
            XCUP,
            /// Make a directory
            XMKD,
            /// Print the current working directory
            XPWD,
            /// 
            XRCP,
            /// Remove the directory
            XRMD,
            /// 
            XRSQ,
            /// Send, mail if cannot
            XSEM,
            /// Send to terminal
            XSEN
        };

		/** A constructor that creates the layer from an existing packet raw data
         * @param[in] data A pointer to the raw data
         * @param[in] dataLen Size of the data in bytes
         * @param[in] prevLayer A pointer to the previous layer
         * @param[in] packet A pointer to the Packet instance where layer will be stored in
         */
        FtpRequestLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet) {}
        
        /**
         * Empty c'tor
         */
        FtpRequestLayer();

        /**
         * D'ctor
         */
        ~FtpRequestLayer();

        /**
         * Set the command of request message
         * @param[in] code Value to set command
         */
        void setCommand(FtpCommand code);

        /**
         * Get the command of request message
         * @return FtpCommand Value of the command
         */
        FtpCommand getCommand() const;

        /**
         * Set the command argument of request message
         * @param[in] value Value to set command argument
         */
        void setCommandOption(const std::string &value);

        /**
         * Get the command argument of request message
         * @return std::string Value of command argument
         */
        std::string getCommandOption() const;

        /**
         * Convert the command to readable string
         * @param[in] code Command code to convert
         * @return std::string Returns the protocol info as readable string
         */
        static std::string getCommandAsString(FtpCommand code);

        // overridden methods
        
        /// Parses the next layer. FTP is the always last so does nothing for this layer
        void parseNextLayer() {}

        /**
         * @return Get the size of the layer
         */
        size_t getHeaderLen() const { return m_DataLen; }

        /// Does nothing for this layer
        void computeCalculateFields() {}

        /**
         * @return The OSI layer level of Telnet (Application Layer).
         */
        OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

        /**
         * @return Returns the protocol info as readable string
         */
        std::string toString() const;
    };

    /**
     * Class for representing the response messages of FTP Layer
     */
    class FtpResponseLayer : public Layer
    {
    private:
    public:
        
        /**
         * Enum for FTP response codes
         */
        enum FtpStatusCode
        {
            /// Restart marker reply
            RESTART_MARKER = 110,
            /// Service ready in nnn minutes
            SERVICE_READY_IN_MIN = 120,
            /// Data connection already open; transfer starting
            DATA_ALREADY_OPEN_START_TRANSFER = 125,
            /// File status okay; about to open data connection
            FILE_OK = 150,
            /// Command okay
            COMMAND_OK = 200,
            /// Command not implemented, superfluous at this site
            COMMAND_NOT_IMPLEMENTED_SUPERFLUOUS = 202,
            /// System status, or system help reply
            SYSTEM_STATUS = 211,
            /// Directory status
            DIR_STATUS = 212,
            /// File status
            FILE_STATUS = 213,
            /// Help message
            HELP_MESSAGE = 214,
            /// NAME system type
            NAME_SYSTEM_TYPE = 215,
            /// Service ready for new user
            SERVICE_READY_FOR_USER = 220,
            /// Service closing control connection
            SERVICE_CLOSING_CONTROL = 221,
            /// Data connection open; no transfer in progress
            DATA_OPEN_NO_TRANSFER = 225,
            /// Closing data connection
            CLOSING_DATA = 226,
            /// Entering Passive Mode
            ENTERING_PASSIVE = 227,
            /// Entering Extended Passive Mode
            ENTERING_EXTENDED_PASSIVE = 229,
            /// User logged in, proceed
            USER_LOG_IN_PROCEED = 230,
            /// User logged in, authorized by security data exchange
            USER_LOG_IN_AUTHORIZED = 232,
            /// Security data exchange complete
            SEC_DATA_EXCHANGE_COMPLETE = 234,
            /// Security data exchange completed successfully
            SEC_DATA_EXCHANGE_COMPLETE_SUCCESS = 235,
            /// Requested file action okay, completed
            REQ_FILE_OK_COMPLETE = 250,
            /// PATHNAME created
            PATHNAME_CREATED = 257,
            /// User name okay, need password
            USER_OK_NEED_PASSWORD = 331,
            /// Need account for login
            NEED_ACCOUNT = 332,
            /// Requested security mechanism is ok
            REQ_SEC_MECHANISM_OK = 334,
            /// Security data is acceptable, more is required
            SEC_IS_ACCEPTABLE = 335,
            /// Username okay, need password. Challenge is ...
            USER_OK_NEED_PASS_CHALLENGE = 336,
            /// Requested file action pending further information
            FILE_PENDING_ACTION = 350,
            /// Service not available, closing control connection
            SERVICE_NOT_AVAILABLE = 421,
            /// Can't open data connection
            CANT_OPEN_DATA_CONNECTION = 425,
            /// Connection closed; transfer aborted
            CONNECTION_CLOSED = 426,
            /// Need some unavailable resource to process security
            NEED_UNAVAILABLE_RESOURCE_TO_SEC = 431,
            /// Requested file action not taken
            REQ_FILE_ACTION_NOT_TAKEN = 450,
            /// Requested action aborted: local error in processing
            REQ_ACTION_ABORTED = 451,
            /// Requested action not taken. Insufficient storage space in system
            REQ_ACTION_NOT_TAKEN = 452,
            /// Syntax error, command unrecognized
            SYNTAX_ERROR_COMMAND_UNRECOGNIZED = 500,
            /// Syntax error in parameters or arguments
            SYNTAX_ERROR_PARAMETER_OR_ARGUMENT = 501,
            /// Command not implemented
            COMMAND_NOT_IMPLEMENTED = 502,
            /// Bad sequence of commands
            BAD_SEQUENCE_COMMANDS = 503,
            /// Command not implemented for that parameter
            COMMAND_NOT_IMPLEMENTED_FOR_PARAMETER = 504,
            /// Network protocol not supported
            NETWORK_PROTOCOL_NOT_SUPPORTED = 522,
            /// Not logged in
            NOT_LOGGED_IN = 530,
            /// Need account for storing files
            NEED_ACCOUNT_FOR_STORE_FILE = 532,
            /// Command protection level denied for policy reasons
            COMMAND_PROTECTION_DENIED = 533,
            /// Request denied for policy reasons
            REQUEST_DENIED = 534,
            /// Failed security check (hash, sequence, etc)
            FAILED_SEC_CHECK = 535,
            /// Requested PROT level not supported by mechanism
            REQ_PROT_LEVEL_NOT_SUPPORTED = 536,
            /// Command protection level not supported by security mechanism
            COMMAND_PROTECTION_LEVEL_NOT_SUPPORTED = 537,
            /// Requested action not taken: File unavailable
            FILE_UNAVAILABLE = 550,
            /// Requested action aborted: page type unknown
            PAGE_TYPE_UNKNOWN = 551,
            /// Requested file action aborted: Exceeded storage allocation
            EXCEED_STORAGE_ALLOCATION = 552,
            /// Requested action not taken: File name not allowed
            FILENAME_NOT_ALLOWED = 553,
            /// Integrity protected reply
            INTEGRITY_PROTECTED = 631,
            /// Confidentiality and integrity protected reply
            CONFIDENTIALITY_AND_INTEGRITY_PROTECTED = 632,
            /// Confidentiality protected reply
            CONFIDENTIALITY_PROTECTED = 633
        };

        /** A constructor that creates the layer from an existing packet raw data
         * @param[in] data A pointer to the raw data
         * @param[in] dataLen Size of the data in bytes
         * @param[in] prevLayer A pointer to the previous layer
         * @param[in] packet A pointer to the Packet instance where layer will be stored in
         */
        FtpResponseLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet) {};

        /**
         * Empty c'tor
         */
        FtpResponseLayer();

        /**
         * D'ctor
         */
        ~FtpResponseLayer();

        /**
         * Set the status code of response message
         * @param[in] code Value to set status code
         */
        void setStatusCode(FtpStatusCode code);

        /**
         * Get the status code of response message
         * @return FtpStatusCode Value of the status code
         */
        FtpStatusCode getStatusCode() const;

        /**
         * Set the argument of response message
         * @param[in] value Value to set argument
         */
        void setStatusOption(const std::string &value);

        /**
         * Get the argument of response message
         * @return std::string Value of argument
         */
        std::string getStatusOption() const;

        /**
         * Convert the status code to readable string
         * @param[in] code Status code to convert
         * @return std::string Returns the protocol info as readable string
         */
        static std::string getStatusCodeAsString(FtpStatusCode code);

        // overridden methods
        
        /// Parses the next layer. FTP is the always last so does nothing for this layer
        void parseNextLayer() {}

        /**
         * @return Get the size of the layer
         */
        size_t getHeaderLen() const { return m_DataLen; }

        /// Does nothing for this layer
        void computeCalculateFields() {}

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

#endif /* PACKETPP_FTP_LAYER */
