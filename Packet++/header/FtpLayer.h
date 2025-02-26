#pragma once

#include "SingleCommandTextProtocol.h"
#include "PayloadLayer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Class for general FTP message
	class FtpLayer : public SingleCommandTextProtocol
	{
	protected:
		FtpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SingleCommandTextProtocol(data, dataLen, prevLayer, packet, FTP) {};
		FtpLayer(const std::string& command, const std::string& option)
		    : SingleCommandTextProtocol(command, option, FTP) {};

	public:
		/// A static method that checks whether the port is considered as FTP control
		/// @param[in] port The port number to be checked
		static bool isFtpPort(uint16_t port)
		{
			return port == 21;
		}

		/// A static method that checks whether the port is considered as FTP data
		/// @param[in] port The port number to be checked
		static bool isFtpDataPort(uint16_t port)
		{
			return port == 20;
		}

		// overridden methods

		/// FTP is the always last so does nothing for this layer
		void parseNextLayer() override
		{}

		/// @return Get the size of the layer
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// @return The OSI layer level of FTP (Application Layer).
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}
	};

	/// Class for representing the request messages of FTP Layer
	class FtpRequestLayer : public FtpLayer
	{
	public:
		/// Enum for FTP command codes
		enum class FtpCommand : int
		{
			/// Unknown command
			UNK,
			/// Abort an active file transfer.
			ABOR = ('A') | ('B' << 8) | ('O' << 16) | ('R' << 24),
			/// Account information.
			ACCT = ('A') | ('C' << 8) | ('C' << 16) | ('T' << 24),
			/// Authentication/Security Data
			ADAT = ('A') | ('D' << 8) | ('A' << 16) | ('T' << 24),
			/// Allocate sufficient disk space to receive a file.
			ALLO = ('A') | ('L' << 8) | ('L' << 16) | ('O' << 24),
			/// Append (with create)
			APPE = ('A') | ('P' << 8) | ('P' << 16) | ('E' << 24),
			/// Authentication/Security Mechanism
			AUTH = ('A') | ('U' << 8) | ('T' << 16) | ('H' << 24),
			/// Get the available space
			AVBL = ('A') | ('V' << 8) | ('B' << 16) | ('L' << 24),
			/// Clear Command Channel
			CCC = ('C') | ('C' << 8) | ('C' << 16),
			/// Change to Parent Directory.
			CDUP = ('C') | ('D' << 8) | ('U' << 16) | ('P' << 24),
			/// Confidentiality Protection Command
			CONF = ('C') | ('O' << 8) | ('N' << 16) | ('F' << 24),
			/// Client / Server Identification
			CSID = ('C') | ('S' << 8) | ('I' << 16) | ('D' << 24),
			/// Change working directory.
			CWD = ('C') | ('W' << 8) | ('D' << 16),
			/// Delete file.
			DELE = ('D') | ('E' << 8) | ('L' << 16) | ('E' << 24),
			/// Get the directory size
			DSIZ = ('D') | ('S' << 8) | ('I' << 16) | ('Z' << 24),
			/// Privacy Protected Channel
			ENC = ('E') | ('N' << 8) | ('C' << 16),
			/// Specifies an extended address and port to which the server should connect.
			EPRT = ('E') | ('P' << 8) | ('R' << 16) | ('T' << 24),
			/// Enter extended passive mode.
			EPSV = ('E') | ('P' << 8) | ('S' << 16) | ('V' << 24),
			/// Get the feature list implemented by the server.
			FEAT = ('F') | ('E' << 8) | ('A' << 16) | ('T' << 24),
			/// Returns usage documentation on a command if specified, else a general help document is returned.
			HELP = ('H') | ('E' << 8) | ('L' << 16) | ('P' << 24),
			/// Identify desired virtual host on server, by name.
			HOST = ('H') | ('O' << 8) | ('S' << 16) | ('T' << 24),
			/// Language Negotiation
			LANG = ('L') | ('A' << 8) | ('N' << 16) | ('G' << 24),
			/// Returns information of a file or directory if specified, else information of the current working
			/// directory is returned.
			LIST = ('L') | ('I' << 8) | ('S' << 16) | ('T' << 24),
			/// Specifies a long address and port to which the server should connect.
			LPRT = ('L') | ('P' << 8) | ('R' << 16) | ('T' << 24),
			/// Enter long passive mode.
			LPSV = ('L') | ('P' << 8) | ('S' << 16) | ('V' << 24),
			/// Return the last-modified time of a specified file.
			MDTM = ('M') | ('D' << 8) | ('T' << 16) | ('M' << 24),
			/// Modify the creation time of a file.
			MFCT = ('M') | ('F' << 8) | ('C' << 16) | ('T' << 24),
			/// Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).
			MFF = ('M') | ('F' << 8) | ('F' << 16),
			/// Modify the last modification time of a file.
			MFMT = ('M') | ('F' << 8) | ('M' << 16) | ('T' << 24),
			/// Integrity Protected Command
			MIC = ('M') | ('I' << 8) | ('C' << 16),
			/// Make directory.
			MKD = ('M') | ('K' << 8) | ('D' << 16),
			/// Lists the contents of a directory in a standardized machine-readable format.
			MLSD = ('M') | ('L' << 8) | ('S' << 16) | ('D' << 24),
			/// Provides data about exactly the object named on its command line in a standardized machine-readable
			/// format.
			MLST = ('M') | ('L' << 8) | ('S' << 16) | ('T' << 24),
			/// Sets the transfer mode (Stream, Block, or Compressed).
			MODE = ('M') | ('O' << 8) | ('D' << 16) | ('E' << 24),
			/// Returns a list of file names in a specified directory.
			NLST = ('N') | ('L' << 8) | ('S' << 16) | ('T' << 24),
			/// No operation (dummy packet; used mostly on keepalives).
			NOOP = ('N') | ('O' << 8) | ('O' << 16) | ('P' << 24),
			/// Select options for a feature (for example OPTS UTF8 ON).
			OPTS = ('O') | ('P' << 8) | ('T' << 16) | ('S' << 24),
			/// Authentication password.
			PASS = ('P') | ('A' << 8) | ('S' << 16) | ('S' << 24),
			/// Enter passive mode.
			PASV = ('P') | ('A' << 8) | ('S' << 16) | ('V' << 24),
			/// Protection Buffer Size
			PBSZ = ('P') | ('B' << 8) | ('S' << 16) | ('Z' << 24),
			/// Specifies an address and port to which the server should connect.
			PORT = ('P') | ('O' << 8) | ('R' << 16) | ('T' << 24),
			/// Data Channel Protection Level.
			PROT = ('P') | ('R' << 8) | ('O' << 16) | ('T' << 24),
			/// Print working directory. Returns the current directory of the host.
			PWD = ('P') | ('W' << 8) | ('D' << 16),
			/// Disconnect.
			QUIT = ('Q') | ('U' << 8) | ('I' << 16) | ('T' << 24),
			/// Re initializes the connection.
			REIN = ('R') | ('E' << 8) | ('I' << 16) | ('N' << 24),
			/// Restart transfer from the specified point.
			REST = ('R') | ('E' << 8) | ('S' << 16) | ('T' << 24),
			/// Retrieve a copy of the file
			RETR = ('R') | ('E' << 8) | ('T' << 16) | ('R' << 24),
			/// Remove a directory.
			RMD = ('R') | ('M' << 8) | ('D' << 16),
			/// Remove a directory tree
			RMDA = ('R') | ('M' << 8) | ('D' << 16) | ('A' << 24),
			/// Rename from.
			RNFR = ('R') | ('N' << 8) | ('F' << 16) | ('R' << 24),
			/// Rename to.
			RNTO = ('R') | ('N' << 8) | ('T' << 16) | ('O' << 24),
			/// Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP
			/// output for complete list of supported commands.
			SITE = ('S') | ('I' << 8) | ('T' << 16) | ('E' << 24),
			/// Return the size of a file.
			SIZE = ('S') | ('I' << 8) | ('Z' << 16) | ('E' << 24),
			/// Mount file structure.
			SMNT = ('S') | ('M' << 8) | ('N' << 16) | ('T' << 24),
			/// Use single port passive mode (only one TCP port number for both control connections and passive-mode
			/// data connections)
			SPSV = ('S') | ('P' << 8) | ('S' << 16) | ('V' << 24),
			/// Returns information on the server status, including the status of the current connection
			STAT = ('S') | ('T' << 8) | ('A' << 16) | ('T' << 24),
			/// Accept the data and to store the data as a file at the server site
			STOR = ('S') | ('T' << 8) | ('O' << 16) | ('R' << 24),
			/// Store file uniquely.
			STOU = ('S') | ('T' << 8) | ('O' << 16) | ('U' << 24),
			/// Set file transfer structure.
			STRU = ('S') | ('T' << 8) | ('R' << 16) | ('U' << 24),
			/// Return system type.
			SYST = ('S') | ('Y' << 8) | ('S' << 16) | ('T' << 24),
			/// Get a thumbnail of a remote image file
			THMB = ('T') | ('H' << 8) | ('M' << 16) | ('B' << 24),
			/// Sets the transfer mode (ASCII/Binary).
			TYPE = ('T') | ('Y' << 8) | ('P' << 16) | ('E' << 24),
			/// Authentication username.
			USER = ('U') | ('S' << 8) | ('E' << 16) | ('R' << 24),
			/// Change to the parent of the current working directory
			XCUP = ('X') | ('C' << 8) | ('U' << 16) | ('P' << 24),
			/// Make a directory
			XMKD = ('X') | ('M' << 8) | ('K' << 16) | ('D' << 24),
			/// Print the current working directory
			XPWD = ('X') | ('P' << 8) | ('W' << 16) | ('D' << 24),
			///
			XRCP = ('X') | ('R' << 8) | ('C' << 16) | ('P' << 24),
			/// Remove the directory
			XRMD = ('X') | ('R' << 8) | ('M' << 16) | ('D' << 24),
			///
			XRSQ = ('X') | ('R' << 8) | ('S' << 16) | ('Q' << 24),
			/// Send, mail if cannot
			XSEM = ('X') | ('S' << 8) | ('E' << 16) | ('M' << 24),
			/// Send to terminal
			XSEN = ('X') | ('S' << 8) | ('E' << 16) | ('N' << 24)
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		FtpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : FtpLayer(data, dataLen, prevLayer, packet) {};

		/// A constructor that creates layer with provided input values
		/// @param[in] command FTP command
		/// @param[in] option Argument of the command
		explicit FtpRequestLayer(const FtpCommand& command, const std::string& option = "")
		    : FtpLayer(getCommandAsString(command), option) {};

		/// Set the command of request message
		/// @param[in] code Value to set command
		/// @return True if the operation is successful, false otherwise
		bool setCommand(FtpCommand code);

		/// Get the command of request message
		/// @return FtpCommand Value of the command
		FtpCommand getCommand() const;

		/// Get the command of request message as string
		/// @return std::string Value of the command as string
		std::string getCommandString() const;

		/// Set the command argument of request message
		/// @param[in] value Value to set command argument
		/// @return True if the operation is successful, false otherwise
		bool setCommandOption(const std::string& value);

		/// Get the command argument of request message
		/// @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		/// @return std::string Value of command argument
		std::string getCommandOption(bool removeEscapeCharacters = true) const;

		/// Convert the command info to readable string
		/// @param[in] code Command code to convert
		/// @return std::string Returns the command info as readable string
		static std::string getCommandInfo(FtpCommand code);

		/// Convert the command to readable string
		/// @param[in] code Command code to convert
		/// @return std::string Returns the command as readable string
		static std::string getCommandAsString(FtpCommand code);

		// overridden methods

		/// @return Returns the protocol info as readable string
		std::string toString() const override;
	};

	/// Class for representing the response messages of FTP Layer
	class FtpResponseLayer : public FtpLayer
	{
	public:
		/// Enum for FTP response codes
		enum class FtpStatusCode : int
		{
			/// Unknown status code
			UNKNOWN,
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

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		FtpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : FtpLayer(data, dataLen, prevLayer, packet) {};

		/// A constructor that creates layer with provided input values
		/// @param[in] code Status code
		/// @param[in] option Argument of the status code
		explicit FtpResponseLayer(const FtpStatusCode& code, const std::string& option = "")
		    : FtpLayer(std::to_string(int(code)), option) {};

		/// Set the status code of response message
		/// @param[in] code Value to set status code
		/// @return True if the operation is successful, false otherwise
		bool setStatusCode(FtpStatusCode code);

		/// Get the status code of response message
		/// @return FtpStatusCode Value of the status code
		FtpStatusCode getStatusCode() const;

		/// Get the status code of response message as string
		/// @return std::string Value of the status code as string
		std::string getStatusCodeString() const;

		/// Set the argument of response message
		/// @param[in] value Value to set argument
		/// @return True if the operation is successful, false otherwise
		bool setStatusOption(const std::string& value);

		/// Get the argument of response message
		/// @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		/// @return std::string Value of argument
		std::string getStatusOption(bool removeEscapeCharacters = true) const;

		/// Convert the status code to readable string
		/// @param[in] code Status code to convert
		/// @return std::string Returns the status info as readable string
		static std::string getStatusCodeAsString(FtpStatusCode code);

		// overridden methods

		/// @return Returns the protocol info as readable string
		std::string toString() const override;
	};

	/// Class for representing the data of FTP Layer
	class FtpDataLayer : public PayloadLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		FtpDataLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : PayloadLayer(data, dataLen, prevLayer, packet)
		{
			m_Protocol = FTP;
		};

		/// @return Returns the protocol info as readable string
		std::string toString() const override;
	};
}  // namespace pcpp
