#define LOG_MODULE PacketLogModuleFtpLayer

#include "FtpLayer.h"

#include <unordered_map>

namespace pcpp
{

	const std::unordered_map<FtpRequestLayer::FtpCommand, std::string> FtpCommandToString{
		{FtpRequestLayer::FtpCommand::ABOR, "Abort an active file transfer."},
		{FtpRequestLayer::FtpCommand::ACCT, "Account information."},
		{FtpRequestLayer::FtpCommand::ADAT, "Authentication/Security Data"},
		{FtpRequestLayer::FtpCommand::ALLO, "Allocate sufficient disk space to receive a file."},
		{FtpRequestLayer::FtpCommand::APPE, "Append (with create)"},
		{FtpRequestLayer::FtpCommand::AUTH, "Authentication/Security Mechanism"},
		{FtpRequestLayer::FtpCommand::AVBL, "Get the available space"},
		{FtpRequestLayer::FtpCommand::CCC, "Clear Command Channel"},
		{FtpRequestLayer::FtpCommand::CDUP, "Change to Parent Directory."},
		{FtpRequestLayer::FtpCommand::CONF, "Confidentiality Protection Command"},
		{FtpRequestLayer::FtpCommand::CSID, "Client / Server Identification"},
		{FtpRequestLayer::FtpCommand::CWD, "Change working directory."},
		{FtpRequestLayer::FtpCommand::DELE, "Delete file."},
		{FtpRequestLayer::FtpCommand::DSIZ, "Get the directory size"},
		{FtpRequestLayer::FtpCommand::ENC, "Privacy Protected Channel"},
		{FtpRequestLayer::FtpCommand::EPRT,
		 "Specifies an extended address and port to which the server should connect."},
		{FtpRequestLayer::FtpCommand::EPSV, "Enter extended passive mode."},
		{FtpRequestLayer::FtpCommand::FEAT, "Get the feature list implemented by the server."},
		{FtpRequestLayer::FtpCommand::HELP,
		 "Returns usage documentation on a command if specified, else a general help document is returned."},
		{FtpRequestLayer::FtpCommand::HOST, "Identify desired virtual host on server, by name."},
		{FtpRequestLayer::FtpCommand::LANG, "Language Negotiation"},
		{FtpRequestLayer::FtpCommand::LIST,
		 "Returns information of a file or directory if specified, else information of the current working "
		 "directory is returned."},
		{FtpRequestLayer::FtpCommand::LPRT, "Specifies a long address and port to which the server should connect."},
		{FtpRequestLayer::FtpCommand::LPSV, "Enter long passive mode."},
		{FtpRequestLayer::FtpCommand::MDTM, "the last-modified time of a specified file."},
		{FtpRequestLayer::FtpCommand::MFCT, "Modify the creation time of a file."},
		{FtpRequestLayer::FtpCommand::MFF,
		 "Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file)."},
		{FtpRequestLayer::FtpCommand::MFMT, "Modify the last modification time of a file."},
		{FtpRequestLayer::FtpCommand::MIC, "Integrity Protected Command"},
		{FtpRequestLayer::FtpCommand::MKD, "Make directory."},
		{FtpRequestLayer::FtpCommand::MLSD,
		 "Lists the contents of a directory in a standardized machine-readable format."},
		{FtpRequestLayer::FtpCommand::MLST,
		 "Provides data about exactly the object named on its command line in a standardized "
		 "machine-readable format."},
		{FtpRequestLayer::FtpCommand::MODE, "Sets the transfer mode (Stream, Block, or Compressed)."},
		{FtpRequestLayer::FtpCommand::NLST, "Returns a list of file names in a specified directory."},
		{FtpRequestLayer::FtpCommand::NOOP, "No operation (dummy packet}, used mostly on keepalives)."},
		{FtpRequestLayer::FtpCommand::OPTS, "Select options for a feature (for example OPTS UTF8 ON)."},
		{FtpRequestLayer::FtpCommand::PASS, "Authentication password."},
		{FtpRequestLayer::FtpCommand::PASV, "Enter passive mode."},
		{FtpRequestLayer::FtpCommand::PBSZ, "Protection Buffer Size"},
		{FtpRequestLayer::FtpCommand::PORT, "Specifies an address and port to which the server should connect."},
		{FtpRequestLayer::FtpCommand::PROT, "Data Channel Protection Level."},
		{FtpRequestLayer::FtpCommand::PWD, "Print working directory. Returns the current directory of the host."},
		{FtpRequestLayer::FtpCommand::QUIT, "Disconnect."},
		{FtpRequestLayer::FtpCommand::REIN, "Re initializes the connection."},
		{FtpRequestLayer::FtpCommand::REST, "Restart transfer from the specified point."},
		{FtpRequestLayer::FtpCommand::RETR, "Retrieve a copy of the file"},
		{FtpRequestLayer::FtpCommand::RMD, "Remove a directory."},
		{FtpRequestLayer::FtpCommand::RMDA, "Remove a directory tree"},
		{FtpRequestLayer::FtpCommand::RNFR, "Rename from."},
		{FtpRequestLayer::FtpCommand::RNTO, "Rename to."},
		{FtpRequestLayer::FtpCommand::SITE,
		 "Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE "
		 "HELP output for complete list of supported commands."},
		{FtpRequestLayer::FtpCommand::SIZE, "The size of a file."},
		{FtpRequestLayer::FtpCommand::SMNT, "Mount file structure."},
		{FtpRequestLayer::FtpCommand::SPSV,
		 "Use single port passive mode (only one TCP port number for both control connections and "
		 "passive-mode data connections)"},
		{FtpRequestLayer::FtpCommand::STAT,
		 "Returns information on the server status, including the status of the current connection"},
		{FtpRequestLayer::FtpCommand::STOR, "Accept the data and to store the data as a file at the server site"},
		{FtpRequestLayer::FtpCommand::STOU, "Store file uniquely."},
		{FtpRequestLayer::FtpCommand::STRU, "Set file transfer structure."},
		{FtpRequestLayer::FtpCommand::SYST, "system type."},
		{FtpRequestLayer::FtpCommand::THMB, "Get a thumbnail of a remote image file"},
		{FtpRequestLayer::FtpCommand::TYPE, "Sets the transfer mode (ASCII/Binary)."},
		{FtpRequestLayer::FtpCommand::USER, "Authentication username."},
		{FtpRequestLayer::FtpCommand::XCUP, "Change to the parent of the current working directory"},
		{FtpRequestLayer::FtpCommand::XMKD, "Make a directory"},
		{FtpRequestLayer::FtpCommand::XPWD, "Print the current working directory"},
		{FtpRequestLayer::FtpCommand::XRCP, ""},
		{FtpRequestLayer::FtpCommand::XRMD, "Remove the directory"},
		{FtpRequestLayer::FtpCommand::XRSQ, ""},
		{FtpRequestLayer::FtpCommand::XSEM, "Send, mail if cannot"},
		{FtpRequestLayer::FtpCommand::XSEN, "Send to terminal"}};

	const std::unordered_map<FtpResponseLayer::FtpStatusCode, std::string> FtpStatusCodeToString {
		{FtpResponseLayer::FtpStatusCode::RESTART_MARKER, "Restart marker reply"},
		{FtpResponseLayer::FtpStatusCode::SERVICE_READY_IN_MIN, "Service ready in nnn minutes"},
		{FtpResponseLayer::FtpStatusCode::DATA_ALREADY_OPEN_START_TRANSFER,
		 "Data connection already open}, transfer starting"},
		{FtpResponseLayer::FtpStatusCode::FILE_OK, "File status okay}, about to open data connection"},
		{FtpResponseLayer::FtpStatusCode::COMMAND_OK, "Command okay"},
		{FtpResponseLayer::FtpStatusCode::COMMAND_NOT_IMPLEMENTED_SUPERFLUOUS,
		 "Command not implemented, superfluous at this site"},
		{FtpResponseLayer::FtpStatusCode::SYSTEM_STATUS, "System status, or system help reply"},
		{FtpResponseLayer::FtpStatusCode::DIR_STATUS, "Directory status"},
		{FtpResponseLayer::FtpStatusCode::FILE_STATUS, "File status"},
		{FtpResponseLayer::FtpStatusCode::HELP_MESSAGE, "Help message"},
		{FtpResponseLayer::FtpStatusCode::NAME_SYSTEM_TYPE, "NAME system type"},
		{FtpResponseLayer::FtpStatusCode::SERVICE_READY_FOR_USER, "Service ready for new user"},
		{FtpResponseLayer::FtpStatusCode::SERVICE_CLOSING_CONTROL, "Service closing control connection"},
		{FtpResponseLayer::FtpStatusCode::DATA_OPEN_NO_TRANSFER, "Data connection open}, no transfer in progress"},
		{FtpResponseLayer::FtpStatusCode::CLOSING_DATA, "Closing data connection"},
		{FtpResponseLayer::FtpStatusCode::ENTERING_PASSIVE, "Entering Passive Mode"},
		{FtpResponseLayer::FtpStatusCode::ENTERING_EXTENDED_PASSIVE, "Entering Extended Passive Mode"},
		{FtpResponseLayer::FtpStatusCode::USER_LOG_IN_PROCEED, "User logged in, proceed"},
		{FtpResponseLayer::FtpStatusCode::USER_LOG_IN_AUTHORIZED,
		 "User logged in, authorized by security data exchange"},
		{FtpResponseLayer::FtpStatusCode::SEC_DATA_EXCHANGE_COMPLETE, "Security data exchange complete"},
		{FtpResponseLayer::FtpStatusCode::SEC_DATA_EXCHANGE_COMPLETE_SUCCESS,
		 "Security data exchange completed successfully"},
		{FtpResponseLayer::FtpStatusCode::REQ_FILE_OK_COMPLETE, "Requested file action okay, completed"},
		{FtpResponseLayer::FtpStatusCode::PATHNAME_CREATED, "PATHNAME created"},
		{FtpResponseLayer::FtpStatusCode::USER_OK_NEED_PASSWORD, "User name okay, need password"},
		{FtpResponseLayer::FtpStatusCode::NEED_ACCOUNT, "Need account for login"},
		{FtpResponseLayer::FtpStatusCode::REQ_SEC_MECHANISM_OK, "Requested security mechanism is ok"},
		{FtpResponseLayer::FtpStatusCode::SEC_IS_ACCEPTABLE, "Security data is acceptable, more is required"},
		{FtpResponseLayer::FtpStatusCode::USER_OK_NEED_PASS_CHALLENGE,
		 "Username okay, need password. Challenge is ..."},
		{FtpResponseLayer::FtpStatusCode::FILE_PENDING_ACTION, "Requested file action pending further information"},
		{FtpResponseLayer::FtpStatusCode::SERVICE_NOT_AVAILABLE, "Service not available, closing control connection"},
		{FtpResponseLayer::FtpStatusCode::CANT_OPEN_DATA_CONNECTION, "Can't open data connection"},
		{FtpResponseLayer::FtpStatusCode::CONNECTION_CLOSED, "Connection closed}, transfer aborted"},
		{FtpResponseLayer::FtpStatusCode::NEED_UNAVAILABLE_RESOURCE_TO_SEC,
		 "Need some unavailable resource to process security"},
		{FtpResponseLayer::FtpStatusCode::REQ_FILE_ACTION_NOT_TAKEN, "Requested file action not taken"},
		{FtpResponseLayer::FtpStatusCode::REQ_ACTION_ABORTED, "Requested action aborted: local error in processing"},
		{FtpResponseLayer::FtpStatusCode::REQ_ACTION_NOT_TAKEN,
		 "Requested action not taken. Insufficient storage space in system"},
		{FtpResponseLayer::FtpStatusCode::SYNTAX_ERROR_COMMAND_UNRECOGNIZED, "Syntax error, command unrecognized"},
		{FtpResponseLayer::FtpStatusCode::SYNTAX_ERROR_PARAMETER_OR_ARGUMENT,
		 "Syntax error in parameters or arguments"},
		{FtpResponseLayer::FtpStatusCode::COMMAND_NOT_IMPLEMENTED, "Command not implemented"},
		{FtpResponseLayer::FtpStatusCode::BAD_SEQUENCE_COMMANDS, "Bad sequence of commands"},
		{FtpResponseLayer::FtpStatusCode::COMMAND_NOT_IMPLEMENTED_FOR_PARAMETER,
		 "Command not implemented for that parameter"},
		{FtpResponseLayer::FtpStatusCode::NETWORK_PROTOCOL_NOT_SUPPORTED, "Network protocol not supported"},
		{FtpResponseLayer::FtpStatusCode::NOT_LOGGED_IN, "Not logged in"},
		{FtpResponseLayer::FtpStatusCode::NEED_ACCOUNT_FOR_STORE_FILE, "Need account for storing files"},
		{FtpResponseLayer::FtpStatusCode::COMMAND_PROTECTION_DENIED,
		 "Command protection level denied for policy reasons"},
		{FtpResponseLayer::FtpStatusCode::REQUEST_DENIED, "Request denied for policy reasons"},
		{FtpResponseLayer::FtpStatusCode::FAILED_SEC_CHECK, "Failed security check (hash, sequence, etc)"},
		{FtpResponseLayer::FtpStatusCode::REQ_PROT_LEVEL_NOT_SUPPORTED,
		 "Requested PROT level not supported by mechanism"},
		{FtpResponseLayer::FtpStatusCode::COMMAND_PROTECTION_LEVEL_NOT_SUPPORTED,
		 "Command protection level not supported by security mechanism"},
		{FtpResponseLayer::FtpStatusCode::FILE_UNAVAILABLE, "Requested action not taken: File unavailable"},
		{FtpResponseLayer::FtpStatusCode::PAGE_TYPE_UNKNOWN, "Requested action aborted: page type unknown"},
		{FtpResponseLayer::FtpStatusCode::EXCEED_STORAGE_ALLOCATION,
		 "Requested file action aborted: Exceeded storage allocation"},
		{FtpResponseLayer::FtpStatusCode::FILENAME_NOT_ALLOWED, "Requested action not taken: File name not allowed"},
		{FtpResponseLayer::FtpStatusCode::INTEGRITY_PROTECTED, "Integrity protected reply"},
		{FtpResponseLayer::FtpStatusCode::CONFIDENTIALITY_AND_INTEGRITY_PROTECTED,
		 "Confidentiality and integrity protected reply"},
		{FtpResponseLayer::FtpStatusCode::CONFIDENTIALITY_PROTECTED, "Confidentiality protected reply"}};

	// ----------------- Class FtpRequestLayer -----------------
	bool FtpRequestLayer::setCommand(FtpCommand code)
	{
		return setCommandInternal(getCommandAsString(code));
	}

	FtpRequestLayer::FtpCommand FtpRequestLayer::getCommand() const
	{
		size_t val = 0;
		std::string field = getCommandString();

		for (size_t idx = 0; idx < field.size(); ++idx)
			val |= (field.c_str()[idx] << (idx * 8));

		return static_cast<FtpCommand>(val);
	}

	std::string FtpRequestLayer::getCommandString() const
	{
		return getCommandInternal();
	}

	bool FtpRequestLayer::setCommandOption(const std::string &value)
	{
		return setCommandOptionInternal(value);
	}

	std::string FtpRequestLayer::getCommandOption(bool removeEscapeCharacters) const
	{
		if (removeEscapeCharacters)
		{
			std::stringstream ss;
			std::string field = getCommandOptionInternal();
			for (size_t idx = 0; idx < field.size(); ++idx)
			{
				if (int(field.c_str()[idx]) < 127 && int(field.c_str()[idx]) > 31) // From SPACE to ~
					ss << field.c_str()[idx];
			}
			return ss.str();
		}
		return getCommandOptionInternal();
	}

	std::string FtpRequestLayer::getCommandInfo(FtpCommand code)
	{
		auto commandString = FtpCommandToString.find(code);
		if (commandString == FtpCommandToString.end())
		{
			return "Unknown command";
		}
		return commandString->second;
	}

	std::string FtpRequestLayer::getCommandAsString(FtpCommand code)
	{
		std::stringstream oss;
		for (size_t idx = 0; idx < 4; ++idx)
			oss << char((int(code) >> (8 * idx)) & UINT8_MAX);
		return oss.str();
	}

	std::string FtpRequestLayer::toString() const
	{
		return "FTP Request: " + getCommandString();
	}

	// ----------------- Class FtpResponseLayer -----------------
	bool FtpResponseLayer::setStatusCode(FtpStatusCode code)
	{
		std::ostringstream oss;
		oss << int(code);
		return setCommandInternal(oss.str());
	}

	FtpResponseLayer::FtpStatusCode FtpResponseLayer::getStatusCode() const
	{
		return static_cast<FtpStatusCode>(atoi(getCommandInternal().c_str()));
	}

	std::string FtpResponseLayer::getStatusCodeString() const
	{
		return getCommandInternal();
	}

	bool FtpResponseLayer::setStatusOption(const std::string &value)
	{
		return setCommandOptionInternal(value);
	}

	std::string FtpResponseLayer::getStatusOption(bool removeEscapeCharacters) const
	{
		if (removeEscapeCharacters)
		{
			std::stringstream ss;
			std::string field = getCommandOptionInternal();
			for (size_t idx = 0; idx < field.size(); ++idx)
			{
				if (int(field.c_str()[idx]) < 127 && int(field.c_str()[idx]) > 31) // From SPACE to ~
					ss << field.c_str()[idx];
			}
			return ss.str();
		}
		return getCommandOptionInternal();
	}

	std::string FtpResponseLayer::getStatusCodeAsString(FtpStatusCode code)
	{
		auto statusString = FtpStatusCodeToString.find(code);
		if (statusString == FtpStatusCodeToString.end())
		{
			return "Unknown status code";
		}
		return statusString->second;
	}

	std::string FtpResponseLayer::toString() const
	{
		return "FTP Response: " + getStatusCodeString();
	}

	std::string FtpDataLayer::toString() const
	{
		return "FTP Data";
	}

} // namespace pcpp
