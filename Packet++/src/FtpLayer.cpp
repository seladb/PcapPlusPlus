#define LOG_MODULE PacketLogModuleFtpLayer

#include "FtpLayer.h"

namespace pcpp
{

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
		{
			val |= static_cast<size_t>(field.c_str()[idx]) << (idx * 8);
		}

		return static_cast<FtpCommand>(val);
	}

	std::string FtpRequestLayer::getCommandString() const
	{
		return getCommandInternal();
	}

	bool FtpRequestLayer::setCommandOption(const std::string& value)
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
				if (int(field.c_str()[idx]) < 127 && int(field.c_str()[idx]) > 31)  // From SPACE to ~
					ss << field.c_str()[idx];
			}
			return ss.str();
		}
		return getCommandOptionInternal();
	}

	std::string FtpRequestLayer::getCommandInfo(FtpCommand code)
	{
		switch (code)
		{
		case FtpCommand::ABOR:
			return "Abort an active file transfer";
		case FtpCommand::ACCT:
			return "Account information";
		case FtpCommand::ADAT:
			return "Authentication/Security Data";
		case FtpCommand::ALLO:
			return "Allocate sufficient disk space to receive a file";
		case FtpCommand::APPE:
			return "Append (with create)";
		case FtpCommand::AUTH:
			return "Authentication/Security Mechanism";
		case FtpCommand::AVBL:
			return "Get the available space";
		case FtpCommand::CCC:
			return "Clear Command Channel";
		case FtpCommand::CDUP:
			return "Change to Parent Directory";
		case FtpCommand::CONF:
			return "Confidentiality Protection Command";
		case FtpCommand::CSID:
			return "Client / Server Identification";
		case FtpCommand::CWD:
			return "Change working directory";
		case FtpCommand::DELE:
			return "Delete file";
		case FtpCommand::DSIZ:
			return "Get the directory size";
		case FtpCommand::ENC:
			return "Privacy Protected Channel";
		case FtpCommand::EPRT:
			return "Specifies an extended address and port to which the server should connect";
		case FtpCommand::EPSV:
			return "Enter extended passive mode";
		case FtpCommand::FEAT:
			return "Get the feature list implemented by the server";
		case FtpCommand::HELP:
			return "Returns usage documentation on a command if specified, else a general help document is returned";
		case FtpCommand::HOST:
			return "Identify desired virtual host on server, by name";
		case FtpCommand::LANG:
			return "Language Negotiation";
		case FtpCommand::LIST:
			return "Returns information of a file or directory if specified, else information of the current working directory is returned";
		case FtpCommand::LPRT:
			return "Specifies a long address and port to which the server should connect";
		case FtpCommand::LPSV:
			return "Enter long passive mode";
		case FtpCommand::MDTM:
			return "Return the last-modified time of a specified file";
		case FtpCommand::MFCT:
			return "Modify the creation time of a file";
		case FtpCommand::MFF:
			return "Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file)";
		case FtpCommand::MFMT:
			return "Modify the last modification time of a file";
		case FtpCommand::MIC:
			return "Integrity Protected Command";
		case FtpCommand::MKD:
			return "Make directory";
		case FtpCommand::MLSD:
			return "Lists the contents of a directory in a standardized machine-readable format";
		case FtpCommand::MLST:
			return "Provides data about exactly the object named on its command line in a standardized machine-readable format";
		case FtpCommand::MODE:
			return "Sets the transfer mode (Stream, Block, or Compressed)";
		case FtpCommand::NLST:
			return "Returns a list of file names in a specified directory";
		case FtpCommand::NOOP:
			return "No operation (dummy packet; used mostly on keepalives)";
		case FtpCommand::OPTS:
			return "Select options for a feature (for example OPTS UTF8 ON)";
		case FtpCommand::PASS:
			return "Authentication password";
		case FtpCommand::PASV:
			return "Enter passive mode";
		case FtpCommand::PBSZ:
			return "Protection Buffer Size";
		case FtpCommand::PORT:
			return "Specifies an address and port to which the server should connect";
		case FtpCommand::PROT:
			return "Data Channel Protection Level";
		case FtpCommand::PWD:
			return "Print working directory. Returns the current directory of the host";
		case FtpCommand::QUIT:
			return "Disconnect";
		case FtpCommand::REIN:
			return "Re initializes the connection";
		case FtpCommand::REST:
			return "Restart transfer from the specified point";
		case FtpCommand::RETR:
			return "Retrieve a copy of the file";
		case FtpCommand::RMD:
			return "Remove a directory";
		case FtpCommand::RMDA:
			return "Remove a directory tree";
		case FtpCommand::RNFR:
			return "Rename from";
		case FtpCommand::RNTO:
			return "Rename to";
		case FtpCommand::SITE:
			return "Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands";
		case FtpCommand::SIZE:
			return "Return the size of a file";
		case FtpCommand::SMNT:
			return "Mount file structure";
		case FtpCommand::SPSV:
			return "Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections)";
		case FtpCommand::STAT:
			return "Returns information on the server status, including the status of the current connection";
		case FtpCommand::STOR:
			return "Accept the data and to store the data as a file at the server site";
		case FtpCommand::STOU:
			return "Store file uniquely";
		case FtpCommand::STRU:
			return "Set file transfer structure";
		case FtpCommand::SYST:
			return "Return system type";
		case FtpCommand::THMB:
			return "Get a thumbnail of a remote image file";
		case FtpCommand::TYPE:
			return "Sets the transfer mode (ASCII/Binary)";
		case FtpCommand::USER:
			return "Authentication username";
		case FtpCommand::XCUP:
			return "Change to the parent of the current working directory";
		case FtpCommand::XMKD:
			return "Make a directory";
		case FtpCommand::XPWD:
			return "Print the current working directory";
		case FtpCommand::XRCP:
			return "";
		case FtpCommand::XRMD:
			return "Remove the directory";
		case FtpCommand::XRSQ:
			return "";
		case FtpCommand::XSEM:
			return "Send, mail if cannot";
		case FtpCommand::XSEN:
			return "Send to terminal";
		default:
			return "Unknown command";
		}
	}

	std::string FtpRequestLayer::getCommandAsString(FtpCommand code)
	{
		std::stringstream oss;
		for (size_t idx = 0; idx < 4; ++idx)
		{
			char val = (uint64_t(code) >> (8 * idx)) & UINT8_MAX;
			if (val)  // Dont push if it is a null character
			{
				oss << val;
			}
		}
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

	bool FtpResponseLayer::setStatusOption(const std::string& value)
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
				if (int(field.c_str()[idx]) < 127 && int(field.c_str()[idx]) > 31)  // From SPACE to ~
					ss << field.c_str()[idx];
			}
			return ss.str();
		}
		return getCommandOptionInternal();
	}

	std::string FtpResponseLayer::getStatusCodeAsString(FtpStatusCode code)
	{
		switch (code)
		{
		case FtpStatusCode::RESTART_MARKER:
			return "Restart marker reply";
		case FtpStatusCode::SERVICE_READY_IN_MIN:
			return "Service ready in nnn minutes";
		case FtpStatusCode::DATA_ALREADY_OPEN_START_TRANSFER:
			return "Data connection already open; transfer starting";
		case FtpStatusCode::FILE_OK:
			return "File status okay; about to open data connection";
		case FtpStatusCode::COMMAND_OK:
			return "Command okay";
		case FtpStatusCode::COMMAND_NOT_IMPLEMENTED_SUPERFLUOUS:
			return "Command not implemented, superfluous at this site";
		case FtpStatusCode::SYSTEM_STATUS:
			return "System status, or system help reply";
		case FtpStatusCode::DIR_STATUS:
			return "Directory status";
		case FtpStatusCode::FILE_STATUS:
			return "File status";
		case FtpStatusCode::HELP_MESSAGE:
			return "Help message";
		case FtpStatusCode::NAME_SYSTEM_TYPE:
			return "NAME system type";
		case FtpStatusCode::SERVICE_READY_FOR_USER:
			return "Service ready for new user";
		case FtpStatusCode::SERVICE_CLOSING_CONTROL:
			return "Service closing control connection";
		case FtpStatusCode::DATA_OPEN_NO_TRANSFER:
			return "Data connection open; no transfer in progress";
		case FtpStatusCode::CLOSING_DATA:
			return "Closing data connection";
		case FtpStatusCode::ENTERING_PASSIVE:
			return "Entering Passive Mode";
		case FtpStatusCode::ENTERING_EXTENDED_PASSIVE:
			return "Entering Extended Passive Mode";
		case FtpStatusCode::USER_LOG_IN_PROCEED:
			return "User logged in, proceed";
		case FtpStatusCode::USER_LOG_IN_AUTHORIZED:
			return "User logged in, authorized by security data exchange";
		case FtpStatusCode::SEC_DATA_EXCHANGE_COMPLETE:
			return "Security data exchange complete";
		case FtpStatusCode::SEC_DATA_EXCHANGE_COMPLETE_SUCCESS:
			return "Security data exchange completed successfully";
		case FtpStatusCode::REQ_FILE_OK_COMPLETE:
			return "Requested file action okay, completed";
		case FtpStatusCode::PATHNAME_CREATED:
			return "PATHNAME created";
		case FtpStatusCode::USER_OK_NEED_PASSWORD:
			return "User name okay, need password";
		case FtpStatusCode::NEED_ACCOUNT:
			return "Need account for login";
		case FtpStatusCode::REQ_SEC_MECHANISM_OK:
			return "Requested security mechanism is ok";
		case FtpStatusCode::SEC_IS_ACCEPTABLE:
			return "Security data is acceptable, more is required";
		case FtpStatusCode::USER_OK_NEED_PASS_CHALLENGE:
			return "Username okay, need password. Challenge is ...";
		case FtpStatusCode::FILE_PENDING_ACTION:
			return "Requested file action pending further information";
		case FtpStatusCode::SERVICE_NOT_AVAILABLE:
			return "Service not available, closing control connection";
		case FtpStatusCode::CANT_OPEN_DATA_CONNECTION:
			return "Can't open data connection";
		case FtpStatusCode::CONNECTION_CLOSED:
			return "Connection closed; transfer aborted";
		case FtpStatusCode::NEED_UNAVAILABLE_RESOURCE_TO_SEC:
			return "Need some unavailable resource to process security";
		case FtpStatusCode::REQ_FILE_ACTION_NOT_TAKEN:
			return "Requested file action not taken";
		case FtpStatusCode::REQ_ACTION_ABORTED:
			return "Requested action aborted: local error in processing";
		case FtpStatusCode::REQ_ACTION_NOT_TAKEN:
			return "Requested action not taken. Insufficient storage space in system";
		case FtpStatusCode::SYNTAX_ERROR_COMMAND_UNRECOGNIZED:
			return "Syntax error, command unrecognized";
		case FtpStatusCode::SYNTAX_ERROR_PARAMETER_OR_ARGUMENT:
			return "Syntax error in parameters or arguments";
		case FtpStatusCode::COMMAND_NOT_IMPLEMENTED:
			return "Command not implemented";
		case FtpStatusCode::BAD_SEQUENCE_COMMANDS:
			return "Bad sequence of commands";
		case FtpStatusCode::COMMAND_NOT_IMPLEMENTED_FOR_PARAMETER:
			return "Command not implemented for that parameter";
		case FtpStatusCode::NETWORK_PROTOCOL_NOT_SUPPORTED:
			return "Network protocol not supported";
		case FtpStatusCode::NOT_LOGGED_IN:
			return "Not logged in";
		case FtpStatusCode::NEED_ACCOUNT_FOR_STORE_FILE:
			return "Need account for storing files";
		case FtpStatusCode::COMMAND_PROTECTION_DENIED:
			return "Command protection level denied for policy reasons";
		case FtpStatusCode::REQUEST_DENIED:
			return "Request denied for policy reasons";
		case FtpStatusCode::FAILED_SEC_CHECK:
			return "Failed security check (hash, sequence, etc)";
		case FtpStatusCode::REQ_PROT_LEVEL_NOT_SUPPORTED:
			return "Requested PROT level not supported by mechanism";
		case FtpStatusCode::COMMAND_PROTECTION_LEVEL_NOT_SUPPORTED:
			return "Command protection level not supported by security mechanism";
		case FtpStatusCode::FILE_UNAVAILABLE:
			return "Requested action not taken: File unavailable";
		case FtpStatusCode::PAGE_TYPE_UNKNOWN:
			return "Requested action aborted: page type unknown";
		case FtpStatusCode::EXCEED_STORAGE_ALLOCATION:
			return "Requested file action aborted: Exceeded storage allocation";
		case FtpStatusCode::FILENAME_NOT_ALLOWED:
			return "Requested action not taken: File name not allowed";
		case FtpStatusCode::INTEGRITY_PROTECTED:
			return "Integrity protected reply";
		case FtpStatusCode::CONFIDENTIALITY_AND_INTEGRITY_PROTECTED:
			return "Confidentiality and integrity protected reply";
		case FtpStatusCode::CONFIDENTIALITY_PROTECTED:
			return "Confidentiality protected reply";
		default:
			return "Unknown Status Code";
		}
	}

	std::string FtpResponseLayer::toString() const
	{
		return "FTP Response: " + getStatusCodeString();
	}

	std::string FtpDataLayer::toString() const
	{
		return "FTP Data";
	}

}  // namespace pcpp
