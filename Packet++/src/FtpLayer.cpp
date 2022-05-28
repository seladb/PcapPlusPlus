#define LOG_MODULE PacketLogModuleFtpLayer

#include "FtpLayer.h"

namespace pcpp
{

	// ----------------- Class FtpRequestLayer -----------------
	FtpRequestLayer::FtpRequestLayer()
	{
		m_Protocol = FTP;
		m_Data = NULL;
		m_DataLen = 0;
	}

	void FtpRequestLayer::setCommand(FtpCommand code)
	{
		setCommandField(getCommandAsString(code));
	}

	FtpRequestLayer::FtpCommand FtpRequestLayer::getCommand() const
	{
		size_t val = 0;
		std::string field = getCommandField();

		for (size_t idx = 0; idx < field.size(); ++idx)
			val |= (field.c_str()[idx] << (idx * 8));

		return static_cast<FtpCommand>(val);
	}

	std::string FtpRequestLayer::getCommandString() const
	{
		return getCommandField();
	}

	void FtpRequestLayer::setCommandOption(std::string value)
	{
		setOptionField(value);
	}

	std::string FtpRequestLayer::getCommandOption(bool removeEscapeCharacters) const
	{
		if (removeEscapeCharacters)
		{
			std::stringstream ss;
			std::string field = getOptionField();
			for (size_t idx = 0; idx < field.size(); ++idx)
			{
				if (int(field.c_str()[idx]) < 127 && int(field.c_str()[idx]) > 31) // From SPACE to ~
					ss << field.c_str()[idx];
			}
			return ss.str();
		}
		return getOptionField();
	}

	std::string FtpRequestLayer::getCommandInfoAsString(FtpCommand code)
	{
		switch (code)
		{
		case ABOR:
			return "Abort an active file transfer.";
		case ACCT:
			return "Account information.";
		case ADAT:
			return "Authentication/Security Data";
		case ALLO:
			return "Allocate sufficient disk space to receive a file.";
		case APPE:
			return "Append (with create)";
		case AUTH:
			return "Authentication/Security Mechanism";
		case AVBL:
			return "Get the available space";
		case CCC:
			return "Clear Command Channel";
		case CDUP:
			return "Change to Parent Directory.";
		case CONF:
			return "Confidentiality Protection Command";
		case CSID:
			return "Client / Server Identification";
		case CWD:
			return "Change working directory.";
		case DELE:
			return "Delete file.";
		case DSIZ:
			return "Get the directory size";
		case ENC:
			return "Privacy Protected Channel";
		case EPRT:
			return "Specifies an extended address and port to which the server should connect.";
		case EPSV:
			return "Enter extended passive mode.";
		case FEAT:
			return "Get the feature list implemented by the server.";
		case HELP:
			return "Returns usage documentation on a command if specified, else a general help document is returned.";
		case HOST:
			return "Identify desired virtual host on server, by name.";
		case LANG:
			return "Language Negotiation";
		case LIST:
			return "Returns information of a file or directory if specified, else information of the current working "
				"directory is returned.";
		case LPRT:
			return "Specifies a long address and port to which the server should connect.";
		case LPSV:
			return "Enter long passive mode.";
		case MDTM:
			return "Return the last-modified time of a specified file.";
		case MFCT:
			return "Modify the creation time of a file.";
		case MFF:
			return "Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).";
		case MFMT:
			return "Modify the last modification time of a file.";
		case MIC:
			return "Integrity Protected Command";
		case MKD:
			return "Make directory.";
		case MLSD:
			return "Lists the contents of a directory in a standardized machine-readable format.";
		case MLST:
			return "Provides data about exactly the object named on its command line in a standardized "
				"machine-readable format.";
		case MODE:
			return "Sets the transfer mode (Stream, Block, or Compressed).";
		case NLST:
			return "Returns a list of file names in a specified directory.";
		case NOOP:
			return "No operation (dummy packet; used mostly on keepalives).";
		case OPTS:
			return "Select options for a feature (for example OPTS UTF8 ON).";
		case PASS:
			return "Authentication password.";
		case PASV:
			return "Enter passive mode.";
		case PBSZ:
			return "Protection Buffer Size";
		case PORT:
			return "Specifies an address and port to which the server should connect.";
		case PROT:
			return "Data Channel Protection Level.";
		case PWD:
			return "Print working directory. Returns the current directory of the host.";
		case QUIT:
			return "Disconnect.";
		case REIN:
			return "Re initializes the connection.";
		case REST:
			return "Restart transfer from the specified point.";
		case RETR:
			return "Retrieve a copy of the file";
		case RMD:
			return "Remove a directory.";
		case RMDA:
			return "Remove a directory tree";
		case RNFR:
			return "Rename from.";
		case RNTO:
			return "Rename to.";
		case SITE:
			return "Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE "
				"HELP output for complete list of supported commands.";
		case SIZE:
			return "Return the size of a file.";
		case SMNT:
			return "Mount file structure.";
		case SPSV:
			return "Use single port passive mode (only one TCP port number for both control connections and "
				"passive-mode data connections)";
		case STAT:
			return "Returns information on the server status, including the status of the current connection";
		case STOR:
			return "Accept the data and to store the data as a file at the server site";
		case STOU:
			return "Store file uniquely.";
		case STRU:
			return "Set file transfer structure.";
		case SYST:
			return "Return system type.";
		case THMB:
			return "Get a thumbnail of a remote image file";
		case TYPE:
			return "Sets the transfer mode (ASCII/Binary).";
		case USER:
			return "Authentication username.";
		case XCUP:
			return "Change to the parent of the current working directory";
		case XMKD:
			return "Make a directory";
		case XPWD:
			return "Print the current working directory";
		case XRCP:
			return "";
		case XRMD:
			return "Remove the directory";
		case XRSQ:
			return "";
		case XSEM:
			return "Send, mail if cannot";
		case XSEN:
			return "Send to terminal";
		default:
			return "Unknown command";
		}
	}

	std::string FtpRequestLayer::getCommandAsString(FtpCommand code)
	{
		std::stringstream oss;
		for (size_t idx = 0; idx < 4; ++idx)
			oss << char((code >> (8 * idx)) & UINT8_MAX);
		return oss.str();
	}

	std::string FtpRequestLayer::toString() const
	{
		return "FTP Request: " + getCommandString();
	}

	// ----------------- Class FtpResponseLayer -----------------
	FtpResponseLayer::FtpResponseLayer()
	{
		m_Protocol = FTP;
		m_Data = NULL;
		m_DataLen = 0;
	}

	void FtpResponseLayer::setStatusCode(FtpStatusCode code)
	{
		std::ostringstream oss;
		oss << code;
		setCommandField(oss.str());
	}

	FtpResponseLayer::FtpStatusCode FtpResponseLayer::getStatusCode() const
	{
		return static_cast<FtpStatusCode>(atoi(getCommandField().c_str()));
	}

	std::string FtpResponseLayer::getStatusCodeString() const
	{
		return getCommandField();
	}

	void FtpResponseLayer::setStatusOption(std::string value)
	{
		setOptionField(value);
	}

	std::string FtpResponseLayer::getStatusOption(bool removeEscapeCharacters) const
	{
		if (removeEscapeCharacters)
		{
			std::stringstream ss;
			std::string field = getOptionField();
			for (size_t idx = 0; idx < field.size(); ++idx)
			{
				if (int(field.c_str()[idx]) < 127 && int(field.c_str()[idx]) > 31) // From SPACE to ~
					ss << field.c_str()[idx];
			}
			return ss.str();
		}
		return getOptionField();
	}

	std::string FtpResponseLayer::getStatusCodeAsString(FtpStatusCode code)
	{
		switch (code)
		{
		case RESTART_MARKER:
			return "Restart marker reply";
		case SERVICE_READY_IN_MIN:
			return "Service ready in nnn minutes";
		case DATA_ALREADY_OPEN_START_TRANSFER:
			return "Data connection already open; transfer starting";
		case FILE_OK:
			return "File status okay; about to open data connection";
		case COMMAND_OK:
			return "Command okay";
		case COMMAND_NOT_IMPLEMENTED_SUPERFLUOUS:
			return "Command not implemented, superfluous at this site";
		case SYSTEM_STATUS:
			return "System status, or system help reply";
		case DIR_STATUS:
			return "Directory status";
		case FILE_STATUS:
			return "File status";
		case HELP_MESSAGE:
			return "Help message";
		case NAME_SYSTEM_TYPE:
			return "NAME system type";
		case SERVICE_READY_FOR_USER:
			return "Service ready for new user";
		case SERVICE_CLOSING_CONTROL:
			return "Service closing control connection";
		case DATA_OPEN_NO_TRANSFER:
			return "Data connection open; no transfer in progress";
		case CLOSING_DATA:
			return "Closing data connection";
		case ENTERING_PASSIVE:
			return "Entering Passive Mode";
		case ENTERING_EXTENDED_PASSIVE:
			return "Entering Extended Passive Mode";
		case USER_LOG_IN_PROCEED:
			return "User logged in, proceed";
		case USER_LOG_IN_AUTHORIZED:
			return "User logged in, authorized by security data exchange";
		case SEC_DATA_EXCHANGE_COMPLETE:
			return "Security data exchange complete";
		case SEC_DATA_EXCHANGE_COMPLETE_SUCCESS:
			return "Security data exchange completed successfully";
		case REQ_FILE_OK_COMPLETE:
			return "Requested file action okay, completed";
		case PATHNAME_CREATED:
			return "PATHNAME created";
		case USER_OK_NEED_PASSWORD:
			return "User name okay, need password";
		case NEED_ACCOUNT:
			return "Need account for login";
		case REQ_SEC_MECHANISM_OK:
			return "Requested security mechanism is ok";
		case SEC_IS_ACCEPTABLE:
			return "Security data is acceptable, more is required";
		case USER_OK_NEED_PASS_CHALLENGE:
			return "Username okay, need password. Challenge is ...";
		case FILE_PENDING_ACTION:
			return "Requested file action pending further information";
		case SERVICE_NOT_AVAILABLE:
			return "Service not available, closing control connection";
		case CANT_OPEN_DATA_CONNECTION:
			return "Can't open data connection";
		case CONNECTION_CLOSED:
			return "Connection closed; transfer aborted";
		case NEED_UNAVAILABLE_RESOURCE_TO_SEC:
			return "Need some unavailable resource to process security";
		case REQ_FILE_ACTION_NOT_TAKEN:
			return "Requested file action not taken";
		case REQ_ACTION_ABORTED:
			return "Requested action aborted: local error in processing";
		case REQ_ACTION_NOT_TAKEN:
			return "Requested action not taken. Insufficient storage space in system";
		case SYNTAX_ERROR_COMMAND_UNRECOGNIZED:
			return "Syntax error, command unrecognized";
		case SYNTAX_ERROR_PARAMETER_OR_ARGUMENT:
			return "Syntax error in parameters or arguments";
		case COMMAND_NOT_IMPLEMENTED:
			return "Command not implemented";
		case BAD_SEQUENCE_COMMANDS:
			return "Bad sequence of commands";
		case COMMAND_NOT_IMPLEMENTED_FOR_PARAMETER:
			return "Command not implemented for that parameter";
		case NETWORK_PROTOCOL_NOT_SUPPORTED:
			return "Network protocol not supported";
		case NOT_LOGGED_IN:
			return "Not logged in";
		case NEED_ACCOUNT_FOR_STORE_FILE:
			return "Need account for storing files";
		case COMMAND_PROTECTION_DENIED:
			return "Command protection level denied for policy reasons";
		case REQUEST_DENIED:
			return "Request denied for policy reasons";
		case FAILED_SEC_CHECK:
			return "Failed security check (hash, sequence, etc)";
		case REQ_PROT_LEVEL_NOT_SUPPORTED:
			return "Requested PROT level not supported by mechanism";
		case COMMAND_PROTECTION_LEVEL_NOT_SUPPORTED:
			return "Command protection level not supported by security mechanism";
		case FILE_UNAVAILABLE:
			return "Requested action not taken: File unavailable";
		case PAGE_TYPE_UNKNOWN:
			return "Requested action aborted: page type unknown";
		case EXCEED_STORAGE_ALLOCATION:
			return "Requested file action aborted: Exceeded storage allocation";
		case FILENAME_NOT_ALLOWED:
			return "Requested action not taken: File name not allowed";
		case INTEGRITY_PROTECTED:
			return "Integrity protected reply";
		case CONFIDENTIALITY_AND_INTEGRITY_PROTECTED:
			return "Confidentiality and integrity protected reply";
		case CONFIDENTIALITY_PROTECTED:
			return "Confidentiality protected reply";
		default:
			return "Unknown Status Code";
		}
	}

	std::string FtpResponseLayer::toString() const
	{
		return "FTP Response: " + getStatusCodeString();
	}

} // namespace pcpp
