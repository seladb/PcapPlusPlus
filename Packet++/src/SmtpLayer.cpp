#define LOG_MODULE PacketLogModuleSmtpLayer

#include "SmtpLayer.h"

#include <algorithm>

namespace pcpp
{
	// ----------------- Class SmtpRequestLayer -----------------
	bool SmtpRequestLayer::setCommand(SmtpCommand code)
	{
		return setCommandInternal(getCommandAsString(code));
	}

	SmtpRequestLayer::SmtpCommand SmtpRequestLayer::getCommand() const
	{
		size_t val = 0;
		std::string field = getCommandString();

		for (size_t idx = 0; idx < std::min(field.size(), static_cast<size_t>(8)); ++idx)
		{
			val |= static_cast<size_t>(field.c_str()[idx]) << (idx * 8);
		}

		return static_cast<SmtpCommand>(val);
	}

	std::string SmtpRequestLayer::getCommandString() const
	{
		return getCommandInternal();
	}

	bool SmtpRequestLayer::setCommandOption(const std::string& value)
	{
		return setCommandOptionInternal(value);
	}

	std::string SmtpRequestLayer::getCommandOption(bool removeEscapeCharacters) const
	{
		std::string option = getCommandOptionInternal();
		if (!removeEscapeCharacters)
		{
			return option;
		}

		std::string optionWithEscapeChars;
		for (char ch : option)
		{
			if (ch < 127 && ch > 31)
			{
				optionWithEscapeChars.push_back(ch);
			}
		}

		return optionWithEscapeChars;
	}

	std::string SmtpRequestLayer::getCommandInfo(SmtpCommand code)
	{
		switch (code)
		{
		case SmtpCommand::DATA:
			return "Starting mail body";
		case SmtpCommand::EHLO:
			return "Initiate conversation";
		case SmtpCommand::EXPN:
			return "Expand the mailing list";
		case SmtpCommand::HELO:
			return "Initiate conversation";
		case SmtpCommand::HELP:
			return "Ask information";
		case SmtpCommand::MAIL:
			return "Sender indication";
		case SmtpCommand::NOOP:
			return "No operation";
		case SmtpCommand::QUIT:
			return "Close conversation";
		case SmtpCommand::RCPT:
			return "Receiver indication";
		case SmtpCommand::RSET:
			return "Abort transaction";
		case SmtpCommand::VRFY:
			return "Identify user";
		case SmtpCommand::STARTTLS:
			return "Start TLS handshake";
		case SmtpCommand::TURN:
			return "Reverse the role of sender and receiver";
		case SmtpCommand::SEND:
			return "Send mail to terminal";
		case SmtpCommand::SOML:
			return "Send mail to terminal or to mailbox";
		case SmtpCommand::SAML:
			return "Send mail to terminal and mailbox";
		case SmtpCommand::AUTH:
			return "Authenticate client and server";
		case SmtpCommand::ATRN:
			return "Reverse the role of sender and receiver";
		case SmtpCommand::BDAT:
			return "Submit mail contents";
		case SmtpCommand::ETRN:
			return "Request to start SMTP queue processing";
		case SmtpCommand::XADR:
			return "Release status of the channel";
		case SmtpCommand::XCIR:
			return "Release status of the circuit checking facility";
		case SmtpCommand::XSTA:
			return "Release status of the number of messages in channel queues";
		case SmtpCommand::XGEN:
			return "Release status of whether a compiled configuration and character set are in use";
		default:
			return "Unknown command";
		}
	}

	std::string SmtpRequestLayer::getCommandAsString(SmtpCommand code)
	{
		std::stringstream oss;
		for (size_t idx = 0; idx < 8; ++idx)
		{
			char val = (uint64_t(code) >> (8 * idx)) & UINT8_MAX;
			if (val)  // Dont push if it is a null character
			{
				oss << val;
			}
		}
		return oss.str();
	}

	std::string SmtpRequestLayer::toString() const
	{
		return "SMTP request layer, command: " + getCommandInfo(getCommand());
	}

	// ----------------- Class SmtpResponseLayer -----------------
	bool SmtpResponseLayer::setStatusCode(SmtpStatusCode code)
	{
		std::ostringstream oss;
		oss << int(code);
		return setCommandInternal(oss.str());
	}

	SmtpResponseLayer::SmtpStatusCode SmtpResponseLayer::getStatusCode() const
	{
		return static_cast<SmtpStatusCode>(atoi(getCommandInternal().c_str()));
	}

	std::string SmtpResponseLayer::getStatusCodeString() const
	{
		return getCommandInternal();
	}

	bool SmtpResponseLayer::setStatusOption(const std::string& value)
	{
		return setCommandOptionInternal(value);
	}

	std::string SmtpResponseLayer::getStatusOption(bool removeEscapeCharacters) const
	{
		std::string option = getCommandOptionInternal();
		if (!removeEscapeCharacters)
		{
			return option;
		}

		std::string optionWithEscapeChars;
		for (char ch : option)
		{
			if (ch < 127 && ch > 31)
			{
				optionWithEscapeChars.push_back(ch);
			}
		}

		return optionWithEscapeChars;
	}

	std::string SmtpResponseLayer::getStatusCodeAsString(SmtpStatusCode code)
	{
		switch (code)
		{
		case SmtpStatusCode::SYSTEM_STATUS:
			return "System status, or system help reply";
		case SmtpStatusCode::HELP_MESSAGE:
			return "Help message";
		case SmtpStatusCode::SERVICE_READY:
			return "Service ready";
		case SmtpStatusCode::SERVICE_CLOSE:
			return "Service closing transmission channel";
		case SmtpStatusCode::AUTH_SUCCESS:
			return "Authentication successful";
		case SmtpStatusCode::COMPLETED:
			return "Requested mail action okay, completed";
		case SmtpStatusCode::WILL_FORWARD:
			return "User not local; will forward to <forward-path>";
		case SmtpStatusCode::CANNOT_VERIFY:
			return "Cannot VRFY user, but will accept message and attempt delivery";
		case SmtpStatusCode::AUTH_INPUT:
			return "AUTH input";
		case SmtpStatusCode::MAIL_INPUT:
			return "Start mail input; end with <CRLF>.<CRLF>";
		case SmtpStatusCode::SERVICE_UNAVAILABLE:
			return "Service not available, closing transmission channel";
		case SmtpStatusCode::PASS_NEEDED:
			return "A password transition is needed";
		case SmtpStatusCode::MAILBOX_UNAVAILABLE_TEMP:
			return "Requested mail action not taken: mailbox unavailable (mail busy or temporarily blocked)";
		case SmtpStatusCode::ABORT_LOCAL_ERROR:
			return "Requested action aborted: local error in processing";
		case SmtpStatusCode::INSUFFICIENT_STORAGE:
			return "Requested action not taken: insufficient system storage";
		case SmtpStatusCode::TEMP_AUTH_FAILED:
			return "Temporary authentication failed";
		case SmtpStatusCode::PARAM_NOT_ACCOMMODATED:
			return "Server unable to accommodate parameters";
		case SmtpStatusCode::CMD_NOT_RECOGNIZED:
			return "Syntax error, command unrecognized";
		case SmtpStatusCode::SYNTAX_ERROR_PARAM:
			return "Syntax error in parameters or arguments";
		case SmtpStatusCode::CMD_NOT_IMPLEMENTED:
			return "Command not implemented";
		case SmtpStatusCode::CMD_BAD_SEQUENCE:
			return "Bad sequence of commands";
		case SmtpStatusCode::PARAM_NOT_IMPLEMENTED:
			return "Command parameter not implemented";
		case SmtpStatusCode::MAIL_NOT_ACCEPTED:
			return "Server does not accept mail";
		case SmtpStatusCode::ENCRYPT_NEED:
			return "Encryption needed";
		case SmtpStatusCode::AUTH_REQUIRED:
			return "Authentication required";
		case SmtpStatusCode::AUTH_TOO_WEAK:
			return "Authentication mechanism is too weak";
		case SmtpStatusCode::AUTH_CRED_INVALID:
			return "Authentication credentials invalid";
		case SmtpStatusCode::ENCRYPT_REQUIRED:
			return "Encryption required for requested authentication mechanism";
		case SmtpStatusCode::MAILBOX_UNAVAILABLE:
			return "Requested action not taken: mailbox unavailable";
		case SmtpStatusCode::USER_NOT_LOCAL:
			return "User not local; please try <forward-path>";
		case SmtpStatusCode::EXCEED_STORAGE:
			return "Requested mail action aborted: exceeded storage allocation";
		case SmtpStatusCode::NAME_NOT_ALLOWED:
			return "Requested action not taken: mailbox name not allowed";
		case SmtpStatusCode::TRANSACTION_FAIL:
			return "Transaction failed";
		case SmtpStatusCode::DOMAIN_NOT_ACCEPT:
			return "Domain does not accept mail";
		default:
			return "Unknown status code";
		}
	}

	std::string SmtpResponseLayer::toString() const
	{
		return "SMTP response layer, status code: " + getStatusCodeAsString(getStatusCode());
	}

}  // namespace pcpp
