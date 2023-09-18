#define LOG_MODULE PacketLogModuleSmtpLayer

#include "SmtpLayer.h"

namespace pcpp
{
	// ----------------- Class SmtpRequestLayer -----------------
	bool SmtpRequestLayer::setCommand(SmtpCommand code) { return setCommandInternal(getCommandAsString(code)); }

	SmtpRequestLayer::SmtpCommand SmtpRequestLayer::getCommand() const
	{
		size_t val = 0;
		std::string field = getCommandString();

		for (size_t idx = 0; idx < field.size(); ++idx)
			val |= (field.c_str()[idx] << (idx * 8));

		return static_cast<SmtpCommand>(val);
	}

	std::string SmtpRequestLayer::getCommandString() const { return getCommandInternal(); }

	bool SmtpRequestLayer::setCommandOption(const std::string &value) { return setCommandOptionInternal(value); }

	std::string SmtpRequestLayer::getCommandOption(bool removeEscapeCharacters) const
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

	std::string SmtpRequestLayer::getCommandInfo(SmtpCommand code)
	{
		switch (code)
		{
		case SmtpCommand::HELO:
			return "Sender identification";
		case SmtpCommand::MAIL:
			return "Originator of the mail";
		case SmtpCommand::RCPT:
			return "Mail recipient";
		case SmtpCommand::DATA:
			return "Beginning of mail";
		case SmtpCommand::QUIT:
			return "Close connection";
		case SmtpCommand::RSET:
			return "Abort mail transaction";
		case SmtpCommand::VRFY:
			return "Verify username";
		case SmtpCommand::NOOP:
			return "No operation";
		case SmtpCommand::TURN:
			return "Reverse the role of sender and receiver";
		case SmtpCommand::EXPN:
			return "Expand mailing list";
		case SmtpCommand::HELP:
			return "System specific documentation";
		case SmtpCommand::SEND:
			return "Send mail to terminal";
		case SmtpCommand::SOML:
			return "Send mail to terminal or to mailbox";
		case SmtpCommand::SAML:
			return "Send mail to terminal and mailbox";
		default:
			return "Unknown command";
		}
	}

	std::string SmtpRequestLayer::getCommandAsString(SmtpCommand code)
	{
		std::stringstream oss;
		for (size_t idx = 0; idx < 4; ++idx)
			oss << char((int(code) >> (8 * idx)) & UINT8_MAX);
		return oss.str();
	}

	std::string SmtpRequestLayer::toString() const { return "SMTP Request: " + getCommandString(); }

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

	std::string SmtpResponseLayer::getStatusCodeString() const { return getCommandInternal(); }

	bool SmtpResponseLayer::setStatusOption(const std::string &value) { return setCommandOptionInternal(value); }

	std::string SmtpResponseLayer::getStatusOption(bool removeEscapeCharacters) const
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

	std::string SmtpResponseLayer::getStatusCodeAsString(SmtpStatusCode code)
	{
		switch (code)
		{
		case SmtpStatusCode::SYSTEM_STATUS:
			return "System status, or system help reply";
		case SmtpStatusCode::HELP_MESSAGE:
			return "Help message";
		case SmtpStatusCode::SERVER_READY:
			return "Server ready";
		case SmtpStatusCode::SERVER_CLOSE:
			return "Server closing transmission channel";
		case SmtpStatusCode::COMMAND_COMPLETE:
			return "Requested mail action okay, completed";
		case SmtpStatusCode::FORWARD_PATH:
			return "User not local; will forward";
		case SmtpStatusCode::CANNOT_VERIFY:
			return "Cannot VRFY user, but will accept message and attempt delivery";
		case SmtpStatusCode::SERVER_CHALLENGE:
			return "Server challenge";
		case SmtpStatusCode::START_MAIL:
			return "Start mail input";
		case SmtpStatusCode::SERVER_UNAVAILABLE:
			return "Service not available, closing transmission channel";
		case SmtpStatusCode::MAILBOX_UNAVAILABLE_TEMP:
			return "Requested mail action not taken: mailbox unavailable (mailbox busy or temporarily blocked)";
		case SmtpStatusCode::SERVER_ABORT_LOCAL:
			return "Requested action aborted: local error in processing";
		case SmtpStatusCode::SERVER_ABORT_STORAGE:
			return "Requested action not taken: insufficient system storage";
		case SmtpStatusCode::PARAM_NOT_ACCOMMODATED:
			return "Server unable to accommodate parameters";
		case SmtpStatusCode::SYNTAXX_ERROR_CMD:
			return "Syntax error, command unrecognized";
		case SmtpStatusCode::SYNTAX_ERROR_PARAM:
			return "Syntax error in parameters or arguments";
		case SmtpStatusCode::CMD_NOT_IMPLEMENTED:
			return "Command not implemented";
		case SmtpStatusCode::BAD_CMD_SEQUENCE:
			return "Bad sequence of commands";
		case SmtpStatusCode::PARAM_NOT_IMPLEMENTED:
			return "Command parameter not implemented";
		case SmtpStatusCode::NOT_ACCEPT:
			return "Server does not accept mail";
		case SmtpStatusCode::ENCRYPT_NEED:
			return "Encryption needed";
		case SmtpStatusCode::MAILBOX_UNAVAILABLE:
			return "Requested action not taken: mailbox unavailable (mailbox not found)";
		case SmtpStatusCode::USER_NOT_LOCAL:
			return "User not local";
		case SmtpStatusCode::EXCEED_STORAGE:
			return "Requested mail action aborted: exceeded storage allocation";
		case SmtpStatusCode::NAME_NOT_ALLOWED:
			return "Requested action not taken: mailbox name not allowed";
		case SmtpStatusCode::TRANSACTION_FAIL:
			return "Transaction failed";
		case SmtpStatusCode::DOMAIN_NOT_ACCEPT:
			return "Domain does not accept mail";
		default:
			return "Unknown Status Code";
		}
	}

	std::string SmtpResponseLayer::toString() const { return "SMTP Response: " + getStatusCodeString(); }

} // namespace pcpp
