#ifndef PACKETPP_SMTP_LAYER
#define PACKETPP_SMTP_LAYER

#include "PayloadLayer.h"
#include "SingleCommandTextProtocol.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Class for general SMTP message
	class SmtpLayer : public SingleCommandTextProtocol
	{
	protected:
		SmtpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SingleCommandTextProtocol(data, dataLen, prevLayer, packet, SMTP) {};

		SmtpLayer(const std::string& command, const std::string& option)
		    : SingleCommandTextProtocol(command, option, SMTP) {};

	public:
		/// A static method that checks whether the port is considered as SMTP control
		/// @param[in] port The port number to be checked
		/// @return True if this an SMTP port (25 or 587)
		static bool isSmtpPort(uint16_t port)
		{
			return port == 25 || port == 587;
		}

		// overridden methods

		/// SMTP is the always last so does nothing for this layer
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

		/// @return The OSI layer level of SMTP (Application Layer).
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}
	};

	/// Class for representing the request messages of SMTP Layer
	class SmtpRequestLayer : public SmtpLayer
	{
	public:
		/// Enum for SMTP command codes
		enum class SmtpCommand : uint64_t
		{
			/// Unknown command
			UNK,
			/// Starting mail body
			DATA = ('D') | ('A' << 8) | ('T' << 16) | ('A' << 24),
			/// Initiate conversation
			EHLO = ('E') | ('H' << 8) | ('L' << 16) | ('O' << 24),
			/// Expand the mailing list
			EXPN = ('E') | ('X' << 8) | ('P' << 16) | ('N' << 24),
			/// Initiate conversation
			HELO = ('H') | ('E' << 8) | ('L' << 16) | ('O' << 24),
			/// Ask information
			HELP = ('H') | ('E' << 8) | ('L' << 16) | ('P' << 24),
			/// Sender indication
			MAIL = ('M') | ('A' << 8) | ('I' << 16) | ('L' << 24),
			/// No operation
			NOOP = ('N') | ('O' << 8) | ('O' << 16) | ('P' << 24),
			/// Close conversation
			QUIT = ('Q') | ('U' << 8) | ('I' << 16) | ('T' << 24),
			/// Receiver indication
			RCPT = ('R') | ('C' << 8) | ('P' << 16) | ('T' << 24),
			/// Abort transaction
			RSET = ('R') | ('S' << 8) | ('E' << 16) | ('T' << 24),
			/// Identify user
			VRFY = ('V') | ('R' << 8) | ('F' << 16) | ('Y' << 24),
			/// Start TLS handshake
			STARTTLS = (('S') | ('T' << 8) | ('A' << 16) | ('R' << 24) |
			            static_cast<uint64_t>(('T') | ('T' << 8) | ('L' << 16) | ('S' << 24)) << 32),
			/// Reverse the role of sender and receiver
			TURN = ('T') | ('U' << 8) | ('R' << 16) | ('N' << 24),
			/// Send mail to terminal
			SEND = ('S') | ('E' << 8) | ('N' << 16) | ('D' << 24),
			/// Send mail to terminal or to mailbox
			SOML = ('S') | ('O' << 8) | ('M' << 16) | ('L' << 24),
			/// Send mail to terminal and mailbox
			SAML = ('S') | ('A' << 8) | ('M' << 16) | ('L' << 24),
			/// Authenticate client and server
			AUTH = ('A') | ('U' << 8) | ('T' << 16) | ('H' << 24),
			/// Reverse the role of sender and receiver
			ATRN = ('A') | ('T' << 8) | ('R' << 16) | ('N' << 24),
			/// Submit mail contents
			BDAT = ('B') | ('D' << 8) | ('A' << 16) | ('T' << 24),
			/// Request to start SMTP queue processing
			ETRN = ('E') | ('T' << 8) | ('R' << 16) | ('N' << 24),
			/// Release status of the channel
			XADR = ('X') | ('A' << 8) | ('D' << 16) | ('R' << 24),
			/// Release status of the circuit checking facility
			XCIR = ('X') | ('C' << 8) | ('I' << 16) | ('R' << 24),
			/// Release status of the number of messages in channel queues
			XSTA = ('X') | ('S' << 8) | ('T' << 16) | ('A' << 24),
			/// Release status of whether a compiled configuration and character set are in use
			XGEN = ('X') | ('G' << 8) | ('E' << 16) | ('N' << 24)
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		SmtpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SmtpLayer(data, dataLen, prevLayer, packet) {};

		/// A constructor that creates layer with provided input values
		/// @param[in] command SMTP command
		/// @param[in] option Argument of the command
		explicit SmtpRequestLayer(const SmtpCommand& command, const std::string& option = "")
		    : SmtpLayer(getCommandAsString(command), option) {};

		/// Set the command of request message
		/// @param[in] code Value to set command
		/// @return True if the operation is successful, false otherwise
		bool setCommand(SmtpCommand code);

		/// Get the command of request message
		/// @return Value of the command
		SmtpCommand getCommand() const;

		/// Get the command of request message as string
		/// @return Value of the command as string
		std::string getCommandString() const;

		/// Set the command argument of request message
		/// @param[in] value Value to set command argument
		/// @return True if the operation is successful, false otherwise
		bool setCommandOption(const std::string& value);

		/// Get the command argument of request message
		/// @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		/// @return Value of command argument
		std::string getCommandOption(bool removeEscapeCharacters = true) const;

		/// Convert the command info to readable string
		/// @param[in] code Command code to convert
		/// @return Returns the command info as readable string
		static std::string getCommandInfo(SmtpCommand code);

		/// Convert the command to readable string
		/// @param[in] code Command code to convert
		/// @return Returns the command as readable string
		static std::string getCommandAsString(SmtpCommand code);

		// overridden methods

		/// @return Returns the protocol info as readable string
		std::string toString() const override;
	};

	/// Class for representing the response messages of SMTP Layer
	class SmtpResponseLayer : public SmtpLayer
	{
	public:
		/// Enum for SMTP response codes
		enum class SmtpStatusCode : int
		{
			/// System status, or system help reply
			SYSTEM_STATUS = 211,
			/// Help message
			HELP_MESSAGE = 214,
			/// \<domain\> Service ready
			SERVICE_READY = 220,
			/// \<domain\> Service closing transmission channel
			SERVICE_CLOSE = 221,
			/// Authentication successful
			AUTH_SUCCESS = 235,
			/// Requested mail action okay, completed
			COMPLETED = 250,
			/// User not local; will forward to <forward-path>
			WILL_FORWARD = 251,
			/// Cannot VRFY user, but will accept message and attempt delivery
			CANNOT_VERIFY = 252,
			/// AUTH input
			AUTH_INPUT = 334,
			/// Start mail input; end with \<CRLF\>.\<CRLF\>
			MAIL_INPUT = 354,
			/// \<domain\> Service not available, closing transmission channel
			SERVICE_UNAVAILABLE = 421,
			/// A password transition is needed
			PASS_NEEDED = 432,
			/// Requested mail action not taken: mailbox unavailable (mail busy or temporarily blocked)
			MAILBOX_UNAVAILABLE_TEMP = 450,
			/// Requested action aborted: local error in processing
			ABORT_LOCAL_ERROR = 451,
			/// Requested action not taken: insufficient system storage
			INSUFFICIENT_STORAGE = 452,
			/// Temporary authentication failed
			TEMP_AUTH_FAILED = 454,
			/// Server unable to accommodate parameters
			PARAM_NOT_ACCOMMODATED = 455,
			/// Syntax error, command unrecognized
			CMD_NOT_RECOGNIZED = 500,
			/// Syntax error in parameters or arguments
			SYNTAX_ERROR_PARAM = 501,
			/// Command not implemented
			CMD_NOT_IMPLEMENTED = 502,
			/// Bad sequence of commands
			CMD_BAD_SEQUENCE = 503,
			/// Command parameter not implemented
			PARAM_NOT_IMPLEMENTED = 504,
			/// Server does not accept mail
			MAIL_NOT_ACCEPTED = 521,
			/// Encryption needed
			ENCRYPT_NEED = 523,
			/// Authentication required
			AUTH_REQUIRED = 530,
			/// Authentication mechanism is too weak
			AUTH_TOO_WEAK = 534,
			/// Authentication credentials invalid
			AUTH_CRED_INVALID = 535,
			/// Encryption required for requested authentication mechanism
			ENCRYPT_REQUIRED = 538,
			/// Requested action not taken: mailbox unavailable
			MAILBOX_UNAVAILABLE = 550,
			/// User not local; please try <forward-path>
			USER_NOT_LOCAL = 551,
			/// Requested mail action aborted: exceeded storage allocation
			EXCEED_STORAGE = 552,
			/// Requested action not taken: mailbox name not allowed
			NAME_NOT_ALLOWED = 553,
			/// Transaction failed
			TRANSACTION_FAIL = 554,
			/// Domain does not accept mail
			DOMAIN_NOT_ACCEPT = 556
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		SmtpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SmtpLayer(data, dataLen, prevLayer, packet) {};

		/// A constructor that creates layer with provided input values
		/// @param[in] code Status code
		/// @param[in] option Argument of the status code
		explicit SmtpResponseLayer(const SmtpStatusCode& code, const std::string& option = "")
		    : SmtpLayer(std::to_string(int(code)), option) {};

		/// Set the status code of response message
		/// @param[in] code Value to set status code
		/// @return True if the operation is successful, false otherwise
		bool setStatusCode(SmtpStatusCode code);

		/// Get the status code of response message
		/// @return Value of the status code
		SmtpStatusCode getStatusCode() const;

		/// Get the status code of response message as string
		/// @return Value of the status code as string
		std::string getStatusCodeString() const;

		/// Set the argument of response message
		/// @param[in] value Value to set argument
		/// @return True if the operation is successful, false otherwise
		bool setStatusOption(const std::string& value);

		/// Get the argument of response message
		/// @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		/// @return Value of argument
		std::string getStatusOption(bool removeEscapeCharacters = true) const;

		/// Convert the status code to readable string
		/// @param[in] code Status code to convert
		/// @return Returns the status info as readable string
		static std::string getStatusCodeAsString(SmtpStatusCode code);

		// overridden methods

		/// @return Returns the protocol info as readable string
		std::string toString() const override;
	};
}  // namespace pcpp

#endif  // PACKETPP_SMTP_LAYER
