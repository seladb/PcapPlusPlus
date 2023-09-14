#ifndef PACKETPP_SMTP_LAYER
#define PACKETPP_SMTP_LAYER

#include "PayloadLayer.h"
#include "SingleCommandTextProtocol.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * Class for general SMTP message
	 */
	class SmtpLayer : public SingleCommandTextProtocol
	{
	  protected:
		SmtpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: SingleCommandTextProtocol(data, dataLen, prevLayer, packet)
		{
			m_Protocol = SMTP;
		};
		SmtpLayer(const std::string &command, const std::string &option) : SingleCommandTextProtocol(command, option)
		{
			m_Protocol = SMTP;
		};

	  public:
		/**
		 * A static method that checks whether the port is considered as SMTP control
		 * @param[in] port The port number to be checked
		 */
		static bool isSmtpPort(uint16_t port) { return port == 25 || port == 587; }

		// overridden methods

		/// SMTP is the always last so does nothing for this layer
		void parseNextLayer() {}

		/**
		 * @return Get the size of the layer
		 */
		size_t getHeaderLen() const { return m_DataLen; }

		/// Does nothing for this layer
		void computeCalculateFields() {}

		/**
		 * @return The OSI layer level of SMTP (Application Layer).
		 */
		OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }
	};

	/**
	 * Class for representing the request messages of SMTP Layer
	 */
	class SmtpRequestLayer : public SmtpLayer
	{
	  public:
		/**
		 * Enum for SMTP command codes
		 */
		enum class SmtpCommand : int
		{
			/// Unknown command
			UNK,
			/// Sender identification
			HELO = ('H') | ('E' << 8) | ('L' << 16) | ('O' << 24),
			/// Originator of the mail
			MAIL = ('M') | ('A' << 8) | ('I' << 16) | ('L' << 24),
			/// Mail recipient
			RCPT = ('R') | ('C' << 8) | ('P' << 16) | ('T' << 24),
			/// Beginning of mail
			DATA = ('D') | ('A' << 8) | ('T' << 16) | ('A' << 24),
			/// Close connection
			QUIT = ('Q') | ('U' << 8) | ('I' << 16) | ('T' << 24),
			/// Abort mail transaction
			RSET = ('R') | ('S' << 8) | ('E' << 16) | ('T' << 24),
			/// Verify username
			VRFY = ('V') | ('R' << 8) | ('F' << 16) | ('Y' << 24),
			/// No operation
			NOOP = ('N') | ('O' << 8) | ('O' << 16) | ('P' << 24),
			/// Reverse the role of sender and receiver
			TURN = ('T') | ('U' << 8) | ('R' << 16) | ('N' << 24),
			/// Expand mailing list
			EXPN = ('E') | ('X' << 8) | ('P' << 16) | ('N' << 24),
			/// System specific documentation
			HELP = ('H') | ('E' << 8) | ('L' << 16) | ('P' << 24),
			/// Send mail to terminal
			SEND = ('S') | ('E' << 8) | ('N' << 16) | ('D' << 24),
			/// Send mail to terminal or to mailbox
			SOML = ('S') | ('O' << 8) | ('M' << 16) | ('L' << 24),
			/// Send mail to terminal and mailbox
			SAML = ('S') | ('A' << 8) | ('M' << 16) | ('L' << 24)
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SmtpRequestLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: SmtpLayer(data, dataLen, prevLayer, packet){};

		/**
		 * A constructor that creates layer with provided input values
		 * @param[in] command SMTP command
		 * @param[in] option Argument of the command
		 */
		explicit SmtpRequestLayer(const SmtpCommand &command, const std::string &option = "")
			: SmtpLayer(getCommandAsString(command), option){};

		/**
		 * Set the command of request message
		 * @param[in] code Value to set command
		 * @return True if the operation is successful, false otherwise
		 */
		bool setCommand(SmtpCommand code);

		/**
		 * Get the command of request message
		 * @return SmtpCommand Value of the command
		 */
		SmtpCommand getCommand() const;

		/**
		 * Get the command of request message as string
		 * @return std::string Value of the command as string
		 */
		std::string getCommandString() const;

		/**
		 * Set the command argument of request message
		 * @param[in] value Value to set command argument
		 * @return True if the operation is successful, false otherwise
		 */
		bool setCommandOption(const std::string &value);

		/**
		 * Get the command argument of request message
		 * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		 * @return std::string Value of command argument
		 */
		std::string getCommandOption(bool removeEscapeCharacters = true) const;

		/**
		 * Convert the command info to readable string
		 * @param[in] code Command code to convert
		 * @return std::string Returns the command info as readable string
		 */
		static std::string getCommandInfo(SmtpCommand code);

		/**
		 * Convert the command to readable string
		 * @param[in] code Command code to convert
		 * @return std::string Returns the command as readable string
		 */
		static std::string getCommandAsString(SmtpCommand code);

		// overridden methods

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};

	/**
	 * Class for representing the response messages of SMTP Layer
	 */
	class SmtpResponseLayer : public SmtpLayer
	{
	  public:
		/**
		 * Enum for SMTP response codes
		 */
		enum class SmtpStatusCode : int
		{
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SmtpResponseLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: SmtpLayer(data, dataLen, prevLayer, packet){};

		/**
		 * A constructor that creates layer with provided input values
		 * @param[in] code Status code
		 * @param[in] option Argument of the status code
		 */
		explicit SmtpResponseLayer(const SmtpStatusCode &code, const std::string &option = "")
			: SmtpLayer(std::to_string(int(code)), option){};

		/**
		 * Set the status code of response message
		 * @param[in] code Value to set status code
		 * @return True if the operation is successful, false otherwise
		 */
		bool setStatusCode(SmtpStatusCode code);

		/**
		 * Get the status code of response message
		 * @return SmtpStatusCode Value of the status code
		 */
		SmtpStatusCode getStatusCode() const;

		/**
		 * Get the status code of response message as string
		 * @return std::string Value of the status code as string
		 */
		std::string getStatusCodeString() const;

		/**
		 * Set the argument of response message
		 * @param[in] value Value to set argument
		 * @return True if the operation is successful, false otherwise
		 */
		bool setStatusOption(const std::string &value);

		/**
		 * Get the argument of response message
		 * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		 * @return std::string Value of argument
		 */
		std::string getStatusOption(bool removeEscapeCharacters = true) const;

		/**
		 * Convert the status code to readable string
		 * @param[in] code Status code to convert
		 * @return std::string Returns the status info as readable string
		 */
		static std::string getStatusCodeAsString(SmtpStatusCode code);

		// overridden methods

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};
} // namespace pcpp

#endif /* PACKETPP_SMTP_LAYER */