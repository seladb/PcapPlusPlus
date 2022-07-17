#ifndef PACKETPP_LINE_BASED_PROTOCOL_LAYER
#define PACKETPP_LINE_BASED_PROTOCOL_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * Class for general line based protocol (FTP, SMTP) message
	 */
	class LineBasedProtocolMessage : public Layer
	{
	private:
		size_t getArgumentFieldOffset() const;
		void setDelimiter(bool hyphen);
		bool hyphenRequired(std::string value);

	protected:
		LineBasedProtocolMessage(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet) {};
		LineBasedProtocolMessage() = default;

		void setCommandInternal(std::string value);
		void setCommandOptionInternal(std::string value);

		std::string getCommandInternal() const;
		std::string getCommandOptionInternal() const;

	public:

		/**
		 * Checks if the current message is a multi-line reply. Multi-line messages are indicated with a Hyphen (-) immediately after reply code.
		 * @return true If this is a multi-line reply
		 * @return false Otherwise
		 */
		bool isMultiLine() const;

		/**
		 * A static method that takes a byte array and detects whether it is a line based protocol message.
		 * All line based protocol message terminated with single "\r\n".
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as line based protocol message
		 */
		static bool isDataValid(const uint8_t *data, size_t dataSize);
	};
} // namespace pcpp

#endif /* PACKETPP_LINE_BASED_PROTOCOL_LAYER */
