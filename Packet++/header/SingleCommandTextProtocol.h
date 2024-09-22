#pragma once

#include <sstream>
#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * Class for single command text based protocol (FTP, SMTP) messages
	 */
	class SingleCommandTextProtocol : public Layer
	{
	private:
		size_t getArgumentFieldOffset() const;
		void setDelimiter(bool hyphen);
		bool hyphenRequired(const std::string& value);

	protected:
		SingleCommandTextProtocol(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet,
		                          ProtocolType protocol)
		    : Layer(data, dataLen, prevLayer, packet, protocol) {};

		SingleCommandTextProtocol(const std::string& command, const std::string& option, ProtocolType protocol);

		bool setCommandInternal(std::string value);
		bool setCommandOptionInternal(std::string value);

		std::string getCommandInternal() const;
		std::string getCommandOptionInternal() const;

	public:
		/**
		 * Checks if the current message is a multi-line reply. Multi-line messages are indicated with a Hyphen (-)
		 * immediately after reply code.
		 * @return true If this is a multi-line reply
		 * @return false Otherwise
		 */
		bool isMultiLine() const;

		/**
		 * A static method that takes a byte array and detects whether it is a single command text based message.
		 * All single command text based message terminated with single "\r\n".
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as single command text based message
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize);
	};
}  // namespace pcpp
