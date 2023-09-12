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
		SmtpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : SingleCommandTextProtocol(data, dataLen, prevLayer, packet) { m_Protocol = SMTP; };
		SmtpLayer(const std::string &command, const std::string &option) : SingleCommandTextProtocol(command, option) { m_Protocol = SMTP; };

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
}

#endif /* PACKETPP_SMTP_LAYER */