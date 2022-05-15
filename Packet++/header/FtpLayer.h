#ifndef PACKETPP_FTP_LAYER
#define PACKETPP_FTP_LAYER

#include "TextBasedProtocol.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

    /**
     * Represents general FTP message
     */
    class FtpMessage : public TextBasedProtocolMessage
	{
        public:
        protected:
    };

    /**
     * Class for representing the request messages of FTP Layer
     */
    class FtpRequestLayer : public FtpMessage
    {
        private:
        public:
    };

    /**
     * Class for representing the response messages of FTP Layer
     */
    class FtpResponseLayer : public FtpMessage
    {
        private:
        public:
    };
} // namespace pcpp

#endif /* PACKETPP_FTP_LAYER */