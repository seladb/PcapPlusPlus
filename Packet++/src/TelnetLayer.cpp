#define LOG_MODULE PacketLogModuleTelnetLayer

#include "TelnetLayer.h"
#include "Logger.h"

namespace pcpp
{

    std::string TelnetLayer::toString() const
    {
        if (isData)
            return "Telnet Data";
        return "Telnet Control";
    }

} // namespace pcpp