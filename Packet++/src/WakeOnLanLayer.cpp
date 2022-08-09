#define LOG_MODULE PacketLogModuleWakeOnLanLayer

#include "WakeOnLanLayer.h"
#include "Logger.h"


namespace pcpp
{

    pcpp::MacAddress WakeOnLanLayer::getTargetAddr() const
    {
        return pcpp::MacAddress(getWakeOnLanHeader()->addrBody);
    }

    void WakeOnLanLayer::setTargetAddr(const pcpp::MacAddress &targetAddr)
    {
        for (size_t idx = 0; idx < 16; ++idx)
            memcpy(&(getWakeOnLanHeader()->addrBody[idx * 6]), targetAddr.getRawData(), 6);
    }

    std::string WakeOnLanLayer::getPassword() const
    {
		if (m_DataLen <= sizeof(wol_header))
			return "";
		return std::string((char *)&m_Data[sizeof(wol_header)], m_DataLen - sizeof(wol_header));
	}

    void WakeOnLanLayer::setPassword(const std::string &password)
    {

    }

    void WakeOnLanLayer::setPassword(const uint8_t *password, uint8_t len)
    {

    }

    bool WakeOnLanLayer::isDataValid(const uint8_t *data, size_t dataSize)
    {
        if (data && dataSize >= sizeof(wol_header))
        {
            // It should repeat same MAC address at the payload 16 times
            pcpp::MacAddress bufAddr(&data[6]);
            for (size_t idx = 1; idx < 16; ++idx)
            {
                if (bufAddr != pcpp::MacAddress(&data[6 + idx * 6]))
                    return false;
            }
            return true;
        }
        return false;
    }

    std::string WakeOnLanLayer::toString() const
    {
        return "Wake On LAN " + getTargetAddr().toString();
    }

} // namespace pcpp
