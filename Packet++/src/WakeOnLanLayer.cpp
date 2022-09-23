#define LOG_MODULE PacketLogModuleWakeOnLanLayer

#include "WakeOnLanLayer.h"
#include "Logger.h"


namespace pcpp
{

WakeOnLanLayer::WakeOnLanLayer(const pcpp::MacAddress &targetAddr)
{
	m_Data = new uint8_t[sizeof(wol_header)];
	m_DataLen = sizeof(wol_header);
	m_Protocol = WakeOnLan;

	// Init fields
	memset(getWakeOnLanHeader()->sync, 0xFF, 6);
	setTargetAddr(targetAddr);
}

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
	if (m_DataLen - sizeof(wol_header) == 4)
		return IPv4Address(&m_Data[sizeof(wol_header)]).toString();
	if (m_DataLen - sizeof(wol_header) == 6)
		return MacAddress(&m_Data[sizeof(wol_header)]).toString();
	return std::string((char *)&m_Data[sizeof(wol_header)], m_DataLen - sizeof(wol_header));
}

bool WakeOnLanLayer::setPassword(const uint8_t *password, uint8_t len)
{
	if (len)
	{
		if (m_DataLen > sizeof(wol_header) + len)
		{
			if (!shortenLayer(0, m_DataLen - (sizeof(wol_header) + len)))
			{
				PCPP_LOG_ERROR("Can't shorten Wake on LAN layer");
				return false;
			}
		}
		else if (m_DataLen < sizeof(wol_header) + len)
		{
			if (!extendLayer(m_DataLen, (sizeof(wol_header) + len) - m_DataLen))
			{
				PCPP_LOG_ERROR("Can't extend Wake on LAN layer");
				return false;
			}
		}
		memcpy(&m_Data[sizeof(wol_header)], password, len);
	}

	return true;
}

bool WakeOnLanLayer::setPassword(const std::string &password)
{
	return setPassword((uint8_t *)password.c_str(), password.size());
}

bool WakeOnLanLayer::setPassword(const MacAddress &addr)
{
	return setPassword(addr.getRawData(), 6);
}

bool WakeOnLanLayer::setPassword(const IPv4Address &addr)
{
	return setPassword(addr.toBytes(), 4);
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
