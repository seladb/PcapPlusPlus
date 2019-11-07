#ifndef PCAPPP_PORT_LIST
#define PCAPPP_PORT_LIST

#include <stdint.h>
#include <algorithm>

#define MAX_NUM_OF_PORTS 32

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class PortList
	 * TODO:
	 */
	class PortList
	{
	public:
		PortList() : m_PortsCount(0), m_Ports() {}

		PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5,
			uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10)
			: m_PortsCount(10), m_Ports { p1, p2, p3, p4, p5, p6, p7, p8, p9, p10 }
		{
		}

		bool insert(uint16_t port)
		{
			if(port < MAX_NUM_OF_PORTS && m_PortsCount < MAX_NUM_OF_PORTS)
			{
				const uint16_t* start = m_Ports, *end = m_Ports + m_PortsCount;
				if(std::find(start, end, port) == end)
					m_Ports[m_PortsCount++] = port;
				return true;
			}
			return false;
		}

		bool contains(uint16_t port) const
		{
			const uint16_t* start = m_Ports, *end = m_Ports + m_PortsCount;
			return std::find(start, end, port) != end;
		}

		bool remove(uint16_t port)
		{
			// TODO:
			return true;
		}

	protected:
		uint16_t m_PortsCount;
		uint16_t m_Ports[MAX_NUM_OF_PORTS];
	};


} // namespace pcpp

#endif /* PCAPPP_PORT_LIST */
