#ifndef PCAPPP_PORT_LIST
#define PCAPPP_PORT_LIST

#include <stdint.h>
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class PortList
	 * The class that manages the port list. The port list can be changed in runtime.
	 * Its main purpose is to be used in a class that depends on port numbers and that allows to customize the ports in runtime.
	 * All the main methods have a constant complexity. The only disadvantage is that it has 64 Kilobytes in size, so it's better to use it as static class member.
	 * The performance of lookup is almost the same as a function with the hard-coded port numbers (with using of an operator <switch>).
	 */
	class PortList
	{
	public:
		/**
		 * The default constructor that creates an empty list
		 */
		PortList() : m_Ports(65536, false) {}

		/**
		 * A constructor that creates an object by the port number
		 * @param[in] p1 A port number
		 */
		inline PortList(uint16_t p1);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p8 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12,	uint16_t p13);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 * @param[in] p14 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 * @param[in] p14 A port number
		 * @param[in] p15 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 * @param[in] p14 A port number
		 * @param[in] p15 A port number
		 * @param[in] p16 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 * @param[in] p14 A port number
		 * @param[in] p15 A port number
		 * @param[in] p16 A port number
		 * @param[in] p17 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 * @param[in] p14 A port number
		 * @param[in] p15 A port number
		 * @param[in] p16 A port number
		 * @param[in] p17 A port number
		 * @param[in] p18 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 * @param[in] p14 A port number
		 * @param[in] p15 A port number
		 * @param[in] p16 A port number
		 * @param[in] p17 A port number
		 * @param[in] p19 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 * @param[in] p7 A port number
		 * @param[in] p9 A port number
		 * @param[in] p10 A port number
		 * @param[in] p11 A port number
		 * @param[in] p12 A port number
		 * @param[in] p13 A port number
		 * @param[in] p14 A port number
		 * @param[in] p15 A port number
		 * @param[in] p16 A port number
		 * @param[in] p17 A port number
		 * @param[in] p19 A port number
		 * @param[in] p20 A port number
		 */
		inline PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19, uint16_t p20);

		/**
		 * This method inserts a port number to the list with constant complexity
		 * @param[in] port The port number to be inserted
		 */
		void insert(uint16_t port) { m_Ports[port] = true; }

		/**
		 * This method removes a port number from the list with constant complexity
		 * @param[in] port The port number to be removed
		 */
		void remove(uint16_t port) { m_Ports[port] = false; }

		/**
		 * Checks wether the certain port stored in the list with constant complexity
		 * @param[in] port The port number to be checked
		 * @return True if the port number is contained in the list, False otherwise
		 */
		bool contains(uint16_t port) const { return m_Ports[port]; }

		/**
		 * @return The vector filled by the port numbers which are stored in the list
		 */
		std::vector<uint16_t> getPorts() const
		{
			const uint32_t portsLen = sizeof(m_Ports) / sizeof(m_Ports[0]);
			std::vector<uint16_t> result;
			result.reserve(20);

			for (uint32_t i = 0; i < portsLen; ++i)
				if (m_Ports[i] == true)
					result.push_back(static_cast<uint16_t>(i));

			return result;
		}

	protected:
		std::vector<bool> m_Ports;
	}; // class PortList



	
	// implementation of inline methods

	PortList::PortList(uint16_t p1)
		: m_Ports(65536, false)
	{
		m_Ports[p1] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] =
			m_Ports[p14] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] =
			m_Ports[p14] =
			m_Ports[p15] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] =
			m_Ports[p14] =
			m_Ports[p15] =
			m_Ports[p16] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] = 
			m_Ports[p14] =
			m_Ports[p15] =
			m_Ports[p16] =
			m_Ports[p17] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] =
			m_Ports[p14] =
			m_Ports[p15] =
			m_Ports[p16] =
			m_Ports[p17] =
			m_Ports[p18] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] =
			m_Ports[p14] =
			m_Ports[p15] =
			m_Ports[p16] =
			m_Ports[p17] =
			m_Ports[p18] =
			m_Ports[p19] = true;
	}

	PortList::PortList(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19, uint16_t p20)
		: m_Ports(65536, false)
	{
		m_Ports[p1] =
			m_Ports[p2] =
			m_Ports[p3] =
			m_Ports[p4] =
			m_Ports[p5] =
			m_Ports[p6] =
			m_Ports[p7] =
			m_Ports[p8] =
			m_Ports[p9] =
			m_Ports[p10] =
			m_Ports[p11] =
			m_Ports[p12] =
			m_Ports[p13] =
			m_Ports[p14] =
			m_Ports[p15] =
			m_Ports[p16] =
			m_Ports[p17] =
			m_Ports[p18] =
			m_Ports[p19] =
			m_Ports[p20] = true;
	}


} // namespace pcpp

#endif /* PCAPPP_PORT_LIST */
