#ifndef PCAPPP_PORT_LIST2
#define PCAPPP_PORT_LIST2

#include <stdint.h>
#include <vector>
#include <algorithm>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class PortList2
	 * The class that manages the port list. This list can be changed in runtime.
	 * Its main purpose is to be used in a class that depends on port numbers and that allows to customize the port numbers in runtime.
	 */
	class PortList2
	{
	public:

		enum
		{
			/**
			 * The maximum number of ports supported by this class
			 */
			PortMaxSize = 20
		};

		/**
		 * The default constructor that creates an empty list
		 */
		PortList2() : m_PortSize(0), m_Ports() {}

		/**
		 * A constructor that creates an object by the port number
		 * @param[in] p1 A port number
		 */
		inline PortList2(uint16_t p1);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 */
		inline PortList2(uint16_t p1, uint16_t p2);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 */
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 */
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 */
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5);

		/**
		 * A constructor that creates an object by the port list
		 * @param[in] p1 A port number
		 * @param[in] p2 A port number
		 * @param[in] p3 A port number
		 * @param[in] p4 A port number
		 * @param[in] p5 A port number
		 * @param[in] p6 A port number
		 */
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12,	uint16_t p13);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19);

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
		inline PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11, uint16_t p12, uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19, uint16_t p20);


		/**
		 * @return The number of ports currently stored in object. It cannot exceed the PortMaxSize.
		 */
		size_t size() const { return m_PortSize; }

		/**
		 * Checks wheter the list is empty
		 * @return True if the list does not contain any port, False otherwise
		 */
		bool empty() const { return m_PortSize == 0; }

		/**
		 * Checks wheter the list is full
		 * @return True if the list full, False otherwise
		 */
		bool full() const { return size() == PortMaxSize; }

		/**
		 * This method inserts a port number to the list with complexity O(size())
		 * @param[in] port The port number to be inserted
		 * @return True if port is succefully inserted into the list, False otherwise
		 */
		bool insert(uint16_t port)
		{
			if(!full())
			{
				if(!contains(port))
					m_Ports[m_PortSize++] = port;

				return true;
			}
			return false;
		}

		/**
		 * This method removes a port number from the list with constant complexity
		 * @param[in] port The port number to be removed
		 */
		void remove(uint16_t port)
		{
			// TODO: implement
		}

		/**
		 * Checks wether the certain port stored in the list with complexity O(size())
		 * @param[in] port The port number to be checked
		 * @return True if the port number is contained in the list, False otherwise
		 */
		bool contains(uint16_t port) const { return std::find(m_Ports, m_Ports + m_PortSize, port);	}

		/**
		 * @return The unsorted vector filled by the port numbers which are stored in the list
		 */
		std::vector<uint16_t> getPorts() const { return std::vector<uint16_t>(m_Ports, m_Ports + m_PortSize); }

	protected:
		uint16_t m_PortSize;
		uint16_t m_Ports[PortMaxSize];
	}; // class PortList2



	
	// implementation of inline methods

	PortList2::PortList2(uint16_t p1)
		: m_PortSize(1), m_Ports()
	{
		m_Ports[0] = p1;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2)
		: m_PortSize(2), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3)
		: m_PortSize(3), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4)
		: m_PortSize(4), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5)
		: m_PortSize(5), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6)
		: m_PortSize(6), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7)
		: m_PortSize(7), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8)
		: m_PortSize(8), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9)
		: m_PortSize(9), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10)
		: m_PortSize(10), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11)
		: m_PortSize(11), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12)
		: m_PortSize(12), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13)
		: m_PortSize(13), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14)
		: m_PortSize(14), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
		m_Ports[13] = p14;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15)
		: m_PortSize(15), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
		m_Ports[13] = p14;
		m_Ports[14] = p15;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16)
		: m_PortSize(16), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
		m_Ports[13] = p14;
		m_Ports[14] = p15;
		m_Ports[15] = p16;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17)
		: m_PortSize(17), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
		m_Ports[13] = p14;
		m_Ports[14] = p15;
		m_Ports[15] = p16;
		m_Ports[16] = p17;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18)
		: m_PortSize(18), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
		m_Ports[13] = p14;
		m_Ports[14] = p15;
		m_Ports[15] = p16;
		m_Ports[16] = p17;
		m_Ports[17] = p18;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19)
		: m_PortSize(19), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
		m_Ports[13] = p14;
		m_Ports[14] = p15;
		m_Ports[15] = p16;
		m_Ports[16] = p17;
		m_Ports[17] = p18;
		m_Ports[18] = p19;
	}

	PortList2::PortList2(uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4, uint16_t p5, uint16_t p6, uint16_t p7, uint16_t p8, uint16_t p9, uint16_t p10, uint16_t p11,
		uint16_t p12,	uint16_t p13, uint16_t p14, uint16_t p15, uint16_t p16, uint16_t p17, uint16_t p18, uint16_t p19, uint16_t p20)
		: m_PortSize(20), m_Ports()
	{
		m_Ports[0] = p1;
		m_Ports[1] = p2;
		m_Ports[2] = p3;
		m_Ports[3] = p4;
		m_Ports[4] = p5;
		m_Ports[5] = p6;
		m_Ports[6] = p7;
		m_Ports[7] = p8;
		m_Ports[8] = p9;
		m_Ports[9] = p10;
		m_Ports[10] = p11;
		m_Ports[11] = p12;
		m_Ports[12] = p13;
		m_Ports[13] = p14;
		m_Ports[14] = p15;
		m_Ports[15] = p16;
		m_Ports[16] = p17;
		m_Ports[17] = p18;
		m_Ports[18] = p19;
		m_Ports[19] = p20;
	}


} // namespace pcpp

#endif /* PCAPPP_PORT_LIST */
