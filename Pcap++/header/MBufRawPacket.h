#ifndef PCAPPP_MBUF_RAW_PACKET
#define PCAPPP_MBUF_RAW_PACKET

#include <time.h>
#include "Packet.h"
#include "PointerVector.h"

struct rte_mbuf;
struct rte_mempool;

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	class DpdkDevice;
	class KniDevice;

	#define MBUFRAWPACKET_OBJECT_TYPE 1

	/**
	 * @class MBufRawPacket
	 * A class that inherits RawPacket and wraps DPDK's mbuf object (see some info about mbuf in DpdkDevice.h) but is
	 * compatible with PcapPlusPlus framework. Using MBufRawPacket is be almost similar to using RawPacket, the implementation
	 * differences are encapsulated in the class implementation. For example: user can create and manipulate a Packet object from
	 * MBufRawPacket the same way it is done with RawPacket; User can use PcapFileWriterDevice to save MBufRawPacket to pcap the
	 * same way it's used with RawPacket; etc.<BR>
	 * The main difference is that RawPacket contains a pointer to the data itself and MBufRawPacket is holding a pointer to an mbuf
	 * object which contains a pointer to the data. This implies that MBufRawPacket without an mbuf allocated to it is not usable.
	 * Getting instances of MBufRawPacket can be done in one to the following ways:
	 *    - Receiving packets from DpdkDevice. In this case DpdkDevice takes care of getting the mbuf from DPDK and wrapping it with
	 *      MBufRawPacket
	 *    - Creating MBufRawPacket from scratch (in order to send it with DpdkDevice, for example). In this case the user should call
	 *      the init() method after constructing the object in order to allocate a new mbuf from DPDK port pool (encapsulated by DpdkDevice)
	 *
	 * Limitations of this class:
	 *    - Currently chained mbufs are not supported. An mbuf has the capability to be linked to another mbuf and create a linked list
	 *      of mbufs. This is good for Jumbo packets or other uses. MBufRawPacket doesn't support this capability so there is no way to
	 *      access the mbufs linked to the mbuf wrapped by MBufRawPacket instance. I hope I'll be able to add this support in the future
	 */
	class MBufRawPacket : public RawPacket
	{
		friend class DpdkDevice;
		friend class KniDevice;
		static const int MBUF_DATA_SIZE;

	protected:
		struct rte_mbuf* m_MBuf;
		struct rte_mempool* m_Mempool;
		bool m_FreeMbuf;

		void setMBuf(struct rte_mbuf* mBuf, timespec timestamp);
		bool init(struct rte_mempool* mempool);
		bool initFromRawPacket(const RawPacket* rawPacket, struct rte_mempool* mempool);
	public:

		/**
		 * A default c'tor for this class. Constructs an instance of this class without an mbuf attached to it. In order to allocate
		 * an mbuf the user should call the init() method. Without calling init() the instance of this class is not usable.
		 * This c'tor can be used for initializing an array of MBufRawPacket (which requires an empty c'tor)
		 */
		MBufRawPacket() : RawPacket(), m_MBuf(NULL), m_Mempool(NULL), m_FreeMbuf(true) { m_DeleteRawDataAtDestructor = false; }

		/**
		 * A d'tor for this class. Once called it frees the mbuf attached to it (returning it back to the mbuf pool it was allocated from)
		 */
		virtual ~MBufRawPacket();

		/**
		 * A copy c'tor for this class. The copy c'tor allocates a new mbuf from the same pool the original mbuf was
		 * allocated from, attaches the new mbuf to this instance of MBufRawPacket and copies the data from the original mbuf
		 * to the new mbuf
		 * @param[in] other The MBufRawPacket instance to copy from
		 */
		MBufRawPacket(const MBufRawPacket& other);

		/**
		 * @brief Initialize an instance of this class from DpdkDevice.
		 * Initialization includes allocating an mbuf from the pool that resides in DpdkDevice.
		 * The user should call this method only once per instance.
		 * Calling it more than once will result with an error
		 * @param[in] device The DpdkDevice which has the pool to allocate the mbuf from
		 * @return True if initialization succeeded and false if this method was already called for this instance (and an mbuf is
		 * already attached) or if allocating an mbuf from the pool failed for some reason
		 */
		bool init(DpdkDevice* device);
		/**
		 * @brief Initialize an instance of this class from KniDevice.
		 * Initialization includes allocating an mbuf from the pool that resides in KniDevice.
		 * The user should call this method only once per instance.
		 * Calling it more than once will result with an error
		 * @param[in] device The KniDevice which has the pool to allocate the mbuf from
		 * @return True if initialization succeeded and false if this method was already called for this instance (and an mbuf is
		 * already attached) or if allocating an mbuf from the pool failed for some reason
		 */
		bool init(KniDevice* device);

		/**
		 * @brief Initialize an instance of this class and copies the content of a RawPacket object.
		 * Initialization includes allocating an mbuf from the pool that resides in provided DpdkDevice,
		 * and copying the data from the input RawPacket object into this mBuf.
		 * The user should call this method only once per instance.
		 * Calling it more than once will result with an error
		 * @param[in] rawPacket A pointer to a RawPacket object from which data will be copied
		 * @param[in] device The DpdkDevice which has the pool to allocate the mbuf from
		 * @return True if initialization succeeded and false if this method was already called for this instance (and an mbuf is
		 * already attached) or if allocating an mbuf from the pool failed for some reason
		 */
		bool initFromRawPacket(const RawPacket* rawPacket, DpdkDevice* device);
		/**
		 * @brief Initialize an instance of this class and copies the content of a RawPacket object.
		 * Initialization includes allocating an mbuf from the pool that resides in provided KniDevice,
		 * and copying the data from the input RawPacket object into this mBuf.
		 * The user should call this method only once per instance.
		 * Calling it more than once will result with an error
		 * @param[in] rawPacket A pointer to a RawPacket object from which data will be copied
		 * @param[in] device The KniDevice which has the pool to allocate the mbuf from
		 * @return True if initialization succeeded and false if this method was already called for this instance (and an mbuf is
		 * already attached) or if allocating an mbuf from the pool failed for some reason
		 */
		bool initFromRawPacket(const RawPacket* rawPacket, KniDevice* device);

		/**
		 * @return A pointer to the DPDK mbuf stored in this object
		 */
		inline rte_mbuf* getMBuf() { return m_MBuf; }

		// overridden methods

		/**
		 * @return MBufRawPacket object type
		 */
		virtual inline uint8_t getObjectType() const { return MBUFRAWPACKET_OBJECT_TYPE; }

		/**
		 * An assignment operator for this class. Copies the data from the mbuf attached to the other MBufRawPacket to the mbuf
		 * attached to this instance. If instance is not initialized (meaning no mbuf is attached) nothing will be copied and
		 * instance will remain uninitialized (also, an error will be printed)
		 * @param[in] other The MBufRawPacket to assign data from
		 */
		MBufRawPacket& operator=(const MBufRawPacket& other);

		/**
		 * Set raw data to the mbuf by copying the data to it. In order to stay compatible with the ancestor method
		 * which takes control of the data pointer and frees it when RawPacket is destroyed, this method frees this pointer right away after
		 * data is copied to the mbuf. So when using this method please notice that after it's called pRawData memory is free, don't
		 * use this pointer again. In addition, if raw packet isn't initialized (mbuf is NULL), this method will call the init() method
		 * @param[in] pRawData A pointer to the new raw data
		 * @param[in] rawDataLen The new raw data length in bytes
		 * @param[in] timestamp The timestamp packet was received by the NIC
		 * @param[in] layerType The link layer type for this raw data. Default is Ethernet
		 * @param[in] frameLength When reading from pcap files, sometimes the captured length is different from the actual packet length. This parameter represents the packet
		 * length. This parameter is optional, if not set or set to -1 it is assumed both lengths are equal
		 * @return True if raw data was copied to the mbuf successfully, false if rawDataLen is larger than mbuf max size, if initialization
		 * failed or if copying the data to the mbuf failed. In all of these cases an error will be printed to log
		 */
		bool setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp, LinkLayerType layerType = LINKTYPE_ETHERNET, int frameLength = -1);

		/**
		 * Clears the object and frees the mbuf
		 */
		void clear();

		/**
		 * Append packet data at the end of current data. This method uses the same mbuf already allocated and tries to append more space and
		 * copy the data to it. If MBufRawPacket is not initialize (mbuf is NULL) or mbuf append failed an error is printed to log
		 * @param[in] dataToAppend A pointer to the data to append
		 * @param[in] dataToAppendLen Length in bytes of dataToAppend
		 */
		void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);

		/**
		 * Insert raw data at some index of the current data and shift the remaining data to the end. This method uses the
		 * same mbuf already allocated and tries to append more space to it. Then it just copies dataToAppend at the relevant index and shifts
		 * the remaining data to the end. If MBufRawPacket is not initialize (mbuf is NULL) or mbuf append failed an error is printed to log
		 * @param[in] atIndex The index to insert the new data to
		 * @param[in] dataToInsert A pointer to the new data to insert
		 * @param[in] dataToInsertLen Length in bytes of dataToInsert
		 */
		void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

		/**
		 * Remove certain number of bytes from current raw data buffer. All data after the removed bytes will be shifted back. This method
		 * uses the mbuf already allocated and tries to trim space from it
		 * @param[in] atIndex The index to start removing bytes from
		 * @param[in] numOfBytesToRemove Number of bytes to remove
		 * @return True if all bytes were removed successfully, or false if MBufRawPacket is not initialize (mbuf is NULL), mbuf trim
		 * failed or logatIndex+numOfBytesToRemove is out-of-bounds of the raw data buffer. In all of these cases an error is printed to log
		 */
		bool removeData(int atIndex, size_t numOfBytesToRemove);

		/**
		 * This overridden method,in contrast to its ancestor RawPacket#reallocateData() doesn't need to do anything because mbuf is already
		 * allocated to its maximum extent. So it only performs a check to verify the size after re-allocation doesn't exceed mbuf max size
		 * @param[in] newBufferLength The new buffer length as required by the user
		 * @return True if new size is larger than current size but smaller than mbuf max size, false otherwise
		 */
		bool reallocateData(size_t newBufferLength);

		/**
		 * Set an indication whether to free the mbuf when done using it or not ("done using it" means setting another mbuf or class d'tor).
		 * Default value is true.
		 * @param[in] val The value to set. True means free the mbuf when done using it. Default it True
		 */
		inline void setFreeMbuf(bool val = true) { m_FreeMbuf = val; }
	};

	/**
	 * @typedef MBufRawPacketVector
	 * A vector of pointers to MBufRawPacket
	 */
	typedef PointerVector<MBufRawPacket> MBufRawPacketVector;

} // namespace pcpp

#endif /* PCAPPP_MBUF_RAW_PACKET */
