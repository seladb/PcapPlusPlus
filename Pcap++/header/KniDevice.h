#ifndef PCAPPP_KNI_DEVICE
#define PCAPPP_KNI_DEVICE

#include "DpdkDevice.h"
#include "MacAddress.h"

#include <string>

struct rte_kni;

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	struct KniDeviceList;
	class KniDevice;
	class KniRawPacket;

	typedef bool (*OnKniPacketArriveCallback)(KniRawPacket* packets, uint32_t numOfPackets, KniDevice* device, void* userCookie);

	#define KNIRAWPACKET_OBJECT_TYPE 2

	class KniRawPacket : public MBufRawPacket
	{
		friend class KniDevice;
		KniDevice* m_KniDevice;

		using MBufRawPacket::init;
		using MBufRawPacket::initFromRawPacket;
		using MBufRawPacket::setRawData;
	public:
		KniRawPacket() : MBufRawPacket(), m_KniDevice(NULL) {}

		KniRawPacket(const KniRawPacket& other) : MBufRawPacket(other) { m_KniDevice = other.m_KniDevice; }
		KniRawPacket& operator=(const KniRawPacket& other)
		{
			if (this == &other)
				return *this;
			MBufRawPacket::operator=(other);
			m_KniDevice = other.m_KniDevice;
			return *this;
		}
		~KniRawPacket() {}

		bool init(KniDevice* device);

		bool initFromRawPacket(const RawPacket* rawPacket, KniDevice* device);

		bool setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType = LINKTYPE_ETHERNET, int frameLength = -1);

		/**
		 * @return MBufRawPacket object type
		 */
		virtual inline uint8_t getObjectType() const { return KNIRAWPACKET_OBJECT_TYPE; }
	};

	class KniDevice : public IDevice
	{
		friend class KniRawPacket;

	public:
		enum KniLinkState
		{
			LINK_NOT_SUPPORTED = -2,
			LINK_ERROR = -1,
			LINK_DOWN = 0,
			LINK_UP = 1
		};

		enum KniInfoState
		{
			INFO_CACHED = 0,
			INFO_RENEW = 1
		};

		enum KniPromiscuousMode
		{
			PROMISC_DISABLE = 0,
			PROMISC_ENABLE = 1
		};

		struct IoctlCallbacks
		{
			/* Pointer to function of changing MTU */
			int (*change_mtu)(uint16_t port_id, unsigned int new_mtu);
			/* Pointer to function of configuring network interface */
			int (*config_network_if)(uint16_t port_id, uint8_t if_up);
			/* Pointer to function of configuring mac address */
			int (*config_mac_address)(uint16_t port_id, uint8_t mac_addr[]);
			/* Pointer to function of configuring promiscuous mode */
			int (*config_promiscusity)(uint16_t port_id, uint8_t to_on);
		};

		struct KniDeviceConfiguration
		{
			enum
			{
				// Must be correspond to RTE_KNI_NAMESIZE
				KNI_NAME_SIZE = 32
			};
			char name[KNI_NAME_SIZE];
			IoctlCallbacks* callbacks;
			MacAddress* mac;
			uint16_t port_id;
			uint16_t mtu;
			bool bind_kthread;
			uint32_t kthread_core_id;
		};

	private:
		KniDevice(const KniDeviceConfiguration& conf, size_t mempoolSize, int unique);
		KniDevice(const KniDevice&);
		KniDevice& operator=(const KniDevice&);

	protected:
		friend struct KniDeviceList;
		~KniDevice();

	public:
		static KniDevice* DeviceFabric(const KniDeviceConfiguration& conf, size_t mempoolSize);

		static void DestroyDevice(KniDevice* kni_dev);

		static KniDevice* getDeviceByPort(uint16_t port_id);

		static KniDevice* getDeviceByName(const std::string& name);

		inline bool isInitialized() const { return !(m_Device == NULL || m_MBufMempool == NULL); }

		inline std::string getName() const { return std::string(m_DeviceInfo.name); }

		inline uint16_t getPort() const { return m_DeviceInfo.port_id; }

		KniLinkState getLinkState(KniInfoState state = INFO_CACHED);

		MacAddress getMacAddress(KniInfoState state = INFO_CACHED);

		uint16_t getMtu(KniInfoState state = INFO_CACHED);

		KniPromiscuousMode getPromiscuous(KniInfoState state = INFO_CACHED);

		bool setLinkState(KniLinkState state);

		bool setMacAddress(MacAddress mac);

		bool setMtu(uint16_t mtu);

		bool setPromiscuous(KniPromiscuousMode mode);

		KniLinkState updateLinkState(KniLinkState state);

		bool handleRequest();

		bool startRequestHandlerThread(uint16_t sleep_time);

		void stopRequestHandlerThread();

		uint16_t receivePackets(MBufRawPacketVector& rawPacketsArr);

		uint16_t receivePackets(MBufRawPacket** rawPacketsArr, uint16_t rawPacketArrLength);

		uint16_t receivePackets(Packet** packetsArr, uint16_t packetsArrLength);

		uint16_t sendPackets(MBufRawPacket** rawPacketsArr, uint16_t arrLength);

		uint16_t sendPackets(Packet** packetsArr, uint16_t arrLength);

		uint16_t sendPackets(MBufRawPacketVector& rawPacketsVec);

		uint16_t sendPackets(RawPacketVector& rawPacketsVec);

		bool sendPacket(RawPacket& rawPacket);

		bool sendPacket(MBufRawPacket& rawPacket);

		bool sendPacket(Packet& packet);

		bool startCapture(OnKniPacketArriveCallback onPacketArrives, void* onPacketArrivesUserCookie);

		void stopCapture();

		int startCaptureBlockingMode(OnKniPacketArriveCallback onPacketArrives, void* onPacketArrivesUserCookie, int timeout);

		bool open();

		void close();

	private:
		struct rte_kni* m_Device;
		struct rte_mempool* m_MBufMempool;
		struct KniDeviceInfo
		{
			typedef int lin_socket_t;
			lin_socket_t soc;
			KniLinkState link;
			KniPromiscuousMode promisc;
			uint16_t port_id;
			uint16_t mtu;
			char name[KniDeviceConfiguration::KNI_NAME_SIZE];
			MacAddress mac;

			void init(const KniDeviceConfiguration& conf);
			void cleanup();
		} m_DeviceInfo;
		struct KniThread;
		struct KniCapturing
		{
			OnKniPacketArriveCallback callback;
			void* user_cookie;
			KniThread* thread;

			static void* runCapture(void* p);
			inline bool isRunning() const { return thread != NULL; }
			void cleanup();
		} m_Capturing;
		struct KniRequests
		{
			KniThread* thread;

			void cleanup();
		} m_Requests;
	};

} // namespace pcpp
#endif /* PCAPPP_KNI_DEVICE */