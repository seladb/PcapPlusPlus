#ifndef PCAPPP_DEVICE
#define PCAPPP_DEVICE

#include <RawPacket.h>
#include <PcapFilter.h>
#include <PointerVector.h>
#include <pcap.h>

/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	/** A vector of pointers to RawPacket */
	typedef PointerVector<RawPacket> RawPacketVector;

	enum PcapLinkLayerType
	{
		PCAP_LINKTYPE_NULL = 0,
		PCAP_LINKTYPE_ETHERNET = 1,
		PCAP_LINKTYPE_AX25 = 3,
		PCAP_LINKTYPE_IEEE802_5 = 6,
		PCAP_LINKTYPE_ARCNET_BSD = 7,
		PCAP_LINKTYPE_SLIP = 8,
		PCAP_LINKTYPE_PPP = 9,
		PCAP_LINKTYPE_FDDI = 10,
		PCAP_LINKTYPE_PPP_HDLC = 50,
		PCAP_LINKTYPE_PPP_ETHER = 51,
		PCAP_LINKTYPE_ATM_RFC1483 = 100,
		PCAP_LINKTYPE_RAW = 101,
		PCAP_LINKTYPE_C_HDLC = 104,
		PCAP_LINKTYPE_IEEE802_11 = 105,
		PCAP_LINKTYPE_FRELAY = 107,
		PCAP_LINKTYPE_LOOP = 108,
		PCAP_LINKTYPE_LINUX_SLL = 113,
		PCAP_LINKTYPE_LTALK = 114,
		PCAP_LINKTYPE_PFLOG = 117,
		PCAP_LINKTYPE_IEEE802_11_PRISM = 119,
		PCAP_LINKTYPE_IP_OVER_FC = 122,
		PCAP_LINKTYPE_SUNATM = 123,
		PCAP_LINKTYPE_IEEE802_11_RADIOTAP = 127,
		PCAP_LINKTYPE_ARCNET_LINUX = 129,
		PCAP_LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138,
		PCAP_LINKTYPE_MTP2_WITH_PHDR = 139,
		PCAP_LINKTYPE_MTP2 = 140,
		PCAP_LINKTYPE_MTP3 = 141,
		PCAP_LINKTYPE_SCCP = 142,
		PCAP_LINKTYPE_DOCSIS = 143,
		PCAP_LINKTYPE_LINUX_IRDA = 144,
		PCAP_LINKTYPE_IEEE802_11_AVS = 163,
		PCAP_LINKTYPE_BACNET_MS_TP = 165,
		PCAP_LINKTYPE_PPP_PPPD = 166,
		PCAP_LINKTYPE_GPRS_LLC = 169,
		PCAP_LINKTYPE_GPF_T = 170,
		PCAP_LINKTYPE_GPF_F = 171,
		PCAP_LINKTYPE_LINUX_LAPD = 177,
		PCAP_LINKTYPE_BLUETOOTH_HCI_H4 = 187,
		PCAP_LINKTYPE_USB_LINUX = 189,
		PCAP_LINKTYPE_PPI = 192,
		PCAP_LINKTYPE_IEEE802_15_4 = 195,
		PCAP_LINKTYPE_SITA = 196,
		PCAP_LINKTYPE_ERF = 197,
		PCAP_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201,
		PCAP_LINKTYPE_AX25_KISS = 202,
		PCAP_LINKTYPE_LAPD = 203,
		PCAP_LINKTYPE_PPP_WITH_DIR = 204,
		PCAP_LINKTYPE_C_HDLC_WITH_DIR = 205,
		PCAP_LINKTYPE_FRELAY_WITH_DIR = 206,
		PCAP_LINKTYPE_IPMB_LINUX = 209,
		PCAP_LINKTYPE_IEEE802_15_4_NONASK_PHY = 215,
		PCAP_LINKTYPE_USB_LINUX_MMAPPED = 220,
		PCAP_LINKTYPE_FC_2 = 224,
		PCAP_LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225,
		PCAP_LINKTYPE_IPNET = 226,
		PCAP_LINKTYPE_CAN_SOCKETCAN = 227,
		PCAP_LINKTYPE_IPV4 = 228,
		PCAP_LINKTYPE_IPV6 = 229,
		PCAP_LINKTYPE_IEEE802_15_4_NOFCS = 230,
		PCAP_LINKTYPE_DBUS = 231,
		PCAP_LINKTYPE_DVB_CI = 235,
		PCAP_LINKTYPE_MUX27010 = 236,
		PCAP_LINKTYPE_STANAG_5066_D_PDU = 237,
		PCAP_LINKTYPE_NFLOG = 239,
		PCAP_LINKTYPE_NETANALYZER = 240,
		PCAP_LINKTYPE_NETANALYZER_TRANSPARENT = 241,
		PCAP_LINKTYPE_IPOIB = 242,
		PCAP_LINKTYPE_MPEG_2_TS = 243,
		PCAP_LINKTYPE_NG40 = 244,
		PCAP_LINKTYPE_NFC_LLCP = 245,
		PCAP_LINKTYPE_INFINIBAND = 247,
		PCAP_LINKTYPE_SCTP = 248,
		PCAP_LINKTYPE_USBPCAP = 249,
		PCAP_LINKTYPE_RTAC_SERIAL = 250,
		PCAP_LINKTYPE_BLUETOOTH_LE_LL = 251,
		PCAP_LINKTYPE_NETLINK = 253,
		PCAP_LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254,
		PCAP_LINKTYPE_BLUETOOTH_BREDR_BB = 255,
		PCAP_LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256,
		PCAP_LINKTYPE_PROFIBUS_DL = 257,
		PCAP_LINKTYPE_PKTAP = 258,
		PCAP_LINKTYPE_EPON = 259,
		PCAP_LINKTYPE_IPMI_HPM_2 = 260,
		PCAP_LINKTYPE_ZWAVE_R1_R2 = 261,
		PCAP_LINKTYPE_ZWAVE_R3 = 262,
		PCAP_LINKTYPE_WATTSTOPPER_DLM = 263,
		PCAP_LINKTYPE_ISO_14443 = 264
	};

	/**
	 * @class IPcapDevice
	 * An abstract class representing all possible packet capturing devices: files, libPcap, WinPcap, RemoteCapture, PF_RING, etc.
	 * This class cannot obviously be instantiated
	 */
	class IPcapDevice
	{
	protected:
		pcap_t* m_PcapDescriptor;
		PcapLinkLayerType m_PcapLinkLayerType;
		bool m_DeviceOpened;

		// c'tor should not be public
		IPcapDevice() { m_DeviceOpened = false; m_PcapDescriptor = NULL; }

	public:
		virtual ~IPcapDevice();

		/**
		 * Open the device
		 * @return True if device was opened successfully, false otherwise
		 */
		virtual bool open() = 0;

		/**
		 * Close the device
		 */
		virtual void close() = 0;

		/**
		 * @return True if the file is opened, false otherwise
		 */
		inline bool isOpened() { return m_DeviceOpened; }

		/**
		 * Get statistics from device:
		 * - pcap_stat#ps_recv: number of packets received
		 * - pcap_stat#ps_drop: number of packets dropped
		 * - pcap_stat#ps_ifdorp: number of packets dropped by interface
		 * @param[out] stats The stats struct where stats are returned
		 */
		virtual void getStatistics(pcap_stat& stats) = 0;

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be received
		 * @param[in] filter The filter to be set in PcapPlusPlus' GeneralFilter format
		 * @return True if filter set successfully, false otherwise
		 */
		bool setFilter(GeneralFilter& filter);

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be received
		 * @param[in] filterAsString The filter to be set in Berkeley %Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		bool setFilter(std::string filterAsString);
	};

} // namespace pcpp

#endif
