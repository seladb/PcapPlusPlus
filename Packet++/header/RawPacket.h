#ifndef PCAPPP_RAW_PACKET
#define PCAPPP_RAW_PACKET

#include <stdint.h>
#ifdef _MSC_VER
#include <WinSock2.h>
#else
#include <sys/time.h>
#endif
#include <stddef.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * An enum describing all known link layer type. Taken from: http://www.tcpdump.org/linktypes.html .
	 * Currently only Ethernet (1) and SLL (113) are supported
	 */
	enum LinkLayerType
	{
		/** BSD loopback encapsulation */
		LINKTYPE_NULL = 0,
		/** IEEE 802.3 Ethernet */
		LINKTYPE_ETHERNET = 1,
		/** AX.25 packet */
		LINKTYPE_AX25 = 3,
		/** IEEE 802.5 Token Ring */
		LINKTYPE_IEEE802_5 = 6,
		/** ARCNET Data Packets */
		LINKTYPE_ARCNET_BSD = 7,
		/** SLIP, encapsulated with a LINKTYPE_SLIP header */
		LINKTYPE_SLIP = 8,
		/** PPP, as per RFC 1661 and RFC 1662 */
		LINKTYPE_PPP = 9,
		/** FDDI, as specified by ANSI INCITS 239-1994 */
		LINKTYPE_FDDI = 10,
		/** Raw IP */
		LINKTYPE_DLT_RAW1 = 12,
		/** Raw IP (OpenBSD) */
		LINKTYPE_DLT_RAW2 = 14,
		/** PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547 */
		LINKTYPE_PPP_HDLC = 50,
		/** PPPoE */
		LINKTYPE_PPP_ETHER = 51,
		/** RFC 1483 LLC/SNAP-encapsulated ATM */
		LINKTYPE_ATM_RFC1483 = 100,
		/** Raw IP */
		LINKTYPE_RAW = 101,
		/** Cisco PPP with HDLC framing */
		LINKTYPE_C_HDLC = 104,
		/** IEEE 802.11 wireless LAN */
		LINKTYPE_IEEE802_11 = 105,
		/** Frame Relay */
		LINKTYPE_FRELAY = 107,
		/** OpenBSD loopback encapsulation */
		LINKTYPE_LOOP = 108,
		/** Linux "cooked" capture encapsulation */
		LINKTYPE_LINUX_SLL = 113,
		/** Apple LocalTalk */
		LINKTYPE_LTALK = 114,
		/** OpenBSD pflog */
		LINKTYPE_PFLOG = 117,
		/** Prism monitor mode information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_PRISM = 119,
		/** RFC 2625 IP-over-Fibre Channel */
		LINKTYPE_IP_OVER_FC = 122,
		/** ATM traffic, encapsulated as per the scheme used by SunATM devices */
		LINKTYPE_SUNATM = 123,
		/** Radiotap link-layer information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_RADIOTAP = 127,
		/** ARCNET Data Packets, as described by the ARCNET Trade Association standard ATA 878.1-1999 */
		LINKTYPE_ARCNET_LINUX = 129,
		/** Apple IP-over-IEEE 1394 cooked header */
		LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138,
		/** Signaling System 7 Message Transfer Part Level 2 */
		LINKTYPE_MTP2_WITH_PHDR = 139,
		/** Signaling System 7 Message Transfer Part Level 2 */
		LINKTYPE_MTP2 = 140,
		/** Signaling System 7 Message Transfer Part Level 3 */
		LINKTYPE_MTP3 = 141,
		/** Signaling System 7 Signalling Connection Control Part */
		LINKTYPE_SCCP = 142,
		/** Signaling System 7 Signalling Connection Control Part */
		LINKTYPE_DOCSIS = 143,
		/** Linux-IrDA packets */
		LINKTYPE_LINUX_IRDA = 144,
		/** AVS monitor mode information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_AVS = 163,
		/** BACnet MS/TP frames */
		LINKTYPE_BACNET_MS_TP = 165,
		/** PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the 0xff address byte replaced by a direction indication - 0x00 for incoming and 0x01 for outgoing */
		LINKTYPE_PPP_PPPD = 166,
		/** General Packet Radio Service Logical Link Control */
		LINKTYPE_GPRS_LLC = 169,
		/** Transparent-mapped generic framing procedure */
		LINKTYPE_GPF_T = 170,
		/** Frame-mapped generic framing procedure */
		LINKTYPE_GPF_F = 171,
		/** Link Access Procedures on the D Channel (LAPD) frames */
		LINKTYPE_LINUX_LAPD = 177,
		/** Bluetooth HCI UART transport layer */
		LINKTYPE_BLUETOOTH_HCI_H4 = 187,
		/** USB packets, beginning with a Linux USB header */
		LINKTYPE_USB_LINUX = 189,
		/** Per-Packet Information information */
		LINKTYPE_PPI = 192,
		/** IEEE 802.15.4 wireless Personal Area Network */
		LINKTYPE_IEEE802_15_4 = 195,
		/** Various link-layer types, with a pseudo-header, for SITA */
		LINKTYPE_SITA = 196,
		/** Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF record */
		LINKTYPE_ERF = 197,
		/** Bluetooth HCI UART transport layer */
		LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201,
		/** AX.25 packet, with a 1-byte KISS header containing a type indicator */
		LINKTYPE_AX25_KISS = 202,
		/** Link Access Procedures on the D Channel (LAPD) frames */
		LINKTYPE_LAPD = 203,
		/** PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning  "sent by this host" */
		LINKTYPE_PPP_WITH_DIR = 204,
		/** Cisco PPP with HDLC framing */
		LINKTYPE_C_HDLC_WITH_DIR = 205,
		/** Frame Relay */
		LINKTYPE_FRELAY_WITH_DIR = 206,
		/** IPMB over an I2C circuit */
		LINKTYPE_IPMB_LINUX = 209,
		/** IEEE 802.15.4 wireless Personal Area Network */
		LINKTYPE_IEEE802_15_4_NONASK_PHY = 215,
		/** USB packets, beginning with a Linux USB header */
		LINKTYPE_USB_LINUX_MMAPPED = 220,
		/** Fibre Channel FC-2 frames, beginning with a Frame_Header */
		LINKTYPE_FC_2 = 224,
		/** Fibre Channel FC-2 frames */
		LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225,
		/** Solaris ipnet pseudo-header */
		LINKTYPE_IPNET = 226,
		/** CAN (Controller Area Network) frames, with a pseudo-header as supplied by Linux SocketCAN */
		LINKTYPE_CAN_SOCKETCAN = 227,
		/** Raw IPv4; the packet begins with an IPv4 header */
		LINKTYPE_IPV4 = 228,
		/** Raw IPv6; the packet begins with an IPv6 header */
		LINKTYPE_IPV6 = 229,
		/** IEEE 802.15.4 wireless Personal Area Network, without the FCS at the end of the frame */
		LINKTYPE_IEEE802_15_4_NOFCS = 230,
		/** Raw D-Bus messages, starting with the endianness flag, followed by the message type, etc., but without the authentication handshake before the message sequence */
		LINKTYPE_DBUS = 231,
		/** DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the message format specified by the PCAP format for DVB-CI specification */
		LINKTYPE_DVB_CI = 235,
		/** Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010) */
		LINKTYPE_MUX27010 = 236,
		/** D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including both header and data CRCs */
		LINKTYPE_STANAG_5066_D_PDU = 237,
		/** Linux netlink NETLINK NFLOG socket log messages */
		LINKTYPE_NFLOG = 239,
		/** Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the MAC header and ending with the FCS */
		LINKTYPE_NETANALYZER = 240,
		/** Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS */
		LINKTYPE_NETANALYZER_TRANSPARENT = 241,
		/** IP-over-InfiniBand, as specified by RFC 4391 section 6 */
		LINKTYPE_IPOIB = 242,
		/** MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ITU-T Recommendation H.222.0 */
		LINKTYPE_MPEG_2_TS = 243,
		/** Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format as used by their ng40 protocol tester */
		LINKTYPE_NG40 = 244,
		/** Pseudo-header for NFC LLCP packet captures, followed by frame data for the LLCP Protocol as specified by NFCForum-TS-LLCP_1.1 */
		LINKTYPE_NFC_LLCP = 245,
		/** Raw InfiniBand frames, starting with the Local Routing Header */
		LINKTYPE_INFINIBAND = 247,
		/** SCTP packets, as defined by RFC 4960, with no lower-level protocols such as IPv4 or IPv6 */
		LINKTYPE_SCTP = 248,
		/** USB packets, beginning with a USBPcap header */
		LINKTYPE_USBPCAP = 249,
		/** Serial-line packet header for the Schweitzer Engineering Laboratories "RTAC" product */
		LINKTYPE_RTAC_SERIAL = 250,
		/** Bluetooth Low Energy air interface Link Layer packets */
		LINKTYPE_BLUETOOTH_LE_LL = 251,
		/** Linux Netlink capture encapsulation */
		LINKTYPE_NETLINK = 253,
		/** Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack */
		LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254,
		/** Bluetooth Basic Rate and Enhanced Data Rate baseband packets */
		LINKTYPE_BLUETOOTH_BREDR_BB = 255,
		/** Bluetooth Low Energy link-layer packets */
		LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256,
		/** PROFIBUS data link layer packets, as specified by IEC standard 61158-6-3 */
		LINKTYPE_PROFIBUS_DL = 257,
		/** Apple PKTAP capture encapsulation */
		LINKTYPE_PKTAP = 258,
		/** Ethernet-over-passive-optical-network packets */
		LINKTYPE_EPON = 259,
		/** IPMI trace packets, as specified by Table 3-20 "Trace Data Block Format" in the PICMG HPM.2 specification */
		LINKTYPE_IPMI_HPM_2 = 260,
		/** Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profiles R1 and R2 captures */
		LINKTYPE_ZWAVE_R1_R2 = 261,
		/** Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profile R3 captures */
		LINKTYPE_ZWAVE_R3 = 262,
		/** Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures */
		LINKTYPE_WATTSTOPPER_DLM = 263,
		/** Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443 specification */
		LINKTYPE_ISO_14443 = 264
	};

	/**
	 * Max packet size supported
	 */
#define PCPP_MAX_PACKET_SIZE 65536

	/**
	 * @class RawPacket
	 * This class holds the packet as raw (not parsed) data. The data is held as byte array. In addition to the data itself
	 * every instance also holds a timestamp representing the time the packet was received by the NIC.
	 * RawPacket instance isn't read only. The user can change the packet data, add or remove data, etc.
	 */
	class RawPacket
	{
	protected:
		uint8_t* m_pRawData;
		int m_RawDataLen;
		int m_FrameLength;
		timeval m_TimeStamp;
		bool m_DeleteRawDataAtDestructor;
		bool m_RawPacketSet;
		LinkLayerType m_linkLayerType;
		void Init();
		void copyDataFrom(const RawPacket& other, bool allocateData = true);
	public:
		/**
		 * A constructor that receives a pointer to the raw data (allocated elsewhere). This constructor is usually used when packet
		 * is captured using a packet capturing engine (like libPcap. WinPcap, PF_RING, etc.). The capturing engine allocates the raw data
		 * memory and give the user a pointer to it + a timestamp it has arrived to the device
		 * @param[in] pRawData A pointer to the raw data
		 * @param[in] rawDataLen The raw data length in bytes
		 * @param[in] timestamp The timestamp packet was received by the NIC
		 * @param[in] deleteRawDataAtDestructor An indicator whether raw data pointer should be freed when the instance is freed or not. If set
		 * to 'true' than pRawData will be freed when instanced is being freed
		 * @param[in] layerType The link layer type of this raw packet. The default is Ethernet
		 */
		RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor, LinkLayerType layerType = LINKTYPE_ETHERNET);

		/**
		 * A default constructor that initializes class'es attributes to default value:
		 * - data pointer is set to NULL
		 * - data length is set to 0
		 * - deleteRawDataAtDestructor is set to 'true'
		 * @todo timestamp isn't set here to a default value
		 */
		RawPacket();

		/**
		 * A destructor for this class. Frees the raw data if deleteRawDataAtDestructor was set to 'true'
		 */
		virtual ~RawPacket();

		/**
		 * A copy constructor that copies all data from another instance. Notice all raw data is copied (using memcpy), so when the original or
		 * the other instance are freed, the other won't be affected
		 * @param[in] other The instance to copy from
		 */
		RawPacket(const RawPacket& other);

		/**
		 * Assignment operator overload for this class. When using this operator on an already initialized RawPacket instance,
		 * the original raw data is freed first. Then the other instance is copied to this instance, the same way the copy constructor works
		 * @todo free raw data only if deleteRawDataAtDestructor was set to 'true'
		 * @param[in] other The instance to copy from
		 */
		RawPacket& operator=(const RawPacket& other);

		/**
		 * @return RawPacket object type. Each derived class should return a different value
		 */
		virtual inline uint8_t getObjectType() const { return 0; }

		/**
		 * Set a raw data. If data was already set and deleteRawDataAtDestructor was set to 'true' the old data will be freed first
		 * @param[in] pRawData A pointer to the new raw data
		 * @param[in] rawDataLen The new raw data length in bytes
		 * @param[in] timestamp The timestamp packet was received by the NIC
		 * @param[in] layerType The link layer type for this raw data
		 * @param[in] frameLength When reading from pcap files, sometimes the captured length is different from the actual packet length. This parameter represents the packet 
		 * length. This parameter is optional, if not set or set to -1 it is assumed both lengths are equal
		 * @return True if raw data was set successfully, false otherwise
		 */
		virtual bool setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType = LINKTYPE_ETHERNET, int frameLength = -1);

		/**
		 * Get raw data pointer
		 * @return A pointer to the raw data
		 */
		const uint8_t* getRawData();

		/**
		 * Get read only raw data pointer
		 * @return A read-only pointer to the raw data
		 */
		const uint8_t* getRawDataReadOnly() const;

		/**
		 * Get the link layer tpye
		 * @return the type of the link layer
		 */
		LinkLayerType getLinkLayerType() const;

		/**
		 * Get raw data length in bytes
		 * @return Raw data length in bytes
		 */
		int getRawDataLen() const;

		/**
		 * Get frame length in bytes
		 * @return frame length in bytes
		 */
		int getFrameLength() const;
		/**
		 * Get raw data timestamp
		 * @return Raw data timestamp
		 */
		timeval getPacketTimeStamp();

		/**
		 * Get an indication whether raw data was already set for this instance.
		 * @return True if raw data was set for this instance. Raw data can be set using the non-default constructor, using setRawData(), using
		 * the copy constructor or using the assignment operator. Returns false otherwise, for example: if the instance was created using the
		 * default constructor or clear() was called
		 */
		inline bool isPacketSet() { return m_RawPacketSet; }

		/**
		 * Clears all members of this instance, meaning setting raw data to NULL, raw data length to 0, etc. Currently raw data is always freed,
		 * even if deleteRawDataAtDestructor was set to 'false'
		 * @todo deleteRawDataAtDestructor was set to 'true', don't free the raw data
		 * @todo set timestamp to a default value as well
		 */
		virtual void clear();

		/**
		 * Append data to the end of current data. This method works without allocating more memory, it just uses memcpy() to copy dataToAppend at
		 * the end of the current data. This means that the method assumes this memory was already allocated by the user. If it isn't the case then
		 * this method will cause memory corruption
		 * @param[in] dataToAppend A pointer to the data to append to current raw data
		 * @param[in] dataToAppendLen Length in bytes of dataToAppend
		 */
		virtual void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);

		/**
		 * Insert new data at some index of the current data and shift the remaining old data to the end. This method works without allocating more memory,
		 * it just copies dataToAppend at the relevant index and shifts the remaining data to the end. This means that the method assumes this memory was
		 * already allocated by the user. If it isn't the case then this method will cause memory corruption
		 * @param[in] atIndex The index to insert the new data to
		 * @param[in] dataToInsert A pointer to the new data to insert
		 * @param[in] dataToInsertLen Length in bytes of dataToInsert
		 */
		virtual void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

		/**
		 * Remove certain number of bytes from current raw data buffer. All data after the removed bytes will be shifted back
		 * @param[in] atIndex The index to start removing bytes from
		 * @param[in] numOfBytesToRemove Number of bytes to remove
		 * @return True if all bytes were removed successfully, or false if atIndex+numOfBytesToRemove is out-of-bounds of the raw data buffer
		 */
		virtual bool removeData(int atIndex, size_t numOfBytesToRemove);

		/**
		 * Re-allocate raw packet buffer meaning add size to it without losing the current packet data. This method allocates the required buffer size as instructed
		 * by the use and then copies the raw data from the current allocated buffer to the new one. This method can become useful if the user wants to insert or
		 * append data to the raw data, and the previous allocated buffer is too small, so the user wants to allocate a larger buffer and get RawPacket instance to
		 * point to it
		 * @param[in] newBufferLength The new buffer length as required by the user. The method is responsible to allocate the memory
		 * @return True if data was reallocated successfully, false otherwise
		 */
		virtual bool reallocateData(size_t newBufferLength);
	};

} // namespace pcpp

#endif
