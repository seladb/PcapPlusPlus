#ifndef PACKETPP_STP_LAYER
#define PACKETPP_STP_LAYER

#include "Layer.h"
#include "MacAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
    /// STP protocol uses "01:80:C2:00:00:00" multicast address as destination MAC
    const pcpp::MacAddress STP_MULTICAST_DST_MAC = pcpp::MacAddress("01:80:C2:00:00:00");
    /// STP Uplink Fast protocol uses "01:00:0C:CD:CD:CD" as destination MAC
    const pcpp::MacAddress STP_UPLINK_FAST_MULTICAST_DST_MAC = pcpp::MacAddress("01:00:0C:CD:CD:CD");

    /**
	 * @struct stp_header
	 * Represents an Spanning Tree Protocol header
	 */
#pragma pack(push, 1)
	struct stp_header
	{
		/// Destination MAC
		uint8_t dstMac[6];
		/// Source MAC
		uint8_t srcMac[6];
		/// Frame Length
		uint16_t frameLength;
        /// LLC header
        uint8_t llcHeader[3];
	};
#pragma pack(pop)

    /**
     * @struct stp_conf_bpdu 
     * Represents payload configuration of BPDU for STP
     */
#pragma pack(push, 1)
    struct stp_conf_bpdu
    {
        /// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
        uint16_t protoId;
        /// Protocol version. 0x0 for STP
        uint8_t version;
        /// Type of the BPDU. 0x0 for configuration
        uint8_t type;
        /// Flag for indicate purpose of BPDU
        uint8_t flag;
        /// Root bridge ID
        uint64_t rootId;
        /// Cost of path
        uint32_t pathCost;
        /// Bridge ID
        uint64_t bridgeId;
        /// Port ID
        uint16_t portId;
        /// Age of the BPDU
        uint16_t msgAge;
        /// Maximum age of the BPDU
        uint16_t maxAge;
        /// BPDU transmission interval
        uint16_t helloTime;
        /// Delay for STP
        uint16_t forwardDelay;
    };
#pragma pack(pop)

    /**
     * @struct stp_tcn_bpdu 
     * Represents payload of network changes announcements of BPDU
     */
#pragma pack(push, 1)
    struct stp_tcn_bpdu
    {
        /// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
        uint16_t protoId;
        /// Protocol version. 0x0 for STP
        uint8_t version;
        /// Type of the BPDU. 0x80 for TCN
        uint8_t type;
    };
#pragma pack(pop)

    /**
     * @struct rstp_bpdu
     * Represents payload configuration of BPDU for Rapid STP (RSTP)
     */
#pragma pack(push, 1)
    struct rstp_conf_bpdu
    {
        /// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
        uint16_t protoId;
        /// Protocol version. 0x2 for RSTP
        uint8_t version;
        /// Type of the BPDU. 0x2 for RSTP/MSTP
        uint8_t type;
        /// Flag for indicate purpose of BPDU
        uint8_t flag;
        /// Root bridge ID
        uint64_t rootId;
        /// Cost of path
        uint32_t pathCost;
        /// Bridge ID
        uint64_t bridgeId;
        /// Port ID
        uint16_t portId;
        /// Age of the BPDU
        uint16_t msgAge;
        /// Maximum age of the BPDU
        uint16_t maxAge;
        /// BPDU transmission interval
        uint16_t helloTime;
        /// Delay for STP
        uint16_t forwardDelay;
        /// Version1 length. The value is 0x0
        uint8_t version1Len;
    };
#pragma pack(pop)

    /**
     * @struct mstp_bpdu
     * Represents payload configuration of BPDU for Multiple STP (MSTP)
     */
#pragma pack(push, 1)
    struct mstp_conf_bpdu
    {
        /// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
        uint16_t protoId;
        /// Protocol version. 0x3 for MSTP
        uint8_t version;
        /// Type of the BPDU. 0x2 for RSTP/MSTP
        uint8_t type;
        /// Flag for indicate purpose of BPDU
        uint8_t flag;
        /// Root bridge ID
        uint64_t rootId;
        /// Cost of path
        uint32_t pathCost;
        /// Bridge ID
        uint64_t bridgeId;
        /// Port ID
        uint16_t portId;
        /// Age of the BPDU
        uint16_t msgAge;
        /// Maximum age of the BPDU
        uint16_t maxAge;
        /// BPDU transmission interval
        uint16_t helloTime;
        /// Delay for STP
        uint16_t forwardDelay;
        /// Version1 length. The value is 0x0
        uint8_t version1Len;
        /// Version3 length.
        uint16_t version3Len;
        /// Configuration id of MST
        uint8_t mstConfigId[51];
        /// CIST internal root path cost
        uint32_t irpc;
        /// CIST bridge id
        uint64_t bridgeId;
        /// CIST remaining hop count
        uint8_t remainId;
    };
#pragma pack(pop)

    /**
     * @struct msti_conf_msg
     * Represents MSTI configuration messages. Each message contains 16 bytes and MSTP can contain 0 to 64 MSTI messages.
     */
#pragma pack(push, 1)
    struct msti_conf_msg
    {

    }

//// <------------------------------- STP Uplink Fast

    class StpLayer : public Layer
    {

    };

} // namespace pcpp

#endif /* PACKETPP_STP_LAYER */