#ifndef PACKETPP_NTP_LAYER
#define PACKETPP_NTP_LAYER

#include "IPv4Layer.h"
#include "Layer.h"

#include "GeneralUtils.h"
#include "SystemUtils.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/// @file

/// 2^16 as a double
#define NTP_FRIC 65536.
/// 2^32 as a double
#define NTP_FRAC 4294967296.
/// Epoch offset between Unix time and NTP
#define EPOCH_OFFSET 2208988800ULL

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
    /**
     * @brief The NTP packet header consists of an integral number of 32-bit (4 octet) words in network byte order. 
     * The packet format consists of three components: the header itself, one or more optional extension fields, 
     * and an optional message authentication code (MAC). The NTP header is:
     * 
     * @verbatim 
     *   0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Root Delay                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Root Dispersion                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Reference ID                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                     Reference Timestamp (64)                  +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                      Origin Timestamp (64)                    +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                      Receive Timestamp (64)                   +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                      Transmit Timestamp (64)                  +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                Extension Field 1 (variable, only v4)          .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                Extension Field 1 (variable, only v4)          .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Key Identifier                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                   dgst (128 for v4, 64 for v3)                |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * @endverbatim
     * 
     */
#pragma pack(push, 1)
    struct ntp_header
    {
#if (BYTE_ORDER == LITTLE_ENDIAN)
        uint8_t mode:3,
        version:3,
        leapIndicator:2;
#else
        uint8_t leapIndicator:2,
        version:3,
        mode:3;
#endif
        uint8_t stratum;
        int8_t pollInterval,
        precision;
        uint32_t rootDelay,
        rootDispersion,
        referenceIdentifier;
        uint64_t referenceTimestamp,
        originTimestamp,
        receiveTimestamp,
        transmitTimestamp;
    };
#pragma pack(pop)

    /**
     * Authentication part (optional) for NTPv3 with following fields,
     * 
     * KeyID: An integer identifying the cryptographic key used to generate 
     * the message-authentication code
     * Digest: This is an integer identifying the cryptographic key used to
     * generate the message-authentication code. 
     * 
     * For more information RFC-1305 Appendix C
     */
#pragma pack(push,1)
    struct ntp_v3_auth
    {
        uint32_t keyID;
        uint8_t dgst[8]; // 64 bit DES based
    };
#pragma pack(pop)

    /**
     * Authentication part (optional) for NTPv4 with following fields,
     * 
     * KeyID: 32-bit unsigned integer used by the client and server to designate 
     * a secret 128-bit MD5 key.
     * Digest: 128-bit MD5 hash computed over the key followed by the NTP packet 
     * header and extensions fields (but not the Key Identifier or Message Digest
     * fields)
     */
#pragma pack(push,1)
    struct ntp_v4_auth
    {
        uint32_t keyID;
        uint8_t dgst[16]; // MD5 hash (SHA1 not supported for now)
    };
#pragma pack(pop)

    /**
    * Warning of an impending leap second to be inserted or deleted in the last minute of the current month
    */
    enum NTPLeapIndicator
    {
        NoWarning = 0,
        /// Last minute of the day has 61 seconds
        Last61Secs,
        /// Last minute of the day has 59 seconds
        Last59Secs,
        /// Unknown (clock unsynchronized)
        Unknown
    };

    /**
     * Representing the NTP association modes
     */
    enum NTPMode
    {
        Reserved = 0,
        SymActive,
        SymPassive,
        Client,
        Server,
        Broadcast,
        Control,
        PrivateUse
    };

    /**
     * 32-bit code identifying the particular server or reference clock. 
     * The interpretation depends on the value in the stratum field.
     */
    enum NTPClockSource
    {
        // NTPv4

        /// Geosynchronous Orbit Environment Satellite
        GOES = ('G' << 24) | ('O' << 16) | ('E' << 8) | 'S',
        /// Global Position System
        GPS = ('G' << 24) | ('P' << 16) | ('S' << 8),
        /// Galileo Positioning System
        GAL = ('G' << 24) | ('A' << 16) | ('L' << 8),
        /// Generic pulse-per-second
        PPS = ('P' << 24) | ('P' << 16) | ('S' << 8),
        /// Inter-Range Instrumentation Group
        IRIG = ('I' << 24) | ('R' << 16) | ('I' << 8) | 'G',
        /// LF Radio WWVB Ft. Collins, CO 60 kHz
        WWVB = ('W' << 24) | ('W' << 16) | ('V' << 8) | 'B',
        /// LF Radio DCF77 Mainflingen, DE 77.5 kHz
        DCF = ('D' << 24) | ('C' << 16) | ('F' << 8),
        /// LF Radio HBG Prangins, HB 75 kHz
        HBG = ('H' << 24) | ('B' << 16) | ('G' << 8),
        /// LF Radio MSF Anthorn, UK 60 kHz
        MSF = ('M' << 24) | ('S' << 16) | ('F' << 8),
        /// LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz
        JJY = ('J' << 24) | ('J' << 16) | ('Y' << 8),
        /// MF Radio LORAN C station, 100 kHz
        LORC = ('L' << 24) | ('O' << 16) | ('R' << 8) | 'C',
        /// MF Radio Allouis, FR 162 kHz
        TDF = ('T' << 24) | ('D' << 16) | ('F' << 8),
        /// HF Radio CHU Ottawa, Ontario
        CHU = ('C' << 24) | ('H' << 16) | ('U' << 8),
        /// HF Radio WWV Ft. Collins, CO
        WWV = ('W' << 24) | ('W' << 16) | ('V' << 8),
        /// HF Radio WWVH Kauai, HI
        WWVH = ('W' << 24) | ('W' << 16) | ('V' << 8) | 'H',
        /// NIST telephone modem
        NIST = ('N' << 24) | ('I' << 16) | ('S' << 8) | 'T',
        /// NIST telephone modem
        ACTS = ('A' << 24) | ('C' << 16) | ('T' << 8) | 'S',
        /// USNO telephone modem
        USNO = ('U' << 24) | ('S' << 16) | ('N' << 8) | 'O',
        /// European telephone modem
        PTB = ('P' << 24) | ('T' << 16) | ('B' << 8),

        // NTPv3

        /// DCN routing protocol
        DCN = ('D' << 24) | ('C' << 16) | ('N' << 8),
        /// TSP time protocol
        TSP = ('T' << 24) | ('S' << 16) | ('P' << 8),
        /// Digital Time Service
        DTS = ('D' << 24) | ('T' << 16) | ('S' << 8),
        /// Atomic clock (calibrated)
        ATOM = ('A' << 24) | ('T' << 16) | ('O' << 8) | 'M',
        /// VLF radio (OMEGA, etc.)
        VLF = ('V' << 24) | ('L' << 16) | ('F' << 8),

    };

    /**
	 * @class NtpLayer
	 * Represents a NTP (Network Time Protocol) layer
	 */
    class NtpLayer : public Layer
    {
    private:
        ntp_header* getNtpHeader() const { return (ntp_header*)m_Data; }

    public:
        /**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref ntphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
        NtpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = NTP; }

        /**
         * Empty c'tor
         */
        NtpLayer();

        /**
         * Get the leap indicator 
         */
        NTPLeapIndicator getLeapIndicator() const;

        /**
         * Set the leap indicator
         */
        void setLeapIndicator(NTPLeapIndicator val);

        /**
         * Get the version of NTP 
         */
        uint8_t getVersion() const;

        /**
         * Set the version of NTP
         */
        void setVersion(uint8_t val);

        /**
         * Get the mode value
         */
        NTPMode getMode() const;

        /**
         * Get the mode as string
         */
        std::string getModeString() const;

        /**
         * Set the mode
         */
        void setMode(NTPMode val);

        /**
         * Get the value of stratum
         */
        uint8_t getStratum() const;

        /**
         * Set the value of stratum
         */
        void setStratum(uint8_t val);

        /**
         * Get the value of poll interval in log2 seconds 
         */
        int8_t getPollInterval() const;

        /**
         * Set the value of poll interval
         * @param[in] val Poll interval in log2 seconds
         */
        void setPollInterval(int8_t val);

        /**
         * Get the value of poll interval in seconds
         */
        double getPollIntervalInSecs() const;

        /**
         * Get the value of precision in log2 seconds
         */
        int8_t getPrecision() const;

        /**
         * Set the value of precision
         * @param[in] val Precision in log2 seconds
         */
        void setPrecision(int8_t val);

        /**
         * Get the value of precision in seconds
         */
        double getPrecisionInSecs() const;

        /**
         * Get the value of root delay in NTP short format
         */
        uint32_t getRootDelay() const;

        /**
         * Set the value of root delay
         * @param[in] val Root delay in NTP short format
         */
        void setRootDelay(uint32_t val);

        /**
         * Get the value of root delay in seconds
         */
        double getRootDelayInSecs() const;

        /**
         * Set the value of root delay
         * @param[in] val Root delay in seconds
         */
        void setRootDelayInSecs(double val);

        /**
         * Get the value of root dispersion in NTP short format
         */
        uint32_t getRootDispersion() const;

        /**
         * Set the value of root delay
         * @param[in] val Root dispersion in NTP short format 
         */
        void setRootDispersion(uint32_t val);

        /**
         * Get the value of root dispersion in seconds
         */
        double getRootDispersionInSecs() const;

        /**
         * Set the value of root dispersion
         * @param[in] val Root dispersion in seconds
         */
        void setRootDispersionInSecs(double val);

        /**
         * Get the value of reference identifier
         */
        uint32_t getReferenceIdentifier() const;

        /**
         * Set the value of reference identifier
         * @param[in] val Value of the reference identifier, either NTPClockSource, IPv4 address or MD5 hash of first four octets of IPv6
         */
        void setReferenceIdentifier(uint32_t val);

        /**
         * Get the value of reference identifier as a string
         * @return std::string String representation of NTP clock source if stratum is 1, IPv4 address or MD5 hash of first four octets of IPv6
         */
        std::string getReferenceIdentifierString() const;

        /**
         * Get the value of reference timestamp
         * @return Value in NTP timestamp format 
         */
        uint64_t getReferenceTimestamp() const;

        /**
         * Set the value of reference timestamp
         * @param[in] val Timestamp in NTP timestamp format
         */
        void setReferenceTimestamp(uint64_t val);

        /**
         * Get the value of reference timestamp
         * @return Value in seconds from Unix Epoch (1 Jan 1970)
         */
        double getReferenceTimestampInSecs() const;

        /**
         * Set the value of reference timestamp
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setReferenceTimestampInSecs(double val);

        /**
         * Get the value of origin timestamp
         * @return Value in NTP timestamp format 
         */
        uint64_t getOriginTimestamp() const;

        /**
         * Set the value of origin timestamp
         * @param[in] val Value in NTP timestamp format
         */
        void setOriginTimestamp(uint64_t val);

        /**
         * Get the value of origin timestamp
         * @return Value in seconds from Unix Epoch (1 Jan 1970)
         */
        double getOriginTimestampInSecs() const;

        /**
         * Set the value of origin timestamp
         * @param val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setOriginTimestampInSecs(double val);

        /**
         * Get the value of receive timestamp
         * @return Value in NTP timestamp format 
         */
        uint64_t getReceiveTimestamp() const;

        /**
         * Set the value of receive timestamp
         * @param[in] val Value in NTP timestamp format
         */
        void setReceiveTimestamp(uint64_t val);

        /**
         * Get the value of receive timestamp
         * @return Value in seconds from Unix Epoch (1 Jan 1970)
         */
        double getReceiveTimestampInSecs() const;

        /**
         * Set the value of receive timestamp
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setReceiveTimestampInSecs(double val);

        /**
         * Get the value of transmit timestamp
         * @return Value in NTP timestamp format 
         */
        uint64_t getTransmitTimestamp() const;

        /**
         * Set the value of transmit timestamp
         * @param[in] val Value in NTP timestamp format
         */
        void setTransmitTimestamp(uint64_t val);

        /**
         * Get the value of transmit timestamp
         * @return Value in seconds from Unix Epoch (1 Jan 1970)
         */
        double getTransmitTimestampInSecs() const;

        /**
         * Set the value of transmit timestamp
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970) 
         */
        void setTransmitTimestampInSecs(double val);

        /**
         * Get the value of key identifier
         * @return Returns the key identifier if exists, returns 0 on unsupported NTP version or key identifier not found
         */
        uint32_t getKeyID() const;

        /**
         * Get the value of digest. 
         * @param[out] digest 
         * @return Digest value as hexadecimal string, empty string on unsupported version
         */
        std::string getDigest() const;

        /**
         * Convert NTP short format to seconds from the Unix Epoch
         * 
         * @param[in] val Value in NTP short format
         * @return Value in seconds from Unix Epoch (1 Jan 1970)
         */
        static double convertFromShortFormat(const uint32_t val);

        /**
         * Convert NTP timestamp format to seconds from the Unix Epoch
         * 
         * @param[in] val Value in NTP timestamp format
         * @return Value in seconds from Unix Epoch (1 Jan 1970)
         */
        static double convertFromTimestampFormat(const uint64_t val);

        /**
         * Convert seconds from the Unix Epoch to NTP short format
         * 
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         * @return Value in NTP short format
         */
        static uint32_t convertToShortFormat(const double val);

        /**
         * Convert seconds from the Unix Epoch to NTP timestamp format
         * 
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         * @return Value in NTP timestamp format
         */
        static uint64_t convertToTimestampFormat(const double val);

        /**
         * A static method to convert timestamp value to ISO8601 date time format
         * @param[in] timestamp Value in seconds from the Unix Epoch
         * @return std::string ISO8601 formatted string
         */
        static std::string convertToIsoFormat(const double timestamp);

        /**
         * A static method to convert timestamp value to ISO8601 date time format
         * @param[in] timestampInNTPformat Value in NTP timestamp format
         * @return std::string ISO8601 formatted string
         */
        static std::string convertToIsoFormat(const uint64_t timestampInNTPformat);

        /**
		 * A static method that takes a byte array and detects whether it is a NTP message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as NTP message
		 */
        static bool isDataValid(const uint8_t *data, size_t dataSize);

        /**
		 * A static method that checks whether the port is considered as NTP
		 * @param[in] port The port number to be checked
		 */
        static bool isNTPPort(uint16_t port) { return port == 123; }

        // overridden methods

        void parseNextLayer() {}

        size_t getHeaderLen() const { return m_DataLen; }

        void computeCalculateFields() {}

        OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

        std::string toString() const;
    };

} // namespace pcpp

#endif /* PACKETPP_NTP_LAYER */