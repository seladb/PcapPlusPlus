#ifndef PACKETPP_NTP_LAYER
#define PACKETPP_NTP_LAYER

#include "Layer.h"

#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

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

    #pragma pack(push,1)
    struct ntp_header
    {
        uint8_t mode:3,
        version:3,
        leapIndicator:2;
        uint8_t stratum;
        int8_t pollInterval,
        precision;
        uint32_t rootDelay,
        rootDispersion,
        referenceIdentifier;
        uint64_t referenceTimestamp,
        originateTimestamp,
        receiveTimestamp,
        transmitTimestamp;
    };
    #pragma pack(pop)

    #pragma pack(push,1)
    struct ntp_v3_auth
    {
        uint32_t keyID;
        uint8_t dgst[8]; // 64 bit DES based
    };
    #pragma pack(pop)

    #pragma pack(push,1)
    struct ntp_v4_auth
    {
        uint32_t keyID;
        uint8_t dgst[16]; // MD5 hash
    };
    #pragma pack(pop)

    enum NTPLeapIndicator
    {
        NoWarning = 0,
        Last61Secs,
        Last59Secs,
        Unknown
    };

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

    enum NTPClockSource
    {
        // v4
        GOES = ('G' << 24) | ('O' << 16) | ('E' << 8) | 'S',
        GPS = ('G' << 24) | ('P' << 16) | ('S' << 8),
        GAL = ('G' << 24) | ('A' << 16) | ('L' << 8),
        PPS = ('P' << 24) | ('P' << 16) | ('S' << 8),
        IRIG = ('I' << 24) | ('R' << 16) | ('I' << 8) | 'G',
        WWVB = ('W' << 24) | ('W' << 16) | ('V' << 8) | 'B',
        DCF = ('D' << 24) | ('C' << 16) | ('F' << 8),
        HBG = ('H' << 24) | ('B' << 16) | ('G' << 8),
        MSF = ('M' << 24) | ('S' << 16) | ('F' << 8),
        JJY = ('J' << 24) | ('J' << 16) | ('Y' << 8),
        LORC = ('L' << 24) | ('O' << 16) | ('R' << 8) | 'C',
        TDF = ('T' << 24) | ('D' << 16) | ('F' << 8),
        CHU = ('C' << 24) | ('H' << 16) | ('U' << 8),
        WWV = ('W' << 24) | ('W' << 16) | ('V' << 8),
        WWVH = ('W' << 24) | ('W' << 16) | ('V' << 8) | 'H',
        NIST = ('N' << 24) | ('I' << 16) | ('S' << 8) | 'T',
        ACTS = ('A' << 24) | ('C' << 16) | ('T' << 8) | 'S',
        USNO = ('U' << 24) | ('S' << 16) | ('N' << 8) | 'O',
        PTB = ('P' << 24) | ('T' << 16) | ('B' << 8),

        // v3
        DCN = ('D' << 24) | ('C' << 16) | ('N' << 8),
        TSP = ('T' << 24) | ('S' << 16) | ('P' << 8),
        DTS = ('D' << 24) | ('T' << 16) | ('S' << 8),
        ATOM = ('A' << 24) | ('T' << 16) | ('O' << 8) | 'M',
        VLF = ('V' << 24) | ('L' << 16) | ('F' << 8),

    };

    /**
	 * @class NtpLayer
	 * Represents a NTP (Network Time Protocol) layer
	 */
    class NtpLayer : public Layer
    {
    private:
        std::string convertToHex(uint8_t *dgst, int len) const;

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
         * Get the value of originate timestamp
         * @return Value in NTP timestamp format 
         */
        uint64_t getOriginateTimestamp() const;

        /**
         * Set the value of originate timestamp
         * @param[in] val Value in NTP timestamp format
         */
        void setOriginateTimestamp(uint64_t val);

        /**
         * Get the value of originate timestamp
         * @return Value in seconds from Unix Epoch (1 Jan 1970)
         */
        double getOriginateTimestampInSecs() const;

        /**
         * Set the value of originate timestamp
         * @param val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setOriginateTimestampInSecs(double val);

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