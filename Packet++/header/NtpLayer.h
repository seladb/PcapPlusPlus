#ifndef PACKETPP_NTP_LAYER
#define PACKETPP_NTP_LAYER

#include "Logger.h"
#include "Layer.h"
#include "IpAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
    /**
	 * @class NtpLayer
	 * Represents a NTP (Network Time Protocol) layer
     *
     * @brief The NTP packet consists of an integral number of 32-bit (4 octet) words in network byte order.
     * The packet format consists of three components: the header itself, one or more optional extension fields (for v4),
     * and an optional message authentication code (MAC). Currently the extension fields are not supported. The NTP header is:
     *
     * @verbatim
       0                   1                   2                   3
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
     @endverbatim
     *
	 */
    class NtpLayer : public Layer
    {
    private:
#pragma pack(push, 1)
        struct ntp_header
        {
#if (BYTE_ORDER == LITTLE_ENDIAN)
            /// 3-bit integer representing the mode
            uint8_t mode:3,
            /// 3-bit integer representing the NTP version number
            version:3,
            /// LI Leap Indicator (leap): 2-bit integer warning of an impending leap second to be inserted or deleted in the last minute of the current month
            leapIndicator:2;
#else
            /// LI Leap Indicator (leap): 2-bit integer warning of an impending leap second to be inserted or deleted in the last minute of the current month
            uint8_t leapIndicator:2,
            /// 3-bit integer representing the NTP version number
            version:3,
            /// 3-bit integer representing the mode
            mode:3;
#endif
            /// 8-bit integer representing the stratum
            uint8_t stratum;
            /// Total round-trip delay to the reference clock, in log2 seconds.
            int8_t pollInterval,
            /// 8-bit signed integer representing the precision of the system clock, in log2 seconds.
            precision;
            /// Total round-trip delay to the reference clock, in NTP short format.
            uint32_t rootDelay,
            /// Total dispersion to the reference clock, in NTP short format.
            rootDispersion,
            /// 32-bit code identifying the particular server or reference clock.  The interpretation depends on the value in the stratum field.
            referenceIdentifier;
            /// Time when the system clock was last set or corrected, in NTP timestamp format.
            uint64_t referenceTimestamp,
            /// Time at the client when the request departed for the server, in NTP timestamp format.
            originTimestamp,
            /// Time at the client when the request departed for the server, in NTP timestamp format.
            receiveTimestamp,
            /// Time at the server when the response left for the client, in NTP timestamp format.
            transmitTimestamp;
        };
#pragma pack(pop)

#pragma pack(push, 1)
        struct ntp_v3_auth
        {
            /// An integer identifying the cryptographic key used to generate the message-authentication code
            uint32_t keyID;
            /// This is an integer identifying the cryptographic key used to generate the message-authentication code.
            uint8_t dgst[8]; // 64 bit DES based
        };
#pragma pack(pop)

#pragma pack(push, 1)
        struct ntp_v4_auth_md5
        {
            /// 32-bit unsigned integer used by the client and server to designate a secret 128-bit MD5 key.
            uint32_t keyID;
            /// 128-bit MD5 hash
            uint8_t dgst[16];
        };
#pragma pack(pop)

#pragma pack(push, 1)
        struct ntp_v4_auth_sha1
        {
            /// 32-bit unsigned integer used by the client and server to designate a secret 160-bit SHA1 key.
            uint32_t keyID;
            /// 160-bit SHA1 hash
            uint8_t dgst[20];
        };
#pragma pack(pop)

        ntp_header *getNtpHeader() const { return (ntp_header *)m_Data; }

    public:
        /**
        * Warning of an impending leap second to be inserted or deleted in the last minute of the current month
        */
        enum LeapIndicator
        {
            /// Normal, no leap second
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
        enum Mode
        {
            /// Reserved variable
            Reserved = 0,
            /// Symmetrically active
            SymActive,
            /// Symmetrically passive
            SymPassive,
            /// Client mode
            Client,
            /// Server mode
            Server,
            /// Broadcasting mode
            Broadcast,
            /// NTP control messages
            Control,
            /// Reserved for private use
            PrivateUse
        };

        /**
         * 32-bit code identifying the particular server or reference clock.
         * The interpretation depends on the value in the stratum field.
         */
        enum ClockSource
        {
            // NTPv4

            /// Geosynchronous Orbit Environment Satellite
            GOES = ('G') | ('O' << 8) | ('E' << 16) | ('S' << 24),
            /// Global Position System
            GPS = ('G') | ('P' << 8) | ('S' << 16),
            /// Galileo Positioning System
            GAL = ('G') | ('A' << 8) | ('L' << 16),
            /// Generic pulse-per-second
            PPS = ('P') | ('P' << 8) | ('S' << 16),
            /// Inter-Range Instrumentation Group
            IRIG = ('I') | ('R' << 8) | ('I' << 16) | ('G' << 24),
            /// LF Radio WWVB Ft. Collins, CO 60 kHz
            WWVB = ('W') | ('W' << 8) | ('V' << 16) | ('B' << 24),
            /// LF Radio DCF77 Mainflingen, DE 77.5 kHz
            DCF = ('D') | ('C' << 8) | ('F' << 16),
            /// LF Radio HBG Prangins, HB 75 kHz
            HBG = ('H') | ('B' << 8) | ('G' << 16),
            /// LF Radio MSF Anthorn, UK 60 kHz
            MSF = ('M') | ('S' << 8) | ('F' << 16),
            /// LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz
            JJY = ('J') | ('J' << 8) | ('Y' << 16),
            /// MF Radio LORAN C station, 100 kHz
            LORC = ('L') | ('O' << 8) | ('R' << 16) | ('C' << 24),
            /// MF Radio Allouis, FR 162 kHz
            TDF = ('T') | ('D' << 8) | ('F' << 16),
            /// HF Radio CHU Ottawa, Ontario
            CHU = ('C') | ('H' << 8) | ('U' << 16),
            /// HF Radio WWV Ft. Collins, CO
            WWV = ('W') | ('W' << 8) | ('V' << 16),
            /// HF Radio WWVH Kauai, HI
            WWVH = ('W') | ('W' << 8) | ('V' << 16) | ('H' << 24),
            /// NIST telephone modem
            NIST = ('N') | ('I' << 8) | ('S' << 16) | ('T' << 24),
            /// NIST telephone modem
            ACTS = ('A') | ('C' << 8) | ('T' << 16) | ('S' << 24),
            /// USNO telephone modem
            USNO = ('U') | ('S' << 8) | ('N' << 16) | ('O' << 24),
            /// European telephone modem
            PTB = ('P') | ('T' << 8) | ('B' << 16),
            /// Meinberg DCF77 with amplitude modulation (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            DCFa = ('D') | ('C' << 8) | ('F' << 16) | ('a' << 24),
            /// Meinberg DCF77 with phase modulation)/pseudo random phase modulation (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            DCFp = ('D') | ('C' << 8) | ('F' << 16) | ('p' << 24),
            /// Meinberg GPS (with shared memory access) (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            GPSs = ('G') | ('P' << 8) | ('S' << 16) | ('s' << 24),
            /// Meinberg GPS (with interrupt based access) (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            GPSi = ('G') | ('P' << 8) | ('S' << 16) | ('i' << 24),
            /// Meinberg GPS/GLONASS (with shared memory access) (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            GLNs = ('G') | ('L' << 8) | ('N' << 16) | ('s' << 24),
            /// Meinberg GPS/GLONASS (with interrupt based access) (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            GLNi = ('G') | ('L' << 8) | ('N' << 16) | ('i' << 24),
            /// Meinberg Undisciplined local clock (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            LCL = ('L') | ('C' << 8) | ('L' << 16),
            /// Meinberg Undisciplined local clock (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
            LOCL = ('L') | ('O' << 8) | ('C' << 16) | ('L' << 24),

            // NTPv3

            /// DCN routing protocol
            DCN = ('D') | ('C' << 8) | ('N' << 16),
            /// TSP time protocol
            TSP = ('T') | ('S' << 8) | ('P' << 16),
            /// Digital Time Service
            DTS = ('D') | ('T' << 8) | ('S' << 16),
            /// Atomic clock (calibrated)
            ATOM = ('A') | ('T' << 8) | ('O' << 16) | ('M' << 24),
            /// VLF radio (OMEGA, etc.)
            VLF = ('V') | ('L' << 8) | ('F' << 16)

        };

        /**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
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
         * @return The leap indicator
         */
        LeapIndicator getLeapIndicator() const;

        /**
         * Set the leap indicator
         */
        void setLeapIndicator(LeapIndicator val);

        /**
         * @return The version of NTP
         */
        uint8_t getVersion() const;

        /**
         * Set the version of NTP
         */
        void setVersion(uint8_t val);

        /**
         * @return The mode value
         */
        Mode getMode() const;

        /**
         * @return The mode as string
         */
        std::string getModeString() const;

        /**
         * Set the mode
         */
        void setMode(Mode val);

        /**
         * @return The value of stratum
         */
        uint8_t getStratum() const;

        /**
         * Set the value of stratum
         */
        void setStratum(uint8_t val);

        /**
         * @return The value of poll interval in log2 seconds
         */
        int8_t getPollInterval() const;

        /**
         * Set the value of poll interval
         * @param[in] val Poll interval in log2 seconds
         */
        void setPollInterval(int8_t val);

        /**
         * @return The value of poll interval in seconds
         */
        double getPollIntervalInSecs() const;

        /**
         * @return The value of precision in log2 seconds
         */
        int8_t getPrecision() const;

        /**
         * Set the value of precision
         * @param[in] val Precision in log2 seconds
         */
        void setPrecision(int8_t val);

        /**
         * @return The value of precision in seconds
         */
        double getPrecisionInSecs() const;

        /**
         * @return The value of root delay in NTP short format
         */
        uint32_t getRootDelay() const;

        /**
         * Set the value of root delay
         * @param[in] val Root delay in NTP short format
         */
        void setRootDelay(uint32_t val);

        /**
         * @return The value of root delay in seconds
         */
        double getRootDelayInSecs() const;

        /**
         * Set the value of root delay
         * @param[in] val Root delay in seconds
         */
        void setRootDelayInSecs(double val);

        /**
         * @return The value of root dispersion in NTP short format
         */
        uint32_t getRootDispersion() const;

        /**
         * Set the value of root delay
         * @param[in] val Root dispersion in NTP short format
         */
        void setRootDispersion(uint32_t val);

        /**
         * @return The value of root dispersion in seconds
         */
        double getRootDispersionInSecs() const;

        /**
         * Set the value of root dispersion
         * @param[in] val Root dispersion in seconds
         */
        void setRootDispersionInSecs(double val);

        /**
         * @return The value of reference identifier
         */
        uint32_t getReferenceIdentifier() const;

        /**
         * Set the value of reference identifier
         * @param[in] val Value of the reference identifier as IPv4 address
         */
        void setReferenceIdentifier(IPv4Address val);

        /**
         * Set the value of reference identifier
         * @param[in] val Value of the reference identifier as ClockSource
         */
        void setReferenceIdentifier(ClockSource val);

        /**
         * @return The value of reference identifier as a string. String representation of NTP clock source if stratum is 1,
         * IPv4 address or MD5 hash of first four octets of IPv6
         */
        std::string getReferenceIdentifierString() const;

        /**
         * @return The value of reference timestamp in NTP timestamp format
         */
        uint64_t getReferenceTimestamp() const;

        /**
         * Set the value of reference timestamp
         * @param[in] val Timestamp in NTP timestamp format
         */
        void setReferenceTimestamp(uint64_t val);

        /**
         * @return The value of reference timestamp in seconds from Unix Epoch (1 Jan 1970)
         */
        double getReferenceTimestampInSecs() const;

        /**
         * Set the value of reference timestamp
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setReferenceTimestampInSecs(double val);

        /**
         * @return The reference timestamp value as readable string in ISO8601 format
         */
        std::string getReferenceTimestampAsString();

        /**
         * @return The value of origin timestamp in NTP timestamp format
         */
        uint64_t getOriginTimestamp() const;

        /**
         * Set the value of origin timestamp
         * @param[in] val Value in NTP timestamp format
         */
        void setOriginTimestamp(uint64_t val);

        /**
         * @return The value of origin timestamp in seconds from Unix Epoch (1 Jan 1970)
         */
        double getOriginTimestampInSecs() const;

        /**
         * Set the value of origin timestamp
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setOriginTimestampInSecs(double val);

        /**
         * @return the origin timestamp value as readable string in ISO8601 format
         */
        std::string getOriginTimestampAsString();

        /**
         * @return The value of receive timestamp in NTP timestamp format
         */
        uint64_t getReceiveTimestamp() const;

        /**
         * Set the value of receive timestamp
         * @param[in] val Value in NTP timestamp format
         */
        void setReceiveTimestamp(uint64_t val);

        /**
         * @return The value of receive timestampin seconds from Unix Epoch (1 Jan 1970)
         */
        double getReceiveTimestampInSecs() const;

        /**
         * Set the value of receive timestamp
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setReceiveTimestampInSecs(double val);

        /**
         * @return The receive timestamp value as readable string in ISO8601 format
         */
        std::string getReceiveTimestampAsString();

        /**
         * @return The value of transmit timestamp in NTP timestamp format
         */
        uint64_t getTransmitTimestamp() const;

        /**
         * Set the value of transmit timestamp
         * @param[in] val Value in NTP timestamp format
         */
        void setTransmitTimestamp(uint64_t val);

        /**
         * @return The value of transmit timestamp in seconds from Unix Epoch (1 Jan 1970)
         */
        double getTransmitTimestampInSecs() const;

        /**
         * Set the value of transmit timestamp
         * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
         */
        void setTransmitTimestampInSecs(double val);

        /**
         * @return The transmit timestamp value as readable string in ISO8601 format
         */
        std::string getTransmitTimestampAsString();

        /**
         * @return Returns the key identifier if exists, returns 0 on unsupported NTP version or key identifier not found
         */
        uint32_t getKeyID() const;

        /**
         * @return Get the digest value as hexadecimal string, empty string on unsupported version
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

        /// Parses the next layer. NTP is the always last so does nothing for this layer
        void parseNextLayer() {}

        /**
         * @return Get the size of the layer (Including the extension and authentication fields if exists)
         */
        size_t getHeaderLen() const { return m_DataLen; }

        /// Does nothing for this layer
        void computeCalculateFields() {}

        /**
         * @return The OSI layer level of NTP (Application Layer).
         */
        OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

        /**
         * @return Returns the protocol info as readable string
         */
        std::string toString() const;
    };

} // namespace pcpp

#endif /* PACKETPP_NTP_LAYER */
