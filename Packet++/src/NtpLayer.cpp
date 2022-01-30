#define LOG_MODULE PacketLogModuleNtpLayer

#include "NtpLayer.h"
#include "Logger.h"

#include <math.h>
#include <stdlib.h>

/// 2^16 as a double
#define NTP_FRIC 65536.
/// 2^32 as a double
#define NTP_FRAC 4294967296.
/// Epoch offset between Unix time and NTP
#define EPOCH_OFFSET 2208988800ULL

namespace pcpp
{
    NtpLayer::NtpLayer()
    {
        m_DataLen = sizeof(ntp_header);
        m_Data = new uint8_t[sizeof(ntp_header)];
        memset(m_Data, 0, sizeof(ntp_header));
        m_Protocol = NTP;
    }

    NtpLayer::LeapIndicator NtpLayer::getLeapIndicator() const
    {
        if (getNtpHeader()->leapIndicator < 4) // Since leap indicator field is 2bit
            return static_cast<LeapIndicator>(getNtpHeader()->leapIndicator);
        LOG_ERROR("Unknown NTP Leap Indicator");
        return Unknown;
    }

    void NtpLayer::setLeapIndicator(LeapIndicator val)
    {
        getNtpHeader()->leapIndicator = val;
    }

    uint8_t NtpLayer::getVersion() const
    {
        return getNtpHeader()->version;
    }

    void NtpLayer::setVersion(uint8_t val)
    {
        getNtpHeader()->version = val;
    }

    NtpLayer::Mode NtpLayer::getMode() const
    {
        if (getNtpHeader()->mode < 8) // Since mode field 3bit
            return static_cast<Mode>(getNtpHeader()->mode);
        LOG_ERROR("Unknown NTP Mode");
        return Reserved;
    }

    std::string NtpLayer::getModeString() const
    {
        switch (getMode())
        {
        case Reserved:
            return "Reserved";
        case SymActive:
            return "Symmetrically Active";
        case SymPassive:
            return "Symmetrically Passive";
        case Client:
            return "Client";
        case Server:
            return "Server";
        case Broadcast:
            return "Broadcast";
        case Control:
            return "Control";
        case PrivateUse:
            return "Private Use";
        default:
            LOG_ERROR("Unknown NTP Mode");
            return std::string();
        }
    }

    void NtpLayer::setMode(Mode val)
    {
        getNtpHeader()->mode = val;
    }

    uint8_t NtpLayer::getStratum() const
    {
        return getNtpHeader()->stratum;
    }

    void NtpLayer::setStratum(uint8_t val)
    {
        getNtpHeader()->stratum = val;
    }

    int8_t NtpLayer::getPollInterval() const
    {
        return getNtpHeader()->pollInterval;
    }

    void NtpLayer::setPollInterval(int8_t val)
    {
        getNtpHeader()->pollInterval = val;
    }

    double NtpLayer::getPollIntervalInSecs() const
    {
        return pow(2, getPollInterval());
    }

    int8_t NtpLayer::getPrecision() const
    {
        return getNtpHeader()->precision;
    }

    void NtpLayer::setPrecision(int8_t val)
    {
        getNtpHeader()->precision = val;
    }

    double NtpLayer::getPrecisionInSecs() const
    {
        return pow(2, getPrecision());
    }

    uint32_t NtpLayer::getRootDelay() const
    {
        return getNtpHeader()->rootDelay;
    }

    void NtpLayer::setRootDelay(uint32_t val)
    {
        getNtpHeader()->rootDelay = val;
    }

    double NtpLayer::getRootDelayInSecs() const
    {
        return convertFromShortFormat(getRootDelay());
    }

    void NtpLayer::setRootDelayInSecs(double val)
    {
        getNtpHeader()->rootDelay = convertToShortFormat(val);
    }

    uint32_t NtpLayer::getRootDispersion() const
    {
        return getNtpHeader()->rootDispersion;
    }

    void NtpLayer::setRootDispersion(uint32_t val)
    {
        getNtpHeader()->rootDispersion = val;
    }

    double NtpLayer::getRootDispersionInSecs() const
    {
        return convertFromShortFormat(getRootDispersion());
    }

    void NtpLayer::setRootDispersionInSecs(double val)
    {
        getNtpHeader()->rootDispersion = convertToShortFormat(val);
    }

    uint32_t NtpLayer::getReferenceIdentifier() const
    {
        return getNtpHeader()->referenceIdentifier;
    }

    void NtpLayer::setReferenceIdentifier(uint32_t val)
    {
        getNtpHeader()->referenceIdentifier = val;
    }

    std::string NtpLayer::getReferenceIdentifierString() const
    {
        uint8_t stratum = getStratum();

        if (stratum == 0)
        {
            switch (getVersion())
            {
            case 3:
            {
                switch (getReferenceIdentifier())
                {
                case DCN:
                    return "DCN routing protocol";
                case NIST:
                    return "NIST public modem";
                case TSP:
                    return "TSP time protocol";
                case DTS:
                    return "Digital Time Service";
                default:
                    return "Unknown";
                }
            }
            case 4:
                // FIXME: It should return 4-character Kiss Code
                return "Unspecified";
            default:
                return "Unsupported NTP version";
            }
        }
        else if (stratum == 1)
        {
            switch (getVersion())
            {
            case 3:
            {
                switch (getReferenceIdentifier())
                {
                case ATOM:
                    return "Atomic clock";
                case VLF:
                    return "VLF radio";
                case LORC:
                    return "LORAN-C radionavigation";
                case GOES:
                    return "GOES UHF environment satellite";
                case GPS:
                    return "GPS UHF satellite positioning";
                default:
                    return "Unknown";
                }
            }
            case 4:
            {
                switch (getReferenceIdentifier())
                {
                case GOES:
                    return "Geosynchronous Orbit Environment Satellite";
                case GPS:
                    return "Global Position System";
                case GAL:
                    return "Galileo Positioning System";
                case PPS:
                    return "Generic pulse-per-second";
                case IRIG:
                    return "Inter-Range Instrumentation Group";
                case WWVB:
                    return "LF Radio WWVB Ft. Collins, CO 60 kHz";
                case DCF:
                    return "LF Radio DCF77 Mainflingen, DE 77.5 kHz";
                case HBG:
                    return "LF Radio HBG Prangins, HB 75 kHz";
                case MSF:
                    return "LF Radio MSF Anthorn, UK 60 kHz";
                case JJY:
                    return "LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz";
                case LORC:
                    return "MF Radio LORAN C station, 100 kHz";
                case TDF:
                    return "MF Radio Allouis, FR 162 kHz";
                case CHU:
                    return "HF Radio CHU Ottawa, Ontario";
                case WWV:
                    return "HF Radio WWV Ft. Collins, CO";
                case WWVH:
                    return "HF Radio WWVH Kauai, HI";
                case NIST:
                    return "NIST telephone modem";
                case ACTS:
                    return "NIST telephone modem";
                case USNO:
                    return "USNO telephone modem";
                case PTB:
                    return "European telephone modem";
                case DCFa:
                    return "Meinberg DCF77 with amplitud modulation";
                case DCFp:
                    return "Meinberg DCF77 with phase modulation)/pseudo random phase modulation";
                case GPSs:
                    return "Meinberg GPS (with shared memory access)";
                case GPSi:
                    return "Meinberg GPS (with interrupt based access)";
                case GLNs:
                    return "Meinberg GPS/GLONASS (with shared memory access)";
                case GLNi:
                    return "Meinberg GPS/GLONASS (with interrupt based access)";
                case LCL:
                    return "Meinberg Undisciplined local clock";
                case LOCL:
                    return "Meinberg Undisciplined local clock";
                default:
                    return "Unknown";
                }
            }
            }
        }
        else if (stratum > 1)
        {
            // FIXME: Support IPv6 cases for NTPv4, it equals to MD5 hash of first four octets of IPv6 address

            pcpp::IPv4Address addr(getReferenceIdentifier());
            return addr.toString();
        }

        LOG_ERROR("Unknown Stratum type");
        return std::string();
    }

    uint64_t NtpLayer::getReferenceTimestamp() const
    {
        return getNtpHeader()->referenceTimestamp;
    }

    void NtpLayer::setReferenceTimestamp(uint64_t val)
    {
        getNtpHeader()->referenceTimestamp = val;
    }

    double NtpLayer::getReferenceTimestampInSecs() const
    {
        return convertFromTimestampFormat(getReferenceTimestamp());
    }

    void NtpLayer::setReferenceTimestampInSecs(double val)
    {
        getNtpHeader()->referenceTimestamp = convertToTimestampFormat(val);
    }

    std::string NtpLayer::getReferenceTimestampAsString()
    {
        return convertToIsoFormat(getReferenceTimestamp());
    }

    uint64_t NtpLayer::getOriginTimestamp() const
    {
        return getNtpHeader()->originTimestamp;
    }

    void NtpLayer::setOriginTimestamp(uint64_t val)
    {
        getNtpHeader()->originTimestamp = val;
    }

    double NtpLayer::getOriginTimestampInSecs() const
    {
        return convertFromTimestampFormat(getOriginTimestamp());
    }

    void NtpLayer::setOriginTimestampInSecs(double val)
    {
        getNtpHeader()->originTimestamp = convertToTimestampFormat(val);
    }

    std::string NtpLayer::getOriginTimestampAsString()
    {
        return convertToIsoFormat(getOriginTimestamp());
    }

    uint64_t NtpLayer::getReceiveTimestamp() const
    {
        return getNtpHeader()->receiveTimestamp;
    }

    void NtpLayer::setReceiveTimestamp(uint64_t val)
    {
        getNtpHeader()->receiveTimestamp = val;
    }

    double NtpLayer::getReceiveTimestampInSecs() const
    {
        return convertFromTimestampFormat(getReceiveTimestamp());
    }

    void NtpLayer::setReceiveTimestampInSecs(double val)
    {
        getNtpHeader()->receiveTimestamp = convertToTimestampFormat(val);
    }

    std::string NtpLayer::getReceiveTimestampAsString()
    {
        return convertToIsoFormat(getReceiveTimestamp());
    }

    uint64_t NtpLayer::getTransmitTimestamp() const
    {
        return getNtpHeader()->transmitTimestamp;
    }

    void NtpLayer::setTransmitTimestamp(uint64_t val)
    {
        getNtpHeader()->transmitTimestamp = val;
    }

    double NtpLayer::getTransmitTimestampInSecs() const
    {
        return convertFromTimestampFormat(getTransmitTimestamp());
    }

    void NtpLayer::setTransmitTimestampInSecs(double val)
    {
        getNtpHeader()->transmitTimestamp = convertToTimestampFormat(val);
    }

    std::string NtpLayer::getTransmitTimestampAsString()
    {
        return convertToIsoFormat(getTransmitTimestamp());
    }

    uint32_t NtpLayer::getKeyID() const
    {
        switch (getVersion())
        {
        case 3:
        {
            if (m_DataLen < (sizeof(ntp_header) + sizeof(ntp_v3_auth)))
                return 0;

            ntp_v3_auth *header = (ntp_v3_auth *)(m_Data + sizeof(ntp_header));
            return header->keyID;
        }
        case 4:
        {
            // FIXME: Add support for extension fields
            if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_md5)))
            {
                ntp_v4_auth_md5 *header = (ntp_v4_auth_md5 *)(m_Data + m_DataLen - sizeof(ntp_v4_auth_md5));
                return header->keyID;
            }
            if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_sha1)))
            {
                ntp_v4_auth_sha1 *header = (ntp_v4_auth_sha1 *)(m_Data + m_DataLen - sizeof(ntp_v4_auth_sha1));
                return header->keyID;
            }

            LOG_ERROR("NTP authentication parsing with extension fields are not supported");
            return 0;
        }
        default:
        {
            LOG_ERROR("NTP version not supported");
            return 0;
        }
        }
    }

    std::string NtpLayer::getDigest() const
    {
        switch (getVersion())
        {
        case 3:
        {
            if (m_DataLen < (sizeof(ntp_header) + sizeof(ntp_v3_auth)))
                return std::string();

            ntp_v3_auth *header = (ntp_v3_auth *)(m_Data + sizeof(ntp_header));
            return byteArrayToHexString(header->dgst, 8);
        }
        case 4:
        {
            if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_md5)))
            {
                ntp_v4_auth_md5 *header = (ntp_v4_auth_md5 *)(m_Data + m_DataLen - sizeof(ntp_v4_auth_md5));
                return byteArrayToHexString(header->dgst, 16);
            }
            if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_sha1)))
            {
                ntp_v4_auth_sha1 *header = (ntp_v4_auth_sha1 *)(m_Data + m_DataLen - sizeof(ntp_v4_auth_sha1));
                return byteArrayToHexString(header->dgst, 20);
            }

            LOG_ERROR("NTP authentication parsing with extension fields are not supported");
            return std::string();
        }
        default:
            LOG_ERROR("NTP version not supported");
            return std::string();
        }
    }

    double NtpLayer::convertFromShortFormat(const uint32_t val)
    {
        double integerPart, fractionPart;

        integerPart = netToHost16(val & 0xFFFF);
        fractionPart = netToHost16(((val & 0xFFFF0000) >> 16)) / NTP_FRIC;

        return integerPart + fractionPart;
    }

    double NtpLayer::convertFromTimestampFormat(const uint64_t val)
    {
        double integerPart, fractionPart;

        integerPart = netToHost32(val & 0xFFFFFFFF);
        fractionPart = netToHost32(((val & 0xFFFFFFFF00000000) >> 32)) / NTP_FRAC;

        // FIXME: Return integer and fraction parts as struct to increase precision
        // Offset change should be done here because of overflow
        return integerPart + fractionPart - EPOCH_OFFSET;
    }

    uint32_t NtpLayer::convertToShortFormat(const double val)
    {
        uint32_t retval = 0;
        double integerPart, fractionPart;
        uint16_t integerPartInt, fractionPartInt;

        fractionPart = modf(val, &integerPart);

        // Cast values to 16bit
        integerPartInt = hostToNet16(integerPart);
        fractionPartInt = hostToNet16(fractionPart * NTP_FRIC);

        retval = retval | uint32_t(integerPartInt);
        retval = retval | (uint32_t(fractionPartInt)) << 16;

        return retval;
    }

    uint64_t NtpLayer::convertToTimestampFormat(const double val)
    {
        uint64_t retval = 0;
        double integerPart, fractionPart;
        uint32_t integerPartInt, fractionPartInt;

        fractionPart = modf(val, &integerPart);

        // Cast values to 32bit
        integerPartInt = hostToNet32(integerPart + EPOCH_OFFSET);
        fractionPartInt = hostToNet32(fractionPart * NTP_FRAC);

        retval = retval | uint64_t(integerPartInt);
        retval = retval | (uint64_t(fractionPartInt) << 32);

        return retval;
    }

    std::string NtpLayer::convertToIsoFormat(const double timestamp)
    {
        char buffer[50], bufferFraction[15];
        double integerPart, fractionPart;
        struct tm *timer;
        time_t timeStruct;

        fractionPart = modf(timestamp, &integerPart);

        timeStruct = integerPart;
#if defined(_WIN32)
        if (timeStruct < 0)
            timeStruct = 0;
        timer = gmtime(&timeStruct);
#else
        struct tm timer_r;
        timer = gmtime_r(&timeStruct, &timer_r);

        if (timer != NULL)
            timer = &timer_r;
#endif
        if (timer == NULL)
        {
            LOG_ERROR("Can't convert time");
            return std::string();
        }
        strftime(buffer, sizeof(buffer) - sizeof(bufferFraction), "%Y-%m-%dT%H:%M:%S", timer);

        snprintf(bufferFraction, sizeof(bufferFraction), "%.04lfZ", fabs(fractionPart));
        strncat(buffer, &bufferFraction[1], sizeof(bufferFraction));

        return std::string(buffer);
    }

    std::string NtpLayer::convertToIsoFormat(const uint64_t timestampInNTPformat)
    {
        return convertToIsoFormat(convertFromTimestampFormat(timestampInNTPformat));
    }

    bool NtpLayer::isDataValid(const uint8_t *data, size_t dataSize)
    {
        return data && dataSize >= sizeof(ntp_header);
    }

    std::string NtpLayer::toString() const
    {
        std::stringstream ss;

        ss << "NTP Layer v" << (int)getVersion() << ", Mode: " << getModeString();

        return ss.str();
    }
}
