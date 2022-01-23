#define LOG_MODULE PacketLogModuleNtpLayer

#include "NtpLayer.h"
#include "Logger.h"

namespace pcpp
{
    static char HexDigitList[] = "0123456789abcdef";

    std::string NtpLayer::convertToHex(uint8_t *dgst, int len) const
    {
        std::string retval;

        retval.append(1, '0');
        retval.append(1, 'x');

        for (int n = 1; n <= len / 4; n++)
        {
            uint32_t x = netToHost32(((uint32_t *)dgst)[n - 1]);
            for (int nd = 8; nd > 0; nd--)
            {
                char c = HexDigitList[(x >> (nd - 1) * 4) & 0xF];
                retval.append(1, c);
            }
        }

        return retval;
    }

    NTPLeapIndicator NtpLayer::getLeapIndicator() const
    {
        return static_cast<NTPLeapIndicator>(((ntp_header *)m_Data)->leapIndicator);
    }

    uint8_t NtpLayer::getVersion() const
    {
        return ((ntp_header *)m_Data)->version;
    }

    NTPMode NtpLayer::getMode() const
    {
        return static_cast<NTPMode>(((ntp_header *)m_Data)->mode);
    }

    uint8_t NtpLayer::getStratum() const
    {
        return ((ntp_header *)m_Data)->stratum;
    }

    int8_t NtpLayer::getPollInterval() const
    {
        return ((ntp_header *)m_Data)->pollInterval;
    }

    double NtpLayer::getPollIntervalInSecs() const
    {
        return pow(2, getPollInterval());
    }

    int8_t NtpLayer::getPrecision() const
    {
        return ((ntp_header *)m_Data)->precision;
    }

    double NtpLayer::getPrecisionInSecs() const
    {
        return pow(2, getPrecision());
    }

    uint32_t NtpLayer::getRootDelay() const
    {
        return ((ntp_header *)m_Data)->rootDelay;
    }

    double NtpLayer::getRootDelayInSecs() const
    {
        return convertFromShortFormat(getRootDelay());
    }

    uint32_t NtpLayer::getRootDispersion() const
    {
        return ((ntp_header *)m_Data)->rootDispersion;
    }

    double NtpLayer::getRootDispersionInSecs() const
    {
        return convertFromShortFormat(getRootDispersion());
    }

    uint32_t NtpLayer::getReferenceIdentifier() const
    {
        return ((ntp_header *)m_Data)->referenceIdentifier;
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
                    return std::string("DCN routing protocol");
                case NIST:
                    return std::string("NIST public modem");
                case TSP:
                    return std::string("TSP time protocol");
                case DTS:
                    return std::string("Digital Time Service");
                default:
                    return std::string("Unknown");
                }
            }
            case 4:
                // FIXME: It should return 4-character Kiss Code
                return std::string("Unspecified");
            default:
                return std::string("Unsupported NTP version");
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
                    return std::string("Atomic clock");
                case VLF:
                    return std::string("VLF radio");
                case LORC:
                    return std::string("LORAN-C radionavigation");
                case GOES:
                    return std::string("GOES UHF environment satellite");
                case GPS:
                    return std::string("GPS UHF satellite positioning");
                default:
                    return std::string("Unknown");
                }
            }
            case 4:
            {
                switch (getReferenceIdentifier())
                {
                case GOES:
                    return std::string("Geosynchronous Orbit Environment Satellite");
                case GPS:
                    return std::string("Global Position System");
                case GAL:
                    return std::string("Galileo Positioning System");
                case PPS:
                    return std::string("Generic pulse-per-second");
                case IRIG:
                    return std::string("Inter-Range Instrumentation Group");
                case WWVB:
                    return std::string("LF Radio WWVB Ft. Collins, CO 60 kHz");
                case DCF:
                    return std::string("LF Radio DCF77 Mainflingen, DE 77.5 kHz");
                case HBG:
                    return std::string("LF Radio HBG Prangins, HB 75 kHz");
                case MSF:
                    return std::string("LF Radio MSF Anthorn, UK 60 kHz");
                case JJY:
                    return std::string("LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz");
                case LORC:
                    return std::string("MF Radio LORAN C station, 100 kHz");
                case TDF:
                    return std::string("MF Radio Allouis, FR 162 kHz");
                case CHU:
                    return std::string("HF Radio CHU Ottawa, Ontario");
                case WWV:
                    return std::string("HF Radio WWV Ft. Collins, CO");
                case WWVH:
                    return std::string("HF Radio WWVH Kauai, HI");
                case NIST:
                    return std::string("NIST telephone modem");
                case ACTS:
                    return std::string("NIST telephone modem");
                case USNO:
                    return std::string("USNO telephone modem");
                case PTB:
                    return std::string("European telephone modem");
                default:
                    return std::string("Unknown");
                }
            }
            }
        }
        else if (stratum > 1)
        {
            // FIXME: Support IPv6 cases for NTPv4, it equals to MD5 hash of first four octets of IPv6 address
            char buffer[INET_ADDRSTRLEN] = {'\0'};
            struct in_addr addr;
            addr.s_addr = getReferenceIdentifier();

            inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);

            return std::string(buffer);
        }

        LOG_ERROR("Unknown Stratum type");
        return std::string();
    }

    uint64_t NtpLayer::getReferenceTimestamp() const
    {
        return ((ntp_header *)m_Data)->referenceTimestamp;
    }

    double NtpLayer::getReferenceTimestampInSecs() const
    {
        return convertFromTimestampFormat(getReferenceTimestamp());
    }

    uint64_t NtpLayer::getOriginateTimestamp() const
    {
        return ((ntp_header *)m_Data)->originateTimestamp;
    }

    double NtpLayer::getOriginateTimestampInSecs() const
    {
        return convertFromTimestampFormat(getOriginateTimestamp());
    }

    uint64_t NtpLayer::getReceiveTimestamp() const
    {
        return ((ntp_header *)m_Data)->receiveTimestamp;
    }

    double NtpLayer::getReceiveTimestampInSecs() const
    {
        return convertFromTimestampFormat(getReceiveTimestamp());
    }

    uint64_t NtpLayer::getTransmitTimestamp() const
    {
        return ((ntp_header *)m_Data)->transmitTimestamp;
    }

    double NtpLayer::getTransmitTimestampInSecs() const
    {
        return convertFromTimestampFormat(getTransmitTimestamp());
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
            if (m_DataLen < (sizeof(ntp_header) + sizeof(ntp_v4_auth)))
                return 0;

            ntp_v4_auth *header = (ntp_v4_auth *)(m_Data + m_DataLen - sizeof(ntp_v4_auth));
            return header->keyID;
        }
        default:
        {
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
            return convertToHex(header->dgst, 8);
        }
        case 4:
        {
            if (m_DataLen < (sizeof(ntp_header) + sizeof(ntp_v4_auth)))
                return std::string();

            ntp_v4_auth *header = (ntp_v4_auth *)(m_Data + m_DataLen - sizeof(ntp_v4_auth));
            return convertToHex(header->dgst, 16);
        }
        default:
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
        struct tm timer;
        time_t timeStruct;

        fractionPart = modf(timestamp, &integerPart);

        timeStruct = integerPart;
        gmtime_r(&timeStruct, &timer);
        strftime(buffer, sizeof(buffer) - sizeof(bufferFraction), "%FT%T", &timer);

        snprintf(bufferFraction, sizeof(bufferFraction), "%.09fZ", abs(fractionPart));
        strncat(buffer, &bufferFraction[1], sizeof(bufferFraction));

        return std::string(buffer);
    }

    std::string NtpLayer::convertToIsoFormat(const uint64_t timestampInNTPformat)
    {
        return convertToIsoFormat(convertFromTimestampFormat(timestampInNTPformat));
    }

    bool NtpLayer::isDataValid(const uint8_t *data, size_t dataSize)
    {
        if (data && dataSize >= sizeof(ntp_header))
            return true;
        return false;
    }

    std::string NtpLayer::toString() const
    {
        std::stringstream ss;

        ss << "NTP Layer, ";
        ss << "Version: " << (int)getVersion() << ", Mode: " << (int)getMode() << ", ";
        ss << "Leap Indicator: " << (int)getLeapIndicator() << ", Stratum: " << (int)getStratum();

        return ss.str();
    }
}
