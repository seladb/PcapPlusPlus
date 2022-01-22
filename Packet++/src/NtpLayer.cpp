#define LOG_MODULE PacketLogModuleNtpLayer

#include "NtpLayer.h"
#include "Logger.h"

namespace pcpp
{

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
        return ((ntp_header*)m_Data)->rootDispersion;
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
                case NTPClockSource::DCN:
                    return std::string("DCN routing protocol");
                case NTPClockSource::NIST:
                    return std::string("NIST public modem");
                case NTPClockSource::TSP:
                    return std::string("TSP time protocol");
                case NTPClockSource::DTS:
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
                case NTPClockSource::ATOM:
                    return std::string("Atomic clock");
                case NTPClockSource::VLF:
                    return std::string("VLF radio");
                case NTPClockSource::LORC:
                    return std::string("LORAN-C radionavigation");
                case NTPClockSource::GOES:
                    return std::string("GOES UHF environment satellite");
                case NTPClockSource::GPS:
                    return std::string("GPS UHF satellite positioning");
                default:
                    return std::string("Unknown");
                }
            }
            case 4:
            {
                switch (getReferenceIdentifier())
                {
                case NTPClockSource::GOES:
                    return std::string("Geosynchronous Orbit Environment Satellite");
                case NTPClockSource::GPS:
                    return std::string("Global Position System");
                case NTPClockSource::GAL:
                    return std::string("Galileo Positioning System");
                case NTPClockSource::PPS:
                    return std::string("Generic pulse-per-second");
                case NTPClockSource::IRIG:
                    return std::string("Inter-Range Instrumentation Group");
                case NTPClockSource::WWVB:
                    return std::string("LF Radio WWVB Ft. Collins, CO 60 kHz");
                case NTPClockSource::DCF:
                    return std::string("LF Radio DCF77 Mainflingen, DE 77.5 kHz");
                case NTPClockSource::HBG:
                    return std::string("LF Radio HBG Prangins, HB 75 kHz");
                case NTPClockSource::MSF:
                    return std::string("LF Radio MSF Anthorn, UK 60 kHz");
                case NTPClockSource::JJY:
                    return std::string("LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz");
                case NTPClockSource::LORC:
                    return std::string("MF Radio LORAN C station, 100 kHz");
                case NTPClockSource::TDF:
                    return std::string("MF Radio Allouis, FR 162 kHz");
                case NTPClockSource::CHU:
                    return std::string("HF Radio CHU Ottawa, Ontario");
                case NTPClockSource::WWV:
                    return std::string("HF Radio WWV Ft. Collins, CO");
                case NTPClockSource::WWVH:
                    return std::string("HF Radio WWVH Kauai, HI");
                case NTPClockSource::NIST:
                    return std::string("NIST telephone modem");
                case NTPClockSource::ACTS:
                    return std::string("NIST telephone modem");
                case NTPClockSource::USNO:
                    return std::string("USNO telephone modem");
                case NTPClockSource::PTB:
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
        return convertFromTimestampFormat(getReferenceTimestamp()) - EPOCH_OFFSET;
    }

    uint64_t NtpLayer::getOriginateTimestamp() const
    {
        return ((ntp_header *)m_Data)->originateTimestamp;
    }

    double NtpLayer::getOriginateTimestampInSecs() const
    {
        return convertFromTimestampFormat(getOriginateTimestamp()) - EPOCH_OFFSET;
    }

    uint64_t NtpLayer::getReceiveTimestamp() const
    {
        return ((ntp_header *)m_Data)->receiveTimestamp;
    }

    double NtpLayer::getReceiveTimestampInSecs() const
    {
        return convertFromTimestampFormat(getReceiveTimestamp()) - EPOCH_OFFSET;
    }

    uint64_t NtpLayer::getTransmitTimestamp() const
    {
        return ((ntp_header *)m_Data)->transmitTimestamp;
    }

    double NtpLayer::getTransmitTimestampInSecs() const
    {
        return convertFromTimestampFormat(getTransmitTimestamp()) - EPOCH_OFFSET;
    }

    uint32_t NtpLayer::getKeyID() const
    {
    }

    int NtpLayer::getDigest(uint64_t &h, uint64_t &l)
    {
    }

    bool NtpLayer::checkDigest()
    {
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

        return integerPart + fractionPart;
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
        integerPartInt = hostToNet32(integerPart);
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
        return convertToIsoFormat(convertFromTimestampFormat(timestampInNTPformat) - EPOCH_OFFSET);
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
        ss << "Version: " << (int)getVersion() << " Mode: " << (int)getMode() << ", ";
        ss << "Leap Indicator: " << (int)getLeapIndicator() << ", ";
        ss << "Stratum: " << (int)getStratum() << ", ";
        ss << "Poll Interval: " << getPollIntervalInSecs() << ", Precision: " << getPrecisionInSecs() << ", ";
        ss << "Root Delay: " << getRootDelayInSecs() << ", Root Dispersion: " << getRootDispersionInSecs() << ", ";
        ss << "Reference Identifier: " << getReferenceIdentifierString() << ", ";
        ss << "Reference Timestamp: " << convertToIsoFormat(getReferenceTimestampInSecs()) << ", ";
        ss << "Originate Timestamp: " << convertToIsoFormat(getOriginateTimestampInSecs()) << ", ";
        ss << "Receive Timestamp: " << convertToIsoFormat(getReceiveTimestampInSecs()) << ", ";
        ss << "Transmit Timestamp: " << convertToIsoFormat(getTransmitTimestampInSecs());

        return ss.str();
    }
}
