#define LOG_MODULE PacketLogModuleNtpLayer

#include "Logger.h"
#include "NtpLayer.h"
#include "SystemUtils.h"
#include "GeneralUtils.h"
#include <cmath>

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
		if (getNtpHeader()->leapIndicator < 4)  // Since leap indicator field is 2bit
			return static_cast<LeapIndicator>(getNtpHeader()->leapIndicator);
		PCPP_LOG_ERROR("Unknown NTP Leap Indicator");
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
		if (getNtpHeader()->mode < 8)  // Since mode field 3bit
			return static_cast<Mode>(getNtpHeader()->mode);
		PCPP_LOG_ERROR("Unknown NTP Mode");
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
			PCPP_LOG_ERROR("Unknown NTP Mode");
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

	void NtpLayer::setReferenceIdentifier(IPv4Address val)
	{
		getNtpHeader()->referenceIdentifier = val.toInt();
	}

	void NtpLayer::setReferenceIdentifier(ClockSource val)
	{
		getNtpHeader()->referenceIdentifier = static_cast<uint32_t>(val);
	}

	void NtpLayer::setReferenceIdentifier(KissODeath val)
	{
		getNtpHeader()->referenceIdentifier = static_cast<uint32_t>(val);
	}

	std::string NtpLayer::getReferenceIdentifierString() const
	{
		uint8_t stratum = getStratum();
		uint8_t version = getVersion();
		uint32_t refID = getReferenceIdentifier();

		if (stratum == 0)
		{
			switch (version)
			{
			case 3:
			{
				switch (static_cast<ClockSource>(refID))
				{
				case ClockSource::DCN:
					return "DCN routing protocol";
				case ClockSource::NIST:
					return "NIST public modem";
				case ClockSource::TSP:
					return "TSP time protocol";
				case ClockSource::DTS:
					return "Digital Time Service";
				default:
					return "Unknown";
				}
			}
			case 4:
			{
				switch (static_cast<KissODeath>(refID))
				{
				case KissODeath::ACST:
					return "The association belongs to a anycast server";
				case KissODeath::AUTH:
					return "Server authentication failed";
				case KissODeath::AUTO:
					return "Autokey sequence failed";
				case KissODeath::BCST:
					return "The association belongs to a broadcast server";
				case KissODeath::CRYP:
					return "Cryptographic authentication or identification failed";
				case KissODeath::DENY:
					return "Access denied by remote server";
				case KissODeath::DROP:
					return "Lost peer in symmetric mode";
				case KissODeath::RSTR:
					return "Access denied due to local policy";
				case KissODeath::INIT:
					return "The association has not yet synchronized for the first time";
				case KissODeath::MCST:
					return "The association belongs to a manycast server";
				case KissODeath::NKEY:
					return "No key found.  Either the key was never installed or is not trusted";
				case KissODeath::RATE:
					return "Rate exceeded.  The server has temporarily denied access because the client exceeded the rate "
					       "threshold";
				case KissODeath::RMOT:
					return "Somebody is tinkering with the association from a remote host running ntpdc.  Not to worry "
					       "unless some rascal has stolen your keys";
				case KissODeath::STEP:
					return "A step change in system time has occurred, but the association has not yet resynchronized";
				default:
				{
					// clang-format off
					char arrBuff[5] = {
						static_cast<char>((refID >> 24) & 0xFF),
						static_cast<char>((refID >> 16) & 0xFF),
						static_cast<char>((refID >> 8) & 0xFF),
						static_cast<char>((refID) & 0xFF), '\0'
					};
					// clang-format on
					return arrBuff;
				}
				}
			}
			}
		}
		else if (stratum == 1)
		{
			switch (version)
			{
			case 3:
			{
				switch (static_cast<ClockSource>(refID))
				{
				case ClockSource::ATOM:
					return "Atomic clock";
				case ClockSource::VLF:
					return "VLF radio";
				case ClockSource::LORC:
					return "LORAN-C radionavigation";
				case ClockSource::GOES:
					return "GOES UHF environment satellite";
				case ClockSource::GPS:
					return "GPS UHF satellite positioning";
				default:
					return "Unknown";
				}
			}
			case 4:
			{
				switch (static_cast<ClockSource>(refID))
				{
				case ClockSource::GOES:
					return "Geosynchronous Orbit Environment Satellite";
				case ClockSource::GPS:
					return "Global Position System";
				case ClockSource::GAL:
					return "Galileo Positioning System";
				case ClockSource::PPS:
					return "Generic pulse-per-second";
				case ClockSource::IRIG:
					return "Inter-Range Instrumentation Group";
				case ClockSource::WWVB:
					return "LF Radio WWVB Ft. Collins, CO 60 kHz";
				case ClockSource::DCF:
					return "LF Radio DCF77 Mainflingen, DE 77.5 kHz";
				case ClockSource::HBG:
					return "LF Radio HBG Prangins, HB 75 kHz";
				case ClockSource::MSF:
					return "LF Radio MSF Anthorn, UK 60 kHz";
				case ClockSource::JJY:
					return "LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz";
				case ClockSource::LORC:
					return "MF Radio LORAN C station, 100 kHz";
				case ClockSource::TDF:
					return "MF Radio Allouis, FR 162 kHz";
				case ClockSource::CHU:
					return "HF Radio CHU Ottawa, Ontario";
				case ClockSource::WWV:
					return "HF Radio WWV Ft. Collins, CO";
				case ClockSource::WWVH:
					return "HF Radio WWVH Kauai, HI";
				case ClockSource::NIST:
					return "NIST telephone modem";
				case ClockSource::ACTS:
					return "NIST telephone modem";
				case ClockSource::USNO:
					return "USNO telephone modem";
				case ClockSource::PTB:
					return "European telephone modem";
				case ClockSource::MRS:
					return "Multi Reference Sources";
				case ClockSource::XFAC:
					return "Inter Face Association Changed";
				case ClockSource::STEP:
					return "Step time change";
				case ClockSource::GOOG:
					return "Google NTP servers";
				case ClockSource::DCFa:
					return "Meinberg DCF77 with amplitude modulation";
				case ClockSource::DCFp:
					return "Meinberg DCF77 with phase modulation)/pseudo random phase modulation";
				case ClockSource::GPSs:
					return "Meinberg GPS (with shared memory access)";
				case ClockSource::GPSi:
					return "Meinberg GPS (with interrupt based access)";
				case ClockSource::GLNs:
					return "Meinberg GPS/GLONASS (with shared memory access)";
				case ClockSource::GLNi:
					return "Meinberg GPS/GLONASS (with interrupt based access)";
				case ClockSource::LCL:
					return "Meinberg Undisciplined local clock";
				case ClockSource::LOCL:
					return "Meinberg Undisciplined local clock";
				default:
					return "Unknown";
				}
			}
			}
		}
		else
		{
			// TODO: Support IPv6 cases for NTPv4, it equals to MD5 hash of first four octets of IPv6 address

			pcpp::IPv4Address addr(getReferenceIdentifier());
			return addr.toString();
		}

		PCPP_LOG_ERROR("Unknown Stratum type");
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

			ntp_v3_auth* header = (ntp_v3_auth*)(m_Data + sizeof(ntp_header));
			return header->keyID;
		}
		case 4:
		{
			// TODO: Add support for extension fields
			if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_md5)))
			{
				ntp_v4_auth_md5* header = (ntp_v4_auth_md5*)(m_Data + m_DataLen - sizeof(ntp_v4_auth_md5));
				return header->keyID;
			}
			if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_sha1)))
			{
				ntp_v4_auth_sha1* header = (ntp_v4_auth_sha1*)(m_Data + m_DataLen - sizeof(ntp_v4_auth_sha1));
				return header->keyID;
			}

			PCPP_LOG_ERROR("NTP authentication parsing with extension fields are not supported");
			return 0;
		}
		default:
		{
			PCPP_LOG_ERROR("NTP version not supported");
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

			ntp_v3_auth* header = (ntp_v3_auth*)(m_Data + sizeof(ntp_header));
			return byteArrayToHexString(header->dgst, 8);
		}
		case 4:
		{
			if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_md5)))
			{
				ntp_v4_auth_md5* header = (ntp_v4_auth_md5*)(m_Data + m_DataLen - sizeof(ntp_v4_auth_md5));
				return byteArrayToHexString(header->dgst, 16);
			}
			if (m_DataLen == (sizeof(ntp_header) + sizeof(ntp_v4_auth_sha1)))
			{
				ntp_v4_auth_sha1* header = (ntp_v4_auth_sha1*)(m_Data + m_DataLen - sizeof(ntp_v4_auth_sha1));
				return byteArrayToHexString(header->dgst, 20);
			}

			PCPP_LOG_ERROR("NTP authentication parsing with extension fields are not supported");
			return std::string();
		}
		default:
			PCPP_LOG_ERROR("NTP version not supported");
			return std::string();
		}
	}

	double NtpLayer::convertFromShortFormat(const uint32_t val)
	{
		double integerPart = netToHost16(val & 0xFFFF);
		double fractionPart = netToHost16(((val & 0xFFFF0000) >> 16)) / NTP_FRIC;

		return integerPart + fractionPart;
	}

	double NtpLayer::convertFromTimestampFormat(const uint64_t val)
	{
		double integerPart = netToHost32(val & 0xFFFFFFFF);
		double fractionPart = netToHost32(((val & 0xFFFFFFFF00000000) >> 32)) / NTP_FRAC;

		// TODO: Return integer and fraction parts as struct to increase precision
		// Offset change should be done here because of overflow
		return integerPart + fractionPart - EPOCH_OFFSET;
	}

	uint32_t NtpLayer::convertToShortFormat(const double val)
	{
		double integerPart;
		double fractionPart = modf(val, &integerPart);

		// Cast values to 16bit
		uint32_t integerPartInt = hostToNet16(integerPart);
		uint32_t fractionPartInt = hostToNet16(fractionPart * NTP_FRIC);

		return integerPartInt | (fractionPartInt << 16);
	}

	uint64_t NtpLayer::convertToTimestampFormat(const double val)
	{
		double integerPart;
		double fractionPart = modf(val, &integerPart);

		// Cast values to 32bit
		uint64_t integerPartInt = hostToNet32(integerPart + EPOCH_OFFSET);
		uint64_t fractionPartInt = hostToNet32(fractionPart * NTP_FRAC);

		return integerPartInt | (fractionPartInt << 32);
	}

	std::string NtpLayer::convertToIsoFormat(const double timestamp)
	{
		double integerPart;
		double fractionPart = modf(timestamp, &integerPart);

		struct tm* timer;
		time_t timeStruct = integerPart;
#if defined(_WIN32)
		if (timeStruct < 0)
			timeStruct = 0;
		timer = gmtime(&timeStruct);
#else
		struct tm timer_r;
		timer = gmtime_r(&timeStruct, &timer_r);

		if (timer != nullptr)
			timer = &timer_r;
#endif
		if (timer == nullptr)
		{
			PCPP_LOG_ERROR("Can't convert time");
			return std::string();
		}
		char buffer[50], bufferFraction[15];
		strftime(buffer, sizeof(buffer) - sizeof(bufferFraction), "%Y-%m-%dT%H:%M:%S", timer);

		snprintf(bufferFraction, sizeof(bufferFraction), "%.04lfZ", fabs(fractionPart));
		strncat(buffer, &bufferFraction[1], sizeof(bufferFraction));

		return std::string(buffer);
	}

	std::string NtpLayer::convertToIsoFormat(const uint64_t timestampInNTPformat)
	{
		return convertToIsoFormat(convertFromTimestampFormat(timestampInNTPformat));
	}

	bool NtpLayer::isDataValid(const uint8_t* data, size_t dataSize)
	{
		return data && dataSize >= sizeof(ntp_header);
	}

	std::string NtpLayer::toString() const
	{
		return std::string("NTP Layer v") + std::to_string(getVersion()) + ", Mode: " + getModeString();
	}
}  // namespace pcpp
