#define LOG_MODULE PacketLogModuleSSLLayer

#include "SSLCommon.h"

namespace pcpp
{

	// -------------------------
	// SSLVersion methods
	// -------------------------

	SSLVersion::SSLVersionEnum SSLVersion::asEnum(bool countTlsDraftsAs1_3)
	{
		if (m_SSLVersionValue >= 0x0300 && m_SSLVersionValue <= 0x0304)
			return static_cast<SSLVersion::SSLVersionEnum>(m_SSLVersionValue);

		if ((m_SSLVersionValue >= 0x7f0e && m_SSLVersionValue <= 0x7f1c) || m_SSLVersionValue == 0xfb17 ||
		    m_SSLVersionValue == 0xfb1a)
		{
			if (countTlsDraftsAs1_3)
				return SSLVersion::TLS1_3;
			else
				return static_cast<SSLVersion::SSLVersionEnum>(m_SSLVersionValue);
		}

		if (m_SSLVersionValue == 0x200)
			return SSLVersion::SSL2;

		return SSLVersion::Unknown;
	}

	std::string SSLVersion::toString(bool countTlsDraftsAs1_3)
	{
		SSLVersionEnum enumValue = asEnum(countTlsDraftsAs1_3);

		switch (enumValue)
		{
		case SSLVersion::TLS1_3:
			return "TLS 1.3";
		case SSLVersion::TLS1_2:
			return "TLS 1.2";
		case SSLVersion::TLS1_1:
			return "TLS 1.1";
		case SSLVersion::TLS1_0:
			return "TLS 1.0";
		case SSLVersion::SSL3:
			return "SSL 3.0";
		case SSLVersion::TLS1_3_D28:
			return "TLS 1.3 (draft 28)";
		case SSLVersion::TLS1_3_D27:
			return "TLS 1.3 (draft 27)";
		case SSLVersion::TLS1_3_D26:
			return "TLS 1.3 (draft 26)";
		case SSLVersion::TLS1_3_D25:
			return "TLS 1.3 (draft 25)";
		case SSLVersion::TLS1_3_D24:
			return "TLS 1.3 (draft 24)";
		case SSLVersion::TLS1_3_D23:
			return "TLS 1.3 (draft 23)";
		case SSLVersion::TLS1_3_D22:
			return "TLS 1.3 (draft 22)";
		case SSLVersion::TLS1_3_D21:
			return "TLS 1.3 (draft 21)";
		case SSLVersion::TLS1_3_D20:
			return "TLS 1.3 (draft 20)";
		case SSLVersion::TLS1_3_D19:
			return "TLS 1.3 (draft 19)";
		case SSLVersion::TLS1_3_D18:
			return "TLS 1.3 (draft 18)";
		case SSLVersion::TLS1_3_D17:
			return "TLS 1.3 (draft 17)";
		case SSLVersion::TLS1_3_D16:
			return "TLS 1.3 (draft 16)";
		case SSLVersion::TLS1_3_D15:
			return "TLS 1.3 (draft 15)";
		case SSLVersion::TLS1_3_D14:
			return "TLS 1.3 (draft 14)";
		case SSLVersion::TLS1_3_FBD23:
			return "TLS 1.3 (Facebook draft 23)";
		case SSLVersion::TLS1_3_FBD26:
			return "TLS 1.3 (Facebook draft 26)";
		case SSLVersion::Unknown:
			return "Unknown";
		case SSLVersion::SSL2:
			return "SSL 2.0";
		default:
			return "Unknown";
		}
	}

}  // namespace pcpp
