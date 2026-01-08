#include "PacketUtils.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "Logger.h"
#include "EndianPortable.h"

namespace pcpp
{

	uint16_t computeChecksum(ScalarBuffer<uint16_t> vec[], size_t vecSize)
	{
		uint32_t sum = 0;
		for (size_t i = 0; i < vecSize; i++)
		{
			uint32_t localSum = 0;

			// vec len is in bytes
			for (size_t j = 0; j < vec[i].len / 2; j++)
			{
				PCPP_LOG_DEBUG("Value to add = 0x" << std::uppercase << std::hex << vec[i].buffer[j]);
				localSum += vec[i].buffer[j];
			}
			PCPP_LOG_DEBUG("Local sum = " << localSum << ", 0x" << std::uppercase << std::hex << localSum);

			// check if there is one byte left
			if (vec[i].len % 2)
			{
				// access to the last byte using an uint8_t pointer
				uint8_t* vecBytes = reinterpret_cast<uint8_t*>(vec[i].buffer);
				uint8_t lastByte = vecBytes[vec[i].len - 1];
				PCPP_LOG_DEBUG("1 byte left, adding value: 0x" << std::uppercase << std::hex << lastByte);
				// We have read the latest byte manually but this byte should be properly interpreted
				// as a 0xFF on LE and a 0xFF00 on BE to have a proper checksum computation
				localSum += be16toh(lastByte << 8);

				PCPP_LOG_DEBUG("Local sum = " << localSum << ", 0x" << std::uppercase << std::hex << localSum);
			}

			// carry count is added to the sum
			while (localSum >> 16)
			{
				localSum = (localSum & 0xffff) + (localSum >> 16);
			}
			PCPP_LOG_DEBUG("Local sum = " << localSum << ", 0x" << std::uppercase << std::hex << localSum);
			sum += localSum;
		}

		while (sum >> 16)
		{
			sum = (sum & 0xffff) + (sum >> 16);
		}
		PCPP_LOG_DEBUG("Sum before invert = " << sum << ", 0x" << std::uppercase << std::hex << sum);

		// To obtain the checksum we take the ones' complement of this result
		uint16_t result = sum;
		result = ~result;

		PCPP_LOG_DEBUG("Calculated checksum = " << sum << ", 0x" << std::uppercase << std::hex << result);

		// We return the result in BigEndian byte order
		return htobe16(result);
	}

	uint16_t computePseudoHdrChecksum(uint8_t* dataPtr, size_t dataLen, IPAddress::AddressType ipAddrType,
	                                  uint8_t protocolType, IPAddress srcIPAddress, IPAddress dstIPAddress)
	{
		PCPP_LOG_DEBUG("Compute pseudo header checksum.\n DataLen = " << dataLen << "IPAddrType = " << ipAddrType
		                                                              << "ProtocolType = " << protocolType << "SrcIP = "
		                                                              << srcIPAddress << "DstIP = " << dstIPAddress);

		uint16_t checksumRes = 0;
		ScalarBuffer<uint16_t> vec[2];
		vec[0].buffer = reinterpret_cast<uint16_t*>(dataPtr);
		vec[0].len = dataLen;

		if (ipAddrType == IPAddress::IPv4AddressType)
		{
			uint32_t srcIP = srcIPAddress.getIPv4().toInt();
			uint32_t dstIP = dstIPAddress.getIPv4().toInt();
			uint16_t pseudoHeader[6];
			pseudoHeader[0] = srcIP >> 16;
			pseudoHeader[1] = srcIP & 0xFFFF;
			pseudoHeader[2] = dstIP >> 16;
			pseudoHeader[3] = dstIP & 0xFFFF;
			pseudoHeader[4] = 0xffff & htobe16(dataLen);
			pseudoHeader[5] = htobe16(0x00ff & protocolType);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 12;
			checksumRes = computeChecksum(vec, 2);
		}
		else if (ipAddrType == IPAddress::IPv6AddressType)
		{
			uint16_t pseudoHeader[18];
			srcIPAddress.getIPv6().copyTo(reinterpret_cast<uint8_t*>(pseudoHeader));
			dstIPAddress.getIPv6().copyTo(reinterpret_cast<uint8_t*>(pseudoHeader + 8));
			pseudoHeader[16] = 0xffff & htobe16(dataLen);
			pseudoHeader[17] = htobe16(0x00ff & protocolType);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = computeChecksum(vec, 2);
		}
		else
		{
			PCPP_LOG_ERROR("Compute pseudo header checksum failed, for unknown IPAddrType = " << ipAddrType);
		}

		PCPP_LOG_DEBUG("Pseudo header checksum = 0xX" << std::uppercase << std::hex << checksumRes);

		return checksumRes;
	}

	template <typename T> struct FnvParams
	{
	};
	template <> struct FnvParams<uint32_t>
	{
		static const uint32_t PRIME = 16777619u;
		static const uint32_t OFFSET_BASIS = 2166136261u;
	};
	template <> struct FnvParams<uint64_t>
	{
		static const uint64_t PRIME = 0x00000100000001b3ull;
		static const uint64_t OFFSET_BASIS = 0xcbf29ce484222325ull;
	};

	template <typename T> T fnvHash(ScalarBuffer<uint8_t> vec[], size_t vecSize)
	{
		T hash = FnvParams<T>::OFFSET_BASIS;
		for (size_t i = 0; i < vecSize; ++i)
		{
			for (size_t j = 0; j < vec[i].len; ++j)
			{
				hash *= FnvParams<T>::PRIME;
				hash ^= vec[i].buffer[j];
			}
		}
		return hash;
	}
	template uint32_t fnvHash<uint32_t>(ScalarBuffer<uint8_t> vec[], size_t vecSize);
	template uint64_t fnvHash<uint64_t>(ScalarBuffer<uint8_t> vec[], size_t vecSize);

	template <typename T> T fnvHash(uint8_t* buffer, size_t bufSize)
	{
		ScalarBuffer<uint8_t> scalarBuf;
		scalarBuf.buffer = buffer;
		scalarBuf.len = bufSize;
		return fnvHash<T>(&scalarBuf, 1);
	}
	template uint32_t fnvHash<uint32_t>(uint8_t* buffer, size_t bufSize);
	template uint64_t fnvHash<uint64_t>(uint8_t* buffer, size_t bufSize);

	bool IHashableConnectionInfo::equals(IHashableConnectionInfo const& other, bool ignoreDirection) const
	{
		if (ipProtocol() != other.ipProtocol())
			return false;

		unsigned ipSize;
		if (isIPv4() && other.isIPv4())
			ipSize = 4;
		else if (isIPv6() && other.isIPv6())
			ipSize = 16;
		else
			return false;

		uint8_t const* lhsIpSrc = ipSrc();
		uint8_t const* lhsIpDst = ipDst();
		uint8_t const* rhsIpSrc = other.ipSrc();
		uint8_t const* rhsIpDst = other.ipDst();
		if (!lhsIpSrc || !lhsIpDst || !rhsIpSrc || !rhsIpDst)
			return false;

		uint16_t lhsPortSrc = portSrc();
		uint16_t lhsPortDst = portDst();
		uint16_t rhsPortSrc = other.portSrc();
		uint16_t rhsPortDst = other.portDst();

		if (lhsPortSrc == rhsPortSrc && lhsPortDst == rhsPortDst && memcmp(lhsIpSrc, rhsIpSrc, ipSize) == 0 &&
		    memcmp(lhsIpDst, rhsIpDst, ipSize) == 0)
			return true;

		if (ignoreDirection && lhsPortSrc == rhsPortDst && lhsPortDst == rhsPortSrc &&
		    memcmp(lhsIpSrc, rhsIpDst, ipSize) == 0 && memcmp(lhsIpDst, rhsIpSrc, ipSize) == 0)
			return true;

		return false;
	}

	PacketHashable::PacketHashable(Packet const* packet)
	{
		m_ipv4Layer = packet->getLayerOfType<IPv4Layer>();
		if (!m_ipv4Layer)
			m_ipv6Layer = packet->getLayerOfType<IPv6Layer>();
		TcpLayer* tcpLayer = packet->getLayerOfType<TcpLayer>(true);  // lookup in reverse order
		if (tcpLayer != nullptr)
		{
			m_portSrc = tcpLayer->getSrcPort();
			m_portDst = tcpLayer->getDstPort();
		}
		else
		{
			UdpLayer* udpLayer = packet->getLayerOfType<UdpLayer>(true);
			if (udpLayer != nullptr)
			{
				m_portSrc = udpLayer->getSrcPort();
				m_portDst = udpLayer->getDstPort();
			}
		}
	}
	bool PacketHashable::isIPv4() const
	{
		return m_ipv4Layer;
	}
	bool PacketHashable::isIPv6() const
	{
		return m_ipv6Layer;
	}
	const uint8_t* PacketHashable::ipSrc() const
	{
		if (m_ipv4Layer)
			return reinterpret_cast<uint8_t*>(&m_ipv4Layer->getIPv4Header()->ipSrc);
		if (m_ipv6Layer)
			return m_ipv6Layer->getIPv6Header()->ipSrc;
		return nullptr;
	}
	const uint8_t* PacketHashable::ipDst() const
	{
		if (m_ipv4Layer)
			return reinterpret_cast<uint8_t*>(&m_ipv4Layer->getIPv4Header()->ipDst);
		if (m_ipv6Layer)
			return m_ipv6Layer->getIPv6Header()->ipDst;
		return nullptr;
	}
	IPProtocolTypes PacketHashable::ipProtocol() const
	{
		if (m_ipv4Layer)
			return static_cast<IPProtocolTypes>(m_ipv4Layer->getIPv4Header()->protocol);
		if (m_ipv6Layer)
			return static_cast<IPProtocolTypes>(m_ipv6Layer->getIPv6Header()->nextHeader);
		return PACKETPP_IPPROTO_IP;
	}
	uint16_t PacketHashable::portSrc() const
	{
		return m_portSrc;
	}
	uint16_t PacketHashable::portDst() const
	{
		return m_portDst;
	}

	template <typename T> T hash5Tuple(Packet* packet, bool const& directionUnique)
	{
		return hash5Tuple<T>(PacketHashable{ packet }, directionUnique);
	}
	template uint32_t hash5Tuple<uint32_t>(Packet* packet, bool const& directionUnique);
	template uint64_t hash5Tuple<uint64_t>(Packet* packet, bool const& directionUnique);

	template <typename T> T hash5Tuple(const IHashableConnectionInfo& target, bool const& directionUnique)
	{
		ScalarBuffer<uint8_t> vec[5];

		unsigned ipSize;
		if (target.isIPv4())
			ipSize = 4;
		else if (target.isIPv6())
			ipSize = 16;
		else
			return 0;

		IPProtocolTypes ipProtocol = target.ipProtocol();
		if (ipProtocol != PACKETPP_IPPROTO_TCP && ipProtocol != PACKETPP_IPPROTO_UDP)
			return 0;

		vec[4].buffer = reinterpret_cast<uint8_t*>(&ipProtocol);
		vec[4].len = 1;

		uint16_t portSrc = htobe16(target.portSrc());
		uint16_t portDst = htobe16(target.portDst());
		int srcPosition = 0;

		if (!directionUnique && portDst < portSrc)
			srcPosition = 1;

		vec[0 + srcPosition].buffer = reinterpret_cast<uint8_t*>(&portSrc);
		vec[0 + srcPosition].len = 2;
		vec[1 - srcPosition].buffer = reinterpret_cast<uint8_t*>(&portDst);
		vec[1 - srcPosition].len = 2;

		const uint8_t* ipSrc = target.ipSrc();
		const uint8_t* ipDst = target.ipDst();
		if (!ipSrc || !ipDst)
			return 0;

		if (!directionUnique && portSrc == portDst && memcmp(ipDst, ipSrc, ipSize) < 0)
			srcPosition = 1;

		vec[2 + srcPosition].buffer = const_cast<uint8_t*>(ipSrc);
		vec[2 + srcPosition].len = ipSize;
		vec[3 - srcPosition].buffer = const_cast<uint8_t*>(ipDst);
		vec[3 - srcPosition].len = ipSize;

		return pcpp::fnvHash<T>(vec, 5);
	}
	template uint32_t hash5Tuple<uint32_t>(const IHashableConnectionInfo& packet, bool const& directionUnique);
	template uint64_t hash5Tuple<uint64_t>(const IHashableConnectionInfo& packet, bool const& directionUnique);

	template <typename T> T hash2Tuple(Packet* packet)
	{
		if (!packet->isPacketOfType(IPv4) && !packet->isPacketOfType(IPv6))
			return 0;

		ScalarBuffer<uint8_t> vec[2];

		IPv4Layer* ipv4Layer = packet->getLayerOfType<IPv4Layer>();
		if (ipv4Layer != nullptr)
		{
			int srcPosition = 0;
			if (ipv4Layer->getIPv4Header()->ipDst < ipv4Layer->getIPv4Header()->ipSrc)
				srcPosition = 1;

			vec[0 + srcPosition].buffer = reinterpret_cast<uint8_t*>(&ipv4Layer->getIPv4Header()->ipSrc);
			vec[0 + srcPosition].len = 4;
			vec[1 - srcPosition].buffer = reinterpret_cast<uint8_t*>(&ipv4Layer->getIPv4Header()->ipDst);
			vec[1 - srcPosition].len = 4;
		}
		else
		{
			IPv6Layer* ipv6Layer = packet->getLayerOfType<IPv6Layer>();
			int srcPosition = 0;
			if (memcmp(ipv6Layer->getIPv6Header()->ipDst, ipv6Layer->getIPv6Header()->ipSrc, 16) < 0)
				srcPosition = 1;

			vec[0 + srcPosition].buffer = ipv6Layer->getIPv6Header()->ipSrc;
			vec[0 + srcPosition].len = 16;
			vec[1 - srcPosition].buffer = ipv6Layer->getIPv6Header()->ipDst;
			vec[1 - srcPosition].len = 16;
		}

		return pcpp::fnvHash<T>(vec, 2);
	}
	template uint32_t hash2Tuple<uint32_t>(Packet* packet);
	template uint64_t hash2Tuple<uint64_t>(Packet* packet);

}  // namespace pcpp
