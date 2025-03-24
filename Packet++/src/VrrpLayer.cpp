#define LOG_MODULE PacketLogModuleVrrpLayer

#include <SystemUtils.h>
#include "PacketUtils.h"
#include "Logger.h"
#include "EndianPortable.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "VrrpLayer.h"

namespace pcpp
{

#define VRRP_PRIO_STOP 0     ///< priority to stop
#define VRRP_PRIO_DEF 100    ///< default priority
#define VRRP_PRIO_OWNER 255  ///< priority of the ip owner

#define VRRP_PACKET_FIX_LEN 8
#define VRRP_PACKET_MAX_IP_ADDRESS_NUM 255

#define VRRP_V2_VERSION 2
#define VRRP_V3_VERSION 3

	// -------- Class VrrpLayer -----------------

	VrrpLayer::VrrpLayer(ProtocolType subProtocol, uint8_t virtualRouterId, uint8_t priority)
	{
		m_DataLen = VRRP_PACKET_FIX_LEN;
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = subProtocol;
		m_AddressType = IPAddress::IPv4AddressType;
		auto vrrpHeader = getVrrpHeader();
		if (subProtocol == VRRPv2)
		{
			vrrpHeader->version = VRRP_V2_VERSION;
		}
		else if (subProtocol == VRRPv3)
		{
			vrrpHeader->version = VRRP_V3_VERSION;
		}
		vrrpHeader->type = static_cast<uint8_t>(VrrpType::VrrpType_Advertisement);
		setVirtualRouterID(virtualRouterId);
		setPriority(priority);
	}

	ProtocolType VrrpLayer::getVersionFromData(uint8_t* data, size_t dataLen)
	{
		if (!data || dataLen <= VRRP_PACKET_FIX_LEN)
		{
			return UnknownProtocol;
		}

		auto* vrrpPacketCommon = (vrrp_header*)data;
		uint8_t version = vrrpPacketCommon->version;
		switch (version)
		{
		case VRRP_V2_VERSION:
			return VRRPv2;
		case VRRP_V3_VERSION:
			return VRRPv3;
		default:
			return UnknownProtocol;
		}
	}

	void VrrpLayer::computeCalculateFields()
	{
		// calculate and fill the checksum to packet
		calculateAndSetChecksum();
	}

	uint8_t VrrpLayer::getIPAddressLen() const
	{
		if (getAddressType() == IPAddress::IPv4AddressType)
		{
			return 4;
		}

		return 16;
	}

	bool VrrpLayer::isChecksumCorrect() const
	{
		auto vrrpHeader = getVrrpHeader();
		if (vrrpHeader == nullptr)
		{
			return false;
		}

		return (calculateChecksum() == be16toh(vrrpHeader->checksum));
	}

	VrrpLayer::VrrpPriority VrrpLayer::getPriorityAsEnum() const
	{
		switch (getVrrpHeader()->priority)
		{
		case VRRP_PRIO_DEF:
			return VrrpLayer::VrrpPriority::Default;

		case VRRP_PRIO_STOP:
			return VrrpLayer::VrrpPriority::Stop;

		case VRRP_PRIO_OWNER:
			return VrrpLayer::VrrpPriority::Owner;

		default:
			return VrrpLayer::VrrpPriority::Other;
		}
	}

	std::string VrrpLayer::toString() const
	{
		return "VRRP v" + std::to_string(getVersion()) +
		       " Layer, virtual router ID: " + std::to_string(getVirtualRouterID()) +
		       ", IP address count: " + std::to_string(getIPAddressesCount());
	}

	uint8_t VrrpLayer::getVersion() const
	{
		return getVrrpHeader()->version;
	}

	VrrpLayer::VrrpType VrrpLayer::getType() const
	{
		if (getVrrpHeader()->type == VrrpType_Advertisement)
		{
			return VrrpType_Advertisement;
		}

		return VrrpType_Unknown;
	}

	uint8_t VrrpLayer::getVirtualRouterID() const
	{
		return getVrrpHeader()->vrId;
	}

	void VrrpLayer::setVirtualRouterID(uint8_t virtualRouterID)
	{
		getVrrpHeader()->vrId = virtualRouterID;
	}

	uint8_t VrrpLayer::getPriority() const
	{
		return getVrrpHeader()->priority;
	}

	void VrrpLayer::setPriority(uint8_t priority)
	{
		getVrrpHeader()->priority = priority;
	}

	uint16_t VrrpLayer::getChecksum() const
	{
		return be16toh(getVrrpHeader()->checksum);
	}

	void VrrpLayer::calculateAndSetChecksum()
	{
		getVrrpHeader()->checksum = htobe16(calculateChecksum());
	}

	uint8_t VrrpLayer::getIPAddressesCount() const
	{
		return getVrrpHeader()->ipAddrCount;
	}

	std::vector<IPAddress> VrrpLayer::getIPAddresses() const
	{
		std::vector<IPAddress> ipAddressesVec;
		auto ipAddressesPtr = getFirstIPAddressPtr();
		while (ipAddressesPtr != nullptr)
		{
			IPAddress ipAddress = getIPAddressFromData(ipAddressesPtr);
			ipAddressesVec.push_back(ipAddress);
			ipAddressesPtr = getNextIPAddressPtr(ipAddressesPtr);
		}

		return ipAddressesVec;
	}

	uint8_t* VrrpLayer::getFirstIPAddressPtr() const
	{
		size_t ipAddressLen = getIPAddressLen();

		// check if there are virtual IP address at all
		if (getHeaderLen() <= VRRP_PACKET_FIX_LEN + ipAddressLen)
		{
			return nullptr;
		}

		return (m_Data + VRRP_PACKET_FIX_LEN);
	}

	uint8_t* VrrpLayer::getNextIPAddressPtr(uint8_t* ipAddressPtr) const
	{
		if (ipAddressPtr == nullptr)
		{
			return nullptr;
		}

		size_t ipAddressLen = getIPAddressLen();

		// prev virtual IP address was the last virtual IP address
		if (ipAddressPtr + ipAddressLen - m_Data >= (int)getHeaderLen())
		{
			return nullptr;
		}

		return (ipAddressPtr + ipAddressLen);
	}

	bool VrrpLayer::addIPAddressesAt(const std::vector<IPAddress>& ipAddresses, int offset)
	{
		if (offset > (int)getHeaderLen())
		{
			PCPP_LOG_ERROR("Cannot add virtual IP address offset(" << offset << ") is out of layer bounds");
			return false;
		}

		for (auto ipAddress : ipAddresses)
		{
			if (!isIPAddressValid(ipAddress))
			{
				PCPP_LOG_ERROR("Cannot add virtual IP address, for IP address is invalid.");
				return false;
			}
		}

		if (getIPAddressesCount() + ipAddresses.size() > VRRP_PACKET_MAX_IP_ADDRESS_NUM)
		{
			PCPP_LOG_ERROR("Cannot add virtual IP address, for virtual IP address has already exceed maximum.");
			return false;
		}

		size_t ipAddrLen = getIPAddressLen();
		size_t ipAddressesLen = ipAddrLen * ipAddresses.size();
		if (ipAddressesLen == 0)
		{
			return true;
		}

		if (!extendLayer(offset, ipAddressesLen))
		{
			PCPP_LOG_ERROR("Cannot add virtual IP address, cannot extend layer");
			return false;
		}

		size_t ipAddrOffset = 0;
		uint8_t* newIpAddresses = getData() + offset;
		for (auto const& ipAddress : ipAddresses)
		{
			copyIPAddressToData(newIpAddresses + ipAddrOffset, ipAddress);
			ipAddrOffset += ipAddrLen;
		}

		getVrrpHeader()->ipAddrCount = getIPAddressesCount() + ipAddresses.size();

		return true;
	}

	bool VrrpLayer::addIPAddresses(const std::vector<IPAddress>& ipAddresses)
	{
		return addIPAddressesAt(ipAddresses, (int)getHeaderLen());
	}

	bool VrrpLayer::addIPAddress(const IPAddress& ipAddress)
	{
		std::vector<IPAddress> ipAddresses;
		ipAddresses.push_back(ipAddress);

		return addIPAddressesAt(ipAddresses, (int)getHeaderLen());
	}

	bool VrrpLayer::removeIPAddressAtIndex(int index)
	{
		int ipAddressCount = (int)getIPAddressesCount();

		if (index < 0 || index >= ipAddressCount)
		{
			PCPP_LOG_ERROR("Cannot remove virtual IP address, index " << index << " is out of bounds");
			return false;
		}

		size_t ipAddressLen = getIPAddressLen();

		size_t offset = VRRP_PACKET_FIX_LEN;
		auto curIpAddressPtr = getFirstIPAddressPtr();
		for (int i = 0; i < index; i++)
		{
			if (curIpAddressPtr == nullptr)
			{
				PCPP_LOG_ERROR("Cannot remove virtual IP address at index "
				               << index << ", cannot find virtual IP address at index " << i);
				return false;
			}

			offset += ipAddressLen;
			curIpAddressPtr = getNextIPAddressPtr(curIpAddressPtr);
		}

		if (!shortenLayer((int)offset, ipAddressLen))
		{
			PCPP_LOG_ERROR("Cannot remove virtual IP address at index " << index << ", cannot shorted layer");
			return false;
		}

		getVrrpHeader()->ipAddrCount = ipAddressCount - 1;

		return true;
	}

	bool VrrpLayer::removeAllIPAddresses()
	{
		size_t offset = VRRP_PACKET_FIX_LEN;
		size_t packetLen = getHeaderLen();
		if (packetLen <= offset)
		{
			return false;
		}

		if (!shortenLayer((int)offset, packetLen - offset))
		{
			PCPP_LOG_ERROR("Cannot remove all virtual IP address(es), cannot shorted layer");
			return false;
		}

		getVrrpHeader()->ipAddrCount = 0;

		return true;
	}

	void VrrpLayer::copyIPAddressToData(uint8_t* data, const IPAddress& ipAddress) const
	{
		size_t ipAddressLen = getIPAddressLen();

		if (ipAddress.isIPv4())
		{
			memcpy(data, ipAddress.getIPv4().toBytes(), ipAddressLen);
		}
		else if (ipAddress.isIPv6())
		{
			memcpy(data, ipAddress.getIPv6().toBytes(), ipAddressLen);
		}
	}

	IPAddress VrrpLayer::getIPAddressFromData(uint8_t* data) const
	{
		if (getAddressType() == IPAddress::IPv4AddressType)
		{
			return IPv4Address(*((uint32_t*)data));
		}

		return IPv6Address(data);
	}

	bool VrrpLayer::isIPAddressValid(IPAddress& ipAddress) const
	{
		if (ipAddress.isIPv6() && (getProtocol() != VRRPv3))
		{
			PCPP_LOG_ERROR("Only VRRPv3 support IPv6 virtual address");
			return false;
		}
		if (ipAddress.getType() != getAddressType())
		{
			PCPP_LOG_ERROR("IP address version is not equal to layer's");
			return false;
		}

		return true;
	}

	IPAddress::AddressType VrrpLayer::getAddressType() const
	{
		return m_AddressType;
	}

	void VrrpLayer::setAddressType(IPAddress::AddressType addressType)
	{
		m_AddressType = addressType;
	}

	// -------- Class Vrrpv2Layer -----------------

	VrrpV2Layer::VrrpV2Layer(uint8_t virtualRouterId, uint8_t priority, uint8_t advInt, uint8_t authType)
	    : VrrpLayer(VRRPv2, virtualRouterId, priority)
	{
		setAdvInt(advInt);
		setAuthType(authType);
	}

	VrrpV2Layer::VrrpAuthType VrrpV2Layer::getAuthTypeAsEnum() const
	{
		auto authType = getAuthType();
		if (authType > 3)
		{
			return VrrpAuthType::Other;
		}

		return static_cast<VrrpAuthType>(authType);
	}

	uint8_t VrrpV2Layer::getAdvInt() const
	{
		uint16_t authAdvInt = getVrrpHeader()->authTypeAdvInt;
		auto authAdvIntPtr = (vrrpv2_auth_adv*)(&authAdvInt);
		return authAdvIntPtr->advInt;
	}

	void VrrpV2Layer::setAdvInt(uint8_t advInt)
	{
		auto authAdvIntPtr = (vrrpv2_auth_adv*)&getVrrpHeader()->authTypeAdvInt;
		authAdvIntPtr->advInt = advInt;
	}

	uint8_t VrrpV2Layer::getAuthType() const
	{
		uint16_t authAdvInt = getVrrpHeader()->authTypeAdvInt;
		auto* authAdvIntPtr = (vrrpv2_auth_adv*)(&authAdvInt);
		return authAdvIntPtr->authType;
	}

	void VrrpV2Layer::setAuthType(uint8_t authType)
	{
		auto authAdvIntPtr = (vrrpv2_auth_adv*)&getVrrpHeader()->authTypeAdvInt;
		authAdvIntPtr->authType = authType;
	}

	uint16_t VrrpV2Layer::calculateChecksum() const
	{
		if ((getData() == nullptr) || (getDataLen() == 0))
		{
			return 0;
		}

		auto vrrpHeader = getVrrpHeader();
		ScalarBuffer<uint16_t> buffer = {};
		buffer.buffer = (uint16_t*)vrrpHeader;
		buffer.len = getHeaderLen();

		uint16_t currChecksumValue = vrrpHeader->checksum;
		vrrpHeader->checksum = 0;
		uint16_t checksum = computeChecksum(&buffer, 1);
		vrrpHeader->checksum = currChecksumValue;

		return checksum;
	}

	// -------- Class Vrrpv3Layer -----------------

	VrrpV3Layer::VrrpV3Layer(IPAddress::AddressType addressType, uint8_t virtualRouterId, uint8_t priority,
	                         uint16_t maxAdvInt)
	    : VrrpLayer(VRRPv3, virtualRouterId, priority)
	{
		setAddressType(addressType);
		setMaxAdvInt(maxAdvInt);
	}

	uint16_t VrrpV3Layer::getMaxAdvInt() const
	{
		uint16_t authAdvInt = getVrrpHeader()->authTypeAdvInt;
		auto rsvdAdv = (vrrpv3_rsvd_adv*)(&authAdvInt);
		return be16toh(rsvdAdv->maxAdvInt);
	}

	void VrrpV3Layer::setMaxAdvInt(uint16_t maxAdvInt)
	{
		if (maxAdvInt > 0xfff)
		{
			throw std::invalid_argument("maxAdvInt must not exceed 12 bits length");
		}
		auto rsvdAdv = (vrrpv3_rsvd_adv*)&getVrrpHeader()->authTypeAdvInt;
		rsvdAdv->maxAdvInt = htobe16(maxAdvInt);
	}

	uint16_t VrrpV3Layer::calculateChecksum() const
	{
		auto* ipLayer = m_Packet->getLayerOfType<pcpp::IPLayer>();
		if (ipLayer == nullptr)
		{
			PCPP_LOG_ERROR("Calculate checksum failed, for can not get IPLayer" << "");
			return 0;
		}

		auto vrrpHeader = getVrrpHeader();
		uint16_t currChecksumValue = vrrpHeader->checksum;
		vrrpHeader->checksum = 0;

		pcpp::IPAddress srcIPAddr = ipLayer->getSrcIPAddress();
		pcpp::IPAddress dstIPAddr = ipLayer->getDstIPAddress();
		uint16_t checksum;
		if (getAddressType() == IPAddress::IPv4AddressType)
		{
			checksum = computePseudoHdrChecksum((uint8_t*)vrrpHeader, getDataLen(), IPAddress::IPv4AddressType,
			                                    PACKETPP_IPPROTO_VRRP, srcIPAddr, dstIPAddr);
		}
		else
		{
			checksum = computePseudoHdrChecksum((uint8_t*)vrrpHeader, getDataLen(), IPAddress::IPv6AddressType,
			                                    PACKETPP_IPPROTO_VRRP, srcIPAddr, dstIPAddr);
		}

		vrrpHeader->checksum = currChecksumValue;

		return checksum;
	}
}  // namespace pcpp
