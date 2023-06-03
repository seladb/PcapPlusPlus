#define LOG_MODULE PacketLogModuleVrrpLayer

#include <SystemUtils.h>
#include "PacketUtils.h"
#include "Logger.h"
#include "EndianPortable.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "VrrpLayer.h"

namespace pcpp {

#define VRRP_PRIO_STOP      0     /* priority to stop  */
#define VRRP_PRIO_DFF       100   /* default priority */
#define VRRP_PRIO_OWNER     255   /* priority of the ip owner */

#define VRRP_AUTH_NONE      0     /* no authentication */
#define VRRP_AUTH_SIMPLE    1     /* Simple Text Authentication [RFC 2338] */
#define VRRP_AUTH_AH        2     /* IP Authentication Header [RFC 2338]  */
#define VRRP_AUTH_MD5       3     /* Cisco VRRP MD5 authentication  */

#define VRRP_PACKET_FIX_LEN 8
#define VRRP_PACKET_MAX_IP_ADDRESS_NUM 255

#define VRRP_V2_VERSION     2
#define VRRP_V3_VERSION     3

	/*************
	 * VrrpLayer
	 *************/

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

	ProtocolType VrrpLayer::getVersionFromData(uint8_t *data, size_t dataLen)
	{
		if (!data || dataLen <= VRRP_PACKET_FIX_LEN)
		{
			return UnknownProtocol;
		}

		auto *vrrpPacketCommon = (vrrp_header *) data;
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

	std::string VrrpLayer::getPriorityDesc() const
	{
		std::string priorityName;
		if (getVrrpHeader()->priority == VRRP_PRIO_DFF)
		{
			priorityName = "(Default priority for a backup VRRP router)";
		}
		else if (getPriority() == VRRP_PRIO_STOP)
		{
			priorityName = "(Current Master has stopped participating in VRRP)";
		}
		else if (getPriority() == VRRP_PRIO_OWNER)
		{
			priorityName = "(This VRRP router owns the virtual router's IP address(es))";
		}

		return priorityName;
	}

	std::string VrrpLayer::getAuthTypeDescByType(uint8_t authType)
	{
		std::string priorityName;
		if (authType == VRRP_AUTH_NONE)
		{
			priorityName = "No Authentication";
		}
		else if (authType == VRRP_AUTH_SIMPLE)
		{
			priorityName = "Simple Text Authentication [RFC 2338] / Reserved [RFC 3768]";
		}
		else if (authType == VRRP_AUTH_AH)
		{
			priorityName = "IP Authentication Header [RFC 2338] / Reserved [RFC 3768]";
		}
		else if (authType == VRRP_AUTH_MD5)
		{
			priorityName = "Cisco VRRP MD5 authentication";
		}

		return priorityName;
	}

	std::string VrrpLayer::toString() const
	{
		return "VRRP v" + std::to_string(getVersion()) + " Layer, virtual router ID: " + std::to_string(getVirtualRouterID()) + ", IP address count: " + std::to_string(getIPAddressesCount());
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

	uint8_t VrrpLayer::getIPAddressesCount() const
	{
		return getVrrpHeader()->ipAddrCount;
	}

	std::vector<IPAddress> VrrpLayer::getIPAddresses() const
	{
		std::vector<IPAddress> ipAddressesVec;
		uint8_t ipAddrCount = getIPAddressesCount();
		uint8_t *ipAddressesPtr = getFirstIPAddress();
		size_t ipAddressLen = getIPAddressLen();
		if ((ipAddrCount == 0) || (ipAddressesPtr == nullptr) || (ipAddressLen == 0))
		{
			return ipAddressesVec;
		}

		for (int i = 0; i < ipAddrCount; i++)
		{
			IPAddress ipAddress;
			if (!getIPAddressFromData(ipAddressesPtr, ipAddress))
			{
				continue;
			}

			ipAddressesVec.push_back(ipAddress);
			ipAddressesPtr += ipAddressLen;
		}

		return ipAddressesVec;
	}

	uint8_t *VrrpLayer::getFirstIPAddress() const
	{
		size_t ipAddressLen = getIPAddressLen();
		if (ipAddressLen == 0)
		{
			PCPP_LOG_ERROR("Cannot get first virtual IP address, for ip address length is invalid.");
			return nullptr;
		}

		// check if there are virtual IP address at all
		if (getHeaderLen() <= VRRP_PACKET_FIX_LEN + ipAddressLen)
		{
			PCPP_LOG_ERROR("Cannot get first virtual IP address, for length(" << getHeaderLen() << ") is too short.");
			return nullptr;
		}

		return (m_Data + VRRP_PACKET_FIX_LEN);
	}

	uint8_t *VrrpLayer::getNextIPAddress(uint8_t *ipAddress) const
	{
		if (ipAddress == nullptr)
		{
			return nullptr;
		}

		size_t ipAddressLen = getIPAddressLen();
		if (ipAddressLen == 0)
		{
			PCPP_LOG_ERROR("Cannot get next virtual IP address, for ip address length is invalid.");
			return nullptr;
		}

		// prev virtual IP address was the last virtual IP address
		if (ipAddress + ipAddressLen - m_Data >= (int) getHeaderLen())
		{
			return nullptr;
		}

		return (ipAddress + ipAddressLen);
	}

	bool VrrpLayer::addIPAddressesAt(const std::vector<IPAddress> &ipAddresses, int offset)
	{
		if (offset > (int) getHeaderLen())
		{
			PCPP_LOG_ERROR("Cannot add virtual IP address offset(" << offset << ") is out of layer bounds");
			return false;
		}

		uint8_t ipAddressCount = getIPAddressesCount();
		if (ipAddressCount + ipAddresses.size() > VRRP_PACKET_MAX_IP_ADDRESS_NUM)
		{
			PCPP_LOG_ERROR("Cannot add virtual IP address, for virtual IP address has already exceed maximum.");
			return false;
		}

		size_t ipAddrLen = getIPAddressLen();
		size_t ipAddressesLen = ipAddrLen * ipAddresses.size();
		if (ipAddressesLen == 0)
		{
			PCPP_LOG_ERROR("Cannot add virtual IP address, for ip address length is invalid.");
			return false;
		}
		if (!extendLayer(offset, ipAddressesLen))
		{
			PCPP_LOG_ERROR("Cannot add virtual IP address, cannot extend layer");
			return false;
		}

		size_t ipAddrOffset = 0;
		uint8_t *newIpAddresses = getData() + offset;
		for (auto ipAddress: ipAddresses)
		{
			if (!isIPAddressValid(ipAddress))
			{
				PCPP_LOG_ERROR("Cannot add virtual IP address, for IP address is invalid.");
				return false;
			}
			copyIPAddressToData(newIpAddresses + ipAddrOffset, ipAddress);

			ipAddrOffset += ipAddrLen;
		}

		getVrrpHeader()->ipAddrCount = getIPAddressesCount() + ipAddresses.size();

		return true;
	}

	bool VrrpLayer::addIPAddresses(const std::vector<IPAddress> &ipAddresses)
	{
		return addIPAddressesAt(ipAddresses, (int) getHeaderLen());
	}

	bool VrrpLayer::addIPAddress(IPAddress &ipAddress)
	{
		std::vector<IPAddress> ipAddresses;
		ipAddresses.push_back(ipAddress);

		return addIPAddressesAt(ipAddresses, (int) getHeaderLen());
	}

	bool VrrpLayer::removeIPAddressAtIndex(int index)
	{
		int ipAddressCount = (int) getIPAddressesCount();

		if (index < 0 || index >= ipAddressCount)
		{
			PCPP_LOG_ERROR("Cannot remove virtual IP address, index " << index << " is out of bounds");
			return false;
		}

		size_t ipAddressLen = getIPAddressLen();
		if (ipAddressLen == 0)
		{
			PCPP_LOG_ERROR("Cannot remove IP address, for ip address length is invalid.");
			return false;
		}

		size_t offset = VRRP_PACKET_FIX_LEN;
		uint8_t *curIpAddress = getFirstIPAddress();
		for (int i = 0; i < index; i++)
		{
			if (curIpAddress == nullptr)
			{
				PCPP_LOG_ERROR("Cannot remove virtual IP address at index "
									   << index << ", cannot find virtual IP address at index " << i);
				return false;
			}

			offset += ipAddressLen;
			curIpAddress = getNextIPAddress(curIpAddress);
		}

		if (!shortenLayer((int) offset, ipAddressLen))
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

	void VrrpLayer::copyIPAddressToData(uint8_t *data, const IPAddress &ipAddress) const
	{
		size_t ipAddressLen = getIPAddressLen();
		if (ipAddressLen == 0)
		{
			PCPP_LOG_ERROR("Cannot copy virtual IP address to data, for ip address length is invalid.");
			return;
		}

		if (ipAddress.isIPv4())
		{
			memcpy(data, ipAddress.getIPv4().toBytes(), ipAddressLen);
		}
		else if (ipAddress.isIPv6())
		{
			memcpy(data, ipAddress.getIPv6().toBytes(), ipAddressLen);
		}
	}

	bool VrrpLayer::getIPAddressFromData(uint8_t *data, IPAddress &ipAddress) const
	{
		if (getAddressType() == IPAddress::IPv4AddressType)
		{
			IPv4Address ipv4Address(*((uint32_t *) data));
			ipAddress = ipv4Address;
		}
		else if (getAddressType() == IPAddress::IPv6AddressType)
		{
			IPv6Address ipv6Address(data);
			ipAddress = ipv6Address;
		}
		else
		{
			return false;
		}

		return true;
	}

	bool VrrpLayer::isIPAddressValid(IPAddress &ipAddress) const
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
		if (!ipAddress.isValid())
		{
			PCPP_LOG_ERROR("IP address is invalid.");
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

	/*************
	 * Vrrpv2Layer
	 *************/

	VrrpV2Layer::VrrpV2Layer(uint8_t virtualRouterId, uint8_t priority, uint8_t advInt, uint8_t authType) : VrrpLayer(VRRPv2, virtualRouterId, priority)
	{
		setAdvInt(advInt);
		setAuthType(authType);
	};

	std::string VrrpV2Layer::getAuthTypeDesc() const
	{
		std::string toStr;

		toStr += "\n\tAuth Type: " + getAuthTypeDescByType(getAuthType());
		toStr += " (";
		toStr += std::to_string(getAuthType());
		toStr += ")";

		return toStr;
	}

	uint8_t VrrpV2Layer::getAdvInt() const
	{
		uint16_t authAdvInt = getVrrpHeader()->authTypeAdvInt;
		auto authAdvIntPtr = (vrrpv2_auth_adv *) (&authAdvInt);
		return authAdvIntPtr->advInt;
	}

	void VrrpV2Layer::setAdvInt(uint8_t advInt)
	{
		auto authAdvIntPtr = (vrrpv2_auth_adv *)&getVrrpHeader()->authTypeAdvInt;
		authAdvIntPtr->advInt = advInt;
	}

	uint8_t VrrpV2Layer::getAuthType() const
	{
		uint16_t authAdvInt = getVrrpHeader()->authTypeAdvInt;
		auto *authAdvIntPtr = (vrrpv2_auth_adv *) (&authAdvInt);
		return authAdvIntPtr->authType;
	}

	void VrrpV2Layer::setAuthType(uint8_t authType)
	{
		auto authAdvIntPtr = (vrrpv2_auth_adv *)&getVrrpHeader()->authTypeAdvInt;
		authAdvIntPtr->authType = authType;
	}

	void VrrpV2Layer::calculateAndSetChecksum()
	{
		getVrrpHeader()->checksum = htobe16(calculateChecksum());
	}

	uint16_t VrrpV2Layer::calculateChecksum() const
	{
		if ((getData() == nullptr) || (getDataLen() == 0))
		{
			return 0;
		}

		auto vrrpHeader = getVrrpHeader();
		ScalarBuffer<uint16_t> buffer = {};
		buffer.buffer = (uint16_t *) vrrpHeader;
		buffer.len = getHeaderLen();

		uint16_t currChecksumValue = vrrpHeader->checksum;
		vrrpHeader->checksum = 0;
		uint16_t checksum = computeChecksum(&buffer, 1);
		vrrpHeader->checksum = currChecksumValue;

		return checksum;
	}

	/*************
	 * Vrrpv3Layer
	 *************/

	VrrpV3Layer::VrrpV3Layer(IPAddress::AddressType addressType, uint8_t virtualRouterId, uint8_t priority, uint16_t maxAdvInt) : VrrpLayer(
			VRRPv3, virtualRouterId, priority)
	{
		setAddressType(addressType);
		setMaxAdvInt(maxAdvInt);
	};

	std::string VrrpV3Layer::getAuthTypeDesc() const
	{
		std::string toStr;

		return toStr;
	}

	uint16_t VrrpV3Layer::getMaxAdvInt() const
	{
		uint16_t authAdvInt = getVrrpHeader()->authTypeAdvInt;
		auto rsvdAdv = (vrrpv3_rsvd_adv *) (&authAdvInt);
		return rsvdAdv->maxAdvInt;
	}

	void VrrpV3Layer::setMaxAdvInt(uint16_t maxAdvInt)
	{
		if (maxAdvInt > 0xfff)
		{
			throw std::invalid_argument("maxAdvInt must not exceed 12 bits length");
		}
		auto rsvdAdv = (vrrpv3_rsvd_adv *)&getVrrpHeader()->authTypeAdvInt;
		rsvdAdv->maxAdvInt = htobe16(maxAdvInt);
	}

	void VrrpV3Layer::calculateAndSetChecksum()
	{
		uint16_t checksum = calculateChecksum();

		getVrrpHeader()->checksum = htobe16(checksum);
	}

	uint16_t VrrpV3Layer::calculateChecksum() const
	{
		auto *ipLayer = m_Packet->getLayerOfType<pcpp::IPLayer>();
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
			checksum = computePseudoHdrChecksum((uint8_t *) vrrpHeader, getDataLen(), IPAddress::IPv4AddressType,
												PACKETPP_IPPROTO_VRRP, srcIPAddr, dstIPAddr);
		}
		else
		{
			checksum = computePseudoHdrChecksum((uint8_t *) vrrpHeader, getDataLen(), IPAddress::IPv6AddressType,
												PACKETPP_IPPROTO_VRRP, srcIPAddr, dstIPAddr);
		}

		vrrpHeader->checksum = currChecksumValue;

		return checksum;
	}
}
