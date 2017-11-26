#include "VxlanLayer.h"
#include "EthLayer.h"
#include <string.h>
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif


namespace pcpp
{

VxlanLayer::VxlanLayer(uint32_t vni, uint16_t groupPolicyID, bool setGbpFlag, bool setPolicyAppliedFlag, bool setDontLearnFlag)
{
	m_DataLen = sizeof(vxlan_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = VXLAN;

	if (vni != 0)
		setVNI(vni);

	vxlan_header* vxlanHeader = getVxlanHeader();

	if (groupPolicyID != 0)
		vxlanHeader->groupPolicyID = htons(groupPolicyID);

	vxlanHeader->vniPresentFlag = 1;

	if (setGbpFlag)
		vxlanHeader->gbpFlag = 1;
	if (setPolicyAppliedFlag)
		vxlanHeader->policyAppliedFlag = 1;
	if (setDontLearnFlag)
		vxlanHeader->dontLearnFlag = 1;
}

uint32_t VxlanLayer::getVNI()
{
	return (ntohl(getVxlanHeader()->vni) >> 8);
}

void VxlanLayer::setVNI(uint32_t vni)
{
	getVxlanHeader()->vni = htonl(vni << 8);
}

std::string VxlanLayer::toString()
{
	return "VXLAN Layer";
}

void VxlanLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(vxlan_header))
		return;

	m_NextLayer = new EthLayer(m_Data + sizeof(vxlan_header), m_DataLen - sizeof(vxlan_header), this, m_Packet);
}

}
