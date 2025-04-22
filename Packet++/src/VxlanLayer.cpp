#include "VxlanLayer.h"
#include "EthLayer.h"
#include "EndianPortable.h"

#include <cstring>

namespace pcpp
{

	VxlanLayer::VxlanLayer(uint32_t vni, uint16_t groupPolicyID, bool setGbpFlag, bool setPolicyAppliedFlag,
	                       bool setDontLearnFlag)
	{
		const size_t headerLen = sizeof(vxlan_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		m_Protocol = VXLAN;

		if (vni != 0)
			setVNI(vni);

		vxlan_header* vxlanHeader = getVxlanHeader();

		if (groupPolicyID != 0)
			vxlanHeader->groupPolicyID = htobe16(groupPolicyID);

		vxlanHeader->vniPresentFlag = 1;

		if (setGbpFlag)
			vxlanHeader->gbpFlag = 1;
		if (setPolicyAppliedFlag)
			vxlanHeader->policyAppliedFlag = 1;
		if (setDontLearnFlag)
			vxlanHeader->dontLearnFlag = 1;
	}

	uint32_t VxlanLayer::getVNI() const
	{
		return (be32toh(getVxlanHeader()->vni) >> 8);
	}

	void VxlanLayer::setVNI(uint32_t vni)
	{
		getVxlanHeader()->vni = htobe32(vni << 8);
	}

	std::string VxlanLayer::toString() const
	{
		return "VXLAN Layer";
	}

	void VxlanLayer::parseNextLayer()
	{
		if (m_DataLen <= sizeof(vxlan_header))
			return;

		m_NextLayer = new EthLayer(m_Data + sizeof(vxlan_header), m_DataLen - sizeof(vxlan_header), this, m_Packet);
	}

}  // namespace pcpp
