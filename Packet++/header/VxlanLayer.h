#ifndef PACKETPP_VXLAN_LAYER
#define PACKETPP_VXLAN_LAYER

#include "Layer.h"

/// @file

namespace pcpp
{

	/**
	 * @struct vxlan_header
	 * Represents a VXLAN protocol header
	 */
#pragma pack(push, 1)
	struct vxlan_header
	{
		#if(BYTE_ORDER == LITTLE_ENDIAN)
			/** Reserved bits */
			uint16_t reserved6_8:3;
			/** VNI present flag */
			uint16_t vniPresentFlag:1;
			/** Reserved bits */
			uint16_t reserved2_4:3;
			/** GBP flag */
			uint16_t gbpFlag:1;
			/** Reserved bits */
			uint16_t reserved14_16:3;
			/** Policy applied flag */
			uint16_t policyAppliedFlag:1;
			/** Reserved bits */
			uint16_t reserved11_12:2;
			/** Don't learn flag */
			uint16_t dontLearnFlag:1;
			/** Reserved bits */
			uint16_t reserved9:1;
		#else
			/** Reserved bits */
			uint16_t reserved9:1;
			/** Don't learn flag */
			uint16_t dontLearnFlag:1;
			/** Reserved bits */
			uint16_t reserved11_12:2;
			/** Policy applied flag */
			uint16_t policyAppliedFlag:1;
			/** Reserved bits */
			uint16_t reserved14_16:3;
			/** GBP flag */
			uint16_t gbpFlag:1;
			/** Reserved bits */
			uint16_t reserved2_4:3;
			/** VNI present flag */
			uint16_t vniPresentFlag:1;
			/** Reserved bits */
			uint16_t reserved6_8:3;
		#endif

		/** Group Policy ID */
		uint16_t groupPolicyID;

		/** VXLAN Network ID (VNI) */
		uint32_t vni:24;
		/** Reserved bits */
		uint32_t pad:8;
	};
#pragma pack(pop)


	/**
	 * @class VxlanLayer
	 * Represents a VXLAN (Virtual eXtensible Local Area Network) protocol layer
	 */
	class VxlanLayer : public Layer
	{
	public:
		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		VxlanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = VXLAN; }

		/**
		 * A constructor that creates a new VXLAN header and allocates the data. Note: the VNI present flag is set automatically
		 * @param[in] vni VNI (VXLAN Network ID) to set. Optional parameter (default is 0)
		 * @param[in] groupPolicyID Group Policy ID to set. Optional parameter (default is 0)
		 * @param[in] setGbpFlag Set GBP flag. Optional parameter (default is false)
		 * @param[in] setPolicyAppliedFlag Set Policy Applied flag. Optional parameter (default is false)
		 * @param[in] setDontLearnFlag Set Don't Learn flag. Optional parameter (default is false)
		 */
		VxlanLayer(uint32_t vni = 0, uint16_t groupPolicyID = 0, bool setGbpFlag = false, bool setPolicyAppliedFlag = false, bool setDontLearnFlag = false);

		~VxlanLayer() {}

		/**
		 * Get a pointer to the VXLAN header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the vxlan_header
		 */
		inline vxlan_header* getVxlanHeader() { return (vxlan_header*)m_Data; }

		/**
		 * @return The VXLAN Network ID (VNI) value
		 */
		uint32_t getVNI();

		/**
		 * Set VXLAN Network ID (VNI) value
		 * @param[in] vni VNI value to set
		 */
		void setVNI(uint32_t vni);


		// implement abstract methods

		/**
		 * Next layer for VXLAN is always Ethernet
		 */
		void parseNextLayer();

		/**
		 * @return Size of vxlan_header
		 */
		inline size_t getHeaderLen() { return sizeof(vxlan_header); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelDataLinkLayer; }

	};

}

#endif // PACKETPP_VXLAN_LAYER
