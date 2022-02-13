#include "SomeIpLayer.h"

#include "SomeIpSdLayer.h"

#include "PayloadLayer.h"

#include <sstream>

namespace pcpp {

SomeIpLayer::SomeIpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
    : Layer(data, dataLen, prevLayer, packet) {

}

SomeIpLayer::~SomeIpLayer() {}

void SomeIpLayer::parseNextLayer() 
{	
    if (m_DataLen <= sizeof(someip_header))
		return;

    someip_header * smhdr = getSomeIpHeader();

	uint8_t* someIpData = m_Data + sizeof(someip_header);
	size_t someIpDataLen = m_DataLen - sizeof(someip_header);

	if(SomeIpServiceDiscoveryLayer::isDataValid(someIpData, someIpDataLen) && smhdr->service_id == 65535)
		m_NextLayer = new SomeIpServiceDiscoveryLayer(someIpData, someIpDataLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(someIpData, someIpDataLen, this, m_Packet);
}

size_t SomeIpLayer::getHeaderLen() const {
    return sizeof(someip_header);
}

someip_header * SomeIpLayer::getSomeIpHeader() const {
    return (someip_header *) m_Data;
}

void SomeIpLayer::computeCalculateFields()
{

}

std::string SomeIpLayer::toString() const {

    std::ostringstream someIpUdp;

    someip_header *header = getSomeIpHeader();

    someIpUdp << "service_id: "          << header->service_id               << " "
              << "client_id: "           << header->client_id                << " "
              << "message_length: "      << header->message_length           << " "
              << "method_id: "           << header->method_id                << " "
              << "interface_version: "   << (int) header->interface_version  << std::endl;

    return someIpUdp.str();
}

bool SomeIpLayer::isDataValid(const uint8_t *data, size_t dataSize) 
{
    return data && dataSize >= sizeof(someip_header);
}

OsiModelLayer SomeIpLayer::getOsiModelLayer() const {
    return pcpp::OsiModelApplicationLayer;
}

} // namespace pcpp
