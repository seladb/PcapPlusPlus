#include "SomeIpLayer.h"
#include "SomeIpSdLayer.h"
#include "PayloadLayer.h"

#include "EndianPortable.h"

#include <sstream>
namespace pcpp {

SomeIpLayer::SomeIpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
    : Layer(data, dataLen, prevLayer, packet) 
{
    m_Protocol = SomeIp;

    computeCalculateFields();
}

SomeIpLayer::~SomeIpLayer() {}

void SomeIpLayer::parseNextLayer() 
{	
    if (m_DataLen <= sizeof(someip_header)) 
    {
		return;
    }

	uint8_t* someIpData = m_Data + sizeof(someip_header);
	size_t someIpDataLen = m_DataLen - sizeof(someip_header);

	if(SomeIpSdLayer::isDataValid(someIpData, someIpDataLen) && isSomeIpSd()) 
    {
		m_NextLayer = new SomeIpSdLayer(someIpData, someIpDataLen, this, m_Packet);
    }
    else 
    {
		m_NextLayer = new PayloadLayer(someIpData, someIpDataLen, this, m_Packet);
    }
}

size_t SomeIpLayer::getHeaderLen() const {
    return sizeof(someip_header);
}

someip_header * SomeIpLayer::getSomeIpHeader() const {
    return (someip_header *) m_Data;
}

void SomeIpLayer::computeCalculateFields()
{
    someip_header * smhdr = getSomeIpHeader();

    service_id = htobe16(smhdr->service_id);
    method_id  = htobe16(smhdr->method_id);

    message_length = htobe32(smhdr->message_length);

    client_id  = htobe16(smhdr->client_id);
    session_id = htobe16(smhdr->session_id);

    protocol_version  = smhdr->protocol_version;
    interface_version = smhdr->interface_version;
    
    message_type = static_cast<MessageType>(smhdr->message_type);
    return_code  = static_cast<ReturnCode>(smhdr->return_code);        
}

std::string SomeIpLayer::toString() const {

    std::ostringstream someIpUdp;

    someIpUdp << "Header: "                                                   << std::endl
              << "-service_id: "          << service_id                       << std::endl
              << "-method_id: "           << method_id                        << std::endl
              << "-client_id: "           << client_id                        << std::endl
              << "-protocol_version: "    << (int) protocol_version           << std::endl
              << "-interface_version: "   << (int) interface_version          << std::endl
              << "-message_length: "      << message_length                   << std::endl;

    return someIpUdp.str();
}

bool SomeIpLayer::isDataValid(const uint8_t *data, size_t dataSize) 
{
    return data && dataSize >= sizeof(someip_header);
}

OsiModelLayer SomeIpLayer::getOsiModelLayer() const {
    return OsiModelApplicationLayer;
}

} // namespace pcpp
