#include "SomeIpSdLayer.h"

#include <sstream>

namespace pcpp {

SomeIpServiceDiscoveryLayer::SomeIpServiceDiscoveryLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
        : SomeIpLayer(data, dataLen, prevLayer, packet) {

}

SomeIpServiceDiscoveryLayer::~SomeIpServiceDiscoveryLayer() {}

size_t SomeIpServiceDiscoveryLayer::getHeaderLen() const {
    return sizeof(someipsd_header);
}

someipsd_header * SomeIpServiceDiscoveryLayer::getSomeIpSdHeader() const {
    return (someipsd_header *) m_Data;
}

bool SomeIpServiceDiscoveryLayer::isDataValid(const uint8_t *data, size_t dataSize) 
{    
    return data && dataSize >= sizeof(someipsd_header);
}

OsiModelLayer SomeIpServiceDiscoveryLayer::getOsiModelLayer() const {
    return pcpp::OsiModelLayerUnknown;
}

std::string SomeIpServiceDiscoveryLayer::toString() const {
    
    std::stringstream someip_sd;

    someip_sd << "Flags: " << " " << std::endl;

    return someip_sd.str();
}

#define bswap_16(value) ((((value)&0xff) << 8) | ((value) >> 8))

#define bswap_32(value)                                                                            \
    (((uint32_t)bswap_16((uint16_t)((value)&0xffff)) << 16)                                        \
     | (uint32_t)bswap_16((uint16_t)((value) >> 16)))


void SomeIpServiceDiscoveryLayer::computeCalculateFields() 
{
    someipsd_header *someipsd_hdr = getSomeIpSdHeader();

    for(int i=0; i != 8; i++) {
        _flags[i] = (someipsd_hdr->flags >> i) & 1;
    }

    uint32_t entries_array_length = bswap_32(*((int *)(m_Data + sizeof(uint32_t))));
    uint32_t entries_array_size = bswap_32(*((int *)(m_Data + sizeof(uint32_t)))) / sizeof(someipsd_entries_array_entry);
    uint32_t options_array_size = bswap_32(*((int *)(m_Data + sizeof(uint32_t)*2 + entries_array_length))) / sizeof(someipsd_options_array_entry);

    someipsd_entries_array_entry *sd_entries = (someipsd_entries_array_entry *)(m_Data + sizeof(uint32_t)*2);
    someipsd_options_array_entry *sd_options = (someipsd_options_array_entry *)(m_Data + sizeof(uint32_t)*3 + entries_array_length);

    _sd_entries.resize(entries_array_size);
    for(uint32_t i=0; i < entries_array_size; i++) {
        _sd_entries[i] = *(sd_entries+i);
    }

    _sd_options.resize(options_array_size);
    for(uint32_t i=0; i < options_array_size; i++) {
        _sd_options[i] = *(sd_options+i);
    }

}


} // namespace pcpp
