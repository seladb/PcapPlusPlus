#include "SomeIpSdLayer.h"

#include <sstream>

namespace pcpp {

SomeIpSdLayer::SomeIpSdLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
        : SomeIpLayer(data, dataLen, prevLayer, packet) 
{
    m_Protocol = SomeIpSd;

    computeCalculateFields();
}

SomeIpSdLayer::~SomeIpSdLayer() {}

size_t SomeIpSdLayer::getHeaderLen() const 
{
    return sizeof(someipsd_header);
}

someipsd_header * SomeIpSdLayer::getSomeIpSdHeader() const 
{
    return (someipsd_header *) m_Data;
}

bool SomeIpSdLayer::isDataValid(const uint8_t *data, size_t dataSize) 
{    
    return data && dataSize >= sizeof(someipsd_header);
}

OsiModelLayer SomeIpSdLayer::getOsiModelLayer() const {
    return OsiModelLayerUnknown;
}

std::string SomeIpSdLayer::toString() const 
{    
    std::stringstream someip_sd;

    someip_sd << "SD Flags: "                                 << std::endl 
              << "-Reboot flag: "                << reboot() << std::endl
              << "-Unicast flag: "               << unicast() << std::endl
              << "-Explicit initial data flag: " << explicit_initial_data() << std::endl;

    return someip_sd.str();
}

void SomeIpSdLayer::computeCalculateFields() 
{
    someipsd_header *smsdhdr = getSomeIpSdHeader();

    for(int i=0; i != 8; i++) {
        _flags[i] = (smsdhdr->flags >> i) & 1;
    }

    uint32_t entries_array_length = htobe32(*((int *)(m_Data + sizeof(uint32_t))));
    uint32_t entries_array_size = htobe32(*((int *)(m_Data + sizeof(uint32_t)))) / sizeof(someipsd_entries_array_entry);
    uint32_t options_array_size = htobe32(*((int *)(m_Data + sizeof(uint32_t)*2 + entries_array_length))) / sizeof(someipsd_options_array_entry);

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
