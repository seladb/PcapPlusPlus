#ifndef PCAPPLUSPLUS_SOMEIPSDLAYER_H
#define PCAPPLUSPLUS_SOMEIPSDLAYER_H

#include "SomeIpLayer.h"

#include <vector>
#include <array>

namespace pcpp {

#pragma pack(push, 1)
    struct someipsd_header {
        /**  
         * 0            1            2                      3 4 5 6 7
         * |            |            |
         * reboot flag  Unicast flag Explicit initial data
         * 24 bit reserved
        */
        uint32_t flags;
        uint32_t entries_array_length;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct someipsd_entries_array_entry {
        uint8_t type;
        uint8_t index_first;
        uint8_t index_second;
        uint8_t reserved;

        uint16_t service_id; 
        uint16_t instance_id;

        uint32_t major_version_ttl;
        uint32_t minor_version;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct someipsd_options_array_entry {
        uint16_t length;
        uint8_t type;
        uint8_t reserved;

        uint32_t ipv4;

        uint8_t reserved_;
        uint8_t l4_proto;
        uint16_t port_number;
    };
#pragma pack(pop)

/**
 * @class SomeIpServiceDiscoveryLayer
 * Represents a SOME/IP Service Discovery protocol layer
 */
class SomeIpServiceDiscoveryLayer final : public SomeIpLayer 
{
public:
    SomeIpServiceDiscoveryLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);
    ~SomeIpServiceDiscoveryLayer();

    /**
     * Does nothing for this layer
     */
    void parseNextLayer() override {};

    /**
     * @return Size of @ref someip_header
     */
    virtual size_t getHeaderLen() const override;

    /**
     * A static method that takes a byte array and detects whether it is a SOME/IP SD message
     * @param[in] data A byte array
     * @param[in] dataSize The byte array size (in bytes)
     * @return True if the data is identified as SOME/IP SD message
     */
    static bool isDataValid(const uint8_t *data, size_t dataSize);

    someipsd_header * getSomeIpSdHeader() const;

    std::string toString() const override;

    OsiModelLayer getOsiModelLayer() const;

    /**
     * Calculates services and options array entries
     */
    void computeCalculateFields() override;

    std::vector<someipsd_entries_array_entry> & services() {
        return _sd_entries;
    }

    std::vector<someipsd_options_array_entry> & options() {
        return _sd_options;
    }

    std::array<bool,8> & flags() {
        return _flags;
    }

    bool reboot() {
        return _flags[0];
    }

    bool unicast() {
        return _flags[1];
    }

    bool explicit_initial_data() {
        return _flags[2];
    }

private: 
    std::vector<someipsd_entries_array_entry> _sd_entries;
    std::vector<someipsd_options_array_entry> _sd_options;

    std::array<bool,8> _flags;

};

} // namespace pcpp

#endif // PCAPPLUSPLUS_SOMEIPSDLAYER_H