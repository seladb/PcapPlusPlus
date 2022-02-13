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
         * 32 bit length of the sd entries array
        */
        uint8_t flags;
        uint8_t  reserved0;
        uint16_t reserved1;
        uint32_t entries_array_length;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct someipsd_entries_array_entry {
        /**
         * SOME/IP service discovery entries element
         */
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
        /**
         * SOME/IP service discovery options element
         */
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
 * @class SomeIpSdLayer
 * Represents a SOME/IP Service Discovery protocol layer
 */
class SomeIpSdLayer final : public SomeIpLayer 
{
public:
    SomeIpSdLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);
    ~SomeIpSdLayer();

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

    OsiModelLayer getOsiModelLayer() const override;

    /**
     * Calculates services and options array entries
     */
    void computeCalculateFields() override;

    std::vector<someipsd_entries_array_entry> & entries() {
        return _sd_entries;
    }

    std::vector<someipsd_options_array_entry> & options() {
        return _sd_options;
    }

    std::array<bool,8> & flags() {
        return _flags;
    }

    bool reboot() const {
        return _flags[7];
    }

    bool unicast() const {
        return _flags[6];
    }

    bool explicit_initial_data() const {
        return _flags[5];
    }

private: 
    std::vector<someipsd_entries_array_entry> _sd_entries;
    std::vector<someipsd_options_array_entry> _sd_options;

    std::array<bool,8> _flags;

};

} // namespace pcpp

#endif // PCAPPLUSPLUS_SOMEIPSDLAYER_H