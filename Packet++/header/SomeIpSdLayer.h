#ifndef PCAPPLUSPLUS_SOMEIPSDLAYER_H
#define PCAPPLUSPLUS_SOMEIPSDLAYER_H

#include "SomeIpLayer.h"

namespace pcpp {

#pragma pack(push, 1)
    struct someipsd_header {
    };
#pragma pack(pop)

/**
 * @class SomeIPServiceDiscoveryLayer
 * Represents a SOME/IP Service Discovery protocol layer
 */
class SomeIPServiceDiscoveryLayer final : public SomeIpLayer 
{
    SomeIPServiceDiscoveryLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);
    ~SomeIPServiceDiscoveryLayer();

    /**
     * Does nothing for this layer
     */
    void parseNextLayer() override;

    /**
     * A static method that takes a byte array and detects whether it is a SOME/IP SD message
     * @param[in] data A byte array
     * @param[in] dataSize The byte array size (in bytes)
     * @return True if the data is identified as SOME/IP SD message
     */
    static bool isDataValid(const uint8_t *data, size_t dataSize);

    virtual std::string toString() const override;
};

} // namespace pcpp

#endif // PCAPPLUSPLUS_SOMEIPSDLAYER_H