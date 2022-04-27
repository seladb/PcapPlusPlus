#include "SomeIpSdLayer.h"

namespace pcpp {

SomeIPServiceDiscoveryLayer::SomeIPServiceDiscoveryLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
        : SomeIpLayer(data, dataLen, prevLayer, packet) {

}

SomeIPServiceDiscoveryLayer::~SomeIPServiceDiscoveryLayer() {}

} // namespace pcpp
