#ifndef PCAPPLUSPLUS_SomeIpLayer_H
#define PCAPPLUSPLUS_SomeIpLayer_H

#include "Layer.h"

namespace pcpp {

#pragma pack(push, 1)
    struct someip_header {
        /* SOME/IP Service ID */
        uint16_t service_id;
        /* SOME/IP Service Method ID */
        uint16_t method_id;
        /* SOME/IP Message length */
        uint32_t message_length;
        /* SOME/IP Client ID */
        uint16_t client_id;
        /* SOME/IP Session ID */
        uint16_t session_id;
        /* SOME/IP protocol version */
        uint8_t protocol_version;
        /* SOME/IP Interface version */
        uint8_t interface_version;
        /* SOME/IP Message type */
        uint8_t message_type;
        /* SOME/IP return code */
        uint8_t return_code;
    };
#pragma pack(pop)

/**
 * @class SomeIpLayer
 * Represents a SomeIpLayer protocol layer
 * https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-1/AUTOSAR_PRS_SOMEIPProtocol.pdf
 */
class SomeIpLayer : public Layer {
public:

    /**
     * [PRS_SOMEIP_00055] d The Message Type field is used to differentiate different
     * types of messages and shall contain the following values a
     */
    enum MessageType {
        /** A request expecting a response (even void) */
        REQUEST = 0x00,
        /** A fire&forget request */
        REQUEST_NO_RETURN = 0x01,
        /** A request of a notification/event callback expecting no response */
        NOTIFICATION = 0x02,
        /** The response message */
        RESPONSE = 0x80,
        /** The response containing an error) */
        ERROR = 0x81,
        /** A TP request expecting a response (even void) */
        TP_REQUEST = 0x20, 
        /** A TP fire&forget request */
        TP_REQUEST_NO_RETURN = 0x21,
        /** A TP request of a notification/event callback expecting no response */ 
        TP_NOTIFICATION = 0x22,
        /** The TP response message */
        TP_RESPONSE = 0x23,
        /** The TP response containing an error) */
        TP_ERROR = 0x24
    };

    /**
     * The Return Code shall be used to signal whether a request 
     * was successfully processed. For simplification of the header layout, every message
     * transports the field Return Code.  
     * 0x0b - 0x1f - Reserved for generic SOME/IP errors
     * 0x20 - 0x5E - Reserved for specific errors of services and methods.
     */
    enum ReturnCode {
        /** No error occurred */
        E_OK = 0x00,
        /** An unspecified error occurred */
        E_NOT_OK = 0x01,
        /** The requested Service ID is unknown. */
        E_UNKNOWN_SERVICE = 0x01,
        /** The requested Method ID is unknown. Service ID is known. */
        E_UNKNOWN_METHOD = 0x03, 
        /** Service ID and Method ID are known. Application not running. */ 
        E_NOT_READY = 0x04, 
        /** System running the service is not reachable (internal error code only). */ 
        E_NOT_REACHABLE = 0x05,
        /** A timeout occurred (internal error code only). */
        E_TIMEOUT = 0x06, 
        /** Version of SOME/IP protocol not supported */        
        E_WRONG_PROTOCOL_VERSION = 0x07,
        /** Interface version mismatch */        
        E_WRONG_INTERFACE_VERSION = 0x08,
        /** Deserialization error, so that payload cannot be deserialized. */
        E_MALFORMED_MESSAGE = 0x09,
        /** An unexpected message type was received (e.g. REQUEST_NO_RETURN for a method defined as REQUEST.) */
        E_WRONG_MESSAGE_TYPE = 0x0a
    };

    /** A constructor that creates the layer from an existing packet raw data
     * @param[in] data A pointer to the raw data
     * @param[in] dataLen Size of the data in bytes
     * @param[in] prevLayer A pointer to the previous layer
     * @param[in] packet A pointer to the Packet instance where layer will be stored in
     */
    SomeIpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);
    ~SomeIpLayer();

    // TODO: should check for the SOME/IP SD layer and return it or nullptr
    /**
     * Looking up for the SOME/IP SD and returning @ref SomeIPServiceDiscoveryLayer
     */
    void parseNextLayer() override;

    /**
     * @return Size of @ref someip_header
     */
    size_t getHeaderLen() const override;

    /**
     * Get a pointer to the SOME/IP header
     * @return A pointer to the @ref someip_header
     */
    someip_header *getSomeIpHeader() const;

    /**
     * Does nothing for this layer
     */
    void computeCalculateFields() override;

    /**
     * A static method that takes a byte array and detects whether it is a SOME/IP message
     * @param[in] data A byte array
     * @param[in] dataSize The byte array size (in bytes)
     * @return True if the data is identified as SOME/IP SD message
     */
    static bool isDataValid(const uint8_t *data, size_t dataSize);

    std::string toString() const override;

    OsiModelLayer getOsiModelLayer() const;
};
    
} // namespace pcpp

#endif //PCAPPLUSPLUS_SomeIpLayer_H

