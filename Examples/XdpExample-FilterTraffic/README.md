Filter Traffic AF_XDP example application
=========================================

This application demonstrates PcapPlusPlus AF_XDP APIs.

It opens an AF_XDP socket, receives all packets on the socket and matches them by user-defined matching criteria such as source/dest IP, source/dest TCP/UDP port and more.
Matched packets can be sent to another AF_XDP socket (or to the same socket), and/or be saved to a pcap file.

In addition, the application collect statistics on received, sent and matched packets: total RX/TX, number of packets per protocol, number of matched flows and number of matched packets.

Important:
----------
- This application runs only on Linux (XDP is not supported on non-Linux platforms)
- In order to build this application follow the instructions on how to build PcapPlusPlus with XDP
- This application (like all applications using XDP) should be run as 'sudo'

Using the utility
-----------------
    Basic usage:
        XdpTrafficFilter [-hvl] [-s INTERFACE_NAME] [-f FILENAME] [-i IPV4_ADDR] [-I IPV4_ADDR] [-p PORT] [-P PORT] [-r PROTOCOL] -n INTERFACE_NAME

    Options:
        -h|--help                                  : Displays this help message and exits
        -v|--version                               : Displays the current version and exits
        -l|--list                                  : Print the list of network interfaces and exit
        -n|--interface-name       INTERFACE_NAME   : An interface name to open AF_XDP socket and receive packets from.
                                                     To see all available interfaces use the -l switch
        -s|--send-matched-packets INTERFACE_NAME   : Network interface name to send matched packets to.
                                                     The app will open another AF_XDP socket for sending packets.
                                                     Note: this interface can be the same one used to receive packets.
        -f|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH.
        -i|--match-source-ip      IPV4_ADDR        : Match source IPv4 address
        -I|--match-dest-ip        IPV4_ADDR        : Match destination IPv4 address
        -p|--match-source-port    PORT             : Match source TCP/UDP port
        -P|--match-dest-port      PORT             : Match destination TCP/UDP port
        -r|--match-protocol       PROTOCOL         : Match protocol. Valid values are 'TCP' or 'UDP'
