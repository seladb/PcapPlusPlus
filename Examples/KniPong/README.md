KNI Pong
========

This application emulates working of Unix NETCAT utility that run with `-u` key.
Basically it is a ping/pong client/server channel using user provided input from `stdin`.
User provided input is sent to KNI device in UDP packets. Application reads this packets and sends them back to Linux kernel with same string so the string will be shown on terminal twice.
It shows how to work with KNI devices in isolation from DPDK ports.
KniPong will stop if `SIGINT` is received (Ctrl+C).

Using the utility
-----------------

    Basic usage:
        KniPong -s <src_ipv4> -d <dst_ipv4> [-n <kni_device_name>] [-p <port>] [-v] [-h]
    Options:
        -s --src <src_ipv4>           : IP to assign to created KNI device
        -d --dst <dst_ipv4>           : Virtual IP to communicate with. Must be in /24 subnet with <src_ipv4>
        -n --name <kni_device_name>   : Name for KNI device
        -p --port <port>              : Port for communication
        -v --version                  : Displays the current version and exits
        -h --help                     : Displays this help message and exits

Example
-------

Next line will:
> sudo ./KniPong -s 192.168.0.100 -d 192.168.0.150 -p 44300 -n my_kni0

* create KNI device named `my_kni0`
* set it IP to `192.168.0.100/24`
* create UDP socket at `192.168.0.100:44300`
* connect to `192.168.0.150:44300`
* start to forward what You type to `stdin` to created UDP socket
* if something is received from socket it will be dumped to `stdout`

The thread that handles packets from KNI device will response to any ARP request with same MAC and for any UDP packet with same packet.
So that netstat utility (`netstat | grep 192.168.0.100`) will show something like :
> udp 0 0 192.168.0.100:44300 192.168.0.150:44300 ESTABLISHED

You can capture the traffic on KNI device via (default kni_device_name is `pcppkni0`):
> sudo tcpdump -i kni_device_name -w dump.pcap
