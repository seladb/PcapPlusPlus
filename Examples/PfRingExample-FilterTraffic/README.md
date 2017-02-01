Filter Traffic PF_RING example application
==========================================

This application demonstrates PcapPlusPlus PF_RING APIs. 
It listens to a PF_RING interface, captures all traffic and matches packets by user-defined matching criteria such as source/dest IP, source/dest TCP/UDP port and more. 
Matched packets can be send to another PF_RING interface and/or be save to a pcap file. In addition the application collects statistics on received and matched packets.
In addition the application collect statistics on received and matched packets: number of packets per protocol, number of matched flows and number of matched packets.

The application uses PfRingDevice's multi-threaded capturing. Number of capture threads can be set by the user (to the maximum of machine's core number minus 1) or set to default 
(default is all machine cores minus one management core the application runs on). Each core is assigned with one capture thread.
PfRingDevice tries to assign one RX channel for each capturing thread (to improve performance), but if NIC doesn't enough RX channels to provide one for each thread, it will assign several thread with the same RX channel
For example: if NIC supports 4 RX channels but the user asks for 6 capturing threads than 4 cores will share 2 RX channels and the 2 remaining cores will use RX channels of their own.
Each capturing thread does exactly the same work: receiving packets, collecting packet statistics, matching flows and sending/saving matched packets.

Another thing this application demonstrates is getting interface details such as total RX channels available, MAC address, PF_RING interface index, MTU, etc.

Important:
----------
- This application runs only on Linux (PF_RING is not supported on Windows and Mac OS X)
- Before compiling this application make sure you set Compile PcapPlusPlus with PF_RING to y in configure-linux.sh. Otherwise the application won't compile
- Before running the application make sure you load the PF_RING kernel module: sudo insmod <PF_RING_LOCATION>/kernel/pf_ring.ko , otherwise the application will exit with an error log that instructs you to load the kernel module
- This application (like all applications using PF_RING) should be run as 'sudo'

Using the utility
-----------------
	Basic usage: 
		PfRingFilterTraffic [-hl] [-s INTERFACE_NAME] [-f FILENAME] [-i IPV4_ADDR] [-I IPV4_ADDR] [-p PORT] [-P PORT] [-r PROTOCOL] [-c NUM_OF_THREADS] -n INTERFACE_NAME

	Options:
		-h|--help                                  : Displays this help message and exits
		-l|--list                                  : Print the list of PF_RING devices and exists
		-n|--interface-name       INTERFACE_NAME   : A PF_RING interface name to receive packets from. To see all available interfaces
													 use the -l switch
		-s|--send-matched-packets INTERFACE_NAME   : PF_RING interface name to send matched packets to
		-f|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH. Packets matched by thread X will be saved under 'FILEPATH/ThreadX.pcap'
		-i|--match-source-ip      IPV4_ADDR        : Match source IPv4 address
		-I|--match-dest-ip        IPV4_ADDR        : Match destination IPv4 address
		-p|--match-source-port    PORT             : Match source TCP/UDP port
		-P|--match-dest-port      PORT             : Match destination TCP/UDP port
		-r|--match-protocol       PROTOCOL         : Match protocol. Valid values are 'TCP' or 'UDP'
		-t|--num-of-threads       NUM_OF_THREADS   : Number of capture threads to open. Should be in the range of 1 to NUM_OF_CORES_ON_MACHINE-1.
													 Default is using all machine cores except the core the application is running on);