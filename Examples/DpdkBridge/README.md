DPDK Bridge example application
===============================

This application demonstrates how to create a bridge between two network devices using PcapPlusPlus DPDK APIs.
It listens to two DPDK ports (a.k.a DPDK devices), and forwards all the traffic received on one port to the other, acting like a L2 bridge. 

The application uses the concept of worker threads. Number of cores can be set by the user or set to default (default is all machine cores minus one management core). 
Each core is assigned with one worker thread. The application assigns each DPDK port and all its RX queues to one worker thread, and its only TX queue to the other worker thread. Each worker thread does exactly the same work: receiving packets on one port and sending them to the other port.

For example: if there are 2 DPDK ports with 4 RX queues to listen to then worker #1 will get packets from RX queues 1-4 of port 1 an send them to TX queue 1 of port 2. Worker #2 will do the opposite, get packets from RX queues 1-4 of port 2 an send them to TX queue 1 of port 1

Important: 
----------
- This application runs only on Linux (DPDK is not supported on Windows and Mac OS X)
- This application (like all applications using DPDK) should be run as 'sudo'


Using the utility
-----------------
	Basic usage: 
		DpdkBridge [-hlv] [-c CORE_MASK] [-m POOL_SIZE] -d PORT_1,PORT_2 [-q QUEUE_QTY]

	Options:
	    -h|--help                                  : Displays this help message and exits
	    -l|--list                                  : Print the list of DPDK ports and exits
		-v|--version                               : Displays the current version and exits
	    -c|--core-mask CORE_MASK                   : Core mask of cores to use. For example: use 7 (binary 0111) to use cores 0,1,2.
	                                                 Default is using all cores except management core
	    -m|--mbuf-pool-size POOL_SIZE              : DPDK mBuf pool size to initialize DPDK with. Default value is 4095);
	    -d|--dpdk-ports PORT_1,PORT_2              : A comma-separated list of DPDK port numbers to be bridged.
	                                                 To see all available DPDK ports use the -l switch
	    -q|--queue-quantity QUEUE_QTY              : Quantity of RX queues to be opened for each DPDK device. Default value is 1

