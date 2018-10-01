DPDK Bridge example application
===============================

This application demonstrates how to create a bridge between two network devices using PcapPlusPlus DPDK APIs. 

It listens to two DPDK ports (a.k.a DPDK devices), and forwards all the traffic received on one port to the other, acting like a L2 bridge. 

The application uses the concept of worker threads. Number of cores can be set by the user or set to default (default is all machine cores minus one management core). 
Each core is assigned with one worker thread. The application divides the DPDK ports and RX queues equally between worker threads.
For example: if there are 2 DPDK ports to listen to, each one with 6 RX queues and there are 3 worker threads, then worker #1 will get RX queues 1-4 of port 1, worker #2 will get RX queues 5-6 of port 1 
and RX queues 1-2 of port 2, and worker #3 will get RX queues 3-6 of port 2.

Each worker thread does exactly the same work: receiving packets on one port and sending them to the other port.

Important: 
----------
- This application runs only on Linux (DPDK is not supported on Windows and Mac OS X)
- This application (like all applications using DPDK) should be run as 'sudo'


Using the utility
-----------------
	Basic usage: 
		DpdkBridge [-hl] [-c CORE_MASK] [-m POOL_SIZE] -d PORT_1,PORT_2

	Options:
	    -h|--help                                  : Displays this help message and exits
	    -l|--list                                  : Print the list of DPDK ports and exists
	    -d|--dpdk-ports PORT_1,PORT_2              : A comma-separated list of DPDK port numbers to be bridged.
	                                                 To see all available DPDK ports use the -l switch
	    -c|--core-mask            CORE_MASK        : Core mask of cores to use. For example: use 7 (binary 0111) to use cores 0,1,2.
	                                                 Default is using all cores except management core
	    -m|--mbuf-pool-size       POOL_SIZE        : DPDK mBuf pool size to initialize DPDK with. Default value is 4095);