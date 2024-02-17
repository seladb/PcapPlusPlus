DPDK Bridge example application
===============================

This application demonstrates how to create a bridge between two network devices using PcapPlusPlus DPDK APIs.
It listens to two DPDK ports (a.k.a. DPDK devices), and forwards all the traffic received on one port to the other, acting like a L2 bridge.

The application is very similar to [DPDK's L2 forwarding example](https://doc.dpdk.org/guides/sample_app_ug/l2_forward_real_virtual.html)
and demonstrates how to achieve the same functionality with PcapPlusPlus using less and easier to understand C++ code.

The application uses the concept of worker threads. It creates 2 worker threads running in an endless loop (as long as the app is running):
one for receiving packets on NIC#1 and sending them to NIC#2, and another for receiving packets on NIC#2 and sending them to NIC#1.

Important:
----------
- This application runs only on Linux (DPDK is not supported on non-Linux platforms)
- In order to build this application follow the instructions on how to build PcapPlusPlus with DPDK
- This application (like all applications using DPDK) should be run as 'sudo'
- In order to test this application you need an environment where the bridge is connected directly (back-to-back) to the two machines the
  bridge wants to connect


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
