TCP Reassembly
==============

This is an application that captures data transmitted as part of TCP connections, organizes the data and stores it in a way that is convenient for protocol analysis and debugging.
This application reconstructs the TCP data streams and stores each connection in a separate file(s). TcpReassembly understands TCP sequence numbers and will correctly reconstruct
data streams regardless of retransmissions, out-of-order delivery or data loss.

TcpReassembly works more or less the same like tcpflow (https://linux.die.net/man/1/tcpflow) but probably with less options.
The main purpose of it is to demonstrate the TCP reassembly capabilities in PcapPlusPlus.

Main features and capabilities:
- Captures packets from pcap/pcapng files or live traffic
- Handles TCP retransmission, out-of-order packets and packet loss
- Possibility to set a BPF filter to process only part of the traffic
- Write each connection to a separate file
- Write each side of each connection to a separate file
- Limit the max number of open files in each point in time (to avoid running out of file descriptors for large files / heavy traffic)
- Write a metadata file (txt file) for each connection with various stats on the connection: number of packets (in each side + total), number of TCP messages (in each side + total), umber of bytes (in each side + total)
- Write to console only (instead of files)
- Set a directory to write files to (default is current directory)

Using the utility
-----------------
	TcpReassembly [-hlcms] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter] [-f max_files]

	Options:

		-r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file
		-i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. Required argument for capturing from live interface
		-o output_dir : Specify output directory (default is '.')
		-e bpf_filter : Apply a BPF filter to capture file or live interface, meaning TCP reassembly will only work on filtered packets
		-f max_files  : Maximum number of file descriptors to use
		-c            : Write all output to console (nothing will be written to files)
		-m            : Write a metadata file for each connection
		-s            : Write each side of each connection to a separate file (default is writing both sides of each connection to the same file)
		-l            : Print the list of interfaces and exit
		-h            : Display this help message and exit