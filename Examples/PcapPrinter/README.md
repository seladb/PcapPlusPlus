Pcap Printer
============

This application takes a pcap or pcapng file, parses its packets using Packet++ and output each layer in each packet as a readable string (quite similar to the way Wireshark shows packets).
In addition it prints a short summary of the file (with details such as file name, size, etc.)

The result is printed to stdout (by default) or to a file (if specified). It can also print only the first X packets of a file

Using the utility
-----------------
	Basic usage:
		PcapPrinter [-h] [-o output_file] [-c packet_count] [-i filter] [-s] -f pcap_file
	
	Options:
		-f pcap_file   : Input pcap/pcapng file name
		-o output_file : Save output to text file (default output is stdout)
		-c packet_count: Print only first packet_count number of packet
		-i filter      : Apply a BPF filter, meaning only filtered packets will be printed
		-s             : Print only file summary and exit
		-h             : Displays this help message and exits);