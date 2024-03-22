HTTP Traffic Analyzer
=====================

This application reassembless HTTP 1.x packets and generate a file from the payload. It read packets from a pcap/pcap-ng file.

Using the utility (Work In Progress)
-----------------
When extracting HTTP traffic payload a pcap/pcap-ng file:

	Basic usage:
		HttpAnalyzer [-h] -f input_file
	Options:
		-f           : The input pcap file to analyze. Required argument for this mode
		-h           : Displays this help message and exits
