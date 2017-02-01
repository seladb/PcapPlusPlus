Pcap Search
===========

This application searches all pcap and pcapng files in a given directory and all its sub-directories (unless stated otherwise) and outputs how many and which packets in those files match a certain pattern given by the user. 
The pattern is given in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html). 

For example: if running the application with the following parameters:

	PcapSearch.exe -d C:\ -s "ip net 1.1.1.1" -r C:\report.txt

The application will search all '.pcap' or 'pcapng' files in all directories under C drive and try to match packets that matches IP 1.1.1.1. The result will be printed to stdout and a more detailed report will be printed 
to c:\report.txt

Output example:

	1 packets found in 'C:\\path\example\Dns.pcap'
	5 packets found in 'C:\\path\example\bla1\my_pcap2.pcap'
	7299 packets found in 'C:\\path2\example\example2\big_pcap.pcap'
	7435 packets found in 'C:\\path3\dir1\dir2\dir3\dir4\another.pcap'
	435 packets found in 'C:\\path3\dirx\diry\dirz\ok.pcap'
	4662 packets found in 'C:\\path4\gotit.pcap'
	7299 packets found in 'C:\\enough.pcap'

There are switches that allows the user to search only in the provided folder (without sub-directories), search user-defined file extensions (sometimes pcap files have an extension which is not '.pcap'), and output or not output the detailed report

Using the utility
-----------------
	Basic usage:
		PcapPrinter [-h] [-o output_file] [-c packet_count] [-i filter] -f pcap_file

	Options:
		-f pcap_file   : Input pcap file name
		-o output_file : Save output to text file (default output is stdout)
		-c packet_count: Print only first packet_count number of packet
		-i filter      : Apply a BPF filter, meaning only filtered packets will be printed
		-h             : Displays this help message and exits
