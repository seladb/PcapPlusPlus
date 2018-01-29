IPDefragUtil
============

A utility for reassembling IP fragments back into full packets. Both IPv4 and IPv6 reassmbly is supported. 
The utility works on pcap and pcapng files and it allows the user to choose which packets will be reassembled, either by choosing
specific IP IDs (for IPv4) and/or choosing specific fragment IDs (for IPv6) and/or set a Berkeley Packet Filter (BPF) filter.


Using the utility
-----------------
**The must-have inputs for this utility are:**  
- Input file (pcap or pcapng format)
- Output file, where fragments will be written to ('-o' flag)

**Filtering packets:**  
If no filter is specified, the default is that all fragment packets will be reassembled.
The user can set two types of filters. Both types can be set together or each one separately:
- Berkeley Packet Filter (BPF) filter - all fragments that match this filter will be reassembled ('-f' flag)
- A comma-separated list of IP IDs (for IPv4) and/or fragment IDs (for IPv6) in decimal format. Fragments matching one of these IDs will be reassembled ('-d' flag)

**Output:**  
Output file type will be identical to input file type. So for pcap file the output will be a pcap file, and same for pcapng.
The default is that only reassembled packets are written to output file, but the user may choose to copy also the packets 
that weren't reassembled to the output file (using '-a' flag).
In addition to the output file the utility outputs to console basic statistics about the process:  

	Summary:
	========
	Total packets read:                      65
	IPv4 packets read:                       29
	IPv6 packets read:                       36
	Total fragments matched:                 65
	IPv4 fragments matched:                  29
	IPv6 fragments matched:                  36
	Total packets reassembled:               6
	IPv4 packets reassembled:                2
	IPv6 packets reassembled:                4
	Total packets written to output file:    6


**Usage examples:**  
Reassemble all fragments in mypcap.pcap:  

	IPDefragUtil mypcap.pcap -o output.pcap
	
Reassemble only fragments with IP ID / fragment ID of 12345, 12346 and 12347. Only these packets will be written to output file:  

	IPDefragUtil mypcap.pcap -o output.pcap -d 12345,12346,12347

Reassemble only fragments with source IP of 10.0.0.1. Only the reassembled packets will be written to output file:  

	IPDefragUtil mypcap.pcap -o output.pcap -f "ip src 10.0.0.1"
	
Reassemble only fragments with source IP of 10.0.0.1. All packets in mypcap.pcapng will be writen to output file: both those matching the 
filter (and reassembled) and those who don't:  

	IPDefragUtil mypcap.pcapng -o output.pcapng f "src ip 10.0.0.1" -a

Reassemble only fragments with source IP of 10.0.0.1 and IP ID of 123. All packets in mypcap.pcapng will be writen to output file: both those
matching the filter (and fragmented) and those who don't:  

	IPDefragUtil mypcap.pcapng -o output.pcapng -f "src ip 10.0.0.1" -d 123 -a

Reassemble an IPv4 packet with IP ID 1234 and an IPv6 packet with fragment ID 5678:  

	IPDefragUtil mypcap.pcap -o output.pcap -d 1234,5678

Reassemble only IPv6 fragments with dest address of 2001:4f8:3:d::61:  

	IPDefragUtil mypcap.pcap -o output.pcapng -f "ip6 dst 2001:4f8:3:d::61"


**Usage:**  

	Basic usage:
	
		IPDefragUtil input_file -o output_file [-d frag_ids] [-f bpf_filter] [-a] [-h] [-v]

	Options:

	    input_file      : Input pcap/pcapng file
	    -o output_file  : Output file. Output file type (pcap/pcapng) will match the input file type
	    -d frag_ids     : De-fragment only fragments that match this comma-separated list of IP IDs (for IPv4) or
	                      fragment IDs (for IPv6) in decimal format
	    -f bpf_filter   : De-fragment only fragments that match bpf_filter. Filter should be provided in Berkeley Packet Filter (BPF)
	                      syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'
	    -a              : Copy all packets (those who were de-fragmented and those who weren't) to output file
	    -v              : Displays the current version and exits
	    -h              : Displays this help message and exits
