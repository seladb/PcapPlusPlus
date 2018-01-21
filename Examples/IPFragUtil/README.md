IPFragUtil
==========

A utility for splitting IP packets into fragmets. Both IPv4 and IPv6 packets are supported. The utility works only on pcap and pcapng files. 
It allows the user to choose the fragment size by which packets will be split by
and also allows to specify which packets will be split by setting a Berkeley Packet Filter (BPF) filter and/or specifying a list of IP IDs (for IPv4 packets only).
 

Using the utility
-----------------
**The must-have input params for this utility are:**  
- Input file (pcap or pcapng format)
- Output file, where fragments will be written to ('-o' flag)
- Fragment size by which packets will be split ('-s' flag). This number must be a multiple of 8, according to IPv4/IPv6 RFC

**Filtering packets:**  
If no filter is specified, the default is that all packets will be fragmented. Exceptions are non-IP packets and IP packets which their 
payload is smaller than requested fragment size.
The user can set two types of filters. Both types can be set together or each one separately:
- Berkeley Packet Filter (BPF) filter - all packets that match this filter will be fragmeneted ('-f' flag)
- For IPv4 packets only: a comma-separated list of IP IDs in decimal format. Packets matching one of these IP IDs will be fragmented ('-d' flag)

**Output:**  
Output file type will be identical to input file type. So for pcap file the output will be a pcap file, and same for pcapng.
The default is that only fragmeneted packets are written to output file, but the user may choose to copy also the packets 
that weren't fragmented to the output file (using '-a' flag).
In addition to the output file the utility outputs to console basic statistics about the process:  

	Summary:
	========
	Total packets read:                      100
	IPv4 packets read:                       50
	IPv6 packets read:                       10
	IPv4 packets match IP ID list:           4
	IP packets match BPF filter:             8
	IP packets smaller than fragment size:   46
	IPv4 packets fragmented:                 4
	IPv6 packets fragmented:                 4
	Total packets written to output file:    70 

**Usage examples:**  
Fragment all packets in mypcap.pcap to fragments size of 64B:  

	IPFragUtil mypcap.pcap -o output.pcap -s 64 
	
Fragment only IPv4 packets with IP ID of 12345, 12346 and 12347 to 128B fragments. Only these fragments will be written to output file:  

	IPFragUtil mypcap.pcap -o output.pcap -s 128 -d 12345,12346,12347

Fragment only packets with source address of 10.0.0.1 to 8B fragments. Only packets matching this filter will be written to output file:  

	IPFragUtil mypcap.pcap -o output.pcap -s 8 -f "ip src 10.0.0.1"
	
Fragment only packets with source address of 10.0.0.1 to 8B fragments. All packets in mypcap.pcapng will be writen to output file: both those
matching the filter (and fragmented) and those who don't:  

	IPFragUtil mypcap.pcapng -o output.pcapng -s 8 -f "src ip 10.0.0.1" -a

Fragment only IPv4 packets with source address of 10.0.0.1 and IP ID of 123 to 16B fragments. All packets in mypcap.pcapng will be writen to output file: both those
matching the filter (and fragmented) and those who don't:  

	IPFragUtil mypcap.pcapng -o output.pcapng -s 16 -f "src ip 10.0.0.1" -d 123 -a

Fragment only IPv6 packets with dest address of 2001:4f8:3:d::61 to 16B fragments:  

	IPFragUtil mypcap.pcap -o output.pcapng -s 16 -f "ip6 dst 2001:4f8:3:d::61"


**Usage:**  

	Basic usage:
	 
		IPFragUtil input_file -s frag_size -o output_file [-d ip_ids] [-f bpf_filter] [-a] [-h] [-v]

	Options:
		input_file      : Input pcap/pcapng file
		-s frag_size    : Size of each fragment
		-o output_file  : Output file. Output file type (pcap/pcapng) will match the input file type
		-d ip_ids       : Fragment only packets that match this comma-separated list of IP IDs in decmial format
		-f bpf_filter   : Fragment only packets that match bpf_filter. Filter should be provided in Berkeley Packet Filter (BPF)
		                  syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'
		-a              : Copy all packets (those who were fragmented and those who weren't) to output file
		-v              : Displays the current version and exits
		-h              : Displays this help message and exits

