Pcap Splitter
=============

A utility for splitting a pcap file into smaller pcap files by a user-defined criteria:
- File-size - splits the pcap file to smaller pcap files, each file with a certain size defined by the user
- Packet-count - splits the pcap file to smaller pcap files, each with number of packets defined by the user
- Client-IP - splits the pcap file to smaller pcap files so each file contains all TCP/UDP connections initiated by a certain client-ip, for example: file#1 will contain connections initiated by 1.1.1.1, file#2 will contain 
  connections initiated by 1.2.3.4, and so on. The user can limit the number of output files, in this case multiple client-ips will be written to the same file. If the user doesn't set such limit - each file will contain 
  one client-ip
- Server-IP - splits the pcap file to smaller pcap files so each file contains all TCP/UDP connections to a certain server-ip, for example: file#1 will contain connections to 8.8.8.8, file#2 will contain connections 
  to 10.12.13.14, and so on. The user can limit the number of output files, in this case multiple server-ips will be written to the same file. If the user doesn't set such limit - each file will contain one server-ip
- Server-port - splits the pcap file to smaller pcap files so each file contains all TCP/UDP connections to a certain server port, for example: file#1 will contain all port 80 connections (HTTP), file#2 will contain
  all port 25 (SMTP) connections, and so on. The user can limit the number of output files, in this case connections to multiple server ports will be written to the same file. If the user doesn't set such limit - each file will
  contain connection to one server port only
- IP source and IP dest - splits the pcap file to smaller pcap files so each file contains all connections made between two IP addresses. The user can limit the number of output files, in this case multiple pairs of IP source
  and dest will be written to the same file. If the user doesn't set such limit - all connection of one pair of source and dest IP will be written to each file
- Connection - splits a pcap file to smaller pcap files by TCP/UDP connection meaning each connection will be written to a certain file. The user can limit the number of output files, in this case an equal number of connections will
  be written to the same file. If the user doesn't set such limit - each file will contain one connection
- BPF filter - splits the pcap file into two files: one that contains all packets matching the input BPF filter and the other one with the rest of the packets
- Round-robin - each packet read from the input file is written to a different output file in a round-robing manner
 
Remarks
-------
- Options 3-7 supports both IPv4 and IPV6
- Number of output files isn't limited, unless the user set such limit in options 3-7
- There is no limit on the size of the input file, the number of packets it contains or the number of connections it contains
- The user can also set a BPF filter to instruct the application to handle only packets filtered by the filter. The rest of the packets in the input file will be ignored
- In options 3-5 & 7 all packets which aren't UDP or TCP (hence don't belong to any connection) will be written to one output file, separate from the other output files (usually file#0)
- Works only on files of the pcap (TCPDUMP) format

Using the utility
-----------------
	Basic usage:
		PcapSplitter [-h] [-i filter] -f pcap_file -o output_dir -m split_method [-p split_param]

	Options:
		-f pcap_file    : Input pcap file name
		-o output_dir   : The directory where the output files shall be written
		-m split_method : The method to split with. Can take one of the following params:
						  'file-size'    - split files by size in bytes
						  'packet-count' - split files by packet count
						  'client-ip'    - split files by client IP, meaning all connections with
										   the same client IP will be in the same file
						  'server-ip'    - split files by server IP, meaning all connections with
										   the same server IP will be in the same file
						  'server-port'  - split files by server port, meaning all connections with
										   the same server port will be in the same file
						  'ip-src-dst'   - split files by IP src and dst (2-tuple), meaning all connections
										   with the same IPs will be in the same file
						  'connection'   - split files by connection (5-tuple), meaning all packets
										   of a connection will be in the same file
						  'bpf-filter'   - split file into two files: one that contains all packets
										   matching the given BPF filter (file #0) and one that contains
										   the rest of the packets (file #1)
						  'round-robin'  - split the file in a round-robin manner - each packet to a
										   different file
						  
		-p split-param  : The relevant parameter for the split method:
						  'method = file-size'    => split-param is the max size per file (in bytes).
													 split-param is required for this method
						  'method = packet-count' => split-param is the number of packet per file.
													 split-param is required for this method
						  'method = client-ip'    => split-param is max number of files to open.
													 If not provided the default is unlimited number of files
						  'method = server-ip'    => split-param is max number of files to open.
													 If not provided the default is unlimited number of files
						  'method = server-port'  => split-param is max number of files to open.
													 If not provided the default is unlimited number of files
						  'method = ip-src-dst'   => split-param is max number of files to open.
													 If not provided the default is unlimited number of files
						  'method = connection'   => split-param is max number of files to open.
													 If not provided the default is unlimited number of files
						  'method = bpf-filter'   => split-param is the BPF filter to match upon
						  'method = round-robin'  => split-param is number of files to round-robin packets between
		-i filter       : Apply a BPF filter, meaning only filtered packets will be counted in the split
		-h              : Displays this help message and exits);
