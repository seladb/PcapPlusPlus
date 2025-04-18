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
               PcapSearch [-h] [-v] [-n] [-r file_name] [-e extension_list] -d directory -s search_criteria
	Options:
            -d directory        : Input directory
            -n                  : Don't include sub-directories (default is include them)
            -s search_criteria  : Criteria to search in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'
            -r file_name        : Write a detailed search report to a file
            -e extension_list   : Set file extensions to search. The default is searching '.pcap' and '.pcapng' files.
                                  extension_list should be a comma-separated list of extensions, for example: pcap,net,dmp
            -v                  : Displays the current version and exists
            -h                  : Displays this help message and exits
