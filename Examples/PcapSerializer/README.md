Pcap Serializer
===============

This application parses packets using Packet++ and serializes them into a structured, machine-readable format (JSON, YAML or XML) using the serializers available in Common++.

Packets can be read from a capture file (pcap, pcapng or snoop) or captured from a live network interface. In live mode, capturing continues until ctrl-c is pressed or until the requested number of packets was captured.

The result is written to stdout (by default) or to a file (if specified). It can also serialize only the first X packets, or only packets matching a BPF filter.

Using the utility
-----------------
	Basic usage:
		PcapSerializer (-f input_file | -i interface) [-hvl] [-F format] [-o output_file] [-c packet_count] [-e bpf_filter]

	Options:
		-f input_file  : Read packets from a capture file (pcap, pcapng or snoop)
		-i interface   : Capture packets from a live interface. Can be an interface name (e.g eth0) or an
		                 interface IPv4 address. Capturing stops on ctrl-c or after packet_count packets
		-F format      : Output format: 'json', 'yaml' or 'xml' (default: json)
		-o output_file : Write the serialized output to a file (default output is stdout)
		-c packet_count: Serialize only the first packet_count packets
		-e bpf_filter  : Apply a BPF filter, meaning only filtered packets will be serialized
		-l             : Print the list of interfaces and exit
		-v             : Display the current version and exit
		-h             : Display this help message and exit

	Examples:
		Serialize the first 10 packets of a pcap file to JSON:
			PcapSerializer -f input.pcap -c 10

		Serialize all DNS packets of a pcapng file to a YAML file:
			PcapSerializer -f input.pcapng -e "udp port 53" -F yaml -o dns.yaml

		Capture 100 packets from a live interface and serialize them to XML:
			PcapSerializer -i eth0 -c 100 -F xml -o capture.xml
