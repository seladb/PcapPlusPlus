TLS Fingerprinting
==================

This application demonstrates how to extract and use TLS fingerprinting data using PcapPlusPlus.
It processes packets from a pcap/pcapng file or from a live interface, looks for TLS ClientHello and/or ServerHello packets, extracts the TLS fingerprints out of them and writes them to an output file in a csv format (where 'tab' is the default separator since comma is used in the TLS fingerprint itself).

The user can choose whether to extract ClientHello TLS fingerprint (which is similar to [JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)), ServerHello TLS fingerprint (which is similar to [JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)), or both.

The application's output includes the following information about each packet:
- A string representation of the TLS fingerprint (for example: `771,4866-4867-4865-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2`)
- An MD5 representation of the TLS fingerprint
- TLS message type: ClientHello or ServerHello
- Source and dest IP addresses
- Source and dest TCP ports

Here is an example output file:

| TLS Fingerprint (MD5) | TLS Fingerprint | TLS Fingerprint type |IP Source | TCP Source Port | IP Dest | TCP Dest Port |
| --------------------- | --------------- | -------------------- | -------- | --------------- | ------- | ------------- |
| b246ccf5a502097ab57ba9bc5eed3a18 | 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-10-11-13-16-23-43-51-65281,29-23-24,0 | ClientHello | 1647:647:8b02:1d2e:c5ab:3f10:aead:1843 | 57493 | 7607:f8bf:4f05:e0b::2231 | 443 |
| 134c270d52dd3495d39878f76f646581 | 772,4865,51-43 | ServerHello | 192.168.0.2 | 443 | 192.168.0.1 | 57493 |

The application also prints to console general information that includes:
- Number of total packets processed
- Number of TLS ClientHello and/or ServerHello packets processed
- Number of unique TLS fingerprints found
- A table of the top 10 most common TLS fingerprints found in the capture file or live interface

Using the utility
-----------------

    TLSFingerprinting [-hvlcms] [-r input_file] [-i interface] [-o output_file_name] [-s separator] [-t tls_fp_type] [-e bpf_filter]

    Options:

        -r input_file       : Input pcap/pcapng file to analyze. Required argument for reading from file" << std::endl
        -i interface        : Use the specified interface. Can be interface name (e.g eth0) or IP address.
                              Required argument for capturing from live interface
        -o output_file_name : Output file name. This is a csv file (where 'tab' is the default separator)
                              which contains information about all of the TLS fingerprints found in the
                              capture file or live interface. It includes the TLS fingerprint itself
                              (raw string and MD5), IP addresses, TCP ports and SSL message type (ClientHello
                              or ServerHello). If this argument is not specified the output file name is the
                              name of capture file or the live interface and it is written to the current
                              directory ('.')
        -s separator        : The separator to use in the csv output file. Valid values are a single character
                              which is not alphanumeric and not one of the following: '.', ',', ':', '-'.
                              If this argument is not specified the default separator is 'tab' ('\\t')
        -t tls_fp_type      : Specify whether to calculate TLS fingerprints for ClientHello packets only ('ch'),
                              ServerHello packets only ('sh') or both ('ch_sh'). The only valid values are
                              'ch', 'sh', 'ch_sh'. If this argument is not specified the default value is
                              ClientHello ('ch')
        -e bpf_filter       : Apply a BPF filter to the capture file or live interface, meaning TLS fingerprint
                              will only be generated for the filtered packets
        -l                  : Print the list of interfaces and exit
        -v                  : Display the current version and exit
        -h                  : Display this help message and exit
