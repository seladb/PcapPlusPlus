PcapPlusPlus Coding Example - Break Pcap File To Streams
========================================================

This application is a simple example for packet parsing and working with pcap files. 
It takes a pcap file (example.pcap) and classifies all TCP/UDP packets into the streams they belong to (stream is also known as connection or flow). 
Then each stream is saved to a separate pcap file under the Output directory

Using the utility
-----------------
Just run the application (without any parameters). Please make sure example.pcap is in the same directory as the executable: 
	Pcap++Examples.BreakPcapFileToStreams