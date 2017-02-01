PcapPlusPlus Coding Example - Packet Parsing
============================================

This application is a short guide for parsing packets using Pcap++ and Packet++. 
The application reads a file containing raw packet data in hex format (UdpPacket.dat), converts it into RawPacket object, parses it into a Packet object and then queries the packet for all sorts of data (protocols, IPs, etc.)

Using the utility
-----------------
Just run the application (without any parameters). Please make sure UdpPacket.dat is in the same directory as the executable: 
	Pcap++Examples.PacketParsing