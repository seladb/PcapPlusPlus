ICMP File Transfer
==================

This utility demonstrates how to transfer files between 2 machines using only ICMP messages. The basic idea is to use the data part of ICMP messages to transfer chunks of the file between the machines.
You can read more about it here:
http://www.unixist.com/security/data-transfer-over-icmp/index.html

When is it needed?
------------------
Mostly in cases you don't have a standard file-transfer access between machines. Sometimes it's because of security reasons, sometimes for other reasons. But in many of these cases ICMP (ping requests/replies) is enabled and not blocked.
So it's possible to use ICMP echo (ping) messages to create a file transfer capability between thses machines. Of course this method doesn't have the speed and reliability of standard file-transfer protocols (such as SMB),
but it can provide a basic file transfer capability in places you have no other choice.

How does it work?
-----------------
ICMP echo (ping) request and response have the following structure:

    |  Byte 1  |  Byte 2  |  Byte 3  |  Byte 4  |
    +----------+----------+----------+----------+
    |   Type   |   Code   | ICMP header checksum|
    +----------+----------+---------------------+
    |     ICMP ID         |      Sequence       |
    +---------------------+---------------------+
    |           Timestamp (2 higher bytes)      |
    +-------------------------------------------+
    |           Timestamp (2 lower bytes)       |
    +-------------------------------------------+
    |                                           |
    |                 Data...                   |
    |                                           |
    +-------------------------------------------+

As you can see it has a data part which is a collection of bytes that is virtually unlimited with size (up to the size of the packet of course).
This data part can be used to transfer chunks of the file. If you send multiple ICMP echo (ping) requests you can transfer the whole file

ICMP file transfer implementation in PcapPlusPlus
-------------------------------------------------
This utility in PcapPlusPlus has 2 parts:
- Pitcher - which sends ICMP echo (ping) requests to the catcher with the relevant data
- Catcher - which receives ICMP echo (ping) requests from the pitcher and sends back ICMP echo (ping) replies

In most implementations I came across on the Internet a pitcher-like utility was always used for sending the file and a catcher-like utility was always used for receiving the file.
This implementation is unique in that both pitcher and catcher can be configured to send files or receive files. So you can either send a file from the pitcher to the catcher 
or vice versa (send a file from the catcher to the pitcher).
when can this feature be useful? for cases where one of the machines can only reply to ICMP requests but not initiate ICMP requests to the other side. 
For example: if one of the machines is in a closed network where you can only access it from outside but you cannot access the outside from within that network.
In this case you can put the pitcher in the outside network and configure it to receive files, and put the catcher in the closed network and configure it to send files.
Here you have a way to copy files from the closed network to the outside world.

So how does file transfer through ICMP works?

Sending files from pitcher to catcher
-------------------------------------
The protocol is as follows:
- Pitcher sends a ICMP echo (ping) request to the catcher with the filename in the data part of the request
- It awaits for a response from the catcher. If it doesn't arrive it keeps sending these requests periodically until it gets an answer
- The catcher gets the request and extracts the name of the file that should be sent. It then sends the pitcher an ICMP reply that acts like an "ack" message to signal the pitcher it got the filename and ready to start receiving the file content
- Then the pitcher starts sending ICMP echo (ping) requests, each one containing a chunk of the file data. Each request have an ICMP ID subsequent to the ID of the message before it. That way the catcher can identify if messages get lost. The data chunk is sent in the data part of the request
- The catcher gets these requests, verifies it didn't miss any message and writes the data to a file
- After the pitcher finished sending the file, it sends another ICMP echo (ping) request stating file content was fully sent
- The catcher gets this message and closes the file

Sending files from catcher to pitcher
-------------------------------------
The situation here is a little bit more complicated as the catcher cannot instantiate ICMP requests, it has to wait for ICMP requests coming from the pitcher and reply to them:
- Pitcher sends an ICMP echo (ping) request to the catcher asking it to start file transfer. It'll keep sending these requests periodically until the catcher answers
- Catcher gets the request and sends back an ICMP echo (ping) reply containing the filename in the data part of the reply
- The pitcher gets this reply and knows the name of the file that should be sent
- Then the pitcher starts sending ICMP echo (ping) requests asking the catcher for the file content
- The catcher answers each request with an ICMP echo (ping) reply containing a chunk of the file in the data part of the reply
- The pitcher gets these replies, extracts the file data chunk and writes it to a file
- When the catcher finishes sending all file content it send an ICMP echo (ping) reply with a special message type stating file content was fully sent
- The pitcher gets this message and closes the file

Using the utility
-----------------
    Pitcher:  
        Basic usage:  
            IcmpFileTransfer-pitcher [-h] [-l] -i pitcher_interface -d catcher_ip -s file_path -r [-p messages_per_sec] [-b block_size]
        Options:
            -i pitcher_interface : The pitcher interface to use. Can be interface name (e.g eth0) or interface IPv4 address
            -d catcher_ip        : Catcher IPv4 address
            -s file_path         : Configure the pitcher to send a file to the catcher. file_path is the path of the file (cannot be set together with -r switch)
            -r                   : Configure the pitcher to receive a file from the catcher (cannot be set together with -s switch)
            -p messages_per_sec  : The file transfer speed between the pitcher and the catcher can be configured to X messages per second by this parameter. It's good for cases
				                   where the network between the pitcher and the catcher isn't reliable enough and messages transferred too fast get lost.
				                   This parameter is set only in the pitcher as the pitcher is the initiator of the ICMP requests and it's the one setting the pace.
            -b block_size        : Set the size of data chunk sent in each ICMP message (in bytes). The default is 1400 bytes. Relevant only in send file mode (when -s is set)
            -l                   : Print the list of interfaces and exit the program
            -h                   : Display help screen and exit the program
				
    Catcher:
        Basic usage: 
            IcmpFileTransfer-catcher [-h] [-l] -i catcher_interface -d pitcher_ip -s file_path -r [-b block_size]
        Options:
            -i catcher_interface : The catcher interface to use. Can be interface name (e.g eth0) or interface IPv4 address
            -d pitcher_ip        : Pitcher IPv4 address
            -s file_path         : Configure the catcher to send a file to the pitcher. file_path is the path of the file (cannot be set together with -r switch)
            -r                   : Configure the catcher to receive a file from the pitcher (cannot be set together with -s switch)
            -b block_size        : Set the size of data chunk sent in each ICMP message (in bytes). The default is 1400 bytes. Relevant only in send file mode (when -s is set)
            -l                   : Print the list of interfaces and exit the program
            -h                   : Display help screen and exit the program

Limitations
-----------
- Currently supports ICMPv4 only, ICMPv6 is not supported
- Only one file can be sent each time
