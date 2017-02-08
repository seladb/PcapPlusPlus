ARP Spoofing - Visual Studio 2015 Example Project
=================================================

This is a solution and project already configured for working with PcapPlusPlus. You can compile and run the existing code or delete it and write you own code. 
All include paths, lib paths and linked libs are already set. This solution and project are also relocatable. You can copy/move them to wherever you want.
Before opening this solution, please make sure you run configure-windows-visual-studio.bat. It prepares PcapPlusPlusPropertySheet.props which contains paths to 
PcapPlusPlus location and other 3rd party components (such as WinPcap and pthreads-win32)

Using the utility
-----------------
Same as the ARP spoofing application but without the -i, -v and -g switches

	Basic usage:
		ArpSpoofing <INTERFACE_IP> <VICTIM_IP> <GATEWAY_IP>

	Options:
		INTERFACE_IP : Use the specified interface, identified by its IPv4 address
		VICTIM_IP    : The IPv4 address of the victim which will be spoofed
		GATEWAY_IP   : The gateway IPv4 address