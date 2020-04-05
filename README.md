# DHCP-Listener
DHCP attack detection system proof of concept. Capture and analyze DHCP traffic.


About
____________________________________________________________________________
The Dynamic Host Configuration Protocol (DHCP) is insecure and introduces an additional attack vector to the LAN. An analysis of DHCP traffic allows an eavesdropper to obtain the configuration information of devices within a broadcast domain. The Python programming language has several libraries that make packet capture and analysis possible.

This security tool was developed to monitor DHCP traffic and detect DHCP attacks. The tool is written in Python and utilizes the scapy library to filter, collect, and examine DHCP packets.
The tool reports data on the timestamp, DHCP message type, device hostname, MAC address, and vendor, and, if applicable, the requested IP address. This information is displayed to the
terminal live and written to a log file. From the log file, it is possible to map the exchange between servers and clients and see how it changes based on various conditions. The tool can detect anomalous and malicious DHCP activity.

The tool exploits the insecure nature of DHCP traffic and collects as much interesting information as possible. The Python language in combination with the scapy library allows
for packet capture and inspection. The tool passively listens for DHCP traffic. Once a packet is found, the tool searches through its contents and extracts the DHCP message type, the
source device’s hostname, MAC address, and requested IP if applicable. With knowledge of the source device’s MAC address, the device’s vendor can be determined. All acquired device information is sent to the terminal and written to a log file for later use.


Usage
____________________________________________________________________________
Because of its convenience, DHCPv4 is a widely implemented protocol that operates on the majority of IPV4 networks. DHCP offers an automated way for clients to obtain an IP address, subnet mask, default gateway, and DNS information without administrator intervention. This tool can be run on any network configured with DHCPv4 to report information on DHCP servers and clients operating on that broadcast domain.

The insecure nature of DHCP leaves it vulnerable to various attacks: eavesdropping, starvation, masquerading, and man-in-the-middle. The tool collects and reports information on devices operating within a broadcast domain. With this information, the script can detect and report on various DHCP attacks in progress. A sudden high volume of DISCOVER and REQUEST messages tip off a starvation attack. Similarly, examination of the subnet mask, default gateway, and DNS information being provide to clients would alert admins of a rouge server, or man-in-the-middle in progress.

Alternatively, this information enables an adversary to build profiles on clients containing the devices hostname, MAC address, vendor, and potentially their IP address. Using these profiles, an adversary can target specific users, and determine device-specific vulnerabilities based on the manufacturer. They could also target the DHCP server by performing a starvation attack. With the data provided by this tool, an adversary could also launch a masquerading attack
where it pretends to be a DHCP server and hands out illegitimate configuration parameters to clients. A successful masquerading attack enables adversaries to man-in-the-middle
clients. By passing their IP addresses in place of the legitimate gateway IP address they can redirect traffic destined to an external network to themselves.

This tool can be run on any network configured with DHCPv4 to report information on DHCP
servers and clients operating on that broadcast domain.


Installation/Step up
____________________________________________________________________________
Required libraries include sys, time, pandas, argparse, and scapy. 
If you are missing any of these libraries, simply use pip to install them (ex. pip install scapy)

Required files include macaddress.io-db.csv originally pulled from https://macvendors.com. 
Place this file in the same directory as this script. 

To use the script follow the usage guide described with the -h or --help option.
Ex: python dhcp-listen.py -f DHCP_capture.txt -i wlp2s0


Special note
____________________________________________________________________________
The current logical execution of the tool leads to the potential loss of DHCP packets. After a DHCP packet is captured, the tool executes a process that extracts valuable information from the packet. During the analysis process, the tool briefly stops listening for DHCP traffic. The analysis process takes an average of 4.012 nanoseconds. If any DHCP traffic were to be transmitted during this time, it would go unseen. 

To remedy this, an new implementation would use the multiprocessing library to enable the capture and analyze functionality to be executed simultaneously. Concurrent execution allows for continuous packet capture, and live analysis and output to the terminal.


Tips
____________________________________________________________________________
How to find your interface names.
Linux: use either ip -a or ifconfig in the terminal
Windows: use ipconfig in command prompt
