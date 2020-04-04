######################################################## 
# 
# Cassandra Shay
# Spring 2020
#
# Security tool: DHCP Attack Detection System
# Description: DHCP lister that reports and records: 
# timestamp, DHCP message type, client device hostname, 
# vendor, MAC address, and requested IP if applicable 
# within a broadcast domain
# 
########################################################

import sys, time, pandas, argparse
from datetime import datetime, timedelta
from scapy.all import sniff, Ether, DHCP

welcome= """DHCP Attack Dectection System Proof of Concept.
DHCP listener that reports and records: timestamp, DHCP message type,
client device hostname, vendor, MAC address, and requested IP if applicable
within a broadcast domain. Press Ctrl + C to exit."""
pizazz="The quieter you become, the more you are able to hear."
parser = argparse.ArgumentParser(prog='dhcp-listen.py',
                                 usage='%(prog)s -f file path -i interface name',
                                 description=welcome,
                                 epilog=pizazz)
parser.add_argument('-f','--log_file',required=True, help='define output file to save results of stdout. i.e. "DHCP_capture.txt"')
parser.add_argument('-i','--interface',required=True, help='define the interface on which to capture traffic. i.e "eth0,wlan0,wlp2s0"')
parser.parse_args()
args=parser.parse_args()
log_file=args.log_file
interface=args.interface


class Device():
    def __init__(self, name="", MAC=""):
	self.name= name
	self.MAC= MAC

class Packet():
    def __init__(self, name="", MAC="", oui="", vendor="", message_type="", 
                 requested_ip="", subnet_mask="", gateway="", DNS=""):
        self.name= name
        self.MAC= MAC
        self.oui= oui
        self.vendor= vendor
        self.message_type= message_type
        self.requested_ip= requested_ip
        self.subnet_mask= subnet_mask
        self.gateway= gateway
        self.DNS= DNS

# Message types
message_type = {
	"1" : "Discover",
	"2" : "Offer",
	"3" : "Request",
	"4" : "Decline",
	"5" : "ACK",
	"6" : "NAK",
	"7" : "Release",
	"8" : "Inform"}

# create local oui to vendor map from csv
# pulled from http://api.macvendors.com 
oui_map= pandas.read_csv('macaddress.io-db.csv', 
	usecols=["oui", "companyName"])

# Track seen devices
all_devices= []


def extract_data(traffic,oui_map):
    hostname="Unknown"
    MAC_addr= traffic[Ether][0].src.upper()
    oui_id= MAC_addr[0:8]
    vend= "unknown"
    request_addr= "unavailable"
    subnet= "unavailable"
    gw= "unavailable"
    DNS_addr= "unavailable"
	
    # when DHCP packet found find message type, and hostname
    # search DHCP options for message type, requested IP address, 
    # hostname, subnet mask, router, DNS
    for info in traffic[0][DHCP].options:	
	if isinstance(info,tuple):

	    # if reg key value pair
            if len(info)== 2:
		option,value= info

	    # key value pair with two values		
	    else:
	        option, value, alt_value= info

	    if option == "message-type": message= str(value)
	    if option == "requested_addr": request_addr= str(value)
	    if option == "hostname": hostname= value
	    if option == "subnet_mask": subnet= value
	    if option == "router": gw= value
	    if option == "name_server": DNS_addr= value, alt_value

    vend= oui_lookup(oui_map,oui_id)
    packet=Packet(name=hostname,MAC=MAC_addr,oui=oui_id, vendor=vend, message_type=message,
                  requested_ip=request_addr,subnet_mask=subnet,gateway=gw,DNS=DNS_addr)
    return packet


def track_device(packet, all_devices):
    # create and append device to all_devices if not previously seen
    for dev in all_devices:
        if not dev.MAC == MAC_addr:
            device= Device(name=packet.name, MAC=packet.MAC)
            all_devices.append(device)

    return all_devices


def is_server(packet, dhcp_message):
    # overwrite hostname if the device is DHCP_server
    if (packet.message_type == list(dhcp_message.keys())
            [list(dhcp_message.values()).index("Offer")] or
            packet.message_type == list(dhcp_message.keys())
            [list(dhcp_message.values()).index("ACK")] or
            packet.message_type == list(dhcp_message.keys())
            [list(dhcp_message.values()).index("NAK")]):
        return True
    else:
        return False
    


def oui_lookup(oui_map, oui_id):
    # look up vendor in local oui map
    # if the OUI is not a known entry in the csv, 
    # the vendor will be reported as: "Series([], Name: companyName, dtype: object"
    vendor= oui_map.loc[oui_map['oui'].isin([oui_id])]['companyName']
    for val in vendor.values:
	vendor= val

    return vendor


def format_data(packet,dhcp_message,time):
    # Format data based on message type 
    # if message is type Request, print IP info too
    if (packet.message_type == list(dhcp_message.keys())
        [list(dhcp_message.values()).index("Request")] 
        and packet.requested_ip is not "unavailable"):
        dhcp_info= "{}: {} {} {} ({}) requested IP: {}".format(
                    time, dhcp_message[packet.message_type], packet.name, 
                    packet.MAC, packet.vendor, packet.requested_ip)

    # if message is type ACK, print subnet mask, gateway, and DNS info too
    elif( packet.message_type== list(dhcp_message.keys())
        [list(dhcp_message.values()).index("ACK")]):
        dhcp_info= "{}: {} {} {} ({})\nsubnet: {} default_GW: {} DNS: {}".format(
                    time, dhcp_message[packet.message_type], packet.name, 
                    packet.MAC,	packet.vendor, packet.subnet_mask, packet.gateway, packet.DNS)		

    else:
        dhcp_info= "{}: {} {} {} ({})".format(
                    time, dhcp_message[packet.message_type], 
                    packet.name, packet.MAC, packet.vendor)

    return dhcp_info


def log(log_file, info):
    # log
    write_to= open(log_file, "a" )
    write_to.write(info + "\n")
    write_to.close()




print "Listening on interface {}\nLogging to {}".format(interface, log_file)


while True:
        try:
            current_time= datetime.now()

            # listen on the interface for DHCP traffic
            traffic= sniff(iface=interface, filter="port 67 or port 68", count=1)
            dhcp_packet= extract_data(traffic,oui_map)
            
            # Keep track of all seen devices
            all_devices= track_device(dhcp_packet,all_devices)

            if is_server(dhcp_packet,message_type):
                dhcp_packet.name= "DHCP server"

            #format data
            dhcp_info= format_data(dhcp_packet, message_type, current_time)

            # "real time" display to terminal
            print dhcp_info

            #log
            log(log_file, dhcp_info)

        except KeyboardInterrupt:
            break
        except:
            break

sys.exit()
