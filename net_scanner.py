#!/usr/bin/env python3

# we need to check if the network interface that provided is up or not
import netifaces as netifaces
# we will create packets to scan for networks devices
import scapy.all as scapy
# to let the user enter information
import optparse
# to look for the MAC vendor/company
from mac_vendor_lookup import MacLookup, VendorNotFoundError
# not necessary, we just use it to clear the terminal before printing
import subprocess
# to run a regex check
import re


# here we provide the available options for the user
def get_input():
    reader = optparse.OptionParser()
    reader.add_option("-r", "--range", dest="ip_range", help="IP range to scan. Ex, 10.X.X.X/24, 192.168.X.X/24")
    reader.add_option("-i", "--interface", dest="iface", help="Network interface to use in scanning. Ex, eth0, wlan0")
    return reader


# here we check if the network interface exists
def interface_exists(interface):
    try:
        addr = netifaces.ifaddresses(interface)
        return netifaces.AF_INET in addr
    except ValueError:
        return False


# here we check if the user entered correct information to work on or not
def set_input():
    parser = get_input()
    options, args = parser.parse_args()
    # if he entered an interface
    if options.iface:
        # if that interface exists
        if interface_exists(options.iface):
            # if he entered an ip
            if options.ip_range:
                ipv4_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
                # if that ip in a correct format
                if ipv4_pattern.search(options.ip_range):
                    subprocess.call(["clear"])
                    print_results(scan(options.ip_range, options.iface))
                else:
                    print(parser.error("[-] Make sure to enter a correct IP range, use --help for more info"))
            else:
                print(parser.error("[-] PLease provide an IP, use --help for more info"))
        else:
            print(parser.error("[-] Interface is down or it does not exist."))
    else:
        print(parser.error("[-] Please provide an interface, use --help for more info"))


def scan(ip_to_scan, iface):
    # here we create an arp packet that will look for the IP
    arp_sends = scapy.ARP(pdst=ip_to_scan)
    # here we create an Ether frame, so we can transfer data in it, and the dst has to be ff:ff... so it looks for all
    # the devices not only one.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # we combine both packets
    whole_packet = broadcast / arp_sends
    # now we send the packet that we just created, and at the same time we return the answered devices list
    return scapy.srp(whole_packet, timeout=1, iface=iface, verbose=False)[0]


def print_results(packets_list):
    # print a nice interface
    print("\n" + str(len(packets_list)) + " devices are up\n_________________________________________________________"
                                          "__________________________________________________")
    print("IP{}MAC Address{}Vendor".format("\t\t\t\t", "\t\t\t\t"))
    print("-----------------------------------------------------------------------------------------------------------")
    # we get the mac vendors list
    mac_lookup = MacLookup()
    #  you can run the commented command below to update that list, but it will take extra time

    # mac_lookup.update_vendors()

    # just print the information
    for i in packets_list:
        print(i[1].psrc + "{}".format("\t\t\t") + i[1].hwsrc, end="\t\t\t")
        try:
            print(mac_lookup.lookup(i[1].hwsrc))
        except VendorNotFoundError:
            print("Unknown")

    print("\n")


set_input()
