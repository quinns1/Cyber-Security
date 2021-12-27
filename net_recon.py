#!/usr/bin/python3

#Imports
import sys
from scapy.all import *
import os
import subprocess


def help():
    """
    Function to print help information to the terminal.
    """

    print('\n'+'-'*50)
    print('\nNet Recon - Help\n')
    print('-'*50)
    print('\nRequired parameters:')
    print('-i  |  --iface           Interface reconnaissance will be initiated on. Format should be -i <interface> or -iface <interface>')
    print('-p  |  --passive:        Launch passive network reconnaissance on interface specified by user (cannot be used with -a/--active)')
    print('-a  |  --active:         Launch active network reconnaissance on interface specified by user (cannot be used with -p/--passive)')
    print('Example usage: \'python3 net_recon.py -p -i enp0s3\' - Initiate passive reconnaissance on network interface enp0s3\n')
    print('-'*50+'\n')
    

def arp_filter(src_addresses):
    """
    Nested packet handler allows us to save packet information outside packet handler
    """

    def passive_pkt_handler(p):
        """
        Packet handler which saves the source IP & MAC of is-at ARP traffic or ARP replys
        """
        
        # Check if packet is-at (reply)
        if p[ARP].op == 2:
            
            src_mac =  p[Ether].src
            src_ip = p[ARP].psrc
            src = [src_ip, src_mac]

            if src not in src_addresses:
                # If we've not seen this IP/MAC combo before, save in src_addresses list & print
                src_addresses.append(src)
                print(src)

    return passive_pkt_handler


def passive_scan(nic):
    """
    Initiate passive scan
    Using Scapy sniff function: Sniff ARP messages and parse source IP and MAC address.
    """

    print('\nInitiating PASSIVE scan on interface \'{}\'.'.format(nic))
    print('Sniffing for ARP messages. \nListing source IP & MAC addresses in the format [ <Source IP>, <Source MAC> ]')
    print('\'Ctrl C\' to exit scan\n')

    addresses = []
    capture = sniff(iface=nic, prn=arp_filter(addresses), filter='arp')
    
    # print('\nPassive scan recieved the following IP/MACs ARP replys')
    # for a in addresses:
    #     print(a)


def active_recon(nic):
    """
    Get IP address of 'nic'
    Send ICMP request to all hosts on /24 network
    Detect if ICMP reply recieved
    """

    print('\nInitiating ACTIVE scan on interface \'{}\''.format(nic))
    print('Sending ICMP requests to all addresses on the same /24 subnet as interface \'{}\'\n'.format(nic))

    # Get IP address of interface 'nic'
    iface_ip = get_if_addr(nic)
    
    # Split address into list of octets
    split_ip = iface_ip.split('.')
    response_addresses = []
    for i in range(256):

        # Build IP address 
        new_ip = split_ip[0] + '.' + split_ip[1] + '.' +  split_ip[2] + '.' +  str(i) 
        if new_ip == iface_ip:
            # print('Skipping interface IP ', new_ip)
            continue
        # else :
            # print('Scanning IP: ', new_ip, end='')

        # Send ICMP to new_ip
        responses, unans = sr(IP(dst=new_ip)/ICMP(), timeout=0.05, verbose=False)

        # Check if any responses recieved
        if len(responses) == 0:
            #No response, do nothing
            # print('\t\t-\tNo response recieved')
            pass
        else:
            #ICMP response recieved. Save destination IP address
            response_addresses.append(new_ip)
            # print('\t\t-\tResponse recieved')

    print("\nRecieved responses on the following addresses:")
    for r in response_addresses:
        print(r)



def main(passed_args):
    """
    Vaidate input arguments
    Call scan function specified by the user
    """

    #Boolean True for active scan, False for passive scan
    active = False                                

    # Validate number of arguments passed       
    if not len(passed_args)  == 4:
        print('\nError: Incorrect number of arguments')
        help()
        return
    
    # Identify if passive/active scan
    if '-p' in passed_args or '--passive' in passed_args:
        active = False
    elif '-a' in passed_args or '--active' in passed_args:
        active = True
    else:
        print('\nError: Invalid Arguments - Passive/Active not specified')
        help()
        return
    
    # Parse Interface from args
    if '-i' in passed_args:
        i = passed_args.index('-i')
    elif '--iface' in passed_args:
        i = passed_args.index('--iface')
    else: 
        print('\nError: No interface specified')
        help()
        return

    try:
        i_face = passed_args[i+1]
    except IndexError:
        print('\nError: No interface specified')
        help()
        return

    # Validate interface given by pinging loopback address
    result = subprocess.run(['timeout', '0.1', 'ping', '-I', i_face, '0.0.0.0'], stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
    if not result.stderr == b'':
        print('\nError: Invalid interface chosen')
        # print(result.stderr)                              # Print stderr message for increased verbosity
        help()
        return

    # At this point we have validated the input arguments and identified what kind of scan we'll be performing
    if active:
        active_recon(i_face)
    else:
        passive_scan(i_face)


if __name__ == '__main__':
    main(sys.argv)
