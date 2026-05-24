#!/usr/bin/env python3

import sys
import socket
import subprocess
import time
import argparse
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1
from scapy.all import send
from concurrent.futures import ThreadPoolExecutor

args = argparse.ArgumentParser(add_help=False)
args.add_argument("-t", type=str, required=False)
args.add_argument("-l", required=False, type=int)
args.add_argument("-s", required=False, type=str)
args.add_argument("-h", required=False, action="store_true")
ex_args = args.parse_args()
target = ex_args.t
target1 = ex_args.s
help1 = ex_args.h
min_port = 1
max_port = ex_args.l

banner = (r"""
=============================================
    ____           _______                
   / __ \___  ____/ / ___/_________ _____ 
  / /_/ / _ \/ __  /\__ \/ ___/ __ `/ __ \
 / _, _/  __/ /_/ /___/ / /__/ /_/ / / / /
/_/ |_|\___/\__,_//____/\___/\__,_/_/ /_/ 
                                          
=============================================
""")

print(f"\033[31m{banner}\033[0m")

print("[+] welcome to RedScan")
time.sleep(1)

def normal_scan(target):
    print(f"[+] scanning {target}")
    def pinging(target):
        try:
            cmd = f"ping -c 1 {target}"
            call = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if call == 0:
                print("[+] target is alive")
            else:
                print("[-] target seems to be down")
                sys.exit()
        except KeyboardInterrupt:
            sys.exit()
    pinging(target)
    def scanning(target, min_port, max_port):
        for ports in range(min_port, max_port + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                con = s.connect_ex((target, ports))
                if con == 0:
                    print(f"[+] port {ports} is open")
                else:
                    pass
            except ConnectionRefusedError:
                pass
            except KeyboardInterrupt:
                sys.exit()
            finally:
                s.close()
    with ThreadPoolExecutor(max_workers=100) as executor:
        scanning(target, min_port, max_port)
    def services(target, min_port, max_port):
        for ports in range(min_port, max_port + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target, ports))
                banner = s.recv(1024).decode().strip()
                if banner:
                    print(f"[+] {banner} detected")
            except ConnectionRefusedError:
                pass
            except TimeoutError:
                pass
            except KeyboardInterrupt:
                sys.exit()
            finally:
                s.close()
    with ThreadPoolExecutor(max_workers=100) as executor:
        services(target, min_port, max_port)
if target:
    normal_scan(target)

def syn_scan(target):
    print(f"[+] scanning {target}")
    def pinging1(target1):
        try:
            cmd1 = f"ping -c 1 {target1}"
            response1 = subprocess.call(cmd1, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if response1 == 0:
                print("[+] target is alive")
            else:
                print(f"[-] target seems to be down")
                sys.exit()
        except KeyboardInterrupt:
            sys.exit()
    pinging1(target)
    def scanning2(target1, min_port, max_port):
        for ports in range(min_port, max_port + 1):
            try:
                packet = (IP(dst=target1) / TCP(dport=ports, flags="S"))
                response = sr1(packet, timeout=2, verbose=0)
                if response[TCP].flags == 0x12:
                    print(f"[+] port {ports} is open")
                if response is None:
                    pass
                elif response[TCP].flags == 0x14:
                    pass
                send(IP(dst=target1) / TCP(dport=ports, flags="R"), verbose=0)
            except KeyboardInterrupt:
                sys.exit()
    with ThreadPoolExecutor(max_workers=100) as executor:
        scanning2(target, min_port, max_port)
if target1:
    syn_scan(target1)

if help1:
    print("""
    
   ======================================================================================= 
    -t to specify target for normal scan (normal scan detects services, syn scan does not
   =======================================================================================  
    -s for syn scan, only ports, no service detection yet
   =======================================================================================
    -l to specify the amount of ports to scan
   =======================================================================================
    
    """)