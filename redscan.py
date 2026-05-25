#!/usr/bin/env python3

import socket
import sys
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor
import argparse
from scapy.layers.inet import IP, TCP
from scapy.all import sr1

banner1 = (r"""
=============================================
    ____           _______                
   / __ \___  ____/ / ___/_________ _____ 
  / /_/ / _ \/ __  /\__ \/ ___/ __ `/ __ \
 / _, _/  __/ /_/ /___/ / /__/ /_/ / / / /
/_/ |_|\___/\__,_//____/\___/\__,_/_/ /_/ 

=============================================
""")

print(f"\033[31m{banner1}\033[0m")

print("[+] welcome to RedScan")
time.sleep(1)

args = argparse.ArgumentParser(add_help=False)
args.add_argument("-t", required=False, type=str)
args.add_argument("-s", required=False, type=str)
args.add_argument("-l", required=False, type=int)
args.add_argument("-h", required=False, action='store_true')
ex_args = args.parse_args()
target = ex_args.t
limit = ex_args.l
target1 = ex_args.s
help1 = ex_args.h

def normal_scan():
    print(f"[+] scanning {target}")
    def pinging(target):
        try:
            cmd = f"ping -4 -c 1 {target}"
            ex_cmd = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ex_cmd == 0:
                print(f"[+] {target} is alive")
            else:
                print(f"[-] {target} seems to be down")
        except KeyboardInterrupt:
            sys.exit()
    pinging(target)
    def scanning(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            res = s.connect_ex((target, port))
            if res == 0:
                print(f"[+] port {port} is open")
            else:
                pass
        except ConnectionRefusedError:
            pass
        except KeyboardInterrupt:
            sys.exit()
        finally:
            s.close()
    try:
         with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scanning, range(1, limit+1))
    except KeyboardInterrupt:
        sys.exit()
    def banner_scan(ports):
        try:
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.settimeout(1)
            s1.connect((target, ports))
            banner = s1.recv(1024).decode().strip()
            print(banner)
        except KeyboardInterrupt:
            sys.exit()
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(banner_scan, range(1, limit+1))
if target:
    normal_scan()
def syn_scan0():
    print(f"[+] scanning {target1}")
    def pinging1(syn_scan):
        try:
            cmd = f"ping -4 -c 1 {syn_scan}"
            res2 = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res2 == 0:
                print(f"[+] {syn_scan} is alive")
            else:
                print(f"[-] {target} seems to be down")
                sys.exit()
        except KeyboardInterrupt:
            sys.exit()
    pinging1(target1)
    def scanning2(port1):
        try:
            pkt = IP(dst=target1)/TCP(dport=port1, flags="S")
            response = sr1(pkt, timeout=2, verbose=0)
            if response is None:
                return "[-] filtered"
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    print(f"[+] port {port1} is open")
                    sr1(IP(dst=target1)/TCP(dport=port1, flags="R"), timeout=2, verbose=0)
                elif response[TCP].flags == 0x14:
                    pass
        except KeyboardInterrupt:
            sys.exit()
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(scanning2, range(1, limit+1))
if target1:
    syn_scan0()

if help1:
    print("""

   ======================================================================================= 
    -t to specify target for normal scan, with banner detection
   =======================================================================================  
    -s for syn scan, no banner detection, it's not anonymous
   =======================================================================================
    -l to specify the amount of ports to scan
   =======================================================================================

    """)