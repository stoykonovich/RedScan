# RedScan
# Description:
RedScan is a python port scanner that can do both normal and syn scans, the normal mode grabs banners
# Usage: (for python version)
python3 redscan.py -t {the target IP} -l {the max port you want to scan} for normal mode
python3 redscan.py -s {the target IP} -l {the max port you want to scan} for syn mode
# Usage (for C version wich is a work in progress)
gcc redscan.c -o redscan
./redscan -t {the target IP}
# Disclaimer:
Please only use in permitted enviornments
