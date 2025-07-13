# nids_blackhole.py
import subprocess
from scapy.all import sniff, IP

THRESHOLD = 10
counts = {}

def block_ip(ip):
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j DROP'])
    print(f"👎 Blackholed {ip}")

def monitor(pkt):
    if IP in pkt:
        src = pkt[IP].src
        counts[src] = counts.get(src, 0) + 1
        if counts[src] == THRESHOLD:
            block_ip(src)

if __name__ == "__main__":
    print("Starting NIDS...")
    sniff(prn=monitor, store=False)
