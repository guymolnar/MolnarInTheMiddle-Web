from scapy.all import *
from scapy.all import get_if_list
print(conf.ifaces)
answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.100.102.0/24"), timeout=2, verbose=0)

for sent, received in answered:
    print(f"{received.psrc} → {received.hwsrc}")