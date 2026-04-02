from scapy.all import *
from scapy.layers.l2 import Ether


NOISE = {
    "_tcp.lan", "a2z.com", "aaplimg.com", "adblockplus.org",
    "agkn.com", "akamai.net", "akamaiedge.net", "akadns.net",
    "amazon-adsystem.com", "ampproject.org", "app-analytics-services.com",
    "app-measurement.com", "apple-dns.net", "apple.com", "appsflyersdk.com",
    "amazonaws.com", "byteglb.com", "byteoversea.net",
    "cdn77.org", "cdninstagram.com", "clinch.co", "cloudfront.net",
    "datadoghq.com", "doubleclick.net", "exelator.com", "exp-tas.com",
    "fastly-edge.com", "fastly.net", "fbcdn.net", "fbsbx.com",
    "gcdn.co", "githubassets.com", "githubusercontent.com", "google.com",
    "googleadservices.com", "googleapis.com", "googletagmanager.com",
    "googleusercontent.com", "gstatic.com", "icloud.com", "local.",
    "media-amazon.com", "mookie1.com", "msftconnecttest.com",
    "msftncsi.com", "napps-1.com", "onetrust.com", "onetrust.io",
    "sc-cdn.net", "sc-gw.com", "snapkit.com",
    "ssl-images-amazon.com", "static.microsoft", "steamserver.net", "steamstatic.com",
    "tiktokcdn-eu.com", "tiktokcdn-us.com", "tiktokv.com",
    "ttdns2.com", "vscode-cdn.net", "windowsupdate.com", "wpad.lan",
    "ytimg.com"
}

def forward_packet(packet, devices, ip_to_mac, gateway_mac, my_mac, blacklisted):
    if not packet.haslayer(Ether):
        return

    if packet[Ether].src in blacklisted:
        return

    if packet[Ether].src in devices:
        if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].dport == 53 and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode()
            parts = domain.rstrip(".").split(".")
            if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "edu", "ac"}:
                root = ".".join(parts[-3:])
            else:
                root = ".".join(parts[-2:])
            if root not in NOISE:
                info = devices[packet[Ether].src]
                if info['name'] == "Unknown":
                    print(f"Unknown ({packet[Ether].src}) -> {root}")
                else:
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

def start_forwarding(devices, ip_to_mac, gateway_mac, my_mac, blacklisted):
    sniff(
        filter="not arp",
        prn=lambda pkt: forward_packet(pkt, devices, ip_to_mac, gateway_mac, my_mac, blacklisted),
        store=0
    )
