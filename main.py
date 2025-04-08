import scapy.all as scapy

def scan(ip):
    """
    Scans the network for connected devices using the ARP protocol.
    """
    # Send an ARP request to find devices in the network
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Collect the information of the connected devices
    devices_list = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device_info)
    return devices_list

def print_result(devices_list):
    """
    Prints the IP and MAC addresses of the connected devices.
    """
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices_list:
        print(f"{device['ip']}\t\t{device['mac']}")

# Define the range of IP addresses to scan (adjust this range based on your network)
ip_range = "192.168.1.1/24"  # You can change this to your network range
devices = scan(ip_range)
print_result(devices)
