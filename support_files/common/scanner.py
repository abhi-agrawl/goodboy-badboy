#! usr/bin/env python3

import scapy.all as scapy
import requests


def get_vendor(mac):
    url = "https://api.maclookup.app/v1/macs/"

    request_url = "{0}{1}".format(url, mac)
    get_data = requests.get(request_url)

    try:
        vendor = get_data.json()['company']
    except KeyError:
        vendor = "Unknown Vendor"

    return vendor


def send_requests(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answer = scapy.srp(arp_request_broadcast,
                       timeout=3,
                       verbose=False,
                       iface=interface)[0]

    return answer


def print_function(targets, interface):
    print("[+] Scanned on Interface: {0}".format(interface))
    print("[+] Total number of hosts: {0}".format(len(targets)))

    print("_" * 70)
    print(" {0:^12} \t {1:^17}    {2}".format("IP", "MAC Address", "MAC Vendor / Hostname"))
    print("-" * 70)

    for target in targets:
        print(" {0:<12} \t {1:<17}   {2}".format(target['ip'], target['mac'], target['vendor']))


def start_scan(ip, interface):
    ips_data = send_requests(ip, interface)
    targets = []

    for ip_data in ips_data:
        mac = ip_data[1].hwsrc
        target_dict = {'ip': ip_data[1].psrc, 'mac': mac, 'vendor': get_vendor(mac)}
        targets.append(target_dict)

    return targets


class Scanner:

    def __init__(self, ip, interface, verbose):
        self.ip = ip
        self.interface = interface
        self.verbose = verbose
        print("\n[+] Initializing Network Scanner")

    def scan_network(self):

        if self.verbose == 'yes':
            print("[+] Scanning initiated...")

        scan_results = start_scan(self.ip, self.interface)
        scans = start_scan(self.ip, self.interface)

        for scan in scans:
            flag = True
            ip_check = scan['ip']
            for scan_result in scan_results:
                if ip_check == scan_result['ip']:
                    flag = False
            if flag:
                scan_results.append(scan)

        return scan_results

    def print_data(self, data):

        print("\n[+] Scanned IP Range: {0}".format(self.ip))
        print_function(data, self.interface)


class MACs:

    def __init__(self, ips, interface):
        self.ips = ips
        self.interface = interface

    def get_macs(self):
        networks = []

        for ip in self.ips:
            try:
                mac = send_requests(ip, self.interface)[0][1].hwsrc
                vendor = get_vendor(mac)
                networks.append({'ip': ip, 'mac': mac, 'vendor': vendor})
            except IndexError:
                print("\n[-] No device found! Check IP Address: {0}\n".format(ip))

        return networks

    def print_data(self, data):
        print_function(data, self.interface)
