#! /usr/bin/env python3

import scapy.all as scapy
import socket


def get_banner(ip, port):
    try:
        socket.setdefaulttimeout(0.5)
        sock = socket.socket()
        sock.connect((ip, port))
        banner = sock.recv(1024)
        try:
            banner = str(banner).rsplit("b'")[1]
        except IndexError:
            banner = str(banner).rsplit('b"')[1]
        return banner.rsplit("\\donation")[0].rsplit("\\r")[0]
    except socket.timeout:
        return "No Banner"


class SCAN_PORT:

    def __init__(self, interface, ip):
        self.interface = interface
        self.ip = ip

    def start_scan(self):
        ports = range(0, 1024)

        open_ports = []

        for port in ports:
            syn_packet = scapy.IP(dst=self.ip)/scapy.TCP(dport=port, flags='S')
            response = scapy.sr1(syn_packet, verbose=0, timeout=0.5, iface=self.interface)

            print("\r[+] Scanning Port: " + str(port), end="")

            if response is not None and response.haslayer(scapy.TCP):
                if response.getlayer(scapy.TCP).flags == 'SA':
                    banner = get_banner(self.ip, port)
                    open_ports.append({'port': port, 'banner': banner})

                rst_packet = scapy.IP(dst=self.ip)/scapy.TCP(dport=response.sport, flags='R')
                scapy.sr(rst_packet, verbose=0, timeout=0.5, iface=self.interface)

        return open_ports

    def print_data(self, data):

        if len(data) == 0:
            print("\n[-] Oops! No Open Ports found.")

        else:
            print("\n[+] Scanned on Interface: " + self.interface)
            print("[+] Total number of Open Ports: {}".format(len(data)))

            print("_" * 40)
            print(" {0:^4} \t {1}".format("Port", "Version/Service"))
            print("-" * 40)

            for port in data:
                print(" {0:<4} \t {1}".format(port['port'], port['banner']))
