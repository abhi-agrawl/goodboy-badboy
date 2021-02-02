#! /usr/bin/env python3

from support_files import common, good
from random import randint as random
from datetime import datetime
import os
import subprocess
import configparser

ROUTER = {}
IP = ""
WHICH_BOY = ""
INTERFACE = ""
SPECIFIC_TARGETS = []
VERBOSE = ""
LOG_FILE = open("logs/{0}.txt".format(datetime.now().strftime("%d-%m-%Y")), 'at')
DT_FORMAT = "%H:%M:%S"
PORT_SCAN = ''
CHECK_PORT_ONLINE = ''
IDS = ''
BAD_ARGUMENTS = ''


def get_arguments():
    global IP, ROUTER, INTERFACE, SPECIFIC_TARGETS, WHICH_BOY, VERBOSE
    global PORT_SCAN, CHECK_PORT_ONLINE, IDS
    global BAD_ARGUMENTS

    config = configparser.ConfigParser()
    config.read('configuration.ini')

    common_part = config['COMMON']
    good_boy = config['GOOD']
    BAD_ARGUMENTS = config['BAD']

    ROUTER['ip'] = common_part['router_ip']
    ROUTER['netmask'] = common_part['netmask']
    IP = "{0}/{1}".format(ROUTER['ip'], ROUTER['netmask'])
    WHICH_BOY = common_part['which_boy']
    INTERFACE = common_part['interface']
    SPECIFIC_TARGETS = common_part['specific_targets'].split(',')
    VERBOSE = common_part['verbose']

    PORT_SCAN = good_boy['port_scanner']
    CHECK_PORT_ONLINE = good_boy['check_cve']
    IDS = good_boy['ids']


def do_arp(target, location, report_file):
    arp_spoofer = common.ARPAttack(INTERFACE, target, ROUTER, LOG_FILE, VERBOSE, report_file)
    packets_count = arp_spoofer.start_arp(location, WHICH_BOY, BAD_ARGUMENTS)
    return packets_count


def start_port_scan(ip):
    print("\n\n[+] Port Scanning Initiated...")

    LOG_FILE.write("\n[{0}] Port Scanning Initiated".format(datetime.now().strftime(DT_FORMAT)))

    port_scan = good.SCAN_PORT(INTERFACE, ip)
    open_port = port_scan.start_scan()

    if VERBOSE == 'yes':
        port_scan.print_data(open_port)

    return open_port


def check_cve_details(open_ports):
    if VERBOSE == 'yes':
        print("\n[*] Checking for vulnerability...")

    LOG_FILE.write("\n[{0}] Checking for vulnerabilities".format(datetime.now().strftime(DT_FORMAT)))

    cve = good.Check_CVE_Details(open_ports, VERBOSE)
    cve_details = cve.start_check()

    return cve_details


def scan_port(target, report_file):
    open_ports = start_port_scan(target['ip'])

    report_file.write("\n[{0}] Open Ports: {1}".format(datetime.now().strftime(DT_FORMAT),
                                                       open_ports))

    if CHECK_PORT_ONLINE == 'yes' and len(open_ports) != 0:
        cve_details = check_cve_details(open_ports)

        for i in range(len(open_ports)):

            if type(cve_details[i][0]) is dict:
                report_file.write("\n\n[{0}] CVE Details : {1}"
                                  .format(datetime.now().strftime(DT_FORMAT),
                                          open_ports[i]['banner']))
                for j in range(len(cve_details[i])):
                    report_file.write("\n[{0}] {1}".format(datetime.now().strftime(DT_FORMAT),
                                                           cve_details[i][j]))


def main():

    try:
        os.mkdir("logs")
        os.mkdir("reports")
    except FileExistsError:
        pass

    try:
        global ROUTER

        print("[+] Initializing GoodBoy BadBoy Program...")
        LOG_FILE.write("[{0}] Initializing GoodBoy BadBoy Program...".format(datetime.now().strftime(DT_FORMAT)))

        common_obj = common.Main(ROUTER, INTERFACE, SPECIFIC_TARGETS, VERBOSE, LOG_FILE)
        networks, ROUTER = common_obj.get_targets_info()

        LOG_FILE.write("\n[{0}] Scan Results: {1}".format(datetime.now().strftime(DT_FORMAT), networks))

        if IDS == 'yes' or WHICH_BOY == 'B':
            for i in range(2):
                subprocess.call("sudo sysctl -w net.ipv4.ip_forward=1",
                                shell=True,
                                stderr=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL)
            print("\n\n[+] Packet Forward is Enabled.")

        while len(networks) != 0:

            target = networks[random(0, len(networks) - 1)]
            networks.remove(target)

            if target['ip'] != ROUTER['ip']:

                print("\n\n[+] Working on IP: {0}".format(target['ip']))

                file_name = target['ip'].replace(".", "-")
                location = "reports/{0}".format(file_name)

                try:
                    os.mkdir(location)
                except FileExistsError:
                    pass

                report_file = open("{0}/{1}.txt".format(location, datetime.now().strftime("%d-%m-%Y")), 'at')
                report_file.write("[{0}] Target Details -> IP: {1}, MAC: {2}, VENDOR: {3}"
                                  .format(datetime.now().strftime(DT_FORMAT),
                                          target['ip'],
                                          target['mac'],
                                          target['vendor']))

                LOG_FILE.write("\n[{0}] Working on: {1}".format(datetime.now().strftime(DT_FORMAT), target))

                if WHICH_BOY == 'G':
                    print("[+] Initializing GoodBoy Program.")
                    report_file.write(
                        "\n[{0}] Initializing GoodBoy Program.".format(datetime.now().strftime(DT_FORMAT)))

                    if PORT_SCAN == 'yes':
                        scan_port(target, report_file)

                if IDS == 'yes' or WHICH_BOY == 'B':
                    packets_sent = do_arp(target, location, report_file)
                    report_file.write("\n[{0}] Total ARP Packets Sent: {1}"
                                      .format(datetime.now().strftime(DT_FORMAT), packets_sent))
                    if WHICH_BOY == 'B':
                        print("[*] Please use kill command to stop all the bad_boy scripts.\n")

                report_file.close()

        print("[+] Program is shutting down...")
        LOG_FILE.write("\n[{0}] Program is shutting down...\n\n".format(datetime.now().strftime(DT_FORMAT)))

    except KeyboardInterrupt:
        print("[-] Program is stopped by the user...")
        LOG_FILE.write("\n[{0}] Program is stopped by the user...\n\n".format(datetime.now().strftime(DT_FORMAT)))

    except BaseException as e:
        print("[-] Error: {0}".format(e))
        LOG_FILE.write("\n[{0}] Error: {1}\n\n".format(datetime.now().strftime(DT_FORMAT), e))

    except KeyError:
        print("[-] Error! Misconfiguration, run the setup.py again!")
        LOG_FILE.write("\n[{0}] Error because of misconfiguration...\n\n".format(datetime.now().strftime(DT_FORMAT)))

    finally:
        LOG_FILE.close()


###################################################
if __name__ == "__main__":
    main()
