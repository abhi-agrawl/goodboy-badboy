#! /usr/bin/env python3

from .scanner import Scanner
from .arp_spoofer import ARPAttack
from .scanner import MACs
from datetime import datetime
import sys


def scan_network(router, interface, log_file, verbose):
    ip = "{0}/{1}".format(router['ip'], router['netmask'])

    scan_net = Scanner(ip, interface, verbose)
    log_file.write("\n[{0}] Initializing Network Scanner".format(datetime.now().strftime("%H:%M:%S")))

    scan_results = scan_net.scan_network()

    if verbose == 'yes':
        scan_net.print_data(scan_results)

    return scan_results


def get_router_mac(verbose, router, interface, log_file, dt_format):
    if verbose == 'yes':
        print("\n[+] Getting MAC Address for Router.")

    ip = router['ip'].split()

    mac = MACs(ip, interface)
    result = mac.get_macs()

    if not result:
        print("[-] Please check the router's IP.")
        sys.exit()
    else:
        result = result[0]['mac']

    log_file.write("\n[{0}] Router's MAC Address: {1}".format(datetime.now().strftime(dt_format),
                                                              result))

    if verbose == 'yes':
        print("[+] Router's MAC Address: {0}".format(result))

    return result


def get_target_mac(log_file, targets, dt_format, interface, verbose):
    print("\n[*] Checking IPs and getting MAC Address...\n")

    log_file.write("\n[{0}] Checking IPs and getting MAC Address...".format(datetime.now().strftime(dt_format)))

    macs = MACs(targets, interface)
    result = macs.get_macs()

    if not result:
        print("[-] Please check the IPs.")
        sys.exit()

    if verbose == 'yes':
        macs.print_data(result)

    return result


class Main:

    def __init__(self, router, interface, targets, verbose, log_file):
        self.router = router
        self.interface = interface
        self.targets = targets
        self.verbose = verbose
        self.log_file = log_file
        self.dt_format = "%H:%M:%S"

    def get_targets_info(self):

        self.router['mac'] = get_router_mac(self.verbose, self.router, self.interface, self.log_file, self.dt_format)

        if self.targets[0] == '' and len(self.targets) == 1:
            if self.verbose == 'yes':
                print("\n[*] No Specific Target(s) found.")
            results = scan_network(self.router, self.interface, self.log_file, self.verbose)
        else:
            results = get_target_mac(self.log_file, self.targets, self.dt_format, self.interface, self.verbose)

        return [results, self.router]
