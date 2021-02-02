#! /usr/bin/env python3

import re
import subprocess
import configparser


def common_input():
    while True:
        router_ip = input("\n[*] Enter Router's IP Address:\n>> ")

        if re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", router_ip):
            break
        print("[-] Error! Enter correct IP Address.")

    while True:
        try:
            netmask = input("\n[*] Enter Subnet mask (in decimal):\n>> ")

            if 0 <= int(netmask) <= 32:
                break
            print("[-] Invalid Input! Enter netmask between 0 and 32.")
        except ValueError:
            print("[-] Invalid Input! Enter netmask between 0 and 32.")

    while True:
        interface = input("\n[*] Please enter the interface name:\n>> ")
        try:
            subprocess.check_call(["sudo", "ifconfig", interface],
                                  stdin=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL)
            break
        except subprocess.CalledProcessError:
            print("[-] Error! No interface (" + interface + ") found.")

    while True:
        which_boy = input("\n[*] How to do you want me to behave? Good or Bad (G\B)\n>> ").upper()

        if which_boy in ['G', 'B']:
            break
        print("[-] Invalid Input! Enter G for Good or B for Bad.")

    specific_target = input("\n[*] Work on Specific Target (leave blank if no specific targets)?"
                            " Specify targets separated by comma (,):\n>> ")

    if not specific_target:
        print("[+] No specific target(money) found. The whole network will be scanned.")
    else:
        print("[+] Total target(money) is/are {0}.".format(len(specific_target.split())))

    try:
        verbose = int(input("\n[*] Enter Verbosity Level(1:Basic, 2:Everything[Default])[1/2]\n>> "))
        if verbose in [1, 2]:
            print("[+] Verbosity Level is set to {0}".format("Basic" if verbose == 1 else "Everything"))
            verbose = 'yes' if verbose == 2 else 'no'
        else:
            print("[-] Invalid Input! Default is 2 - Everything.")
            verbose = 'yes'
    except ValueError:
        print("[-] Invalid Input! Default is 2 - Everything.")
        verbose = 'yes'

    return {"ROUTER_IP": router_ip, "NETMASK": netmask, "WHICH_BOY": which_boy, "INTERFACE": interface,
            "SPECIFIC_TARGETS": specific_target, "VERBOSE": verbose}


def good_input():
    options = ['otp', 'donation', 'no', 'yes']

    ids = input("\n[*] Would you like to monitor the target? Default(Y)\n>> ").lower()
    if ids in options:
        print("[+] You choose {0} to monitor target.".format(ids))
    else:
        print("[-] Invalid Option! Default is YES.")

    ids = 'no' if ids in ['donation', 'no'] else 'yes'

    port_scanner = input("\n[*] Would like to check open ports? Default(Y)\n>> ").lower()
    if port_scanner in options:
        print("[+] You choose {0} to run port scanning.".format(port_scanner))
    else:
        print("[-] Invalid Option! Default is YES.")

    port_scanner = 'no' if port_scanner in ['donation', 'no'] else 'yes'

    check_cve = ""
    if port_scanner == 'yes':
        check_cve = input("\n[*] Would you like to check CVE Details for Open Ports? Default(N)\n>> ").lower()
        if check_cve in options:
            print("[+] You choose {0} to check for CVE Details.".format(check_cve))
        else:
            print("[-] Invalid Option! Default is NO.")

    check_cve = 'yes' if check_cve in ['otp', 'yes'] else 'no'

    return {"IDS": ids, "PORT_SCANNER": port_scanner, "CHECK_CVE": check_cve}


def bad_input():
    try:
        queue_num = int(input("\nEnter the Queue Number for IPTABLES which has no rules on it. Default(0)\n>> "))
    except ValueError:
        queue_num = 0
        print("[-] Invalid Input! Default value will be 0.")

    dns_website_to_spoof = input("\n[*] Enter the website you want to spoof (without http). Eg:facebook.com\n>> ")

    while True:
        dns_ip_spoof_to = input("\n[*] Enter the IP Address you want to spoof to\n>> ")

        if re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", dns_ip_spoof_to):
            break
        print("[-] Invalid Input! Enter correct IP Address.")

    return {"queue_num": queue_num, "dns_website_to_spoof": dns_website_to_spoof, "dns_ip_spoof_to": dns_ip_spoof_to}


def save_to_file(common, good, bad):
    config = configparser.ConfigParser()

    config['COMMON'] = common
    config['GOOD'] = good
    config['BAD'] = bad

    with open("configuration.ini", 'w+') as config_file:
        config.write(config_file)

    print("\n[+] Configuration has been saved.")


def main():
    print("[+] Initiating GoodBoy BadBoy Program....")

    common = common_input()

    print("\n\n[+] Configuration for GoodBoy...")
    good = good_input()

    print("\n\n[*] Configuration for the BadBoy...")
    bad = bad_input()

    save_to_file(common, good, bad)


###################################################
if __name__ == "__main__":
    main()
