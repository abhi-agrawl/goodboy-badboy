# (Good || Bad) Boy

 GoodBoy BadBoy (GB) program uses an Offensive Approach towards Vulnerability Assessment

GB is a program which has two sides Good and Bad.
Good side will do basic Vulnerability Assessment like port scanning and get version/banner and then search the version for any known vulnerability and return top 2 results from the website of CVE Details.

Furthermore, the program will behave as Network based intrusion detection system but actually it is a Hot based intrusion detection system. It will attack every device on the network using ARP Poisoning so the flow of packets will go through the program and an IDS can run to check for malicious activity.

On the other hand, bad side will attack the device using ARP Poisoning, and will run

- DNS Spoofing to Phishing Site.
- Getting user credentials, if any.

#### Works with Python 3.6 and below.

### Supports Platform: Linux, Debain

### How to use:
- Install the packages using pip -> `pip3 install -r requirements.txt`. (Make sure pip3 is for Python3.6)
- Run `setup.py` file -> `python3 setup.py`. This will create **configuration.ini** file. (make sure python3 means python3.6)
- Once the file is created, run `main.py` -> `python3 main.py`

### Licensed: GNU General Public License, version 3

### Available Arguments:

- ***router_ip:*** To identify the router’s IP, helps in scanning the network, and while spoofing the targets using ARP.
- ***netmask:*** To identify the range of IP for scanning the network.
- ***interface:*** Network Interface which can be used for all the process done by the program.
- ***which_boy:*** To know what kind of attack and checks user need to perform. Two options; Good [G] and Bad [B].
- ***specific_targets:*** (Optional) If the user wants to perform all the attacks and checks on a few specific machines, this option can be used. Blank means scan the whole network and attack on every device possible.
- ***verbose:*** Defines the verbosity of the program. Two options; Basic (minimal) or Everything.
- ***ids:*** With this option, the user can capture and save the packets in a `.pcap` file for later use or run a Host-based IDS to check for malicious activities. If nothing is specified default is YES.
- ***port_scanner:*** Open ports on each host can be checked. If nothing is specified default is YES.
- ***check_cve:*** The banner of the open ports will be checked on CVE Details website for any known vulnerability. If nothing is specified default is NO.
- ***queue_num:*** A queue number can be specified which can be used to create IP Tables rules on a specific queue. Default is 0.
- ***dns_website_to_spoof:*** The website which the user wants to spoof to a fake or phishing one, can be specified. Programs ask for a URL without the scheme (like no HTTP or HTTPS)
- ***dns_ip_spoof_to:*** The user has to specify the IP to which the DNS has to be spoofed.
