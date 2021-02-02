#! usr/bin/env python3

from bs4 import BeautifulSoup
import requests
from googlesearch import search


def print_data(data, banner):

    print("\n[+] Checked Vulnerability for: {0}".format(banner))

    for cve in data:
        print(">> {0} -> {1}".format(cve['title'], cve['url']))


def get_banner_data(banner):

    query = "site:https://www.cvedetails.com/ {0}".format(banner)

    banner_data = []

    for url in search(query, lang='en', num_results=2):
        response = requests.get(url)
        data = response.text
        soup = BeautifulSoup(data, 'html.parser')

        title = soup.find_all('h1')[0].text
        title = " ".join(title.split())

        banner_data.append({'title': title, 'url': url})

    return banner_data


class Check_CVE_Details:

    def __init__(self, open_ports, verbose):
        self.open_ports = open_ports
        self.verbose = verbose

    def start_check(self):

        cve_details = []

        for i in range(len(self.open_ports)):

            banner = self.open_ports[i]['banner']

            if banner != "No Banner":
                info = get_banner_data(banner)
                if not info:
                    cve_details.append(["None"])
                else:
                    cve_details.append(info)

                if self.verbose == 'yes':
                    print_data(info, banner)
            else:
                cve_details.append(["None"])

        return cve_details
