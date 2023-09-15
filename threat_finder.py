#!/usr/bin/env python3


import requests
import argparse
import ipaddress

import get_reports


parser = argparse.ArgumentParser(description="VirusTotal Threat Intelligence Tool")
parser.add_argument("--ip", required=False, help="IP eg; 8.8.8.8")
parser.add_argument("--url", required=False, help="URL eg; http://www.maldomain.com")
parser.add_argument("--hash", required=False, help="Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571.")

args = vars(parser.parse_args())


if __name__ == "__main__":
    VT_URL = "https://www.virustotal.com/api/v3"
    session = requests.Session()
    session.headers= {"X-Apikey": "XXX"}

    if ip_addr := args["ip"]:
        response = get_reports.ip_address(session, VT_URL, ip_addr)
        print(response)
