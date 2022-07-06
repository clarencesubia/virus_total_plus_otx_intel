#!/usr/bin/python3
# Author: Clarence Subia
# Usage: 
# ./url_checker.py --url http://malicious-url.com/

import json
import requests
import csv
import time
import argparse
import os
from pwinput import pwinput


base_path = "https://www.virustotal.com/api/v3"

if os.path.exists("vtkey.txt") and os.stat("vtkey.txt").st_size != 0:
    api_key = open("vtkey.txt", "r").readline().strip()
else:
    api_key = pwinput(prompt="Enter API Key: ", mask="*")
    file = open("vtkey.txt", "w")
    file.write(api_key)

parser = argparse.ArgumentParser(description="Virus total URL checker.")
parser.add_argument("--url", "-u", required=True, help="URL to be Checked.")
args = parser.parse_args()
url = args.url

payload = f"url={url}" # Sample: http://38zu.cn/

headers = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "x-apikey": api_key
}

requests.packages.urllib3.disable_warnings()
session = requests.Session()
session.headers.update(headers)

def main():
    print("[*] URL Scan Initiated...")
    scan_url()
    print("Script completed.") 


def scan_url():
    
    response = session.post(f"{base_path}/urls", data=payload)
    data = json.loads(response.text)
    if response.ok:
        id = data["data"]["id"]
        url_analysis(id)
    else:
        print(response.text)


def url_analysis(id):
    response = session.get(f"{base_path}/analyses/{id}")
    data = json.loads(response.text)
    if response.ok:
        
        if data["data"]["attributes"]["status"] == "completed":
            result = data["data"]["attributes"]["results"]
            with open("results.csv", "w") as handle:
                csv_writer = csv.writer(handle)
                
                header = ["Security Vendor", "Category", "Result", "Method"]
                csv_writer.writerow(header)
                
                for item in result:
                    vendor = result[item]
                    cat = vendor["category"]
                    res = vendor["result"]
                    method = vendor["method"]
                    engine = vendor["engine_name"]
                    output = (engine, cat, res, method)
                    # print(output)
                    if res != "clean":
                        csv_writer.writerow(output)
        else:
            time.sleep(5)
            scan_url()
            
            
    
    
if __name__ == "__main__": main()
