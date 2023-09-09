#!/usr/bin/env python3

import json
import time

import argparse
import requests

from getpass import getpass
from ansible_vault import Vault
from ansible.parsing.vault import AnsibleVaultError

def vt_url_scan(target):
    resp = session.post(f"{vt_base_url}/urls", data=f"url={target}")
    if resp.ok:
        url_scan_id =  json.loads(resp.text)["data"]["id"]
        return vt_url_scan_analysis(url_scan_id)
    

def vt_url_scan_analysis(id, vendors=[]):
    resp = session.get(f"{vt_base_url}/analyses/{id}")
    if resp.ok:
        data = json.loads(resp.text)
        status = data["data"]["attributes"]["status"]
        while status != "completed":
            time.sleep(5)
            vt_url_scan()
        else:
            results = data["data"]["attributes"]["results"]
            for vendor in results:
                result = results[vendor]
                if result["result"] == "malware":
                    vendors.append(vendor)
            return vendors


def get_result(hash):
    resp = session.get(url=f"{vt_base_url}/files/{hash}")
    if resp.ok:
        return json.loads(resp.text)


def get_comments(hash):
    resp = session.get(url=f"{vt_base_url}/files/{hash}/comments")
    if  resp.ok:
        return json.loads(resp.text)


def load_vt_token():
    vault_pass = getpass(prompt="Enter vault password: ")
    try:
        vault = Vault(vault_pass)
        return vault.load(open('secrets.yml').read())["api_key"]
    except AnsibleVaultError:
        print(f"{Y}[!] Incorrect vault password.{W}")


def load_parsers():
    parser = argparse.ArgumentParser(description="A VirusToal URL and Hash checker.")
    parser.add_argument("--url", required=False, help="URL or Domain to be checked.")
    parser.add_argument("--hash", required=False, help="Hash of the file to be checked.")
    return parser.parse_args()

    
if __name__ == "__main__":
    
    # Print Colors
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    B = '\033[1m'
    W = '\033[0m'

    token = load_vt_token()
    args = load_parsers()  
    vt_base_url = "https://www.virustotal.com/api/v3"
    session = requests.Session()
    session.headers = {"X-Apikey": token}
    

    if target_url := args.url:
        result = vt_url_scan(target=target_url)
        if result:
            print(f"{G}[!] Vendors with malware verdict:{W}\n\t{', '.join(result)}")
            
    elif target_hash := args.hash:
        attributes = get_result(hash=target_hash)["data"]["attributes"]
        comments = get_comments(hash=target_hash)["data"]
        
        name = attributes["meaningful_name"]
        file_size = attributes["size"]
        file_type = attributes["type_description"]
        file_type_tags = ",".join(attributes["type_tags"])
        sha256 = attributes["sha256"]
        md5 = attributes["md5"]
        sha1 = attributes["sha1"]
        reputation = attributes["reputation"]
        votes = attributes["total_votes"]
        
        print(f"\n{G}[*] File / Hash Attributes:{W}")
        print(f"{G}Name:{W} {name}")
        print(f"{G}Size:{W} {file_size} bytes")
        print(f"{G}File Type:{W} {file_type}\n{G}Tags:{W} {file_type_tags}")
        print(f"\n{G}Hashes:{W} \n\tSHA256: {sha256}\n\tSHA1: {sha1}\n\tMD5: {md5}")
        print(f"\n{G}Reputation:{W} {reputation}")
        print(f"\n{G}Total votes:{W}")
        print(f"\tHarmless: {votes['harmless']}")
        print(f"\tMalicious: {votes['malicious']}")
        
        print(f"\n{G}[*] File / Hash Comments:{W}")
        num = 1
        for line in comments:
            comments = line["attributes"]["text"]
            print(f"\n{num}. {comments}")
            num += 1