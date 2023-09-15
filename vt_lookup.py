#!/usr/bin/env python3

import json
import time

import argparse
import requests

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

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
    
    
def get_ip_address(ip):
    result = {}
    resp = session.get(f"{vt_base_url}/ip_addresses/{ip}")
    if resp.ok:
        data = resp.json()["data"]["attributes"]

        analysis = data["last_analysis_stats"]
        country = data["country"]
        votes = data["last_analysis_results"]
        mal_votes = [vote for vote in votes if votes[vote]["result"] == "clean"]
        
        result["analysis"] = analysis
        result["country"] = country
        result["malicious_vendor_verdicts"] = mal_votes
        
    return result


def get_indicator_details(hash):
    hash_type = IndicatorTypes.FILE_HASH_MD5
    if len(hash) == 64:
        hash_type = IndicatorTypes.FILE_HASH_SHA256
    if len(hash) == 40:
        hash_type = IndicatorTypes.FILE_HASH_SHA1

    return otx.get_indicator_details_full(hash_type, hash)


def get_indicators(id):
    
    results = otx.get_pulse_indicators(pulse_id=id)
    return ", ".join([result["indicator"] for result in results])
        

def load_vt_token():
    vault_pass = getpass(prompt="Enter vault password: ")
    try:
        vault = Vault(vault_pass)
        return vault.load(open('secrets.yml').read())
    except AnsibleVaultError:
        print(f"{Y}[!] Incorrect vault password.{W}")


def load_parsers():
    parser = argparse.ArgumentParser(description="A VirusToal URL and Hash checker.")
    parser.add_argument("--ip", required=False, help="IP eg; 8.8.8.8")
    parser.add_argument("--url", required=False, help="URL eg; http://www.maldomain.com")
    parser.add_argument("--hash", required=False, help="Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571.")
    parser.add_argument("--hash-comments", required=False, action="store_true", help="Retrieve hash comments")
    parser.add_argument("--dump-indicators", required=False, action="store_true", help="Dump indicators from OTX to file.")
    return parser.parse_args()

    
if __name__ == "__main__":
    
    # Print Colors
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    W = '\033[0m'

    token = load_vt_token()
    args = load_parsers()  
    vt_base_url = "https://www.virustotal.com/api/v3"
    session = requests.Session()
    session.headers = {"X-Apikey": token["api_key"]}
    otx = OTXv2(token["otx_key"])
    
    if ip_addr := args.ip:
        result = get_ip_address(ip_addr)
        print(f"\n{G}[*] IP Address Details:{W}")
        for key, value in result.items():
            print(f"\n{G}{key.upper()}:{W}\n{value}")

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
        
        print(f"\n{G}[*] OTX AlienVault Result:{W}")
        otx_result = get_indicator_details(hash=target_hash)["general"]
        
        if tags := otx_result["pulse_info"]["pulses"][0]["tags"]:
            print(f"\n{G}Tags:{W}")
            print(", ".join(tag for tag in tags))
                
        if malware_families := otx_result["pulse_info"]["pulses"][0]["malware_families"]:
            print(f"\n{G}Malware Families:{W}")
            print(f", ".join([mal["display_name"] for mal in malware_families]))

        if attack_ids := otx_result["pulse_info"]["pulses"][0]["attack_ids"]:
            print(f"\n{G}Attack Identifiers:{W}")
            print(f", ".join([attack["display_name"] for attack in attack_ids]))

        if args.dump_indicators:
            if pulse_id := otx_result["pulse_info"]["pulses"][0]["id"]:
                print(f"{G}\n[*] Dumping indicators to a file.{W}")
                indicators = get_indicators(id=pulse_id)
                with open(f"{pulse_id}.txt", "w") as file:
                    file.write(indicators)
        
        
        if args.hash_comments:
            print(f"\n{G}[*] File / Hash Comments:{W}")
            num = 1
            for line in comments:
                comments = line["attributes"]["text"]
                print(f"\n{num}. {comments}")
                num += 1
        

        