#!/usr/bin/env python3
# Usage sample: 
# # python3 vt_scan.py --hash eb84a283ff58906786d63ffe43a8ff2728584428f5f7d9972c664f63f8790113

import json

import argparse
import requests
from getpass import getpass
from ansible_vault import Vault


vault_pass = getpass(prompt="Enter vault password: ")
vault = Vault(vault_pass)
keys = vault.load(open('secrets.yml').read())

vt_base_url = f"https://www.virustotal.com/api/v3/files"

parser = argparse.ArgumentParser(description="A VirusToal File hash checker.")
parser.add_argument("--hash", required=True, help="File hash to be Checked.")
args = parser.parse_args()
hash = args.hash

session = requests.Session()
session.headers = {"X-Apikey": keys["api_key"]}


def get_result(hash):
    response = session.get(url=f"{vt_base_url}/{hash}")
    json_data = json.loads(response.text) # Dump json to python object, usually to dict
    return json_data


def get_comments(hash):
    response = session.get(url=f"{vt_base_url}/{hash}/comments")
    json_data = json.loads(response.text) # Dump json to python object, usually to dict
    return json_data



if __name__ == "__main__":
    attributes = get_result(hash=hash)["data"]["attributes"]
    comments = get_comments(hash=hash)["data"]
    
    name = attributes["meaningful_name"]
    file_size = attributes["size"]
    file_type = attributes["type_description"]
    file_type_tags = ",".join(attributes["type_tags"])
    sha256 = attributes["sha256"]
    md5 = attributes["md5"]
    sha1 = attributes["sha1"]
    reputation = attributes["reputation"]
    votes = attributes["total_votes"]
    
    print(f"\n[*] File / Hash Attributes:")
    print(f"Name: {name}")
    print(f"Size: {file_size} bytes")
    print(f"File Type: {file_type}\nTags: {file_type_tags}")
    print(f"\nHashes: \nSHA256: {sha256}\nSHA1: {sha1}\nMD5: {md5}")
    print(f"Reputation: {reputation}")
    print(f"Total votes:")
    print(f"\tHarmless: {votes['harmless']}")
    print(f"\tMalicious: {votes['malicious']}")
    
    print(f"\n[*] File / Hash Comments: ")
    num = 1
    for line in comments:
        comments = line["attributes"]["text"]
        print(f"\n{num}. {comments}")
        num += 1
    
    
    
    
    
    