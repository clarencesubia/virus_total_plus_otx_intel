# Virustotal / OTX URL, IP, and Hash Analysis through API
![logo](https://github.com/meliodaaf/virus_total_url_checker/blob/main/docs/logo.png)
## Author: Clarence R. Subia

## Prerequisites
```
sudo apt install ansible-vault
pip3 install -r requirements.txt
```

## Setup your API key

- Encrypting your API token key using ansible-vault
```
ansible-vault create secrets.yml

YAML Format:
---
api_key: "YOUR_VT_TOKEN_HERE"
otx_key: "YOUR_OTX_KEY_HERE"
```

## Usage:
- URL / IP Scanning
```
python3 vt_lookup.py --url <DOMAIN NAME / URL>
python3 vt_lookup.py --ip <IP>
```

- Hash Scanning
```
python3 vt_lookup.py --hash <HASH_VALUE | SHA256 | SHA1 | MD5>
```

- Print out comments on hash
```
python3 vt_lookup.py --hash <HASH_VALUE | SHA256 | SHA1 | MD5> --hash-comments
```


## References:

* [VirusTotal API Reference](https://developers.virustotal.com/reference/overview)
* [Commit History Cleanup](https://stackoverflow.com/questions/13716658/how-to-delete-all-commit-history-in-github)
* [Ansible Vault](https://pypi.org/project/ansible-vault/)