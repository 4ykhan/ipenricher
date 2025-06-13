#!/usr/bin/env python3

import requests
import json
import argparse
import urllib3
import re
urllib3.disable_warnings()

# KEYS
API_KEYS = {
    "virustotal": " ",
    "alienvault": " ",
    "abuseipdb": " ",
    "abusech": " "
}

# BANNER
def show_banner():
    banner = r"""
 ██████╗███████╗██████╗ ████████╗ █████╗ ███████╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔══██╗╚══███╔╝
██║     █████╗  ██████╔╝   ██║   ███████║  ███╔╝ 
██║     ██╔══╝  ██╔══██╗   ██║   ██╔══██║ ███╔╝  
╚██████╗███████╗██║  ██║   ██║██╗██║  ██║███████╗
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

         ░░ IP SCANNER ░░
    """
    print(banner)

def show_manual():
    manual = """
Usage:
  -f <file.txt>        : Scan IPs listed in a text file (one IP per line)
  -i <IP1> <IP2> ...    : Scan one or more IPs directly from the command line
  -m                    : Show this manual/help screen

Examples:
  python3 ioc_scanner.py -f ips.txt
  python3 ioc_scanner.py -i 8.8.8.8 1.1.1.1
"""
    print(manual)

# VALIDATOR
def is_valid_ip(ip):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip)

# PROVIDERS
def check_virustotal(ip):
    headers = {"accept": "application/json", "x-apikey": API_KEYS["virustotal"]}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        res = requests.get(url, headers=headers)
        data = res.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "provider": "VirusTotal",
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "undetected": stats["undetected"],
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
    except Exception as e:
        return {"provider": "VirusTotal", "error": str(e)}

def check_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": API_KEYS["alienvault"]}
    try:
        res = requests.get(url, headers=headers, verify=False)
        data = res.json()
        pulse_count = data["pulse_info"]["count"]
        verdict = "not malicious"
        if pulse_count == 1:
            verdict = "possibly malicious"
        elif pulse_count >= 2:
            verdict = "malicious"
        return {
            "provider": "AlienVault",
            "pulse_count": pulse_count,
            "verdict": verdict,
            "link": f"https://otx.alienvault.com/indicator/ip/{ip}"
        }
    except Exception as e:
        return {"provider": "AlienVault", "error": str(e)}

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': API_KEYS["abuseipdb"]}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        res = requests.get(url, headers=headers, params=params)
        data = res.json()['data']
        return {
            "provider": "AbuseIPDB",
            "abuse_score": data["abuseConfidenceScore"],
            "country": data.get("countryCode", "N/A"),
            "usage": data.get("usageType", "N/A"),
            "link": f"https://www.abuseipdb.com/check/{ip}"
        }
    except Exception as e:
        return {"provider": "AbuseIPDB", "error": str(e)}

def check_abusech(ip):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/json", "API-Key": API_KEYS["abusech"]}
    payload = {"query": "search_ioc", "search_term": ip, "exact_match": False}
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        if response.status_code != 200:
            return {"provider": "Abuse.ch", "error": f"HTTP {response.status_code}: {response.text}"}
        data = response.json()
        if data.get("query_status") != "ok":
            return {"provider": "Abuse.ch", "error": f"Query failed: {data}"}
        iocs = data.get("data", [])
        return {
            "provider": "Abuse.ch",
            "ioc_count": len(iocs),
            "threats": list({ioc.get("malware_printable", "Unknown") for ioc in iocs}),
            "link": f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}"
        }
    except Exception as e:
        return {"provider": "Abuse.ch", "error": str(e)}

# MAIN SCAN
def scan_ip(ip):
    print(f"\nScanning IP: {ip}")
    for func in [check_virustotal, check_alienvault, check_abuseipdb, check_abusech]:
        result = func(ip)
        print(f"--- {result['provider']} ---")
        for k, v in result.items():
            if k != 'provider':
                print(f"{k.capitalize()}: {v}")
        print()

def read_ips_from_file(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if is_valid_ip(line.strip())]

# ENTRY POINT
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CERT.AZ IOC Scanner")
    parser.add_argument("-f", "--file", help="Text file with list of IPs")
    parser.add_argument("-i", "--ips", nargs="+", help="List of IPs directly")
    parser.add_argument("-m", "--manual", action="store_true", help="Show usage manual")
    args = parser.parse_args()

    if args.manual:
        show_manual()
        exit(0)

    show_banner()

    ip_list = []

    if args.file:
        try:
            ip_list.extend(read_ips_from_file(args.file))
        except Exception as e:
            print(f"Error reading file: {e}")
            exit(1)

    if args.ips:
        ip_list.extend([ip for ip in args.ips if is_valid_ip(ip)])

    if not ip_list:
        print(" No valid IPs provided. Use -m for manual.")
        exit(1)

    for ip in ip_list:
        scan_ip(ip)
