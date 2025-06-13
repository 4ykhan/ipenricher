# CERT.AZ IOC Enricher

A command-line tool for scanning IP indicators of compromise (IOCs) against multiple public threat intelligence sources.

### Supported:
- [VirusTotal](https://www.virustotal.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [AbuseIPDB](https://abuseipdb.com/)
- [Abuse.ch ThreatFox](https://threatfox.abuse.ch/)

---

## Usage

### Scan from a file  
Provide a `.txt` file with one IP address per line:

```
python3 ioc_scanner.py -f ips.txt
```

### Scan directly from command line  
Provide one or more IPs:

```
python3 ioc_scanner.py -i 8.8.8.8 1.1.1.1
```

### Show usage manual

```
python3 ioc_scanner.py -m
```

---

## Output Example

```
 ██████╗███████╗██████╗ ████████╗ █████╗ ███████╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔══██╗╚══███╔╝
██║     █████╗  ██████╔╝   ██║   ███████║  ███╔╝ 
██║     ██╔══╝  ██╔══██╗   ██║   ██╔══██║ ███╔╝  
╚██████╗███████╗██║  ██║   ██║██╗██║  ██║███████╗
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

         ░░ IP SCANNER ░░

Scanning IP: 144.91.92.251

--- VirusTotal ---
Malicious: 13
Suspicious: 2
Harmless: 51
Undetected: 28
Link: https://www.virustotal.com/gui/ip-address/144.91.92.251

--- AlienVault ---
Pulse_count: 3
Verdict: malicious
Link: https://otx.alienvault.com/indicator/ip/144.91.92.251

--- AbuseIPDB ---
Abuse_score: 0
Country: DE
Usage: Data Center/Web Hosting/Transit
Link: https://www.abuseipdb.com/check/144.91.92.251

--- Abuse.ch ---
Ioc_count: 1
Threats: ['MoDi RAT']
Link: https://threatfox.abuse.ch/browse.php?search=ioc%3A144.91.92.251
```

---

## API Configuration

Edit the API keys at the top of the script:

```
API_KEYS = {
    "virustotal": "<YOUR_VT_API_KEY>",
    "alienvault": "<YOUR_OTX_API_KEY>",
    "abuseipdb": "<YOUR_ABUSEIPDB_API_KEY>",
    "abusech": "<YOUR_ABUSECH_API_KEY>"
}
```
## Requirements

Python 3.x

Install the required dependencies:

```
pip install requests
```

