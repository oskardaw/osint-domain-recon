# OSINT Domain Reconnaissance Tool

A Python-based command-line tool designed to automate passive reconnaissance against target domains. It aggregates DNS records, discovers subdomains using Certificate Transparency logs, and extracts domain registration details via RDAP.

## Features

- **DNS Enumeration**: Queries `A`, `AAAA`, `MX`, `NS`, and `TXT` records.
- **Subdomain Discovery**: Passively extracts subdomains using `crt.sh` Certificate Transparency logs.
- **RDAP / WHOIS Lookup**: Queries domain registration metadata, status, and timeline events via RDAP protocol.
- **Structured Export**: Outputs results directly to JSON format for integration with other tooling.

## Installation

```bash
git clone [https://github.com/oskardaw/osint-domain-recon.git](https://github.com/oskardaw/osint-domain-recon.git)
cd osint-domain-recon
pip install -r requirements.txt

Usage
python osint_recon.py -d example.com

Run a scan and save the results to a JSON file:
python osint_recon.py -d example.com -o results.json

Example Output
{
    "target": "example.com",
    "dns_records": {
        "A": [
            "93.184.216.34"
        ],
        "AAAA": [
            "2606:2800:220:1:248:1893:25c8:1946"
        ],
        "MX": [],
        "NS": [
            "a.iana-servers.net.",
            "b.iana-servers.net."
        ],
        "TXT": [
            "v=spf1 -all"
        ]
    },
    "subdomains_found": 1,
    "subdomains": [
        "[www.example.com](https://www.example.com)"
    ],
    "whois_rdap": {
        "handle": "233154_DOMAIN_COM-VRSN",
        "status": [
            "client delete prohibited",
            "client transfer prohibited",
            "client update prohibited"
        ]
    }
}
