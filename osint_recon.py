import argparse
import json
import socket
import sys
import requests
import dns.resolver

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
            records[rtype] = []
        except Exception:
            records[rtype] = []
            
    return records

def get_subdomains(domain):
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    sub = sub.strip()
                    if sub and not sub.startswith('*') and sub.endswith(domain):
                        subdomains.add(sub)
    except Exception as e:
        print(f"[-] CRT.sh lookup failed: {e}")
        
    return sorted(list(subdomains))

def get_whois_data(domain):
    url = f"https://rdap.org/domain/{domain}"
    whois_info = {}
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            whois_info['handle'] = data.get('handle', 'N/A')
            whois_info['events'] = data.get('events', [])
            whois_info['entities'] = [e.get('vcardArray', []) for e in data.get('entities', []) if 'vcardArray' in e]
            whois_info['status'] = data.get('status', [])
        else:
            whois_info['error'] = f"RDAP query returned status {response.status_code}"
    except Exception as e:
        whois_info['error'] = str(e)
        
    return whois_info

def run_recon(domain, output_file):
    print(f"[*] Starting OSINT Reconnaissance for: {domain}")
    
    print("[+] Querying DNS records...")
    dns_data = get_dns_records(domain)
    
    print("[+] Enumerating subdomains via Certificate Transparency (crt.sh)...")
    subdomains = get_subdomains(domain)
    
    print("[+] Fetching WHOIS/RDAP registration data...")
    whois_data = get_whois_data(domain)
    
    results = {
        "target": domain,
        "dns_records": dns_data,
        "subdomains_found": len(subdomains),
        "subdomains": subdomains,
        "whois_rdap": whois_data
    }
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"[+] Recon complete. Results saved to {output_file}")
        except IOError as e:
            print(f"[-] Failed to write output file: {e}")
    else:
        print("\n" + json.dumps(results, indent=4))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Automated OSINT Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    args = parser.parse_args()
    
    run_recon(args.domain, args.output)
