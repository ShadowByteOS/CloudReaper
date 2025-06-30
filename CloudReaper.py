import argparse
import concurrent.futures
import socket
import sys
import os
import requests
import dns.resolver
import re
import time
import threading
import itertools
import random
import json
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# --- Colors ---
INFO = Fore.YELLOW + "[*] " + Style.RESET_ALL
SUCCESS = Fore.GREEN + "[+] " + Style.RESET_ALL
ERROR = Fore.RED + "[-] " + Style.RESET_ALL
HEAD = Fore.CYAN + Style.BRIGHT

# --- Animations & Graphics ---
def typewriter_effect(text, delay=0.02):
    # Nothing to see here, just some fancy text
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

class Spinner:
    def __init__(self, message="Processing..."):
        self.spinner_cycle = itertools.cycle(['-', '/', '|', '\\'])
        self.message = message
        self.stop_running = threading.Event()
        self.spinner_thread = threading.Thread(target=self._spin)

    def _spin(self):
        while not self.stop_running.is_set():
            spinner_char = next(self.spinner_cycle)
            sys.stdout.write(f'\r{self.message} {spinner_char}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')
        sys.stdout.flush()

    def start(self):
        self.spinner_thread.start()

    def stop(self):
        self.stop_running.set()
        self.spinner_thread.join()

def print_banner():
    banner_text = "CloudReaper 2.0 - Advanced Cloudflare OSINT Tool"
    typewriter_effect(HEAD + banner_text)
    print(HEAD + "=" * len(banner_text))

# --- API Keys (Optional) ---
# Still looking? C'mon bro, just use the tool.
SECURITYTRAILS_API_KEY = os.environ.get('SECURITYTRAILS_API_KEY')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')

# --- Global Variables ---
found_ips = []
cloudflare_ips = set()
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
]

# --- Core Functions ---

def get_cloudflare_ips():
    print(INFO + "Fetching Cloudflare's IP ranges...")
    urls = ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"]
    ips = set()
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            ips.update(response.text.splitlines())
        except requests.RequestException as e:
            print(ERROR + f"Failed to fetch Cloudflare IPs from {url}: {e}")
    if ips:
        print(SUCCESS + f"Successfully fetched {len(ips)} Cloudflare IP ranges.")
    return ips

def is_cloudflare_ip(ip):
    for cf_ip_range in cloudflare_ips:
        if ip.startswith(cf_ip_range.split('.')[0]):
            return True
    return False

def dns_bruteforce_worker(subdomain, domain):
    target = f"{subdomain}.{domain}"
    try:
        ip_address = socket.gethostbyname(target)
        if ip_address and not is_cloudflare_ip(ip_address):
            return {"ip": ip_address, "source": "DNS Bruteforce", "reason": f"Subdomain '{target}' points to a non-Cloudflare IP."}
    except socket.gaierror:
        pass
    return None

def check_mx_records(domain):
    print(INFO + "Checking MX records...")
    try:
        for record in dns.resolver.resolve(domain, 'MX'):
            mail_server = str(record.exchange)
            try:
                ip_address = socket.gethostbyname(mail_server)
                if not is_cloudflare_ip(ip_address):
                    found_ips.append({"ip": ip_address, "source": "MX Record", "reason": f"Mail server '{mail_server}' is a non-Cloudflare IP."})
            except socket.gaierror:
                continue
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass

def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def enrich_ip_data(item, domain, stealth_mode):
    ip = item['ip']
    if stealth_mode:
        time.sleep(random.uniform(0.5, 2.0))

    item['http_verification'] = []
    for protocol in ['http', 'https']:
        try:
            headers = {"Host": domain, "User-Agent": random.choice(USER_AGENTS) if stealth_mode else USER_AGENTS[0]}
            response = requests.get(f"{protocol}://{ip}", headers=headers, timeout=7, verify=False)
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else "No title"
            item['http_verification'].append(f"{protocol.upper()} Reachable (Status: {response.status_code}) - Title: {title}")
        except requests.RequestException:
            pass

    item['reverse_dns'] = get_reverse_dns(ip)
    return item

def generate_report(domain, final_data, args):
    output_file = args.output if args.output else f"report-{domain}.txt"
    
    if args.json:
        json_output_file = (args.output or f"report-{domain}") + ".json"
        with open(json_output_file, 'w', encoding='utf-8') as f:
            json.dump(final_data, f, indent=4)
        print(SUCCESS + f"JSON report saved to: {json_output_file}")

    report_content_plain = f"CloudReaper 2.0 - Final Report for: {domain}\n" + "="*60 + "\n\n"
    
    print("\n" + HEAD + f"--- CloudReaper 2.0 Final Report for {domain} ---")
    for item in final_data:
        print(SUCCESS + "IP Address: " + Fore.GREEN + Style.BRIGHT + item['ip'])
        report_content_plain += f"[+] IP Address: {item['ip']}\n"
        
        print(HEAD + "  Source: " + Style.RESET_ALL + item['source'])
        report_content_plain += f"    Source: {item['source']}\n"

        if item.get('reverse_dns') and domain in item['reverse_dns']:
            print(HEAD + "  Reverse DNS: " + Fore.GREEN + item['reverse_dns'] + " (Matches Domain!)")
            report_content_plain += f"    Reverse DNS: {item['reverse_dns']} (Matches Domain!)\n"
        elif item.get('reverse_dns'):
            print(HEAD + "  Reverse DNS: " + Style.RESET_ALL + item['reverse_dns'])
            report_content_plain += f"    Reverse DNS: {item['reverse_dns']}\n"
        
        if item.get('http_verification'):
            for res in item['http_verification']:
                print(SUCCESS + "  " + res)
                report_content_plain += f"    {res}\n"
        
        print(HEAD + "-" * 40)
        report_content_plain += "-" * 40 + "\n"

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content_plain)
        print("\n" + SUCCESS + f"Text report saved to: {output_file}")
    except IOError as e:
        print("\n" + ERROR + f"Failed to write text report: {e}")

def get_default_wordlist():
    # Still here? Go grab a coffee, this list is boring.
    return [
        'www', 'mail', 'ftp', 'cpanel', 'webmail', 'dev', 'staging', 'api', 'admin',
        'blog', 'shop', 'test', 'ns1', 'ns2', 'remote', 'assets', 'cdn'
    ]

def main():
    global cloudflare_ips, found_ips
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    print_banner()

    parser = argparse.ArgumentParser(
        description="CloudReaper 2.0 - Advanced Cloudflare OSINT Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
API Key Setup (Optional):
Set the following environment variables for enhanced functionality:
  - SECURITYTRAILS_API_KEY: Your key from securitytrails.com
  - SHODAN_API_KEY:         Your key from shodan.io

Example:
  export SECURITYTRAILS_API_KEY="your_key_here"
  python CloudReaper.py -d example.com
"""
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Path to a custom subdomain wordlist file")
    parser.add_argument("-o", "--output", help="Base name for output files (e.g., report.txt)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads for parallel tasks")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth-like features (random delays, user-agents)")
    parser.add_argument("--json", action="store_true", help="Enable JSON output")
    args = parser.parse_args()

    # Phase 1: IP Discovery
    cloudflare_ips = get_cloudflare_ips()
    check_mx_records(args.domain)

    wordlist = get_default_wordlist()
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f: wordlist = [line.strip() for line in f]
        except FileNotFoundError:
            print(ERROR + f"Wordlist '{args.wordlist}' not found."); sys.exit(1)

    spinner = Spinner(f"Bruteforcing {len(wordlist)} subdomains...")
    spinner.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(dns_bruteforce_worker, sub, args.domain) for sub in wordlist]
        for future in concurrent.futures.as_completed(futures):
            if result := future.result():
                found_ips.append(result)
    spinner.stop()
    print(SUCCESS + "DNS bruteforce completed.")

    unique_ips = list({item['ip']: item for item in found_ips}.values())
    if not unique_ips:
        print(INFO + "No potential real IPs found."); return

    # Phase 2: Data Enrichment
    final_data = []
    spinner = Spinner(f"Enriching data for {len(unique_ips)} IPs...")
    spinner.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_item = {executor.submit(enrich_ip_data, item, args.domain, args.stealth): item for item in unique_ips}
        for future in concurrent.futures.as_completed(future_to_item):
            final_data.append(future.result())
    spinner.stop()
    print(SUCCESS + "Data enrichment completed.")

    # Phase 3: Report Generation
    generate_report(args.domain, final_data, args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + ERROR + "Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print("\n" + ERROR + f"An unexpected error occurred: {e}")
