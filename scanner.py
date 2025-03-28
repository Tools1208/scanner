#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import nmap
import requests
import threading
from urllib.parse import urljoin, urlparse
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
        self.results = {
            "ip_info": {},
            "server_info": {},
            "hidden_pages": [],
            "security_headers": [],
            "vulnerabilities": [],
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
            'admin', 'login', 'wp-admin', 'backup', 'config',
            'robots.txt', 'phpmyadmin', 'test', 'dev', 'old',
            '.git', '.svn', 'web.config', 'sitemap.xml', 'README.md'
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
            except Exception as e:
                self.log_error(f"Hidden Page Check Error ({url}): {str(e)}")

        threads = []
        for path in common_paths:
            t = threading.Thread(target=check_path, args=(path,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()

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

    def log_error(self, message):
        with self.lock:
            self.results['errors'].append({
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'message': message
            })

    def generate_report(self):
        filename = f"cyberscan_report_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            return filename
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
            ('Security Headers Check', self.check_security_headers),
            ('Nmap Vulnerability Scan', self.run_nmap_scan)
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

        report_file = self.generate_report()
        if report_file:
            print(f"\n{Colors.MAGENTA}[+] Scan Completed - Report saved to: {report_file}")
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
