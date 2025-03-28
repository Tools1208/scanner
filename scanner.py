#!/usr/bin/env python3

import base64
import requests
import time
import random
import json
import socket
import ssl
import nmap
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, quote, urlparse, parse_qs
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from fake_useragent import UserAgent
import pyfiglet

BANNER = """
##########################################################
#                                                        #
#   ███████╗██╗  ██╗██████╗ ██╗   ██╗███████╗███████╗    #
#   ██╔════╝╚██╗██╔╝██╔══██╗██║   ██║██╔════╝██╔════╝    #
#   █████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗█████╗      #
#   ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║██╔══╝      #
#   ███████╗██╔╝ ██╗██║     ╚██████╔╝███████║███████╗    #
#   ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝    #
#                                                        #
##########################################################
"""

def print_banner():
    print(pyfiglet.figlet_format("Scanner"))
    print("Tool made by Anonymous Jordan Team")
    print("https://t.me/AnonymousJordan\n")

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
        self.headers = {'User-Agent': UserAgent().random}
        
    def check_sql_injection(self, url, param):
        payloads = ["' OR 1=1--", "' UNION SELECT null, version()--"]
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = requests.get(test_url, headers=self.headers, timeout=10)
                if "SQL syntax" in resp.text or "error in your SQL" in resp.text:
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'severity': 'Critical'
                    })
            except Exception as e:
                print(f"[!] SQLi Error: {e}")

    def check_xss(self, url, param):
        payloads = ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>"]
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = requests.get(test_url, headers=self.headers, timeout=10)
                if payload in resp.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'severity': 'High'
                    })
            except Exception as e:
                print(f"[!] XSS Error: {e}")

    def check_ssl_tls(self, host, port=443):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher[1] in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.vulnerabilities.append({
                            'type': 'Weak Cipher',
                            'host': host,
                            'port': port,
                            'cipher': cipher[0],
                            'version': cipher[1],
                            'severity': 'Medium'
                        })
        except Exception as e:
            print(f"[!] SSL Check Error: {e}")

    def run_nikto(self):
        if shutil.which('nikto'):
            try:
                result = subprocess.run(['nikto', '-h', self.target], 
                                       capture_output=True, text=True)
                self.vulnerabilities.append({
                    'type': 'Nikto Scan',
                    'output': result.stdout,
                    'severity': 'Info'
                })
            except Exception as e:
                print(f"[!] Nikto Error: {e}")
        else:
            print("[!] Nikto not found. Please install it.")

    def run_nmap(self):
        nm = nmap.PortScanner()
        nm.scan(self.target, arguments='-sV -O')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    self.vulnerabilities.append({
                        'type': 'Nmap Scan',
                        'host': host,
                        'port': port,
                        'service': nm[host][proto][port]['name'],
                        'version': nm[host][proto][port]['version'],
                        'severity': 'Info'
                    })

    def generate_report(self):
        report = {
            'target': self.target,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'Critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'High'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'Low'),
                'info': sum(1 for v in self.vulnerabilities if v['severity'] == 'Info')
            }
        }
        with open('vulnerability_report.json', 'w') as f:
            json.dump(report, f, indent=4)

def main():
    print_banner()
    target = input("Enter target URL: ").strip()
    
    if not target:
        print("Target URL is required")
        return

    scanner = VulnerabilityScanner(target)
    
    # Run basic HTTP checks
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.submit(scanner.run_nmap)
        executor.submit(scanner.run_nikto)
        executor.submit(scanner.check_ssl_tls, urlparse(target).hostname)
        
        # Add more concurrent checks here

    scanner.generate_report()
    print("\n[+] Scan completed. Report saved to vulnerability_report.json")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
