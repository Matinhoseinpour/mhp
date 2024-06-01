import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import dns.resolver
import tldextract
import socket
import whois
import argparse
import re

links = {}

# Argument parser
parser = argparse.ArgumentParser(description='Crawl websites and collect information.')
parser.add_argument('urls', help='URLs of the websites to crawl')
parser.add_argument('-d', '--depth', type=int, default=2, help='Depth of crawling (default: 2)')
args = parser.parse_args()

def extract_emails_and_phones(text):
    email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    phone_pattern = r'(\+98|0)?9\d{9}'

    emails = re.findall(email_pattern, text)
    phones = re.findall(phone_pattern, text)

    return emails, phones

def crawl(url, depth, max_depth):
    if depth > max_depth:
        return

    try:
        response = requests.get(url)
        response.raise_for_status()
        html_content = response.content
        soup = BeautifulSoup(html_content, 'html.parser')

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full = urljoin(url, href)
            if full.startswith('http') and full not in links:
                links[full] = depth
                crawl(full, depth + 1, max_depth)
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving information from {url}: {e}")

def status_code(url: str):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving status code: {e}")
        return None

def get_title(url: str):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.title.string if soup.title else 'No title found'
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving title: {e}")
        return None

def sub_domain(domain: str):
    data = []
    for subdomain in subs:
        try:
            answers = dns.resolver.resolve(f"{subdomain}.{domain}", "A")
            for ip in answers:
                full_domain = f"https://{subdomain}.{domain}"
                data.append({
                    'subdomain': full_domain,
                    'status_code': status_code(full_domain),
                    'title': get_title(full_domain),
                    'ip': ip.to_text()
                })
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            data.append({'subdomain': f"{subdomain}.{domain}", 'error': str(e)})
    return data

def get_ip(domain: str):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error processing IP for {domain}: {e}")
        return None

def scan_ports(ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995]
    open_ports = []
    try:
        for port in common_ports:  
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
    except Exception as e:
        print(f"Error processing ports: {e}")
    return open_ports

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        whois_info = {
            "Domain registrar": w.registrar,
            "WHOIS server": w.whois_server,
            "Domain creation date": w.creation_date,
            "Domain expiration date": w.expiration_date,
            "Domain last updated": w.last_updated,
            "Name servers": w.name_servers,
            "Registrant name": w.name,
            "Registrant organization": w.org,
            "Registrant email": w.email,
            "Registrant phone": w.phone,
        }
        with open(f"whois_{domain}.txt", "w") as file:
            for key, value in whois_info.items():
                file.write(f"{key}: {value}\n")
        return whois_info
    except Exception as e:
        print(f"Error retrieving WHOIS information for {domain}: {e}")
        return {}

def main():
    with open("subdomains.txt", "r") as file:
        global subs
        subs = file.read().splitlines()
    
    start_url = args.urls
    max_depth = args.depth
    
    crawl(start_url, 1, max_depth)

    print("All crawled URLs:")
    for link, depth in links.items():
        print(f"{link} at depth {depth}")
        
    subdomain_info = {}
    for link in links.keys():
        domain = urlparse(link).netloc
        extracted = tldextract.extract(domain)
        subdomains = sub_domain(f"{extracted.domain}.{extracted.suffix}")
        subdomain_info[domain] = subdomains
        for sub in subdomains:
            print(f"Subdomain: {sub['subdomain']}, Status Code: {sub.get('status_code')}, Title: {sub.get('title')}, IP: {sub.get('ip')}")
            
    ip_info = {}
    for domain, subdomains in subdomain_info.items():
        for sub in subdomains:
            ip = sub.get('ip')
            if ip:
                open_ports = scan_ports(ip)
                ip_info[ip] = open_ports
                print(f"IP: {ip}, Open Ports: {open_ports}")

    emails_phones = []
    for link in links.keys():
        try:
            response = requests.get(link)
            response.raise_for_status()
            emails, phones = extract_emails_and_phones(response.text)
            emails_phones.append({'link': link, 'emails': emails, 'phones': phones})
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving emails and phones from {link}: {e}")

    print("Found emails and phones:")
    for item in emails_phones:
        print(f"URL: {item['link']}, Emails: {item['emails']}, Phones: {item['phones']}")

    whois_info = {}
    for domain in subdomain_info.keys():
        whois_info[domain] = get_whois_info(domain)

if __name__ == "__main__":
    main()
