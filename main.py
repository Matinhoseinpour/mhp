import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import dns.resolver
import tldextract
import socket
import whois
import argparse
from jinja2 import Template

links1 = set()
links2 = set()
links = {}

# Argument parser
parser = argparse.ArgumentParser(description='Crawl websites and collect information.')
parser.add_argument('urls', help='Two URLs of the websites to crawl')
parser.add_argument('-d', '--depth', type=int, default=2, help='Depth of crawling (default: 2)')
args = parser.parse_args()

def sitemap_status(user_url: str):
    try:
        response = requests.get(user_url)
        response.raise_for_status()
        html_content = response.content
        soup = BeautifulSoup(html_content, 'html.parser')

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full = urljoin(user_url, href)
            if full.startswith('http') and full not in links1:
                links1.add(full)
                links[full] = 1

        for link in links1:
            try:
                response = requests.get(link)
                response.raise_for_status()
                html_content = response.content
                soup = BeautifulSoup(html_content, 'html.parser')

                for sublink in soup.find_all('a', href=True):
                    href = sublink.get('href')
                    full = urljoin(link, href)
                    if full.startswith('http') and full not in links2:
                        links2.add(full)
                        links[full] = 2

            except requests.exceptions.RequestException as e:
                print(f"Error in receiving information from the link: {e}")

    except requests.exceptions.RequestException as e:
        print(f"Error in receiving information from the user_url: {e}")

    return links2

def status_code(url: str):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"Error fetching status code: {e}")
        return None

def sub_domain(domain: str):
    data = []
    for subdomain in subs:
        try:
            answers = dns.resolver.resolve(f"{subdomain}.{domain}", "A")
            for ip in answers:
                data.append(f"https://{subdomain}.{domain}")
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            data.append(f"Error in processing the subdomain: {e}")
    return data

def get_ip(domain: str):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print("Error processing IP!")
        return None

def scan_ports(ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995]
    open_ports = []
    try:
        for port in common_ports:  
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  # Set timeout to 1 second
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
    except Exception as e:
        print(f"Error in process of ports: {e}")
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
        return whois_info
    except Exception as e:
        print(f"Error fetching WHOIS info for {domain}: {e}")
        return {}

def main():
    link_data = []
    for link in links2:
        domain = urlparse(link).netloc
        extracted = tldextract.extract(domain)
        subdomains = sub_domain(f"{extracted.domain}.{extracted.suffix}")
        ip_address = get_ip(domain)
        open_ports = scan_ports(ip_address) if ip_address else []
        whois_info = get_whois_info(domain)

        link_info = {
            "URL": link,
            "status_code": status_code(link),
            "ip_address": ip_address,
            "open_ports": open_ports,
            "whois_info": whois_info
        }
        link_data.append(link_info)
    
    with open('matin.html', 'r') as file:
        template = Template(file.read())

    html_content = template.render(results=link_data)

    with open('matin.html', 'w') as file:
        file.write(html_content)

if __name__ == "__main__":
    # Load subdomains from the file
    with open("subdomains.txt", "r") as file:
        subs = file.read().splitlines()

    print(sitemap_status(args.urls))
    main()
