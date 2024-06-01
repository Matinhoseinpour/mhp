import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import dns.resolver
import tldextract
import socket
import whois
import argparse
import re

# Initialize sets and dictionary to keep track of links
links1 = set()
links2 = set()
links = {}

# List of domains to exclude (e.g., social media)
exclude_domains = ["twitter.com", "facebook.com", "instagram.com", "youtube.com", "t.me"]

# Function to check sitemap status and collect links
def sitemap_status(user_url: str):
    try:
        response = requests.get(user_url, timeout=10)
        response.raise_for_status()
        html_content = response.content
        soup = BeautifulSoup(html_content, 'html.parser')

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full = urljoin(user_url, href)
            domain = urlparse(full).netloc
            if full.startswith('http') and full not in links1 and domain not in exclude_domains:
                links1.add(full)
                links[full] = 1

        for link in links1:
            try:
                response = requests.get(link, timeout=10)
                response.raise_for_status()
                html_content = response.content
                soup = BeautifulSoup(html_content, 'html.parser')

                for sublink in soup.find_all('a', href=True):
                    href = sublink.get('href')
                    full = urljoin(link, href)
                    domain = urlparse(full).netloc
                    if full.startswith('http') and full not in links2 and domain not in exclude_domains:
                        links2.add(full)
                        links[full] = 2

            except requests.exceptions.RequestException as e:
                print(f"Error in receiving information from the link: {e}")

    except requests.exceptions.RequestException as e:
        print(f"Error in receiving information from the user_url: {e}")
        
    with open('links.txt', "w", encoding='utf-8') as file:
        for link, depth in links.items():
            file.write(f"{link} at depth {depth} \n")
            
    return links2

# Function to get status code and title of a URL
def status_code_and_title(url: str):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string.strip() if soup.title else 'No title found'
        status = response.status_code
        return status, title
    except requests.exceptions.RequestException as e:
        print(f"Error fetching status code for {url}: {e}")
        return None, None

# Function to find subdomains
def sub_domain(domain: str):
    data = []
    for subdomain in subs:
        try:
            answers = dns.resolver.resolve(f"{subdomain}.{domain}", "A")
            for ip in answers:
                data.append(f"{subdomain}.{domain}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            print(f"Error in processing the subdomain: {e}")
    return data

# Function to get IP address of a domain
def get_ip(domain: str):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error processing IP for {domain}: {e}")
        return None

# Function to scan common ports
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
        print(f"Error in process of ports for {ip}: {e}")
    return open_ports

# Function to get WHOIS information
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

# Function to find emails and phones in content
def find_emails_and_phones(content):
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)
    phones = re.findall(r"\+?\d[\d -]{8,}\d", content)
    return emails, phones

# Main function to run the process
def main():
    with open('subdomains_http_code_title.txt', 'w', encoding='utf-8') as file1, \
         open('subdomains_ip.txt', 'w', encoding='utf-8') as file2, \
         open('ip_open_ports.txt', 'w', encoding='utf-8') as file3, \
         open('emails_phones.txt', 'w', encoding='utf-8') as file4:
        
        for link in links2:
            domain = urlparse(link).netloc
            extracted = tldextract.extract(domain)
            subdomains = sub_domain(f"{extracted.domain}.{extracted.suffix}")
            for sub in subdomains:
                status, title = status_code_and_title(f"https://{sub}")
                if status and title:
                    file1.write(f"{sub} - HTTP {status} - Title: {title}\n")
                
                ip_address = get_ip(sub)
                if ip_address:
                    file2.write(f"{sub} - IP: {ip_address}\n")
                    open_ports = scan_ports(ip_address)
                    if open_ports:
                        file3.write(f"{ip_address} - Open Ports: {', '.join(map(str, open_ports))}\n")
            
            try:
                response = requests.get(link, timeout=10)
                response.raise_for_status()
                emails, phones = find_emails_and_phones(response.text)
                if emails:
                    file4.write(f"Emails found in {link}: {', '.join(emails)}\n")
                if phones:
                    file4.write(f"Phones found in {link}: {', '.join(phones)}\n")
            except requests.exceptions.RequestException as e:
                print(f"Error fetching content from {link}: {e}")
            
            whois_info = get_whois_info(domain)
            for key, value in whois_info.items():
                file4.write(f"{key}: {value}\n")

if __name__ == "__main__":
    # Load subdomains from the file
    with open("subdomains.txt", "r") as file:
        subs = file.read().splitlines()
    
    # Argument parser setup
    parser = argparse.ArgumentParser(description='Crawl websites and collect information.')
    parser.add_argument('urls', nargs='+', help='URLs of the websites to crawl')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Depth of crawling (default: 2)')
    args = parser.parse_args()
    
    for url in args.urls:
        print(f"Processing URL: {url}")
        sitemap_status(url)
    
    main()
