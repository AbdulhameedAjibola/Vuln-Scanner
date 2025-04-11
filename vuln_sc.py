import requests
import re
import json
import pdfkit
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from collections import deque
import logging

# Configure logging
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class WebScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.crawled_urls = deque()
        self.vulnerabilities = []
        self.session = requests.Session()
    
    def crawl(self):
        logging.info("Starting crawl process")
        self.crawled_urls.append(self.base_url)
        
        while self.crawled_urls:
            url = self.crawled_urls.popleft()
            if url in self.visited_urls:
                continue
            self.visited_urls.add(url)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    for link in soup.find_all("a", href=True):
                        full_url = urljoin(url, link["href"])
                        if self.base_url in full_url and full_url not in self.visited_urls:
                            self.crawled_urls.append(full_url)
                    for form in soup.find_all("form"):
                        form_action = form.get("action")
                        form_url = urljoin(url, form_action) if form_action else url
                        self.crawled_urls.append(form_url)
            except Exception as e:
                logging.error(f"Error crawling {url}: {e}")
        logging.info("Crawling completed")

    def test_xss(self, url):
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        try:
            for payload in payloads:
                response = self.session.get(url, params={"q": payload})
                if payload in response.text:
                    self.vulnerabilities.append({"url": url, "vulnerability": "XSS", "payload": payload})
                    logging.warning(f"XSS detected on {url} with payload {payload}")
        except Exception as e:
            logging.error(f"Error testing XSS on {url}: {e}")

    def test_sql_injection(self, url):
        payloads = ["' OR '1'='1", "' UNION SELECT null, username, password FROM users--"]
        try:
            for payload in payloads:
                response = self.session.get(url, params={"id": payload})
                if "error in your SQL syntax" in response.text.lower():
                    self.vulnerabilities.append({"url": url, "vulnerability": "SQL Injection", "payload": payload})
                    logging.warning(f"SQL Injection detected on {url} with payload {payload}")
        except Exception as e:
            logging.error(f"Error testing SQL Injection on {url}: {e}")
    
    def run_scans(self):
        logging.info("Starting security scans")
        for url in self.visited_urls:
            self.test_xss(url)
            self.test_sql_injection(url)
        logging.info("Scanning completed")
    
    def generate_report(self, format="json"):
        if format == "json":
            with open("scan_report.json", "w") as f:
                json.dump(self.vulnerabilities, f, indent=4)
        elif format == "html":
            with open("scan_report.html", "w") as f:
                f.write("<html><body><h1>Scan Report</h1><ul>")
                for vuln in self.vulnerabilities:
                    f.write(f"<li>{vuln['url']} - {vuln['vulnerability']} - Payload: {vuln['payload']}</li>")
                f.write("</ul></body></html>")
        elif format == "pdf":
            pdfkit.from_string(str(self.vulnerabilities), "scan_report.pdf")
        logging.info(f"Report generated in {format} format")

if __name__ == "__main__":
    target_url = input("Enter the website URL to scan: ")
    scanner = WebScanner(target_url)
    scanner.crawl()
    scanner.run_scans()
    scanner.generate_report("html")
