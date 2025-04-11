import requests
import logging

# Set up logging
logging.basicConfig(filename='scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityScanner:
    def __init__(self):
        self.target_url = ""
        self.vulnerabilities = []

    def set_target_url(self):
        self.target_url = input("Enter the URL to scan for vulnerabilities: ")

    def subdomain_enumeration(self):
        subdomains = ["www", "api", "dev", "test", "staging"]
        found_subdomains = []
        for subdomain in subdomains:
            url = f"http://{subdomain}.{self.target_url}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    found_subdomains.append(url)
                    self.vulnerabilities.append(f"Subdomain found: {url}")
                    logging.info(f"Subdomain found: {url}")
            except requests.exceptions.RequestException:
                continue
        if found_subdomains:
            print("Subdomains discovered:")
            for sub in found_subdomains:
                print(f"- {sub}")

    def scan(self):
        self.subdomain_enumeration()
        while True:
            self.display_menu()
            choice = input("Enter your choice (1-9): ")
            if choice == "1":
                self.scan_xss()
            elif choice == "2":
                self.scan_sql_injection()
            elif choice == "3":
                self.scan_directory_traversal()
            elif choice == "4":
                self.scan_command_injection()
            elif choice == "5":
                self.scan_server_misconfiguration()
            elif choice == "6":
                self.scan_weak_passwords()
            elif choice == "7":
                self.scan_network_vulnerabilities()
            elif choice == "8":
                self.scan_web_application_security()
            elif choice == "9":
                break
            else:
                print("Invalid choice. Please try again.")

    # ... [rest of the methods remain unchanged]

    def report_vulnerabilities(self):
        if self.vulnerabilities:
            print("\nVulnerabilities found:")
            for vulnerability in self.vulnerabilities:
                print("- " + vulnerability)
                logging.info(f"Vulnerability found: {vulnerability}")
        else:
            print("\nNo vulnerabilities found")
            logging.info("No vulnerabilities found")
