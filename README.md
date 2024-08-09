# Web Vulnerability Scanner

A powerful tool designed for ethical hackers and cybersecurity professionals to detect and analyze web vulnerabilities such as XSS, SQL Injection, and File Path Traversal. This tool helps identify potential security flaws in websites, ensuring they remain secure and protected against cyber threats.

## Features

- **XSS Vulnerability Detection:** Scans websites for Cross-Site Scripting (XSS) vulnerabilities that allow attackers to inject malicious scripts.
- **SQL Injection Detection:** Identifies SQL Injection (SQLi) vulnerabilities to prevent unauthorized database access.
- **File Path Traversal Detection:** Checks for file path traversal vulnerabilities that expose restricted files or directories.
- **Custom URL Scanning:** Use the `-u` flag to scan specific URLs for targeted analysis.
- **Select Vulnerability Type:** Use the `-t` flag to choose which vulnerability type to scan, such as XSS or SQLi.
- **Dork-Based Site Discovery:** Use the `-d` flag to input dorks, discovering potential sites for vulnerability scans.

## Installation and Usage

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/zeroXyaser/Vscan.git
    cd Vscan
    ```

2. **Install Dependencies and Run the Tool:**

    ```bash
    python3 Vscan.py
    ```

3. **Perform Scanning:**

    Use the following command to start scanning:

    ```bash
    python3 scanner.py -u <target-url> -t <vulnerability-type> -d <dork>
    ```

    Replace `<target-url>` with the URL of the target website, `<vulnerability-type>` with the type of vulnerability you want to scan for (e.g., `xss` or `sql`), and `<dork>` with any dork queries you wish to use for site discovery.
