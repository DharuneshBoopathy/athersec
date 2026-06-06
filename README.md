# Bug Hunting Suite - Cyber Security Major Project

An advanced, locally hosted Bug Hunting and Reconnaissance dashboard designed for identifying security vulnerabilities on Open Bug Bounty targets. This tool automates the initial reconnaissance, directory fuzzing, and security header scanning, while facilitating responsible disclosure through pre-formatted vulnerability report generation.

## Features
- **Reconnaissance Engine (`scripts/recon.py`)**: Performs passive DNS analysis, SSL/TLS certificate details extraction, HTTP security header audits (CSP, XSTS, X-Frame-Options), and basic port scanning.
- **Directory & Parameter Fuzzer (`scripts/fuzzer.py`)**: Searches for hidden endpoints, directories, backup files, and administrative panels using customizable wordlists.
- **Local Integration Server (`server.py`)**: Runs a lightweight API server to execute scans and return JSON results to the frontend.
- **Sleek Web Dashboard (`index.html`)**: A modern, glassmorphic, responsive user interface to manage target domains, view live scan logs, examine visual vulnerability severity badges, and export ready-to-use bug reports.

## Getting Started

### Prerequisites
- Python 3.x

### Running the Suite
1. Run the local Python integration server:
   ```bash
   python server.py
   ```
2. Open the dashboard in your browser. The server will host it at:
   ```
   http://localhost:8000
   ```

## Ethical & Legal Guidelines
When conducting bug hunting on Open Bug Bounty targets, you must strictly follow these rules:
1. **Scope Only**: Only hunt on targets listed as active program participants.
2. **Non-Intrusive**: Avoid performing denial of service (DoS), massive automated brute forcing, or destructive exploits.
3. **Coordinated Disclosure**: Report all findings through the Open Bug Bounty platform. Do not publicly disclose vulnerabilities before they are patched.
4. **No Data Theft**: Do not download sensitive user data. Stop testing once a vulnerability is verified.
