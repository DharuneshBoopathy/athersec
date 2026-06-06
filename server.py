import http.server
import socketserver
import urllib.parse
import json
import os
import sys

# Add scripts directory to path to enable direct importing
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))

try:
    from recon import run_recon
    from fuzzer import run_fuzzer
except ImportError as e:
    print(f"Warning: importing recon/fuzzer failed locally: {e}. Subprocesses will be used if needed.")
    run_recon = None
    run_fuzzer = None

PORT = 8000

class BugHuntingAPIHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers to make testing robust
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        # Route API requests
        if path == "/api/scan":
            self.handle_scan_api(query)
        elif path == "/api/fuzz":
            self.handle_fuzz_api(query)
        else:
            # Fallback to serving static files
            super().do_GET()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/report":
            self.handle_report_api()
        else:
            self.send_error(404, "Endpoint not found")

    def handle_scan_api(self, query):
        if "target" not in query or not query["target"][0]:
            self.send_json_response({"error": "Target parameter is required"}, 400)
            return

        target = query["target"][0]
        print(f"[API] Scan requested for target: {target}")

        try:
            if run_recon:
                data = run_recon(target)
            else:
                # Fallback to running as subprocess
                import subprocess
                import sys
                cmd = [sys.executable, "scripts/recon.py", target, "--json"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                data = json.loads(proc.stdout)
            
            self.send_json_response(data)
        except Exception as e:
            self.send_json_response({"error": f"Scan failed: {str(e)}"}, 500)

    def handle_fuzz_api(self, query):
        if "target" not in query or not query["target"][0]:
            self.send_json_response({"error": "Target parameter is required"}, 400)
            return

        target = query["target"][0]
        print(f"[API] Fuzzing requested for target: {target}")

        try:
            if run_fuzzer:
                data = run_fuzzer(target)
            else:
                import subprocess
                import sys
                cmd = [sys.executable, "scripts/fuzzer.py", target, "--json"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                data = json.loads(proc.stdout)
            
            self.send_json_response(data)
        except Exception as e:
            self.send_json_response({"error": f"Fuzzing failed: {str(e)}"}, 500)

    def handle_report_api(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            report_info = json.loads(post_data.decode('utf-8'))

            target = report_info.get("target", "unknown_target")
            vuln_type = report_info.get("vuln_type", "Vulnerability")
            severity = report_info.get("severity", "Medium")
            payload = report_info.get("payload", "N/A")
            description = report_info.get("description", "")
            remediation = report_info.get("remediation", "")

            # Make report file name friendly
            safe_target = "".join(c for c in target if c.isalnum() or c in ['.', '_', '-']).rstrip()
            os.makedirs("reports", exist_ok=True)
            report_filename = f"reports/{safe_target}_vuln_report.md"

            report_content = f"""# Open Bug Bounty Vulnerability Disclosure Report

**Report Date**: {report_info.get('date', 'N/A')}  
**Target Domain**: {target}  
**Vulnerability Type**: {vuln_type}  
**Severity**: {severity}  

---

## 1. Description of the Vulnerability
{description}

---

## 2. Proof of Concept (PoC)
### Payload:
```
{payload}
```

### Steps to Reproduce:
1. Targets: `{target}`
2. Trigger details/actions:
   - Perform query using the payload above.
   - Verify vulnerability triggers.

---

## 3. Impact
Potential impact includes unauthorized action execution, session takeover, site defacement, or credential exposure depending on client details.

---

## 4. Recommended Remediation
{remediation}

---
**Reported via Open Bug Bounty Coordinated Disclosure Platform.**
"""

            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(report_content)

            self.send_json_response({
                "success": True,
                "file_path": report_filename,
                "content": report_content
            })

        except Exception as e:
            self.send_json_response({"error": f"Failed to save report: {str(e)}"}, 500)

    def send_json_response(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        response_bytes = json.dumps(data).encode('utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

def run_server():
    # Make sure we change dir to server root if we run it from subdirs
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Enable socket re-use to prevent "Address already in use" errors on restarts
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), BugHuntingAPIHandler) as httpd:
        print(f"[*] Bug Hunting Integration Server running on port {PORT}")
        print(f"[*] Open http://localhost:{PORT}/ in your browser to view the Dashboard.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Server shutting down.")

if __name__ == "__main__":
    run_server()
