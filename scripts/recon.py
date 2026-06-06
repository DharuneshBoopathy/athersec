import argparse
import socket
import ssl
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT"
}

def clean_target(target):
    """Extract clean domain name from target input."""
    target = target.strip()
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]
    
    # Remove paths, queries, ports
    target = target.split("/")[0]
    target = target.split(":")[0]
    return target

def fetch_dns_records(domain):
    """Fetch DNS records using Google's DNS-over-HTTPS API to avoid module dependency."""
    records = {}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
    
    for r_type in record_types:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={r_type}"
            req = urllib.request.Request(
                url, 
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                if "Answer" in data:
                    records[r_type] = [ans["data"] for ans in data["Answer"]]
        except Exception as e:
            records[r_type] = [f"Error fetching: {str(e)}"]
    return records

def scan_ports(ip):
    """Scan standard ports using socket connections."""
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append({"port": port, "service": service, "status": "open"})
            s.close()
        except Exception:
            pass
    return open_ports

def audit_security_headers(domain):
    """Fetch HTTP headers and analyze security posture."""
    url = f"https://{domain}"
    results = {
        "headers": {},
        "analysis": {}
    }
    
    # Define headers we want to audit
    security_headers = {
        "Content-Security-Policy": "Mitigates XSS and data injection attacks",
        "Strict-Transport-Security": "Enforces HTTPS connections",
        "X-Frame-Options": "Prevents Clickjacking",
        "X-Content-Type-Options": "Prevents MIME-sniffing",
        "Referrer-Policy": "Controls referrer information passed",
        "Permissions-Policy": "Restricts browser features (camera, geoloc, etc.)"
    }

    try:
        req = urllib.request.Request(
            url, 
            method="HEAD",
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) security-audit/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = {k.title(): v for k, v in response.info().items()}
            results["headers"] = headers
            
            for header, desc in security_headers.items():
                if header in headers:
                    results["analysis"][header] = {
                        "present": True,
                        "value": headers[header],
                        "status": "secure",
                        "description": desc
                    }
                else:
                    results["analysis"][header] = {
                        "present": False,
                        "value": None,
                        "status": "missing",
                        "description": desc
                    }
            
            # Server information disclosures
            server_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            results["disclosures"] = {}
            for sh in server_headers:
                if sh in headers:
                    results["disclosures"][sh] = headers[sh]
    except Exception as e:
        # Fallback to HTTP if HTTPS fails
        if not url.startswith("http://"):
            try:
                url_http = f"http://{domain}"
                req = urllib.request.Request(
                    url_http, 
                    method="HEAD",
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    headers = {k.title(): v for k, v in response.info().items()}
                    results["headers"] = headers
                    for header, desc in security_headers.items():
                        if header in headers:
                            results["analysis"][header] = {"present": True, "value": headers[header], "status": "secure", "description": desc}
                        else:
                            results["analysis"][header] = {"present": False, "value": None, "status": "missing", "description": desc}
            except Exception as ex:
                results["error"] = f"Failed to connect: {str(ex)}"
        else:
            results["error"] = f"Failed to connect: {str(e)}"
            
    return results

def get_ssl_details(domain):
    """Retrieve SSL/TLS certificate details."""
    context = ssl.create_default_context()
    results = {}
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Expiry conversion
                not_after_str = cert.get('notAfter')
                not_before_str = cert.get('notBefore')
                
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    results['expiry'] = not_after.isoformat()
                    results['days_left'] = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
                if not_before_str:
                    not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    results['issued'] = not_before.isoformat()
                
                results['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                results['subject'] = dict(x[0] for x in cert.get('subject', []))
                results['version'] = ssock.version()
                results['cipher'] = ssock.cipher()
    except Exception as e:
        results['error'] = f"SSL lookup failed: {str(e)}"
    return results

def get_geoip_details(ip):
    """Fetch location details for IP."""
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return {"status": "fail", "message": "Failed to retrieve IP metadata"}

def run_recon(target):
    domain = clean_target(target)
    
    # Resolve IP
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return {"error": f"Could not resolve domain: {str(e)}", "target": domain}
        
    print(f"[*] Starting Passive Recon on target: {domain} ({ip})")
    dns_info = fetch_dns_records(domain)
    ssl_info = get_ssl_details(domain)
    headers_info = audit_security_headers(domain)
    geoip_info = get_geoip_details(ip)
    
    print(f"[*] Starting Active Port Scan on: {ip}...")
    ports_info = scan_ports(ip)
    
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": domain,
        "ip": ip,
        "dns": dns_info,
        "ssl": ssl_info,
        "headers": headers_info,
        "geoip": geoip_info,
        "open_ports": ports_info
    }
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Active and Passive Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--json", action="store_true", help="Output only in JSON format")
    
    args = parser.parse_args()
    
    recon_data = run_recon(args.target)
    
    if args.json or "error" in recon_data:
        print(json.dumps(recon_data, indent=4))
    else:
        print("\n" + "="*50)
        print(f"RECON REPORT FOR: {recon_data['target']} ({recon_data['ip']})")
        print("="*50)
        
        print("\n[+] GeoIP Info:")
        g = recon_data['geoip']
        if g.get('status') == 'success':
            print(f"    Country: {g.get('country')} ({g.get('countryCode')})")
            print(f"    Region/City: {g.get('regionName')} / {g.get('city')}")
            print(f"    ISP: {g.get('isp')}")
        else:
            print("    Failed to fetch GeoIP data.")
            
        print("\n[+] DNS Records:")
        for r_type, records in recon_data['dns'].items():
            if records:
                print(f"    {r_type}:")
                for r in records:
                    print(f"      - {r}")
                    
        print("\n[+] SSL Details:")
        ssl_d = recon_data['ssl']
        if 'error' not in ssl_d:
            print(f"    Issuer: {ssl_d['issuer'].get('organizationName', 'N/A')}")
            print(f"    Valid To: {ssl_d.get('expiry')} ({ssl_d.get('days_left')} days left)")
            print(f"    Cipher: {ssl_d.get('cipher')}")
        else:
            print(f"    {ssl_d['error']}")
            
        print("\n[+] Security Headers Analysis:")
        h_info = recon_data['headers']
        if 'error' not in h_info:
            for header, details in h_info['analysis'].items():
                status_icon = "[SECURE]" if details['status'] == 'secure' else "[MISSING]"
                print(f"    {status_icon} {header}: {details['value'] if details['value'] else 'Not Set'}")
            if 'disclosures' in h_info and h_info['disclosures']:
                print("\n[!] Disclosed Software Headers:")
                for sh, val in h_info['disclosures'].items():
                    print(f"    - {sh}: {val}")
        else:
            print(f"    {h_info['error']}")
            
        print("\n[+] Open Ports:")
        if recon_data['open_ports']:
            for port_info in recon_data['open_ports']:
                print(f"    - Port {port_info['port']} ({port_info['service']}) - OPEN")
        else:
            print("    No standard ports open (filtered/closed).")
        print("\n" + "="*50)
