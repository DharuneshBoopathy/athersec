import argparse
import urllib.request
import urllib.parse
import json
import concurrent.futures
import sys
import time

DEFAULT_WORDLIST = [
    "robots.txt",
    ".git/config",
    ".env",
    "wp-config.php",
    "config.php",
    "config.bak",
    "backup.sql",
    "backup.zip",
    "db.sql",
    "admin/",
    "administrator/",
    "login/",
    "login.php",
    "dashboard/",
    "phpmyadmin/",
    "cpanel/",
    "api/",
    "api/v1/",
    "test/",
    "dev/",
    "staging/",
    "uploads/",
    "xmlrpc.php",
    "server-status",
    "info.php",
    "phpinfo.php",
    "readme.html",
    "license.txt",
    "setup.php",
    "install.php",
    "index.php.bak",
    "docker-compose.yml",
    ".htaccess",
    "sitemap.xml",
    "console/",
    "webconsole/",
    "config.json",
    "package.json",
    "composer.json"
]

def format_url(target, path):
    """Ensure target URL and path combine correctly."""
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    
    # Make sure target doesn't end with slash if path starts with it
    if target.endswith("/") and path.startswith("/"):
        return target[:-1] + path
    elif not target.endswith("/") and not path.startswith("/"):
        return target + "/" + path
    else:
        return target + path

def check_endpoint(target, path, timeout=3.0, user_agent=None):
    """Check a single endpoint by sending a GET/HEAD request."""
    url = format_url(target, path)
    if not user_agent:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) bug-hunter/1.0"
        
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": user_agent}
    )
    
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            length = len(response.read())
            r_time = round((time.time() - start_time) * 1000, 2)
            return {
                "path": path,
                "url": url,
                "status": status,
                "length": length,
                "time_ms": r_time,
                "found": True,
                "message": "Available"
            }
    except urllib.error.HTTPError as e:
        r_time = round((time.time() - start_time) * 1000, 2)
        # We still care about redirects, auth required, forbidden
        status = e.code
        # Read content if possible to get length
        try:
            length = len(e.read())
        except Exception:
            length = 0
            
        found = status in [200, 301, 302, 307, 401, 403, 500]
        
        return {
            "path": path,
            "url": url,
            "status": status,
            "length": length,
            "time_ms": r_time,
            "found": found,
            "message": f"HTTP Error {status}" if not found else "Discovered"
        }
    except Exception as e:
        return {
            "path": path,
            "url": url,
            "status": 0,
            "length": 0,
            "time_ms": 0,
            "found": False,
            "message": str(e)
        }

def run_fuzzer(target, wordlist=None, threads=10, timeout=3.0, user_agent=None):
    """Run fuzzer concurrently against the wordlist."""
    if not wordlist:
        wordlist = DEFAULT_WORDLIST
        
    results = []
    print(f"[*] Starting fuzzing on {target} with {len(wordlist)} paths (Threads: {threads})...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Create a map of future to path
        future_to_path = {
            executor.submit(check_endpoint, target, path, timeout, user_agent): path 
            for path in wordlist
        }
        
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                result = future.result()
                if result["found"]:
                    results.append(result)
                    print(f"  [+] Found: /{path} - Status: {result['status']} (Size: {result['length']} bytes)")
            except Exception as exc:
                print(f"  [-] /{path} generated an exception: {exc}")
                
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Directory and Endpoint Fuzzer")
    parser.add_argument("target", help="Target base URL or domain")
    parser.add_argument("--wordlist", help="Path to custom wordlist file")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=float, default=3.0, help="Request timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Output only in JSON format")
    
    args = parser.parse_args()
    
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        except Exception as e:
            print(f"[-] Error reading wordlist file: {e}. Using default list.")
            
    fuzz_results = run_fuzzer(
        args.target, 
        wordlist=wordlist, 
        threads=args.threads, 
        timeout=args.timeout
    )
    
    if args.json:
        # Clear stdout print and output pure JSON
        sys.stdout = sys.__stdout__
        print(json.dumps(fuzz_results, indent=4))
    else:
        print("\n" + "="*50)
        print(f"FUZZING COMPLETED. {len(fuzz_results)} ENDPOINTS DISCOVERED.")
        print("="*50)
        for r in fuzz_results:
            print(f"  /{r['path']:<20} | Status: {r['status']:<3} | Size: {r['length']:<6} bytes | RTT: {r['time_ms']}ms")
        print("="*50)
