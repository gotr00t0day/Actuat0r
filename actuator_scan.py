from colorama import Fore, init, ansi
import requests
import argparse
import concurrent.futures
import threading
from tqdm import tqdm
import urllib.parse
import sys
import os
import time

# Initialize colorama with autoreset=True
init(autoreset=True)

banner = r"""


   _____          __                __   _______         
  /  _  \   _____/  |_ __ _______ _/  |_ \   _  \_______ 
 /  /_\  \_/ ___\   __\  |  \__  \\   __\/  /_\  \_  __ \
/    |    \  \___|  | |  |  // __ \|  |  \  \_/   \  | \/
\____|__  /\___  >__| |____/(____  /__|   \_____  /__|   
        \/     \/                \/             \/ by c0d3Ninja   

"""

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Spring Boot Actuator Scanner - Detects exposed actuator endpoints")
parser.add_argument("-u", "--url", type=str, required=True, help="Target URL")
parser.add_argument("-w", "--wordlist", type=str, help="Custom wordlist for additional endpoints")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
parser.add_argument("-b", "--bypass", action="store_true", help="Enable WAF bypass techniques using URL encoding")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
args = parser.parse_args()

api_endpoints = [
    "/v1/actuator/heapdump",
    "/v1/actuator/prometheus",
    "/v1/actuator/metrics",
    "/v1/actuator/info",
    "/v1/actuator/health",
    "/v1/actuator/threaddump",
    "/v1/actuator/mappings",
    "/v1/actuator/conditions",
    "/v1/actuator/httptrace",
    "/v1/actuator/auditevents",
    "/v1/actuator/env",
    "/v1/actuator/beans",
    "/v1/actuator/caches",
    "/v2/actuator/heapdump",
    "/v2/actuator/prometheus",
    "/v2/actuator/metrics",
    "/v2/actuator/info",
    "/v2/actuator/health",
    "/v2/actuator/threaddump",
    "/v2/actuator/mappings",
    "/v2/actuator/conditions",
    "/v2/actuator/httptrace",
    "/v2/actuator/auditevents",
    "/v2/actuator/env",
    "/v2/actuator/beans",
    "/v2/actuator/caches",
    "/v2/actuator/scheduledtasks",
    "/v2/actuator/sessions",
    "/v2/actuator/shutdown",
    "/v2/actuator/trace"
]


actuator_endpoints = [
    "/actuator/heapdump",
    "/actuator/prometheus",
    "/actuator/metrics",
    "/actuator/info",
    "/actuator/health",
    "/actuator/logfile",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/actuator/mappings",
    "/actuator/conditions",
    "/actuator/httptrace",
    "/actuator/auditevents",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/caches",
    "/actuator/scheduledtasks",
    "/actuator/sessions",
    "/actuator/shutdown",
    "/actuator/threaddump",
    "/actuator/trace"
]

# Generate encoded variations of endpoints for WAF bypass
def generate_encoded_variations(endpoint):
    variations = [endpoint]  # Original endpoint
    
    # Standard URL encoding
    variations.append(urllib.parse.quote(endpoint))
    
    # Double URL encoding
    variations.append(urllib.parse.quote(urllib.parse.quote(endpoint)))
    
    # Partial URL encoding (encode only slashes)
    variations.append(endpoint.replace("/", "%2F"))
    
    # Partial URL encoding (encode only 'actuator')
    if 'actuator' in endpoint:
        variations.append(endpoint.replace("actuator", "%61%63%74%75%61%74%6F%72"))
    
    # Mixed case variations with encoding
    if 'actuator' in endpoint:
        mixed_case = endpoint.replace("actuator", "AcTuAtOr")
        variations.append(mixed_case)
        variations.append(urllib.parse.quote(mixed_case))
    
    return variations

# Try finding directory and filenames to use for actuator endpoints
def check_endpoint(url, endpoint):
    s = requests.Session()
    try:
        # Fix URL construction to avoid double slashes
        if endpoint.startswith('/'):
            endpoint = endpoint[1:]  # Remove leading slash from endpoint
        
        # Ensure URL doesn't end with a slash before joining
        if url.endswith('/'):
            url = url[:-1]  # Remove trailing slash from URL
            
        full_url = f"{url}/{endpoint}"
        
        # First try HEAD request
        r = s.head(full_url, verify=False, timeout=5)
        if r.status_code == 200:
            return full_url
            
        # If HEAD fails, try GET request
        r = s.get(full_url, verify=False, timeout=5)
        if r.status_code == 200:
            return full_url
    except Exception:
        pass
    return None

# Function to create a fixed status bar at the bottom of the terminal
class FixedStatusBar:
    def __init__(self, total, desc=""):
        # Create a progress bar that stays at the bottom
        self.pbar = tqdm(total=total, desc=desc, leave=True, position=0)
        
    def update(self, n=1):
        # Update progress bar directly for each endpoint
        self.pbar.update(n)
        
    def print_above(self, message):
        # Print the message above the progress bar
        tqdm.write(message)
        
    def close(self):
        self.pbar.close()

def wordlist(file: str) -> list:
    try:
        with open(file, 'r') as f:
            dirs = [x.strip() for x in f.readlines()]
            return dirs
    except Exception as e:
        print(f"{Fore.RED}Error reading wordlist file: {e}{Fore.WHITE}")
        sys.exit(1)

def dirbrute_endpoints(url: str, file: str, threads=10, bypass=False) -> list:
    endpoints = wordlist(file)
    results = []
    all_endpoints = []
    
    # Generate encoded variations if bypass mode is enabled
    if bypass:
        for endpoint in endpoints:
            all_endpoints.extend(generate_encoded_variations(endpoint))
        print(f"{Fore.CYAN}Brute forcing endpoints with WAF bypass (URL encoding) using {threads} threads...{Fore.WHITE}")
    else:
        all_endpoints = endpoints
        print(f"{Fore.CYAN}Brute forcing endpoints with {threads} threads...{Fore.WHITE}")
    
    # Create a set to track endpoints we've already shown in verbose mode
    scanned_endpoints = set()
    
    # Create a status bar - limit maximum displayed threads to avoid overwhelming tqdm
    display_threads = min(threads, 10)
    
    # Use a lock to prevent concurrent progress bar updates
    update_lock = threading.Lock()
    
    with tqdm(total=len(all_endpoints), desc="Scanning endpoints", leave=True) as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_endpoint = {executor.submit(check_endpoint, url, endpoint): endpoint for endpoint in all_endpoints}
            
            for future in concurrent.futures.as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    # Print endpoint being scanned if verbose mode is enabled (only once per endpoint)
                    if args.verbose and endpoint not in scanned_endpoints:
                        # Fix URL construction for display
                        display_url = url
                        display_endpoint = endpoint
                        
                        if display_endpoint.startswith('/'):
                            display_endpoint = display_endpoint[1:]
                            
                        if display_url.endswith('/'):
                            display_url = display_url[:-1]
                            
                        tqdm.write(f"{Fore.BLUE}Scanning: {display_url}/{display_endpoint}{Fore.WHITE}")
                        scanned_endpoints.add(endpoint)
                    
                    result = future.result()
                    if result:
                        results.append(result)
                        tqdm.write(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                except Exception as e:
                    if args.verbose:
                        tqdm.write(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                finally:
                    with update_lock:
                        pbar.update(1)
    
    return results

def check_endpoint_for_scan(base_url, endpoint):
    s = requests.Session()
    try:
        # Fix URL construction to avoid double slashes
        if endpoint.startswith('/'):
            endpoint = endpoint[1:]  # Remove leading slash from endpoint
        
        # Ensure URL doesn't end with a slash before joining
        if base_url.endswith('/'):
            base_url = base_url[:-1]  # Remove trailing slash from URL
            
        full_url = f"{base_url}/{endpoint}"
        
        r = s.get(full_url, verify=False, timeout=5)
        if r.status_code == 200:
            return full_url
    except Exception:
        pass
    return None

def check_endpoints(url: str) -> tuple:
    if args.verbose:
        print(f"{Fore.CYAN}Checking if {url} is accessible...{Fore.WHITE}")
    
    # Store the original protocol
    protocol = "https://" if url.startswith("https://") else "http://"
    
    # Extract domain without protocol
    if "https://" in url:
        url_api = url.replace("https://", "")
    elif "http://" in url:
        url_api = url.replace("http://", "")
    elif "https://www." in url:
        url_api = url.replace("https://www.", "")
    elif "http://www." in url:
        url_api = url.replace("http://www.", "")
    else:
        url_api = url  

    if url_api.endswith("/"):
        url_api = url_api[:-1]
    
    if url.endswith("/"):
        url = url[:-1]
        
    check_api_subdomain = f"{protocol}api.{url_api}"
    
    if args.verbose:
        print(f"{Fore.CYAN}Trying base URL: {protocol}{url_api}{Fore.WHITE}")
    
    s = requests.Session()

    try:
        r = s.get(f"{protocol}{url_api}", verify=False, timeout=5)
        if r.status_code == 200:
            if args.verbose:
                print(f"{Fore.GREEN}Successfully connected to {protocol}{url_api} (Status: {r.status_code}){Fore.WHITE}")
            return True, f"{protocol}{url_api}"
        else:
            if args.verbose:
                print(f"{Fore.YELLOW}Received status code {r.status_code} from {protocol}{url_api}{Fore.WHITE}")
    except Exception as e:
        if args.verbose:
            print(f"{Fore.RED}Error checking base domain: {e}{Fore.WHITE}")
        pass
    
    if args.verbose:
        print(f"{Fore.CYAN}Trying API endpoint: {url}/api{Fore.WHITE}")
    
    try:
        r_api = s.get(f"{url}/api", verify=False, timeout=5)
        if r_api.status_code == 200:
            if args.verbose:
                print(f"{Fore.GREEN}Successfully connected to {url}/api (Status: {r_api.status_code}){Fore.WHITE}")
            return True, f"{url}/api"
        else:
            if args.verbose:
                print(f"{Fore.YELLOW}Received status code {r_api.status_code} from {url}/api{Fore.WHITE}")
    except Exception as e:
        if args.verbose:
            print(f"{Fore.RED}Error checking API endpoint: {e}{Fore.WHITE}")
        pass
    
    # If we reach here, neither the base URL nor the API endpoint is accessible
    # Let's force continue even if we couldn't verify accessibility
    if args.verbose:
        print(f"{Fore.YELLOW}Could not verify site accessibility. Continuing with scan anyway...{Fore.WHITE}")
    return True, url

def scan(url: str, threads=10, bypass=False) -> list:
    success, endpoint_url = check_endpoints(url)
    results = []
    
    if args.verbose:
        print(f"{Fore.CYAN}Scanning URL: {endpoint_url}{Fore.WHITE}")
    
    # Check if the URL contains v1 or v2
    contains_version = "v1" in endpoint_url.lower() or "v2" in endpoint_url.lower()
    
    # We'll always scan with the actuator endpoints first
    all_endpoints = []
    
    # Generate encoded variations if bypass mode is enabled
    if bypass:
        print(f"{Fore.CYAN}Checking endpoints with WAF bypass (URL encoding) using {threads} threads...{Fore.WHITE}")
        for endpoint in actuator_endpoints:
            all_endpoints.extend(generate_encoded_variations(endpoint))
    else:
        print(f"{Fore.CYAN}Checking endpoints with {threads} threads...{Fore.WHITE}")
        all_endpoints = actuator_endpoints
    
    # Create a set to track endpoints we've already shown in verbose mode
    scanned_endpoints = set()
    
    # Use a lock to prevent concurrent progress bar updates
    update_lock = threading.Lock()
    
    with tqdm(total=len(all_endpoints), desc="Scanning actuator endpoints", leave=True) as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_endpoint = {executor.submit(check_endpoint_for_scan, endpoint_url, endpoint): endpoint 
                                 for endpoint in all_endpoints}
            
            for future in concurrent.futures.as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    # Print endpoint being scanned if verbose mode is enabled (only once per endpoint)
                    if args.verbose and endpoint not in scanned_endpoints:
                        # Fix URL construction for display
                        display_url = endpoint_url
                        display_endpoint = endpoint
                        
                        if display_endpoint.startswith('/'):
                            display_endpoint = display_endpoint[1:]
                            
                        if display_url.endswith('/'):
                            display_url = display_url[:-1]
                            
                        tqdm.write(f"{Fore.BLUE}Scanning: {display_url}/{display_endpoint}{Fore.WHITE}")
                        scanned_endpoints.add(endpoint)
                        
                    result = future.result()
                    if result:
                        results.append(result)
                        tqdm.write(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                except Exception as e:
                    if args.verbose:
                        tqdm.write(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                finally:
                    with update_lock:
                        pbar.update(1)
    
    # Additionally, check for API-specific endpoints if we found an API endpoint
    if success and not contains_version and ("api." in endpoint_url or "/api" in endpoint_url):
        if args.verbose:
            print(f"{Fore.CYAN}Found API endpoint: {Fore.GREEN}{endpoint_url}{Fore.CYAN}, scanning additional API-specific paths...{Fore.WHITE}")
        
        # Check for API-specific endpoints
        api_all_endpoints = []
        
        # Generate encoded variations if bypass mode is enabled
        if bypass:
            print(f"{Fore.CYAN}Checking API endpoints with WAF bypass (URL encoding) using {threads} threads...{Fore.WHITE}")
            for endpoint in api_endpoints:
                api_all_endpoints.extend(generate_encoded_variations(endpoint))
        else:
            print(f"{Fore.CYAN}Checking API endpoints with {threads} threads...{Fore.WHITE}")
            api_all_endpoints = api_endpoints
        
        # Create a set to track endpoints we've already shown in verbose mode
        api_scanned_endpoints = set()
        
        with tqdm(total=len(api_all_endpoints), desc="Scanning API endpoints", leave=True) as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_endpoint = {executor.submit(check_endpoint_for_scan, endpoint_url, endpoint): endpoint 
                                     for endpoint in api_all_endpoints}
                
                for future in concurrent.futures.as_completed(future_to_endpoint):
                    endpoint = future_to_endpoint[future]
                    try:
                        # Print endpoint being scanned if verbose mode is enabled (only once per endpoint)
                        if args.verbose and endpoint not in api_scanned_endpoints:
                            # Fix URL construction for display
                            display_url = endpoint_url
                            display_endpoint = endpoint
                            
                            if display_endpoint.startswith('/'):
                                display_endpoint = display_endpoint[1:]
                                
                            if display_url.endswith('/'):
                                display_url = display_url[:-1]
                                
                            tqdm.write(f"{Fore.BLUE}Scanning: {display_url}/{display_endpoint}{Fore.WHITE}")
                            api_scanned_endpoints.add(endpoint)
                            
                        result = future.result()
                        if result:
                            results.append(result)
                            tqdm.write(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                    except Exception as e:
                        if args.verbose:
                            tqdm.write(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                    finally:
                        with update_lock:
                            pbar.update(1)
    
    return results

if __name__ == "__main__":
    print(banner + "\n")
    
    print(f"{Fore.CYAN}Scanning {args.url} for Spring Boot Actuator endpoints...{Fore.WHITE}")
    if args.bypass:
        print(f"{Fore.YELLOW}WAF bypass mode enabled - using URL encoding techniques{Fore.WHITE}")
    
    all_results = []
    
    actuator_results = scan(args.url, args.threads, args.bypass)
    all_results.extend(actuator_results)
    
    if args.wordlist:
        wordlist_results = dirbrute_endpoints(args.url, args.wordlist, args.threads, args.bypass)
        all_results.extend(wordlist_results)
    
    if all_results:
        print(f"\n{Fore.GREEN}Found {len(all_results)} vulnerable endpoint(s):{Fore.WHITE}")
        for result in all_results:
            print(f"{Fore.GREEN}- {result}{Fore.WHITE}")
    else:
        print(f"{Fore.RED}No vulnerable endpoints found{Fore.WHITE}")
        if not args.bypass:
            print(f"{Fore.YELLOW}Try running with the -b/--bypass flag to attempt WAF bypass with URL encoding{Fore.WHITE}")

    
    
    



