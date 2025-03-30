from colorama import Fore
import requests
import argparse
import concurrent.futures
from tqdm import tqdm
requests.packages.urllib3.disable_warnings()

banner = """


   _____          __                __   _______         
  /  _  \   _____/  |_ __ _______ _/  |_ \   _  \_______ 
 /  /_\  \_/ ___\   __\  |  \__  \\   __\/  /_\  \_  __ \
/    |    \  \___|  | |  |  // __ \|  |  \  \_/   \  | \/
\____|__  /\___  >__| |____/(____  /__|   \_____  /__|   
        \/     \/                \/             \/ by c0d3Ninja   

"""

args = argparse.ArgumentParser()
args.add_argument("-u", "--url", type=str, required=True)
args.add_argument("-w", "--wordlist", type=str)
args.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
args = args.parse_args()

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

def wordlist(file: str) -> list:
    with open(file, 'r') as f:
        dirs = [x.strip() for x in f.readlines()]
        return dirs

def check_endpoint(url, endpoint):
    s = requests.Session()
    try:
        r = s.head(f"{url}/{endpoint}", verify=False, timeout=5)
        if r.status_code == 200:
            return f"{url}/{endpoint}"
    except Exception:
        pass
    return None

def dirbrute_endpoints(url: str, file: str, threads=10) -> list:
    endpoints = wordlist(file)
    results = []
    
    print(f"{Fore.CYAN}Brute forcing endpoints with {threads} threads...{Fore.WHITE}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_endpoint = {executor.submit(check_endpoint, url, endpoint): endpoint for endpoint in endpoints}
        
        with tqdm(total=len(endpoints), desc="Scanning endpoints") as pbar:
            for future in concurrent.futures.as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        print(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                except Exception as e:
                    print(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                finally:
                    pbar.update(1)
    
    return results

def check_endpoint_for_scan(base_url, endpoint):
    s = requests.Session()
    try:
        r = s.get(f"{base_url}{endpoint}", verify=False, timeout=5)
        if r.status_code == 200:
            return f"{base_url}{endpoint}"
    except Exception:
        pass
    return None

def check_endpoints(url: str) -> tuple:
    protocol = "https://" if url.startswith("https://") else "http://"
    
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
    
    s = requests.Session()

    try:
        r = s.get(f"{protocol}{url_api}", verify=False, timeout=5)
        if r.status_code == 200:
            return True, f"{protocol}{url_api}"
    except Exception as e:
        print(f"Error checking base domain: {e}")
        pass
    
    try:
        r_api = s.get(f"{url}/api", verify=False, timeout=5)
        if r_api.status_code == 200:
            return True, f"{url}/api"
    except Exception as e:
        print(f"Error checking API endpoint: {e}")
        pass

    return False, None

def scan(url: str, threads=10) -> list:
    success, endpoint_url = check_endpoints(url)
    results = []
    
    if success:
        if "api." in endpoint_url:
            print(f"{Fore.CYAN}Checking API subdomain endpoints with {threads} threads...{Fore.WHITE}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_endpoint = {executor.submit(check_endpoint_for_scan, endpoint_url, endpoint): endpoint 
                                     for endpoint in actuator_endpoints}
                
                with tqdm(total=len(actuator_endpoints), desc="Scanning actuator endpoints") as pbar:
                    for future in concurrent.futures.as_completed(future_to_endpoint):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                                print(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                        except Exception as e:
                            endpoint = future_to_endpoint[future]
                            print(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                        finally:
                            pbar.update(1)
                            
        elif "/api" in endpoint_url:
            print(f"{Fore.CYAN}Checking API endpoints with {threads} threads...{Fore.WHITE}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_endpoint = {executor.submit(check_endpoint_for_scan, endpoint_url, endpoint): endpoint 
                                     for endpoint in api_endpoints}
                
                with tqdm(total=len(api_endpoints), desc="Scanning API endpoints") as pbar:
                    for future in concurrent.futures.as_completed(future_to_endpoint):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                                print(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                        except Exception as e:
                            endpoint = future_to_endpoint[future]
                            print(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                        finally:
                            pbar.update(1)
    
    return results

if __name__ == "__main__":
    print(f"{banner}\n")
    print(f"{Fore.CYAN}Scanning {args.url} for Spring Boot Actuator endpoints...{Fore.WHITE}")
    
    all_results = []
    
    actuator_results = scan(args.url, args.threads)
    all_results.extend(actuator_results)
    
    if args.wordlist:
        wordlist_results = dirbrute_endpoints(args.url, args.wordlist, args.threads)
        all_results.extend(wordlist_results)
    
    if all_results:
        print(f"\n{Fore.GREEN}Found {len(all_results)} vulnerable endpoint(s):{Fore.WHITE}")
        for result in all_results:
            print(f"{Fore.GREEN}- {result}{Fore.WHITE}")
    else:
        print(f"{Fore.RED}No vulnerable endpoints found{Fore.WHITE}")

    
    
    



