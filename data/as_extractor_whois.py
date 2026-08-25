import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import IP2Location
from ipwhois import IPWhois
from ipwhois.exceptions import HTTPLookupError, WhoisLookupError
from tqdm import tqdm

DIR_WITH_DATA = "daily_scans"
IGNORE_INTERNAL_IPS = [] # Removed for anonymized submission
DAY_ANALYSIS = "echo_results_2026-06-18"
COUNTRY_RESTRICTION = ""
MAX_WORKERS = 8

def lookup_ip(ip):
    """Runs in a worker thread. Returns (ip, asn, asn_description) or None on failure."""
    obj = IPWhois(str(ip))
    try:
        res = obj.lookup_rdap()
    except HTTPLookupError as e:
        print(f"RDAP Lookup Error for IP {ip}: {e} ... trying whois")
        try:
            res = obj.lookup_whois()
        except (HTTPLookupError, WhoisLookupError) as e2:
            print(f"Whois Lookup Error for IP {ip}: {e2} ... ignoring...")
            return None

    if res is None:
        return None

    return ip, res.get("asn"), res.get("asn_description")

def main():
    ipsToAnalyze = []
    try:
        with open("ips_left.json", 'r') as f:
            ipsToAnalyze = json.load(f)
    except FileNotFoundError:
        # Extract TCP and UDP first scan day to list
        # If Country flag is set, run through DB and filter for IPs from that country first

        if COUNTRY_RESTRICTION != "":
            database = IP2Location.IP2Location("IP2LOCATION-LITE-DB5.BIN", "SHARED_MEMORY")
        for filename in sorted(os.listdir(DIR_WITH_DATA + "/echo-tcp")):  # loops from oldest to latest
            if filename.count("_") == 3 or not filename.startswith("echo_results") or DAY_ANALYSIS not in filename:  # only use daily scans here
                continue
            # extract TCP
            with open(os.path.join(DIR_WITH_DATA + "/echo-tcp", filename), 'r') as f:
                results = json.load(f)
            for result in tqdm(results):
                if result['result'] == "WORKING":
                    working_ip = result['echoIP']['address']
                    if working_ip in IGNORE_INTERNAL_IPS:
                        continue
                    if COUNTRY_RESTRICTION != "":
                        rec = database.get_all(working_ip)
                        country = rec.country_short
                        if country == COUNTRY_RESTRICTION:
                            ipsToAnalyze.append(working_ip)
                    else:
                        ipsToAnalyze.append(working_ip)

            # extract UDP
            with open(os.path.join(DIR_WITH_DATA + "/echo-udp", filename), 'r') as f:
                results = json.load(f)
            for result in tqdm(results):
                if result['result'] == "WORKING":
                    working_ip = result['echoIP']['address']
                    if working_ip in IGNORE_INTERNAL_IPS:
                        continue
                    if COUNTRY_RESTRICTION != "":
                        rec = database.get_all(working_ip)
                        country = rec.country_short
                        if country == COUNTRY_RESTRICTION and working_ip not in ipsToAnalyze:
                            ipsToAnalyze.append(working_ip)
                    else:
                        if working_ip not in ipsToAnalyze:
                            ipsToAnalyze.append(working_ip)

    try:
        with open(f"as_dict_{COUNTRY_RESTRICTION}.json", 'r') as f:
            asDict = json.load(f)
    except FileNotFoundError:
        asDict = None

    print("Analyzing ASes IPs for first scan day...")
    if asDict is None:
        asDict = {}

    ips_to_process = list(ipsToAnalyze)
    ips_remaining = set(ips_to_process)
    lock = threading.Lock()

    with open("ips_left.json", 'w') as f:
        json.dump(list(ips_remaining), f)

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_ip = {executor.submit(lookup_ip, ip): ip for ip in ips_to_process}

            for future in tqdm(as_completed(future_to_ip), total=len(future_to_ip)):
                ip = future_to_ip[future]

                result = future.result()

                if result is None:
                    continue

                ip_res, asn, asn_desc = result
                with lock:
                    if asn not in asDict:
                        asDict[asn] = [1, asn_desc, [ip_res]]
                    else:
                        asDict[asn][0] += 1
                        asDict[asn][2].append(ip_res)
                    ips_remaining.discard(ip_res)

    except KeyboardInterrupt:
        print("Interrupted by user. Saving partial results...")
    except Exception as e:
        print(e)
        print("Stopping scan because of encountered exception. Saving results")
    finally:
        print(f"First scan day ASes: {len(asDict)}")
        print(f"IPs left to analyze: {len(ips_remaining)}")
        with open(f"as_dict_{COUNTRY_RESTRICTION}.json", 'w') as f:
            json.dump(asDict, f)
        with open("ips_left.json", 'w') as f:
            json.dump(list(ips_remaining), f)

if __name__ == "__main__":
    main()