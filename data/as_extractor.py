import json
import os

import IP2Location
from tqdm import tqdm

from as_extractor_whois import lookup_ip
from as_lookup import as_of

DIR_WITH_DATA = "daily_scans"
IGNORE_INTERNAL_IPS = [] # Removed for anonymized submission
DAY_ANALYSIS = "echo_results_2026-06-18"
COUNTRY_RESTRICTION = "" # Put KZ/KR here for Kazakhstan, South Korea results

ipsToAnalyze = []
try:
    with open("ips_left.json", 'r') as f:
        ipsToAnalyze = json.load(f)
except FileNotFoundError:
    if COUNTRY_RESTRICTION != "":
        database = IP2Location.IP2Location("IP2LOCATION-LITE-DB5.BIN", "SHARED_MEMORY")
    for filename in sorted(os.listdir(DIR_WITH_DATA + "/echo-tcp")):
        if filename.count("_") == 3 or not filename.startswith("echo_results") or DAY_ANALYSIS not in filename:
            continue
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
    asDict = {}

print("Analyzing ASes for scan day...")

ips_remaining = set(ipsToAnalyze)

with open("ips_left.json", 'w') as f:
    json.dump(list(ips_remaining), f)

try:
    for ip in tqdm(list(ipsToAnalyze)):
        result = as_of(ip)
        if result is None:
            continue

        asn, asn_desc = result
        asn_key = str(asn)
        if asn_key not in asDict:
            asDict[asn_key] = [1, asn_desc, [ip]]
        else:
            asDict[asn_key][0] += 1
            asDict[asn_key][2].append(ip)
        ips_remaining.discard(ip)

except KeyboardInterrupt:
    print("Interrupted by user. Saving partial results...")
except Exception as e:
    print(e)
    print("Stopping scan because of encountered exception. Saving results")
finally:
    print(f"ASes found: {len(asDict)}")
    print(f"IPs left to analyze: {len(ips_remaining)}")
    if len(ips_remaining) > 0:
        print("Some IPs not present in dataset, querying whois directly!")
        ipsToAnalyze = set(ips_remaining)
        for ip in ipsToAnalyze:
            result = lookup_ip(ip)
            if result is None:
                continue
            ip_res, asn, asn_desc = result
            if asn not in asDict:
                asDict[asn] = [1, asn_desc, [ip]]
            else:
                asDict[asn][0] += 1
                asDict[asn][2].append(ip)
            ips_remaining.discard(ip)
        if len(ips_remaining) > 0:
            with open("ips_left.json", 'w') as f:
                json.dump(list(ips_remaining), f)
        else:
            if os.path.exists("ips_left.json"):
                os.remove("ips_left.json")
        print(f"ASes found: {len(asDict)}")
        print(f"IPs left to analyze: {len(ips_remaining)}")
    else:
        if os.path.exists("ips_left.json"):
            os.remove("ips_left.json")
    with open(f"as_dict_{COUNTRY_RESTRICTION}.json", 'w') as f:
        json.dump(asDict, f)