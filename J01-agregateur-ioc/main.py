import requests
import sys
import csv
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared.config import ABUSECH_API_KEY, DATA_DIR
from collections import Counter

openphish_url = "https://openphish.com/feed.txt"
urlhaus_url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
threatfox_url = "https://threatfox-api.abuse.ch/api/v1/"

def get_openphish():
    response = requests.get(openphish_url, timeout=30)
    response.raise_for_status()

    urls = []
    for line in response.text.splitlines():
        line = line.strip()
        if line:
            urls.append({
            "ioc": line,
            "type": "url",
            "source": "openphish",
            "malware": "",
            "first_seen": "",
            "tags": "phishing",
            })
    return urls

def get_urlhaus():
    response = requests.get(urlhaus_url, headers={"Auth-Key": ABUSECH_API_KEY}, timeout=30)
    response.raise_for_status()

    data = response.json()
    urls = []
    for element in data["urls"]:
        urls.append({
        "ioc": element["url"],
        "type": "url",
        "source": "urlhaus",
        "malware": "",
        "first_seen": element["date_added"],
        "tags": ",".join(element["tags"] or []),
        })    
    return urls

def get_threatfox():
    response = requests.post(threatfox_url, headers={"Auth-Key": ABUSECH_API_KEY}, json={"query": "get_iocs", "days": 1}, timeout=30)
    response.raise_for_status()

    data = response.json()
    urls = []
    for element in data["data"]:
        urls.append({
        "ioc": element["ioc"],
        "type": element["ioc_type"],
        "source": "threatfox",
        "malware": element["malware_printable"],
        "first_seen": element["first_seen"],
        "tags": ",".join(element["tags"] or []),
        }) 
    return urls

def deduplicate(iocs):
    seen = set()
    unique = []
    for fiche in iocs:
        if fiche["ioc"] not in seen:
            seen.add(fiche["ioc"])
            unique.append(fiche)
    return unique
    
def save_csv(iocs, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(iocs[0].keys()))
        writer.writeheader()
        writer.writerows(iocs)
            
def defang(ioc):
    return ioc.replace("http", "hxxp").replace(".", "[.]")
            
if __name__ == "__main__":
    openphish = get_openphish()
    urlhaus = get_urlhaus()
    threatfox = get_threatfox()
    
    print(f"OpenPhish: {len(openphish)} URL")
    print(f"Urlhaus: {len(urlhaus)} URL")
    print(f"Threatfox: {len(threatfox)} IOC") 

    all_iocs = openphish + urlhaus + threatfox
    unique = deduplicate(all_iocs)

    print(f"Total: {len(all_iocs)} IOC")
    print(f"Doublons supprimés: {len(all_iocs) - len(unique)}")
    print(f"IOC uniques: {len(unique)}")

    output = DATA_DIR / "iocs.csv"
    save_csv(unique, output)
    print(f"CSV écrit : {output}")

    sample = []
    for fiche in openphish[:7] + urlhaus[:7] + threatfox[:7]:
        copie = dict(fiche)
        copie["ioc"] = defang(copie["ioc"])
        sample.append(copie)

    save_csv(sample, DATA_DIR / "iocs_sample.csv")
    print(f"Extrait defangé : {len(sample)} IOC")

    types = []
    for fiche in unique:
        types.append(fiche["type"])

    print("Par type :")
    for nom, nombre in Counter(types).most_common():
        print(f"  {nom}: {nombre}")

    malwares = []
    for fiche in unique:
        if fiche["malware"] and fiche["malware"] != "Unknown malware":
            malwares.append(fiche["malware"])

    print("Top 5 malwares :")
    for nom, nombre in Counter(malwares).most_common(5):
        print(f"  {nom}: {nombre}")
    
