import requests
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared.config import ABUSECH_API_KEY

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
        "malware": element["threat"],
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
    
