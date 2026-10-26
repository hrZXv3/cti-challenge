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
            urls.append(line)
    return urls

def get_urlhaus():
    response = requests.get(urlhaus_url, headers={"Auth-Key": ABUSECH_API_KEY}, timeout=30)
    response.raise_for_status()

    data = response.json()
    urls = []
    for element in data["urls"]:
        urls.append(element["url"])    
    return urls

def get_threatfox():
    response = requests.post(threatfox_url, headers={"Auth-Key": ABUSECH_API_KEY}, json={"query": "get_iocs", "days": 1}, timeout=30)
    response.raise_for_status()

    data = response.json()
    urls = []
    for element in data["data"]:
        urls.append(element["ioc"])
    return urls

            
if __name__ == "__main__":
    openphish = get_openphish()
    urlhaus = get_urlhaus()
    threatfox = get_threatfox()
    
    print(f"OpenPhish: {len(openphish)} URL")
    print(f"Urlhaus: {len(urlhaus)} URL")
    print(f"Threatfox: {len(threatfox)} IOC") 
