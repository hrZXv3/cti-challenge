import requests

openphish_url = "https://openphish.com/feed.txt"

def get_openphish():
    response = requests.get(openphish_url, timeout=30)
    response.raise_for_status()

    urls = []
    for line in response.text.splitlines():
        line = line.strip()
        if line:
            urls.append(line)
    return urls

if __name__ == "__main__":
    urls = get_openphish()
    print(f"OpenPhish: {len(urls)} URL")
