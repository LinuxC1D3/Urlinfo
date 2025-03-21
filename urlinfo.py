import requests
from bs4 import BeautifulSoup
import argparse

# ASCII Art - Willkommenstext
print(r"""
                                   Created by
  _       _________ _                            _______  __    ______   ______  
 ( \      \__   __/( (    /||\     /||\     /|  (  ____ \/  \  (  __  \ / ___  \ 
 | (         ) (   |  \  ( || )   ( |( \   / )  | (    \/\/) ) | (  \  )\/   \  \
 | |         | |   |   \ | || |   | | \ (_) /   | |        | | | |   ) |   ___) /
 | |         | |   | (\ \) || |   | |  ) _ (    | |        | | | |   | |  (___ ( 
 | |         | |   | | \   || |   | | / ( ) \   | |        | | | |   ) |      ) \
 | (____/\___) (___| )  \  || (___) |( /   \ )  | (____/\__) (_| (__/  )/\___/  /
 (_______/\_______/|/    )_)(_______)|/     \|  (_______/\____/(______/ \______/ 
""")

def analyze_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        issues = []

        # Sicherheitstests für Header
        if 'X-Frame-Options' not in headers:
            issues.append("Fehlender X-Frame-Options-Header (Schutz gegen Clickjacking).")
        if 'Content-Security-Policy' not in headers:
            issues.append("Fehlender Content-Security-Policy-Header (Schutz vor XSS).")
        if 'Strict-Transport-Security' not in headers:
            issues.append("Fehlender Strict-Transport-Security-Header (HSTS).")
        if 'X-Content-Type-Options' not in headers:
            issues.append("Fehlender X-Content-Type-Options-Header (MIME-Typ-Schutz).")

        return {"headers": dict(headers), "issues": issues}
    except Exception as e:
        return {"error": str(e)}

def find_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = {
            "internal": [],
            "external": [],
            "broken": []
        }

        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http'):
                try:
                    res = requests.head(href, timeout=5)
                    if res.status_code >= 400:
                        links["broken"].append(href)
                    else:
                        links["external"].append(href)
                except Exception:
                    links["broken"].append(href)
            else:
                links["internal"].append(href)

        return links
    except Exception as e:
        return {"error": str(e)}

def detect_technologies(url):
    try:
        response = requests.get(url)
        headers = response.headers
        tech = []

        # Einfache Technologieerkennung basierend auf Headern
        if 'x-powered-by' in headers:
            tech.append(f"Powered by: {headers['x-powered-by']}")
        if 'server' in headers:
            tech.append(f"Server: {headers['server']}")
        if 'set-cookie' in headers:
            tech.append("Cookies erkannt (möglicherweise Sitzungshandling).")

        return tech
    except Exception as e:
        return {"error": str(e)}

def scan_directory(url):
    common_dirs = ["admin", "login", "backup", "test", "uploads", "config"]
    found_dirs = []

    for directory in common_dirs:
        test_url = f"{url}/{directory}/"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                found_dirs.append(test_url)
        except Exception:
            pass

    return found_dirs

def main(url):
    print(f"Analyzing website: {url}\n")

    print("[1] Analyzing HTTP headers...")
    header_analysis = analyze_headers(url)
    print(header_analysis)

    print("\n[2] Finding links on the page...")
    links = find_links(url)
    print(links)

    print("\n[3] Detecting technologies...")
    technologies = detect_technologies(url)
    print(technologies)

    print("\n[4] Scanning for common directories...")
    directories = scan_directory(url)
    print(directories)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Website Security Scanner")
    parser.add_argument("url", help="URL of the website to scan")
    args = parser.parse_args()

    main(args.url)
