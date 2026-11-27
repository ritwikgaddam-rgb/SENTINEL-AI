
import requests
from bs4 import BeautifulSoup
import ipaddress
import socket
from urllib.parse import urlsplit
def is_safe_url(url):
    ##removes leading and trailing spaces from the URL
    try:
        parts = urlsplit(url)
        ##checks if the URL scheme is either http or https if not returns False
        if parts.scheme not in ["http", "https"]:
            return False
        ##checks if the hostname is valid and if not returns falsr
        hostname = parts.hostname
        if hostname is None:
            return False
        #checks if hostname is ip address and if not returns False
        addresses = socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM)
        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])
            if not ip.is_global:
                return False
        return True
    except (ValueError, OSError):
        return False


def extract_webpage(url):
    if not is_safe_url(url):
        print("Unsafe URL")
        return None
    ##reqyuests the webpage and raises an error if the request fails
    download = requests.get(url,timeout=10,headers={"User-Agent": "SentinelAI/1.0"},allow_redirects=False,stream=True)
    if 300 <= download.status_code < 400:
        print("Redirect detected. Extraction stopped.")
        return None
    download.raise_for_status()


    ##parses webpage using beautfiul soup and limits amount of data downloaded to 1MB
    soup = BeautifulSoup(download.raw.read(1024 * 1024), "html.parser")

    #extracts the title of the webpage if it exists
    title = ""
    if soup.title:
        title = soup.title.get_text(strip=True)

    #removes unnecessary tags
    for tag in soup(["script", "style", "nav", "footer"]):
        tag.decompose()
    ##Extracts the text from webpage
    text = soup.get_text(separator=" ", strip=True)

    #returns the url, title and text of the webpage
    return {
        "url": download.url,
        "title": title,
        "text": text[:5000]}


if __name__ == "__main__":
    result = extract_webpage("http://127.0.0.1")
    print(result)