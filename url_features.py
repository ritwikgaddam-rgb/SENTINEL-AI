
from urllib.parse import urlsplit
import ipaddress
import pandas as pd

def url_feature_values(url):
    ##removes leading and trailing spaces from the URL
    url = url.strip()
    ##if url doesnt start with http or https then it raises an error
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("Invalid URL")

    #Splits url into multiple parts
    parsed = urlsplit(url)
    domain = parsed.hostname

    #if domain is not found then it raises an error
    if domain is None:
        raise ValueError("Invalid domain")

    #checks if the domain is an IP address and if not raises an error
    ip = 0
    try:
        ipaddress.ip_address(domain)
        ip = 1
    except ValueError:
        pass

    #counts the number of letters and digits in the URL
    letters = 0
    digits = 0

    for character in url:
        if character.isalpha():
            letters += 1

        if character.isdigit():
            digits += 1

    #counts the number of subdomains in the domain and if there are no subdomains then it sets the value to 0
    subdomains = len(domain.split(".")) - 2
    if subdomains < 0:
        subdomains = 0

    #checks if the URL is using https and if not sets the value to 0
    https = 0
    if parsed.scheme == "https":
        https = 1
    return {
        "URLLength": len(url),
        "DomainLength": len(domain),
        "IsDomainIP": ip,
        "NoOfSubDomain": subdomains,
        "NoOfLettersInURL": letters,
        "NoOfDegitsInURL": digits,
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "IsHTTPS": https
    }


def extract_url_features(url):
    return pd.DataFrame([url_feature_values(url)])

if __name__ == "__main__":
    url = "https://mail.google.com/login?user=123"

    result = extract_url_features(url)

    print(result.to_string(index=False))
