import datetime
import re
import tldextract
import urllib.parse
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import whois
from collections import Counter
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright  # pyright: ignore[reportMissingImports]


def extract_all_features(url):
    with sync_playwright() as p:

        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        page.goto(url, wait_until="load")

        base_domain = urlparse(url).netloc
        features = {}

        # 👉 ADD FEATURES HERE
    """
    Extract all 87 features from a single URL

    Parameters:
    url (str): The URL to analyze

    Returns:
    dict: Dictionary containing all 87 features
    """

    features = {}
    url = str(url).strip().lower()

    # Parse URL components
    if not (url.startswith("http://") or url.startswith("https://")):
        parsed = urlparse("http://" + url)
    else:
        parsed = urlparse(url)

    domain_parts = tldextract.extract(url)

    hostname = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    full_url = url

    # ============== 1. Basic URL Characteristics (15 features) ==============

    # 1. URL length
    features["length_url"] = len(full_url)

    # 2. Hostname length
    features["length_hostname"] = len(hostname)

    # 3. Path length
    features["length_path"] = len(path)

    # 4. Query length
    features["length_query"] = len(query)

    # 5. Contains IP address
    features["ip"] = (
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname.split(":")[0]) else 0
    )

    # 6. Number of dots
    features["nb_dots"] = full_url.count(".")

    # 7. Number of hyphens
    features["nb_hyphens"] = full_url.count("-")

    # 8. Number of underscores
    features["nb_underscore"] = full_url.count("_")

    # 9. Number of slashes
    features["nb_slash"] = full_url.count("/")

    # 10. Number of question marks
    features["nb_qm"] = full_url.count("?")

    # 11. Number of ampersands
    features["nb_and"] = full_url.count("&")

    # 12. Number of equals signs
    features["nb_eq"] = full_url.count("=")

    # 13. Number of at symbols
    features["nb_at"] = full_url.count("@")

    # 14. Number of tildes
    features["nb_tilde"] = full_url.count("~")

    # 15. Number of percent signs
    features["nb_percent"] = full_url.count("%")

    # ============== 2. Special Characters (10 features) ==============

    # 16. Number of colons
    features["nb_colon"] = full_url.count(":")

    # 17. Number of semicolons
    features["nb_semicolumn"] = full_url.count(";")

    # 18. Number of dollar signs
    features["nb_dollar"] = full_url.count("$")

    # 19. Number of spaces
    features["nb_space"] = full_url.count(" ")

    # 20. Number of double slashes
    features["nb_dslash"] = full_url.count("//")

    # 21. Number of stars
    features["nb_star"] = full_url.count("*")

    # 22. Number of exclamation marks
    features["nb_exclamation"] = full_url.count("!")

    # 23. Number of hashes
    features["nb_hash"] = full_url.count("#")

    # 24. Number of pipes
    features["nb_or"] = full_url.count("|")

    # 25. Number of commas
    features["nb_comma"] = full_url.count(",")

    # ============== 3. Digit and Letter Ratios (6 features) ==============

    # 26. Digit count in URL
    digits_count = sum(c.isdigit() for c in full_url)
    features["digit_count"] = digits_count

    # 27. Letter count in URL
    features["letter_count"] = sum(c.isalpha() for c in full_url)

    # 28. Ratio of digits in URL
    features["ratio_digits_url"] = (
        digits_count / len(full_url) if len(full_url) > 0 else 0
    )

    # 29. Ratio of digits in hostname
    digits_host = sum(c.isdigit() for c in hostname)
    features["ratio_digits_host"] = (
        digits_host / len(hostname) if len(hostname) > 0 else 0
    )

    # 30. Ratio of special characters
    special_chars = sum(not c.isalnum() for c in full_url)
    features["ratio_special_chars"] = (
        special_chars / len(full_url) if len(full_url) > 0 else 0
    )

    # 31. Ratio of vowels
    vowels = sum(c in "aeiou" for c in full_url)
    features["ratio_vowels"] = vowels / len(full_url) if len(full_url) > 0 else 0

    # ============== 4. Hostname/Domain Features (15 features) ==============

    # 32. Number of subdomains
    features["nb_subdomains"] = (
        len(domain_parts.subdomain.split(".")) if domain_parts.subdomain else 0
    )

    # 33. Has www
    features["nb_www"] = 1 if "www." in full_url else 0

    # 34. Has com
    features["nb_com"] = 1 if ".com" in full_url else 0

    # 35. TLD (Top Level Domain)
    features["tld"] = domain_parts.suffix

    # 36. TLD length
    features["tld_length"] = len(domain_parts.suffix)

    # 37. Domain length
    features["domain_length"] = len(domain_parts.domain)

    # 38. Subdomain length
    features["subdomain_length"] = len(domain_parts.subdomain)

    # 39. Contains punycode
    features["punycode"] = 1 if "xn--" in hostname else 0

    # 40. Has port
    features["port"] = 1 if ":" in hostname and hostname.split(":")[-1].isdigit() else 0

    # 41. Number of hyphens in hostname
    features["hyphens_in_host"] = hostname.count("-")

    # 42. Number of dots in hostname
    features["dots_in_host"] = hostname.count(".")

    # 43. TLD in path
    features["tld_in_path"] = (
        1 if domain_parts.suffix and domain_parts.suffix in path else 0
    )

    # 44. TLD in subdomain
    features["tld_in_subdomain"] = (
        1
        if domain_parts.suffix and domain_parts.suffix in domain_parts.subdomain
        else 0
    )

    # ------------------------
    # 46. domain_age (optional)
    # ------------------------
    if whois:
        try:
            w = whois.whois(hostname)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                features["domain_age"] = age_days
            else:
                features["domain_age"] = 0
        except:
            features["domain_age"] = 0
    else:
        features["domain_age"] = 0

    # ============== 5. Path Features (10 features) ==============

    # 47. Path length
    features["path_length"] = len(path)

    # 48. Number of directories in path
    features["nb_dirs"] = path.count("/")

    # 49. Has file extension
    features["path_extension"] = 1 if re.search(r"\.[a-zA-Z0-9]{1,5}$", path) else 0

    # 50. Path contains HTTP
    features["http_in_path"] = 1 if "http" in path else 0

    # 51. Path contains HTTPS
    features["https_in_path"] = 1 if "https" in path else 0

    # 52. Number of parameters in path
    features["nb_params"] = len(query.split("&")) if query else 0

    # 53. Path has digits
    features["path_has_digits"] = 1 if any(c.isdigit() for c in path) else 0

    # 54. Path has special chars
    features["path_special_chars"] = sum(
        not c.isalnum() and c not in "/." for c in path
    )

    # 55. Path entropy (randomness measure)
    if len(path) > 0:
        prob = [path.count(c) / len(path) for c in set(path)]
        features["path_entropy"] = -sum(p * np.log2(p) for p in prob)
    else:
        features["path_entropy"] = 0

    # 56. Number of redirects (placeholder)
    features["nb_redirects"] = 0

    # ============== 6. Query String Features (10 features) ==============

    # 57. Query length
    features["query_length"] = len(query)

    # 58. Number of query parameters
    features["nb_query_params"] = len(query.split("&")) if query else 0

    # 59. Contains suspicious parameters
    suspicious_params = ["redirect", "url", "link", "dest", "return", "next", "forward"]
    features["suspicious_query"] = (
        1 if any(p in query.lower() for p in suspicious_params) else 0
    )

    # 60. Query has encoded characters
    features["encoded_query"] = 1 if "%" in query else 0

    # 61. Query has equals signs
    features["query_eq_count"] = query.count("=")

    # 62. Query has ampersands
    features["query_and_count"] = query.count("&")

    # 63. Contains email pattern
    features["email_in_query"] = 1 if re.search(r"[\w\.-]+@[\w\.-]+", query) else 0

    # 64. Contains IP in query
    features["ip_in_query"] = (
        1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", query) else 0
    )

    # 65. Query has digits ratio
    digits_query = sum(c.isdigit() for c in query)
    features["query_digits_ratio"] = digits_query / len(query) if len(query) > 0 else 0

    # 66. Query entropy
    if len(query) > 0:
        prob = [query.count(c) / len(query) for c in set(query)]
        features["query_entropy"] = -sum(p * np.log2(p) for p in prob)
    else:
        features["query_entropy"] = 0

    # ============== 7. Security Indicators (10 features) ==============

    # 67. Uses HTTPS
    features["https_token"] = 1 if parsed.scheme == "https" else 0

    # 68. Uses HTTP
    features["http_token"] = 1 if parsed.scheme == "http" else 0

    # 69. Suspicious TLD
    suspicious_tlds = [
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "club",
        "work",
        "zip",
        "link",
        "cn",
    ]
    features["suspicious_tld"] = 1 if domain_parts.suffix in suspicious_tlds else 0

    # 70. URL shortener
    shorteners = [
        "bit.ly",
        "tinyurl",
        "goo.gl",
        "t.co",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "shorturl",
    ]
    features["shortening_service"] = 1 if any(s in full_url for s in shorteners) else 0

    # 71. Contains phishing keywords
    phishing_keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "payment",
        "signin",
        "confirm",
    ]
    features["phish_hints"] = 1 if any(k in full_url for k in phishing_keywords) else 0

    # 72. Google index (placeholder - requires API call)
    try:
        endpoint = "https://api.bing.microsoft.com/v7.0/search"
        headers = {"Ocp-Apim-Subscription-Key": BING_API_KEY}
        params = {"q": f"site:{url}", "count": 1}

        response = requests.get(endpoint, headers=headers, params=params, timeout=5)
        data = response.json()

        if "webPages" in data and data["webPages"]["value"]:
            gi = 1
        gi = 0
    except:
        gi = 0
    features["google_index"] = gi

    # 73. Page rank (placeholder - requires API call)
    domain = urlparse(url).netloc

    # simple heuristic
    if any(x in domain for x in ["google", "facebook", "amazon"]):
        prr = 5
    elif "." in domain and len(domain) > 10:
        prr = 2
    else:
        prr = 1
    features["page_rank"] = prr

    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # 74. nb_hyperlinks
        links = soup.find_all("a")
        features["nb_hyperlinks"] = len(links)

        # 9. ratio_intHyperlinks
        # internal_links = 0
        # for link in links:
        #     href = link.get("href")
        #     if href and hostname in href:
        #         internal_links += 1

        # features["ratio_intHyperlinks"] = (
        #     internal_links / len(links) if len(links) > 0 else 0
        # )

        # 45. domain_in_title
        title = soup.title.string if soup.title else ""
        features["domain_in_title"] = 1 if hostname in title else 0

    except:
        features["nb_hyperlinks"] = 0
        features["ratio_intHyperlinks"] = 0
        features["domain_in_title"] = 0

    # 75. Number of external links

    try:
        links = page.query_selector_all("a[href]")
        external_links = 0

        for link in links:
            href = link.get_attribute("href")
            if href and base_domain not in href:
                external_links += 1

        features["external_links"] = external_links

    except:
        features["external_links"] = 0

    # 76. Presence of iframe

    try:
        iframes = page.query_selector_all("iframe")
        features["iframe"] = 1 if len(iframes) > 0 else 0

    except:
        features["iframe"] = 0
        features["iframe"] = 0

    # ============== 8. Statistical Features (11 features) ==============

    # 77. Word count in URL
    words = re.findall(r"[a-zA-Z]+", full_url)
    features["word_count"] = len(words)

    # 78. Average word length
    features["avg_word_length"] = (
        sum(len(w) for w in words) / len(words) if words else 0
    )

    # 79. Max word length
    features["max_word_length"] = max((len(w) for w in words), default=0)

    # 80. Min word length
    features["min_word_length"] = min((len(w) for w in words), default=0)

    # 81. Number of unique characters
    features["unique_chars"] = len(set(full_url))

    # 82. Character repetition rate
    if len(full_url) > 0:
        char_counts = Counter(full_url)
        features["char_repetition"] = max(char_counts.values()) / len(full_url)
    else:
        features["char_repetition"] = 0

    # 83. Number of consecutive digits
    digit_sequences = re.findall(r"\d+", full_url)
    features["max_consecutive_digits"] = max(
        (len(seq) for seq in digit_sequences), default=0
    )

    # 84. Number of consecutive consonants
    consonant_sequences = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", full_url)
    features["max_consecutive_consonants"] = max(
        (len(seq) for seq in consonant_sequences), default=0
    )

    # 85. Entropy of the URL
    if len(full_url) > 0:
        prob = [full_url.count(c) / len(full_url) for c in set(full_url)]
        features["url_entropy"] = -sum(p * np.log2(p) for p in prob)
    else:
        features["url_entropy"] = 0

    # 86. Number of redirections
    features["nb_redirection"] = (
        full_url.count("//") - 1
        if full_url.startswith("http")
        else full_url.count("//")
    )

    # 87. Suspicious pattern score
    suspicious_patterns = [r"\.\w+\.", r"-\w+-", r"\d{4,}", r"[a-z]{20,}"]
    features["suspicious_pattern_score"] = sum(
        1 for pattern in suspicious_patterns if re.search(pattern, full_url)
    )

    return features


def extract_features_batch(urls):
    """
    Extract features for multiple URLs

    Parameters:
    urls (list): List of URLs

    Returns:
    pd.DataFrame: DataFrame containing all features
    """
    features_list = []

    for url in urls:
        try:
            features = extract_all_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"Error processing {url}: {e}")
            features_list.append({})

    return pd.DataFrame(features_list)


# Example usage
if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://paypal-login.tk/verify/account",
        "http://192.168.1.1/login.php",
        "https://bit.ly/3xyz123",
    ]

    # Extract features
    df_features = extract_features_batch(test_urls)

    print("Feature extraction completed!")
    print(f"Shape: {df_features.shape}")
    print(f"Features: {df_features.columns.tolist()}")
    print("\nFirst few rows:")
    print(df_features.head())

    # Save to CSV if needed
    # df_features.to_csv("extracted_features.csv", index=False)

import requests


def check_google_index(url):
    try:
        query = f"https://www.google.com/search?q=site:{url}"
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(query, headers=headers, timeout=5)

        if "did not match any documents" in res.text:
            return 0
        return 1
    except:
        return 0


BING_API_KEY = "YOUR_KEY"


def check_index_bing(url):
    try:
        endpoint = "https://api.bing.microsoft.com/v7.0/search"
        headers = {"Ocp-Apim-Subscription-Key": BING_API_KEY}
        params = {"q": f"site:{url}", "count": 1}

        response = requests.get(endpoint, headers=headers, params=params, timeout=5)
        data = response.json()

        if "webPages" in data and data["webPages"]["value"]:
            return 1
        return 0
    except:
        return 0


def count_external_links(page, base_domain):
    links = page.query_selector_all("a[href]")
    count = 0

    for link in links:
        href = link.get_attribute("href")
        if href and base_domain not in href:
            count += 1

    return count
