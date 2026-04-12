import re
from collections import Counter
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import tldextract


TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)
SUSPICIOUS_TLDS = {
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
}
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl",
    "goo.gl",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "shorturl",
}
PHISHING_KEYWORDS = {
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "payment",
    "signin",
    "confirm",
}
SUSPICIOUS_QUERY_PARAMS = {
    "redirect",
    "url",
    "link",
    "dest",
    "return",
    "next",
    "forward",
}
TRUSTED_BRANDS = {
    "google",
    "facebook",
    "amazon",
    "netflix",
    "apple",
    "microsoft",
    "twitter",
    "linkedin",
    "github",
    "paypal",
    "dropbox",
    "salesforce",
    "adobe",
    "spotify",
    "airbnb",
    "uber",
    "lyft",
    "slack",
    "zoom",
    "stripe",
}


def extract_domain_parts(url: str):
    return TLD_EXTRACTOR(url)


def _normalize_url(url: str) -> tuple[str, object]:
    normalized = str(url).strip().lower()
    if not (normalized.startswith("http://") or normalized.startswith("https://")):
        parsed = urlparse("http://" + normalized)
    else:
        parsed = urlparse(normalized)
    return normalized, parsed


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [text.count(char) / len(text) for char in set(text)]
    return float(-sum(prob * np.log2(prob) for prob in probabilities))


def _encode_tld(suffix: str) -> int:
    return sum(ord(char) for char in suffix)


def extract_basic_features(url):
    """
    Deterministic handcrafted URL features for the L1+L2 path.
    Returns the numeric 87-feature vector expected by the scaler/RF assets.
    """

    full_url, parsed = _normalize_url(url)
    domain_parts = extract_domain_parts(full_url)

    hostname = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    suffix = domain_parts.suffix or ""
    subdomain = domain_parts.subdomain or ""
    domain = domain_parts.domain or ""
    hostname_root = hostname.split(":")[0]

    features = {}

    features["length_url"] = len(full_url)
    features["length_hostname"] = len(hostname)
    features["length_path"] = len(path)
    features["length_query"] = len(query)
    features["ip"] = 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname_root) else 0
    features["nb_dots"] = full_url.count(".")
    features["nb_hyphens"] = full_url.count("-")
    features["nb_underscore"] = full_url.count("_")
    features["nb_slash"] = full_url.count("/")
    features["nb_qm"] = full_url.count("?")
    features["nb_and"] = full_url.count("&")
    features["nb_eq"] = full_url.count("=")
    features["nb_at"] = full_url.count("@")
    features["nb_tilde"] = full_url.count("~")
    features["nb_percent"] = full_url.count("%")

    features["nb_colon"] = full_url.count(":")
    features["nb_semicolumn"] = full_url.count(";")
    features["nb_dollar"] = full_url.count("$")
    features["nb_space"] = full_url.count(" ")
    features["nb_dslash"] = full_url.count("//")
    features["nb_star"] = full_url.count("*")
    features["nb_exclamation"] = full_url.count("!")
    features["nb_hash"] = full_url.count("#")
    features["nb_or"] = full_url.count("|")
    features["nb_comma"] = full_url.count(",")

    digits_count = sum(char.isdigit() for char in full_url)
    digits_host = sum(char.isdigit() for char in hostname)
    features["digit_count"] = digits_count
    features["letter_count"] = sum(char.isalpha() for char in full_url)
    features["ratio_digits_url"] = digits_count / len(full_url) if full_url else 0.0
    features["ratio_digits_host"] = digits_host / len(hostname) if hostname else 0.0
    features["ratio_special_chars"] = (
        sum(not char.isalnum() for char in full_url) / len(full_url)
        if full_url
        else 0.0
    )
    features["ratio_vowels"] = (
        sum(char in "aeiou" for char in full_url) / len(full_url) if full_url else 0.0
    )

    features["nb_subdomains"] = len(subdomain.split(".")) if subdomain else 0
    features["nb_www"] = 1 if "www." in full_url else 0
    features["nb_com"] = 1 if ".com" in full_url else 0
    features["tld"] = _encode_tld(suffix)
    features["tld_length"] = len(suffix)
    features["domain_length"] = len(domain)
    features["subdomain_length"] = len(subdomain)
    features["punycode"] = 1 if "xn--" in hostname else 0
    features["port"] = 1 if ":" in hostname and hostname.split(":")[-1].isdigit() else 0
    features["hyphens_in_host"] = hostname.count("-")
    features["dots_in_host"] = hostname.count(".")
    features["tld_in_path"] = 1 if suffix and suffix in path else 0
    features["tld_in_subdomain"] = 1 if suffix and suffix in subdomain else 0
    features["domain_age"] = 0

    features["path_length"] = len(path)
    features["nb_dirs"] = path.count("/")
    features["path_extension"] = 1 if re.search(r"\.[a-zA-Z0-9]{1,5}$", path) else 0
    features["http_in_path"] = 1 if "http" in path else 0
    features["https_in_path"] = 1 if "https" in path else 0
    features["nb_params"] = len(query.split("&")) if query else 0
    features["path_has_digits"] = 1 if any(char.isdigit() for char in path) else 0
    features["path_special_chars"] = sum(
        not char.isalnum() and char not in "/." for char in path
    )
    features["path_entropy"] = _entropy(path)
    features["nb_redirects"] = 0

    features["query_length"] = len(query)
    features["nb_query_params"] = len(query.split("&")) if query else 0
    features["suspicious_query"] = (
        1 if any(param in query for param in SUSPICIOUS_QUERY_PARAMS) else 0
    )
    features["encoded_query"] = 1 if "%" in query else 0
    features["query_eq_count"] = query.count("=")
    features["query_and_count"] = query.count("&")
    features["email_in_query"] = 1 if re.search(r"[\w\.-]+@[\w\.-]+", query) else 0
    features["ip_in_query"] = (
        1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", query) else 0
    )
    digits_query = sum(char.isdigit() for char in query)
    features["query_digits_ratio"] = digits_query / len(query) if query else 0.0
    features["query_entropy"] = _entropy(query)

    features["https_token"] = 1 if parsed.scheme == "https" else 0
    features["http_token"] = 1 if parsed.scheme == "http" else 0
    features["suspicious_tld"] = 1 if suffix in SUSPICIOUS_TLDS else 0
    features["shortening_service"] = (
        1 if any(shortener in full_url for shortener in URL_SHORTENERS) else 0
    )
    features["phish_hints"] = (
        1 if any(keyword in full_url for keyword in PHISHING_KEYWORDS) else 0
    )
    features["google_index"] = 0
    features["page_rank"] = (
        5
        if any(brand in domain for brand in TRUSTED_BRANDS)
        else 2 if "." in hostname and len(hostname) > 10 else 1
    )
    features["nb_hyperlinks"] = 0
    features["domain_in_title"] = 0
    features["external_links"] = 0
    features["iframe"] = 0

    words = re.findall(r"[a-zA-Z]+", full_url)
    features["word_count"] = len(words)
    features["avg_word_length"] = (
        sum(len(word) for word in words) / len(words) if words else 0.0
    )
    features["max_word_length"] = max((len(word) for word in words), default=0)
    features["min_word_length"] = min((len(word) for word in words), default=0)
    features["unique_chars"] = len(set(full_url))
    if full_url:
        char_counts = Counter(full_url)
        features["char_repetition"] = max(char_counts.values()) / len(full_url)
    else:
        features["char_repetition"] = 0.0
    digit_sequences = re.findall(r"\d+", full_url)
    features["max_consecutive_digits"] = max(
        (len(seq) for seq in digit_sequences), default=0
    )
    consonant_sequences = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", full_url)
    features["max_consecutive_consonants"] = max(
        (len(seq) for seq in consonant_sequences), default=0
    )
    features["url_entropy"] = _entropy(full_url)
    features["nb_redirection"] = (
        full_url.count("//") - 1
        if full_url.startswith("http")
        else full_url.count("//")
    )
    suspicious_patterns = [r"\.\w+\.", r"-\w+-", r"\d{4,}", r"[a-z]{20,}"]
    features["suspicious_pattern_score"] = sum(
        1 for pattern in suspicious_patterns if re.search(pattern, full_url)
    )

    return features, domain_parts


def extract_all_features(url):
    return extract_basic_features(url)


def extract_features_batch(urls):
    features_list = []
    for url in urls:
        try:
            features_list.append(extract_all_features(url))
        except Exception as exc:
            print(f"Error processing {url}: {exc}")
            features_list.append({})
    return pd.DataFrame(features_list)


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://paypal-login.tk/verify/account",
        "http://192.168.1.1/login.php",
        "https://bit.ly/3xyz123",
    ]
    df_features = extract_features_batch(test_urls)
    print("Feature extraction completed!")
    print(f"Shape: {df_features.shape}")
    print(f"Features: {df_features.columns.tolist()}")
    print("\nFirst few rows:")
    print(df_features.head())

    # Save to CSV if needed
    df_features.to_csv("extracted_features_sample.csv", index=False)
