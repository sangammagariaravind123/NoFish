from playwright.sync_api import sync_playwright
from urllib.parse import urlparse
import re
import json

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq"]

def is_ip(url):
    return re.match(r"https?://\d+\.\d+\.\d+\.\d+", url) is not None

def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ""

def analyze_url(url):
    result = {
        "url": url,
        "final_url": None,

        # existing
        "total_requests": 0,
        "external_domains": set(),
        "ip_based_requests": 0,
        "suspicious_tld_count": 0,
        "redirect_count": 0,
        "js_requests": 0,
        "all_requests": [],

        # new
        "request_domains": set(),
        "script_domains": set(),
        "final_url_differs": 0,
        "error_flag": 0,
        "timeout_flag": 0,

        # request types
        "document_requests": 0,
        "script_requests": 0,
        "stylesheet_requests": 0,
        "image_requests": 0,
        "font_requests": 0,
        "xhr_fetch_requests": 0,
        "other_requests": 0
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        context = browser.new_context(
            accept_downloads=False,
            permissions=[]
        )

        page = context.new_page()
        page.set_default_timeout(10000)

        result["download_attempts"] = []

        def handle_download(download):
            result["download_attempts"].append({
                "url": download.url,
                "suggested_filename": download.suggested_filename
            })
            download.cancel()

        page.on("download", handle_download)

        base_domain = get_domain(url)

        def handle_response(response):
            if response.request.redirected_from:
                result["redirect_count"] += 1

        page.on("response", handle_response)

        def handle_request(request):
            req_url = request.url
            req_type = request.resource_type

            result["all_requests"].append(req_url)
            result["total_requests"] += 1

            domain = get_domain(req_url)
            if domain:
                result["request_domains"].add(domain)

            # external domain
            if domain and base_domain and base_domain not in domain:
                result["external_domains"].add(domain)

            # IP based
            if is_ip(req_url):
                result["ip_based_requests"] += 1

            # suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if req_url.endswith(tld) or tld in req_url:
                    result["suspicious_tld_count"] += 1

            # request types
            if req_type == "document":
                result["document_requests"] += 1
            elif req_type == "script":
                result["script_requests"] += 1
                result["js_requests"] += 1
                if domain:
                    result["script_domains"].add(domain)
            elif req_type == "stylesheet":
                result["stylesheet_requests"] += 1
            elif req_type == "image":
                result["image_requests"] += 1
            elif req_type == "font":
                result["font_requests"] += 1
            elif req_type in ["xhr", "fetch"]:
                result["xhr_fetch_requests"] += 1
            else:
                result["other_requests"] += 1

        page.on("request", handle_request)

        try:
            page.goto(url, wait_until="domcontentloaded")

            # wait for dynamic content
            page.wait_for_timeout(5000)   # 5 seconds (important)

            # optional: wait until network settles
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except:
                pass
            page.screenshot(path="shot.png")
            result["final_url"] = page.url

            if result["final_url"] and result["final_url"] != url:
                result["final_url_differs"] = 1

        except Exception as e:
            result["error"] = str(e)
            result["error_flag"] = 1

            if "Timeout" in str(e) or "timeout" in str(e):
                result["timeout_flag"] = 1

        browser.close()

    # derived counts
    result["external_domain_count"] = len(result["external_domains"])
    result["unique_request_domains"] = len(result["request_domains"])
    result["script_domain_count"] = len(result["script_domains"])

    # derived ratios
    if result["total_requests"] > 0:
        result["unique_request_domain_ratio"] = (
            result["unique_request_domains"] / result["total_requests"]
        )
        result["external_request_ratio"] = (
            result["external_domain_count"] / result["total_requests"]
        )
    else:
        result["unique_request_domain_ratio"] = 0
        result["external_request_ratio"] = 0

    # convert sets to lists for JSON
    result["external_domains"] = list(result["external_domains"])
    result["request_domains"] = list(result["request_domains"])
    result["script_domains"] = list(result["script_domains"])

    return result

def get_behavioral_features(url):
    result = analyze_url(url)
    return {
        "total_requests": result["total_requests"],
        "external_domain_count": result["external_domain_count"],
        "redirect_count": result["redirect_count"],
        "js_requests": result["js_requests"],
        "ip_based_requests": result["ip_based_requests"],
        "suspicious_tld_count": result["suspicious_tld_count"],
        "download_attempts": len(result["download_attempts"]),

        # new
        "final_url_differs": result["final_url_differs"],
        "unique_request_domains": result["unique_request_domains"],
        "unique_request_domain_ratio": result["unique_request_domain_ratio"],
        "script_domain_count": result["script_domain_count"],
        "external_request_ratio": result["external_request_ratio"],
        "error_flag": result["error_flag"],
        "timeout_flag": result["timeout_flag"],
        "document_requests": result["document_requests"],
        "script_requests": result["script_requests"],
        "stylesheet_requests": result["stylesheet_requests"],
        "image_requests": result["image_requests"],
        "font_requests": result["font_requests"],
        "xhr_fetch_requests": result["xhr_fetch_requests"],
        "other_requests": result["other_requests"]
    }

if __name__ == "__main__":
    with open("urls.txt") as f:
        urls = [u.strip() for u in f if u.strip()]

    output = []

    for u in urls:
        print(f"Scanning: {u}")
        r = analyze_url(u)
        output.append(r)

    with open("results.json", "w") as f:
        json.dump(output, f, indent=2)

    print("Done. Saved to results.json")