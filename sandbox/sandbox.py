from playwright.sync_api import sync_playwright
from urllib.parse import urlparse
import os, re ,json

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
        "total_requests": 0, #no. of HTML, JS, CSS, img, font, API requests
        "external_domains": set(), # of external domain contacted
        "ip_based_requests": 0, # of requests made directly to an IP address.
        "suspicious_tld_count": 0, # domains with suspicious endings. - xyz, top, tk, ml, ga, cf, gq
        "redirect_count": 0, # of times the page redirected before landing on final URL
        "js_requests": 0, # of javascript files loaded
        "all_requests": [] # A full list of every request URL.
    }

    with sync_playwright() as p:

        browser = p.chromium.launch(headless=True)

        context = browser.new_context(
            accept_downloads=False,
            permissions=[]
        )

        page = context.new_page()
        page.set_default_timeout(10000)

        # DOWNLOAD LOGGING 
        result["download_attempts"] = []

        def handle_download(download):
            result["download_attempts"].append({
                "url": download.url,
                "suggested_filename": download.suggested_filename
            })
            download.cancel()

        page.on("download", handle_download)

        base_domain = get_domain(url)
        # track redirects
        def handle_response(response):
            if response.request.redirected_from:
                result["redirect_count"] += 1

        page.on("response", handle_response)

        # track requests
        def handle_request(request):
            req_url = request.url
            result["all_requests"].append(req_url)
            result["total_requests"] += 1

            domain = get_domain(req_url)

            # external domain
            if domain and base_domain not in domain:
                result["external_domains"].add(domain)

            # IP based
            if is_ip(req_url):
                result["ip_based_requests"] += 1

            # suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if req_url.endswith(tld) or tld in req_url:
                    result["suspicious_tld_count"] += 1

            # JS heavy
            if request.resource_type == "script":
                result["js_requests"] += 1

        page.on("request", handle_request)

        try:
            page.goto(url, wait_until="load")
            page.screenshot(path="shot.png")
            result["final_url"] = page.url
        except Exception as e:
            result["error"] = str(e)

        browser.close()

    # convert set → count
    result["external_domain_count"] = len(result["external_domains"])
    result["external_domains"] = list(result["external_domains"])

    return result

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