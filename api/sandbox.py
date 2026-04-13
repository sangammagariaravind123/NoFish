from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse
import os
import re
import json

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq"]
API_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(API_DIR)
SCREENSHOT_PATHS = (
    os.path.join(API_DIR, "shot.png"),
    os.path.join(PROJECT_ROOT, "sandbox", "shot.png"),
)
REALISTIC_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)
DEFAULT_VIEWPORT = {"width": 1440, "height": 900}
POST_LOAD_WAIT_MS = 1500
BLOCK_KEYWORD_RULES = (
    ("access denied", "Access denied page"),
    ("forbidden", "Forbidden response page"),
    ("request blocked", "Request blocked page"),
    ("bot detected", "Bot-detection page"),
    ("attention required", "Anti-bot challenge page"),
    ("verify you are human", "Human verification challenge"),
    ("captcha", "CAPTCHA / challenge page"),
    ("cf-chl", "Cloudflare challenge page"),
    ("cdn-cgi/challenge-platform", "Cloudflare challenge page"),
    ("that link could not be found", "Invalid or unresolved page"),
    ("this site can’t be reached", "Browser error page"),
    ("this site can't be reached", "Browser error page"),
    ("err_name_not_resolved", "Browser DNS error page"),
)

def is_ip(url):
    return re.match(r"https?://\d+\.\d+\.\d+\.\d+", url) is not None

def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ""


def detect_inaccessible_page(result, page_title="", html="", final_url=""):
    title_lower = (page_title or "").strip().lower()
    html_lower = (html or "").lower()
    final_url_lower = (final_url or "").lower()

    matched_reasons = []
    for needle, reason in BLOCK_KEYWORD_RULES:
        if needle in title_lower or needle in html_lower or needle in final_url_lower:
            matched_reasons.append(reason)

    doc_only = (
        result["document_requests"] == 1
        and result["script_requests"] == 0
        and result["stylesheet_requests"] == 0
        and result["image_requests"] == 0
        and result["font_requests"] == 0
        and result["xhr_fetch_requests"] == 0
        and result["other_requests"] == 0
    )
    suspicious_status = result.get("main_response_status") in {401, 403, 429, 503}
    has_low_info_scan = result["total_requests"] <= 3 or doc_only
    very_small_page = result.get("html_length", 0) <= 12000

    if matched_reasons:
        reason = matched_reasons[0]
        if suspicious_status or (has_low_info_scan and very_small_page):
            return True, reason

    if suspicious_status and has_low_info_scan and very_small_page:
        return True, f"HTTP {result['main_response_status']} access-control response"

    return False, None

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
        "page_title": "",
        "html_length": 0,
        "main_response_status": None,
        "sandbox_accessible": True,
        "denial_detected": False,
        "sandbox_blocked_reason": None,

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
            permissions=[],
            user_agent=REALISTIC_USER_AGENT,
            viewport=DEFAULT_VIEWPORT,
            locale="en-US",
            timezone_id="Asia/Kolkata",
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
            },
        )

        page = context.new_page()
        page.set_default_timeout(10000)
        page.set_default_navigation_timeout(10000)

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
            response = page.goto(url, wait_until="domcontentloaded")
            if response is not None:
                result["main_response_status"] = response.status

            # wait for dynamic content
            page.wait_for_timeout(5000)

            # optional: wait until network settles
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                pass

            for screenshot_path in SCREENSHOT_PATHS:
                page.screenshot(path=screenshot_path)
            result["final_url"] = page.url
            result["page_title"] = page.title() or ""
            html = page.content() or ""
            result["html_length"] = len(html)

            if result["final_url"] and result["final_url"] != url:
                result["final_url_differs"] = 1

            denial_detected, blocked_reason = detect_inaccessible_page(
                result,
                result["page_title"],
                html,
                result["final_url"],
            )
            result["denial_detected"] = denial_detected
            result["sandbox_accessible"] = not denial_detected
            result["sandbox_blocked_reason"] = blocked_reason

        except Exception as e:
            result["error"] = str(e)
            result["error_flag"] = 1

            if "Timeout" in str(e) or "timeout" in str(e):
                result["timeout_flag"] = 1
            result["sandbox_accessible"] = True
            result["denial_detected"] = False
            result["sandbox_blocked_reason"] = None

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
