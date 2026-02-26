# URL Behavior Sandbox

Lightweight dynamic sandbox for analyzing URLs using a headless browser.

## Features

- Runs URLs in isolated Docker container
- Headless Chromium (Playwright)
- Logs network requests
- Detects redirects
- Logs (and blocks) download attempts
- Extracts behavioral features for ML

## Requirements

- Docker Desktop

## Build

```bash
docker build -t url-sandbox .
```

## Add URLs

Edit `urls.txt`:

```
https://example.com
https://google.com
```

## Run

```bash
docker run --rm -v ${PWD}:/app url-sandbox
```

Results will be saved to:

```
results.json
```

## Output Example

```json
{
  "url": "https://example.com",
  "total_requests": 42,
  "external_domain_count": 5,
  "redirect_count": 2,
  "js_requests": 14,
  "download_attempts": []
}
```

---

For academic research and phishing detection experiments only.