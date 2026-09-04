##############################################################imports#################################################
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse
from urllib.parse import urlparse

###############################################################utility functions###############################################
def normalize_url(url: str) -> str:
    """Ensure URL has a scheme (default to https)."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"https://{url}"
    return url



def analyze_cookies(headers: dict[str, str]) -> list[dict]:
    """Analyze Set-Cookie headers for security attributes."""

    findings: list[dict] = []

    cookies = []

    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookies.append(value)

    if not cookies:
        return findings

    for cookie in cookies:
        parts = [part.strip() for part in cookie.split(";")]

        cookie_name = parts[0].split("=", 1)[0].strip()

        attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}

        if "secure" not in attributes:
            findings.append(
                {
                    "id": "COOKIE-001",
                    "category": "Cookie",
                    "issue": f"Cookie '{cookie_name}' missing Secure flag",
                    "severity": "MEDIUM",
                    "risk": (
                        "The cookie may be transmitted over an unencrypted "
                        "HTTP connection."
                    ),
                    "fix": (
                        f"Add the Secure attribute to the '{cookie_name}' " "cookie."
                    ),
                }
            )

        if "httponly" not in attributes:
            findings.append(
                {
                    "id": "COOKIE-002",
                    "category": "Cookie",
                    "issue": f"Cookie '{cookie_name}' missing HttpOnly flag",
                    "severity": "MEDIUM",
                    "risk": (
                        "Client-side JavaScript may access the cookie, "
                        "increasing the impact of XSS attacks."
                    ),
                    "fix": (
                        f"Add the HttpOnly attribute to the '{cookie_name}' " "cookie."
                    ),
                }
            )

        if "samesite" not in attributes:
            findings.append(
                {
                    "id": "COOKIE-003",
                    "category": "Cookie",
                    "issue": f"Cookie '{cookie_name}' missing SameSite attribute",
                    "severity": "LOW",
                    "risk": (
                        "The cookie has no explicit cross-site request " "policy."
                    ),
                    "fix": (
                        f"Add SameSite=Lax, SameSite=Strict, or an "
                        f"appropriate SameSite policy to '{cookie_name}'."
                    ),
                }
            )

    return findings

################################################################fetch headers####################################################
def fetch_headers(url: str, method="GET", follow_redirects=True, timeout=10):
    """
    Fetches headers from the target URL.
    Returns a dictionary containing headers, status code, and URL.
    """
    target_url = normalize_url(url)

    # Configure retry logic (3 attempts)
    retry_strategy = Retry(
        total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    try:
        response = session.request(
            method=method,
            url=target_url,
            allow_redirects=follow_redirects,
            timeout=timeout,
            headers={"User-Agent": "HeaderScan-Tool/1.0"},  # Polite User-Agent
        )

        return {
            "success": True,
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "http_version": response.raw.version,
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "url": target_url,
            "error": "Request timed out. The server took too long to respond.",
        }
    except requests.exceptions.SSLError:
        return {
            "success": False,
            "url": target_url,
            "error": "SSL verification failed. The certificate might be invalid.",
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "url": target_url,
            "error": "Failed to connect to the server. Please check the URL and your internet connection.",
        }
    except requests.exceptions.TooManyRedirects:
        return {
            "success": False,
            "url": target_url,
            "error": "Too many redirects. The URL might be in a redirect loop.",
        }
    except requests.exceptions.MissingSchema:
        return {
            "success": False,
            "url": target_url,
            "error": "Invalid URL format. Missing schema (http:// or https://).",
        }
    except requests.exceptions.InvalidURL:
        return {
            "success": False,
            "url": target_url,
            "error": "Invalid URL. Please check the URL and try again.",
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "url": target_url,
            "error": f"An error occurred: {e!s}",
        }

################################################analysis functions################################################



def analyze_headers(headers_data):
    """
    Analyzes the raw headers and returns a list of findings.
    """
    if not headers_data.get("success"):
        return []

    headers = {k.lower(): v for k, v in headers_data["headers"].items()}
    findings = []

    # --- 1. Security Headers Analysis ---

    # Content-Security-Policy
    if "content-security-policy" not in headers:
        findings.append(
            {
                "id": "SEC-001",
                "category": "Security",
                "issue": "Missing Content-Security-Policy",
                "severity": "HIGH",
                "risk": "XSS (Cross-Site Scripting) attacks are easier to exploit.",
                "fix": "Add a 'Content-Security-Policy' header defining allowed content sources.",
            }
        )

    # Strict-Transport-Security (HSTS)
    if "strict-transport-security" not in headers:
        findings.append(
            {
                "id": "SEC-002",
                "category": "Security",
                "issue": "Missing Strict-Transport-Security",
                "severity": "HIGH",
                "risk": "Susceptible to Man-in-the-Middle (MITM) protocol downgrade attacks.",
                "fix": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'.",
            }
        )

    # X-Frame-Options
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append(
            {
                "id": "SEC-003",
                "category": "Security",
                "issue": "Missing X-Frame-Options",
                "severity": "HIGH",
                "risk": "Vulnerable to Clickjacking attacks.",
                "fix": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
            }
        )

    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append(
            {
                "id": "SEC-004",
                "category": "Security",
                "issue": "Missing X-Content-Type-Options",
                "severity": "MEDIUM",
                "risk": "Browsers may MIME-sniff the response body, leading to XSS.",
                "fix": "Add 'X-Content-Type-Options: nosniff'.",
            }
        )

    # --- 2. Information Leakage ---

    # Server Header
    if "server" in headers:
        findings.append(
            {
                "id": "LEAK-001",
                "category": "Leakage",
                "issue": f"Server Header Leaked: {headers['server']}",
                "severity": "LOW",
                "risk": "Reveals server technology, helping attackers verify CVEs.",
                "fix": "Configure server to suppress or obfuscate the 'Server' header.",
            }
        )

    # X-Powered-By
    if "x-powered-by" in headers:
        findings.append(
            {
                "id": "LEAK-002",
                "category": "Leakage",
                "issue": f"X-Powered-By Leaked: {headers['x-powered-by']}",
                "severity": "MEDIUM",
                "risk": "Reveals specific framework/version info.",
                "fix": "Remove the 'X-Powered-By' header in server config.",
            }
        )

    # --- 3. CORS Misconfiguration ---

    if (
        "access-control-allow-origin" in headers
        and headers["access-control-allow-origin"] == "*"
    ):
        findings.append(
            {
                "id": "CORS-001",
                "category": "CORS",
                "issue": "CORS Access-Control-Allow-Origin is '*'",
                "severity": "MEDIUM",
                "risk": "Allows any domain to access resources (dangerous if auth is used).",
                "fix": "Restrict to specific trusted domains.",
            }
        )

    # --- 4. Performance ---

    # Cache-Control
    if "cache-control" not in headers:
        findings.append(
            {
                "id": "PERF-001",
                "category": "Performance",
                "issue": "Missing Cache-Control Header",
                "severity": "LOW",
                "risk": "Browser may not cache resources efficiently, slowing load times.",
                "fix": "Add 'Cache-Control' header (e.g., max-age=3600).",
            }
        )

    # --- 5. Cookie Security ---

    findings.extend(analyze_cookies(headers))

    return findings

#################################################################main function####################################################
def main(url: str):
    headers_data = fetch_headers(url)
    findings = analyze_headers(headers_data)

    if not findings:
        print(f"No issues found for {url}.")
    else:
        print(f"Findings for {url}:")
        for finding in findings:
            print(f"- [{finding['severity']}] {finding['issue']}")
            print(f"  Risk: {finding['risk']}")
            print(f"  Fix: {finding['fix']}\n")
###################################################################entry point########################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HeaderScan: Analyze HTTP headers for security and performance issues."
    )
    parser.add_argument("url", help="The URL to analyze")
    args = parser.parse_args()
    main(args.url)
