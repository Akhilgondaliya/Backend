import re
from urllib.parse import urlparse
import tldextract

# List of suspicious TLDs
SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'bid', 'link', 'click', 'science'}

# List of popular brands to check for brand impersonation
POPULAR_BRANDS = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook', 'instagram', 'twitter', 'linkedin', 'yahoo', 'outlook', 'bankofamerica', 'chase', 'wellsfargo', 'citi', 'binance', 'coinbase']

# List of suspicious phishing keywords
PHISHING_KEYWORDS = ['login', 'verify', 'secure', 'update', 'account', 'webscr', 'signin', 'confirm', 'validation', 'banking', 'billing', 'refund', 'support', 'service']

# List of popular URL shortener domains
SHORTENER_DOMAINS = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'ow.ly', 'goo.gl', 'rebrand.ly', 'shorte.st'}

def check_url(url):
    """
    Performs 13+ heuristic checks on the provided URL.
    Returns a dictionary with the check results, subtotal score, and individual status.
    """
    # Ensure scheme exists for parsing
    parsed_url = url
    if not (url.startswith('http://') or url.startswith('https://')):
        parsed_url = 'http://' + url
    
    try:
        parsed = urlparse(parsed_url)
        extracted = tldextract.extract(parsed_url)
    except Exception:
        # Fallback if parsing fails completely
        return {
            "error": True,
            "results": []
        }

    hostname = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    
    # Remove port from hostname if present
    hostname_clean = hostname.split(':')[0]
    
    results = []

    # 1. No HTTPS Check
    is_not_https = not url.startswith('https://')
    results.append({
        "id": 1,
        "name": "No HTTPS",
        "triggered": is_not_https,
        "points": 20 if is_not_https else 0,
        "description": "The site does not use the secure HTTPS protocol.",
        "category": "Protocol check"
    })

    # 2. IP as Host
    # Regex to match IPv4 or IPv6
    ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$'
    is_ip = bool(re.match(ip_pattern, hostname_clean))
    results.append({
        "id": 2,
        "name": "IP as Host",
        "triggered": is_ip,
        "points": 25 if is_ip else 0,
        "description": "Numeric IP address used as hostname instead of a domain name.",
        "category": "Numeric IP hostname"
    })

    # 3. Suspicious TLD Check
    tld = extracted.suffix.lower()
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    results.append({
        "id": 3,
        "name": "Suspicious TLD",
        "triggered": is_suspicious_tld,
        "points": 20 if is_suspicious_tld else 0,
        "description": f"URL uses a suspicious TLD (.{tld}) commonly used for phishing.",
        "category": "Protocol check"
    })

    # 4. Brand Impersonation Check
    # Check if a brand name is in subdomains or path, but the registered domain is not the brand
    registered_domain = extracted.registered_domain.lower() if extracted.registered_domain else ""
    is_brand_impersonation = False
    impersonated_brand = ""
    for brand in POPULAR_BRANDS:
        # If the brand is in the URL but the registered domain is not exactly brand.tld
        # (e.g. pay-pal-verify.com or paypal.secure-login.tk, but NOT paypal.com)
        brand_in_subdomain = brand in extracted.subdomain.lower()
        brand_in_path = brand in path.lower()
        # brand is in the registered domain but doesn't equal it exactly (e.g. paypal-security.com)
        brand_in_domain_part = brand in extracted.domain.lower() and extracted.domain.lower() != brand
        
        if (brand_in_subdomain or brand_in_path or brand_in_domain_part):
            is_brand_impersonation = True
            impersonated_brand = brand
            break
            
    results.append({
        "id": 4,
        "name": "Brand Impersonation",
        "triggered": is_brand_impersonation,
        "points": 30 if is_brand_impersonation else 0,
        "description": f"Potential brand impersonation detected for '{impersonated_brand}'.",
        "category": "paypal/google in URL"
    })

    # 5. Phishing Keywords Check
    triggered_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in parsed_url.lower():
            triggered_keywords.append(keyword)
    is_keyword_triggered = len(triggered_keywords) > 0
    results.append({
        "id": 5,
        "name": "Phishing Keywords",
        "triggered": is_keyword_triggered,
        "points": 20 if is_keyword_triggered else 0,
        "description": f"URL contains phishing keywords: {', '.join(triggered_keywords)}",
        "category": "login/verify/secure"
    })

    # 6. @ Symbol Check
    has_at = '@' in parsed_url
    results.append({
        "id": 6,
        "name": "@ Symbol",
        "triggered": has_at,
        "points": 15 if has_at else 0,
        "description": "Use of '@' symbol in URL, which ignores everything preceding it.",
        "category": "@ in URL"
    })

    # 7. URL Shortener Check
    is_shortener = hostname_clean.lower() in SHORTENER_DOMAINS
    results.append({
        "id": 7,
        "name": "URL Shortener",
        "triggered": is_shortener,
        "points": 15 if is_shortener else 0,
        "description": "URL uses a link shortener service to hide the final destination.",
        "category": "bit.ly/tinyurl"
    })

    # 8. Deep Subdomain Check
    # Subdomains are separated by dots in extracted.subdomain
    subdomain_parts = [p for p in extracted.subdomain.split('.') if p]
    is_deep_subdomain = len(subdomain_parts) >= 3
    results.append({
        "id": 8,
        "name": "Deep Subdomain",
        "triggered": is_deep_subdomain,
        "points": 15 if is_deep_subdomain else 0,
        "description": f"URL contains deep subdomains ({len(subdomain_parts)} levels).",
        "category": "3+ subdomain levels"
    })

    # 9. Long URL Check
    is_long = len(url) > 100
    results.append({
        "id": 9,
        "name": "Long URL",
        "triggered": is_long,
        "points": 10 if is_long else 0,
        "description": f"URL length is abnormally long ({len(url)} characters).",
        "category": "Length > 100 chars"
    })

    # 10. Hex Encoding Check
    # Check if there are percent encoded hex characters, e.g. %20, %3D
    hex_pattern = r'%[0-9a-fA-F]{2}'
    has_hex = bool(re.search(hex_pattern, parsed_url))
    results.append({
        "id": 10,
        "name": "Hex Encoding",
        "triggered": has_hex,
        "points": 10 if has_hex else 0,
        "description": "URL contains percent-encoded hex patterns to obfuscate text.",
        "category": "%XX patterns"
    })

    # 11. Hyphen in Domain
    has_hyphen = '-' in extracted.domain
    results.append({
        "id": 11,
        "name": "Hyphen in Domain",
        "triggered": has_hyphen,
        "points": 5 if has_hyphen else 0,
        "description": "Domain contains hyphens, typical of phishing domain spoofing.",
        "category": "Hyphens used"
    })

    # 12. Digits in Domain
    has_digits = any(char.isdigit() for char in extracted.domain)
    results.append({
        "id": 12,
        "name": "Digits in Domain",
        "triggered": has_digits,
        "points": 5 if has_digits else 0,
        "description": "Domain contains numbers, which is uncommon for popular brands.",
        "category": "Numbers in domain"
    })

    # 13. Double Slash in Path Check
    # Finding '//' in path (excluding the initial http:// or https://)
    # If the URL had no protocol initially, parsed.path might contain double slash.
    # Let's inspect the original URL after index 8
    clean_url_body = url[8:] if url.startswith('https://') else (url[7:] if url.startswith('http://') else url)
    has_double_slash = '//' in clean_url_body
    results.append({
        "id": 13,
        "name": "Double Slash in Path",
        "triggered": has_double_slash,
        "points": 8 if has_double_slash else 0,
        "description": "URL path contains double slashes '//' used to redirect traffic.",
        "category": "// in path"
    })

    return {
        "error": False,
        "results": results,
        "subtotal": sum(r["points"] for r in results)
    }
