import re
from urllib.parse import urlparse
import tldextract
from url_checker import check_url, POPULAR_BRANDS

# Free email providers list
FREE_PROVIDERS = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'mail.com', 'protonmail.com', 'aol.com', 'zoho.com', 'yandex.com', 'gmx.com', 'icloud.com'}

# Urgent/Threat keywords in subject
URGENT_SUBJECT_KEYWORDS = ['urgent', 'immediate', 'suspended', 'alert', 'unauthorized', 'verification', 'restricted', 'locked', 'action required', 'close', 'expired', 'warning']

# High-risk security words in email body
URGENT_BODY_KEYWORDS = ['password', 'reset', 'verify', 'update', 'credit card', 'social security', 'ssn', 'bank', 'pin', 'otp', 'suspend', 'deactivate', 'security check', 'login immediately']

# Generic greetings
GENERIC_GREETINGS = ['dear customer', 'dear user', 'valued client', 'dear account holder', 'hello customer', 'dear client', 'valued customer', 'dear member']

def extract_links(body):
    """
    Extracts links from HTML anchor tags, and searches for plain text URLs.
    Returns list of dictionaries: {"actual": actual_url, "displayed": displayed_text}
    """
    links = []
    
    # 1. Extract HTML anchor tags: <a href="url">text</a>
    html_pattern = re.compile(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']*)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    html_matches = html_pattern.findall(body)
    
    for url, text in html_matches:
        links.append({
            "actual": url.strip(),
            "displayed": re.sub(r'<[^>]*>', '', text).strip() # Strip any nested HTML tags from text
        })
        
    # 2. Extract plain text URLs that aren't inside an href attribute
    raw_url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    raw_urls = raw_url_pattern.findall(body)
    
    # Filter out URLs already captured in HTML matches
    captured_urls = {l["actual"] for l in links}
    for r_url in raw_urls:
        r_url_clean = r_url.strip().rstrip('.,;:)') # clean ending punctuation
        if r_url_clean not in captured_urls:
            links.append({
                "actual": r_url_clean,
                "displayed": r_url_clean
            })
            
    return links

def check_mail(sender, subject, body):
    sender = (sender or "").strip()
    subject = (subject or "").strip()
    body = (body or "").strip()
    
    results = []
    
    # 1. Sender Analysis
    sender_domain = ""
    is_free_provider = False
    is_spoofed_brand = False
    impersonated_brand = ""
    
    if '@' in sender:
        parts = sender.split('@')
        local_part = parts[0].lower()
        sender_domain = parts[1].lower()
        
        # Check if free provider
        is_free_provider = sender_domain in FREE_PROVIDERS
        
        # Check if brand impersonation in domain
        ext = tldextract.extract("http://" + sender_domain)
        domain_part = ext.domain.lower()
        registered_domain = ext.registered_domain.lower() if ext.registered_domain else ""
        
        for brand in POPULAR_BRANDS:
            # Brand name is in the domain part, but the official domain is not the registered domain
            if brand in domain_part and registered_domain != f"{brand}.com" and registered_domain != f"{brand}.net":
                is_spoofed_brand = True
                impersonated_brand = brand
                break
                
        # If it is a free provider, check if they use a brand in the local part
        if is_free_provider:
            for brand in POPULAR_BRANDS:
                if brand in local_part:
                    is_spoofed_brand = True
                    impersonated_brand = brand
                    break
                    
    # Scoring for Sender Domain
    sender_pts = 0
    if is_spoofed_brand:
        sender_pts = 25
        results.append({
            "id": "S1",
            "name": "Suspicious Sender Domain",
            "triggered": True,
            "points": 25,
            "description": f"The sender's domain spoof/impersonates a popular brand ({impersonated_brand}).",
            "category": "Sender Analysis"
        })
    elif is_free_provider:
        results.append({
            "id": "S2",
            "name": "Public Mail Domain",
            "triggered": True,
            "points": 0,
            "description": "The sender is using a public free mail provider account (Gmail/Yahoo/Outlook).",
            "category": "Sender Analysis"
        })
    
    # 2. Subject Line Heuristics
    subject_pts = 0
    triggered_subject_kws = [kw for kw in URGENT_SUBJECT_KEYWORDS if kw in subject.lower()]
    if triggered_subject_kws:
        subject_pts = 15
        results.append({
            "id": "T1",
            "name": "Urgent Subject Trigger",
            "triggered": True,
            "points": 15,
            "description": f"Subject line contains high-urgency phishing keywords: {', '.join(triggered_subject_kws[:3])}.",
            "category": "Subject Line Analysis"
        })
        
    # 3. Body Text Heuristics
    body_pts = 0
    triggered_body_kws = [kw for kw in URGENT_BODY_KEYWORDS if kw in body.lower()]
    if triggered_body_kws:
        body_pts += 15
        results.append({
            "id": "B1",
            "name": "Coercive Body Language",
            "triggered": True,
            "points": 15,
            "description": f"Email body uses urgency/fear-inducing terms: {', '.join(triggered_body_kws[:3])}.",
            "category": "Body Heuristics"
        })
        
    has_generic = False
    generic_greeting_found = ""
    for greeting in GENERIC_GREETINGS:
        if greeting in body.lower():
            has_generic = True
            generic_greeting_found = greeting
            break
            
    if has_generic:
        body_pts += 10
        results.append({
            "id": "B2",
            "name": "Generic Greeting",
            "triggered": True,
            "points": 10,
            "description": f"The greeting is generic ('{generic_greeting_found}') rather than personalized.",
            "category": "Body Heuristics"
        })
        
    # 4. Links Analysis inside body
    links = extract_links(body)
    link_pts = 0
    spoofed_links = []
    flagged_links = []
    
    for l in links:
        actual_url = l["actual"]
        displayed_text = l["displayed"]
        
        # Check spoofed link
        is_spoofed_link = False
        
        display_clean = displayed_text.lower().replace('https://', '').replace('http://', '').replace('www.', '')
        actual_clean = actual_url.lower().replace('https://', '').replace('http://', '').replace('www.', '')
        
        looks_like_url = '.' in display_clean or '/' in display_clean
        if looks_like_url:
            display_ext = tldextract.extract("http://" + display_clean.split('/')[0])
            actual_ext = tldextract.extract("http://" + actual_clean.split('/')[0])
            
            if display_ext.registered_domain and actual_ext.registered_domain:
                if display_ext.registered_domain != actual_ext.registered_domain:
                    is_spoofed_link = True
                    spoofed_links.append({
                        "displayed": displayed_text,
                        "actual": actual_url
                    })
                    
        # Check actual URL risk score
        url_scan = check_url(actual_url)
        url_score = url_scan.get("subtotal", 0)
        
        if url_score >= 40 or is_spoofed_link:
            flagged_links.append({
                "displayed": displayed_text,
                "actual": actual_url,
                "score": url_score,
                "is_spoofed": is_spoofed_link
            })
            
    if spoofed_links:
        link_pts += 30
        results.append({
            "id": "L1",
            "name": "Link Impersonation / Spoofing",
            "triggered": True,
            "points": 30,
            "description": "Email contains links where display text differs from actual redirect (URL hijacking).",
            "category": "Link Analysis"
        })
        
    high_risk_links = [fl for fl in flagged_links if fl["score"] >= 70]
    medium_risk_links = [fl for fl in flagged_links if 40 <= fl["score"] < 70]
    
    if high_risk_links:
        link_pts += 35
        results.append({
            "id": "L2",
            "name": "High-Risk Links Contained",
            "triggered": True,
            "points": 35,
            "description": "Email body contains links pointing to known phishing or high-risk domains.",
            "category": "Link Analysis"
        })
    elif medium_risk_links:
        link_pts += 15
        results.append({
            "id": "L3",
            "name": "Suspicious Links Contained",
            "triggered": True,
            "points": 15,
            "description": "Email body contains links pointing to young or unencrypted domains.",
            "category": "Link Analysis"
        })
        
    total_score = min(sender_pts + subject_pts + body_pts + link_pts, 100)
    
    if total_score >= 70:
        verdict = "Phishing"
    elif total_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        
    if not results:
        results.append({
            "id": "C1",
            "name": "Clean Email",
            "triggered": False,
            "points": 0,
            "description": "No typical phishing signals or sender spoofing indicators were found.",
            "category": "Clean Scan"
        })
        
    return {
        "score": total_score,
        "verdict": verdict,
        "results": results,
        "sender_analysis": {
            "email": sender,
            "domain": sender_domain,
            "is_free_provider": is_free_provider,
            "is_spoofed_brand": is_spoofed_brand,
            "impersonated_brand": impersonated_brand
        },
        "body_analysis": {
            "generic_greeting": has_generic,
            "generic_greeting_text": generic_greeting_found,
            "urgent_keywords_found": triggered_body_kws,
            "sensitive_info_requested": any(w in body.lower() for w in ['password', 'credit card', 'pin', 'ssn', 'otp'])
        },
        "link_analysis": {
            "total_links": len(links),
            "spoofed_links_count": len(spoofed_links),
            "spoofed_links": spoofed_links,
            "flagged_links_count": len(flagged_links),
            "flagged_links": flagged_links
        }
    }
