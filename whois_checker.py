import whois
import tldextract
from datetime import datetime, timezone

def check_whois(url):
    """
    Looks up the domain details via WHOIS, extracts creation date,
    and returns its age, risk classification, and custom risk points.
    """
    try:
        # Extract the registered domain (e.g., paypal-secure.verify.tk -> verify.tk)
        extracted = tldextract.extract(url)
        domain = extracted.registered_domain
        if not domain:
            return {
                "age_days": 0,
                "creation_date": "N/A",
                "risk_level": "Unknown",
                "points": 0,
                "registrar": "N/A",
                "error": "Domain extraction failed"
            }

        # Query WHOIS
        w = whois.whois(domain)
        creation_date = w.creation_date
        registrar = w.registrar if hasattr(w, 'registrar') and w.registrar else "Unknown"

        # Sometimes creation_date is a list of datetime objects (e.g., for multi-registrar entries)
        if isinstance(creation_date, list):
            dt_objects = [item for item in creation_date if isinstance(item, datetime)]
            if dt_objects:
                creation_date = dt_objects[0]
            elif creation_date:
                creation_date = creation_date[0]
            else:
                creation_date = None

        if not creation_date:
            return {
                "age_days": 0,
                "creation_date": "Unknown (Private/Restricted)",
                "risk_level": "Medium",
                "points": 5,
                "registrar": registrar,
                "error": "WHOIS creation date not found"
            }

        # If creation_date is a string, try parsing it
        if isinstance(creation_date, str):
            for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%SZ', '%d-%b-%Y', '%Y.%m.%d'):
                try:
                    creation_date = datetime.strptime(creation_date.strip(), fmt)
                    break
                except ValueError:
                    pass
            else:
                creation_date = None

        if not isinstance(creation_date, datetime):
            return {
                "age_days": 0,
                "creation_date": str(creation_date) if creation_date else "Unknown",
                "risk_level": "Medium",
                "points": 5,
                "registrar": registrar,
                "error": "Creation date date-time parse failure"
            }

        # Calculate domain age in days
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age_days = (now - creation_date).days

        # Classify risk level based on domain age
        if age_days < 30:
            risk_level = "Very High"
            points = 25
        elif age_days < 180:
            risk_level = "High"
            points = 10
        elif age_days < 365:
            risk_level = "Medium"
            points = 5
        else:
            risk_level = "Low"
            points = 0

        # Handle list-type registrar names gracefully (take first)
        if isinstance(registrar, list):
            registrar = registrar[0]

        return {
            "age_days": max(0, age_days),
            "creation_date": creation_date.strftime('%Y-%m-%d'),
            "risk_level": risk_level,
            "points": points,
            "registrar": registrar,
            "error": None
        }

    except Exception as e:
        return {
            "age_days": 0,
            "creation_date": "N/A",
            "risk_level": "Unknown",
            "points": 5,
            "registrar": "N/A",
            "error": str(e)
        }
