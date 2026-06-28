import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

def check_ssl(url):
    """
    Connects to the given URL's host over port 443 and fetches SSL certificate details.
    Returns a dictionary indicating if it is valid, issuer, expiry date, days left, and warning status.
    """
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url
        
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {
                "valid": False,
                "issuer": "None",
                "expiry_date": "N/A",
                "days_left": 0,
                "warning": False,
                "error": "No hostname found"
            }
        
        # If the user specifically parsed http://, it might not have SSL
        if parsed.scheme == 'http':
            return {
                "valid": False,
                "issuer": "None",
                "expiry_date": "N/A",
                "days_left": 0,
                "warning": False,
                "error": "HTTP protocol used (No SSL)"
            }

        context = ssl.create_default_context()
        # Set socket connection timeout to 5 seconds
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Fetch expiration date
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    # Example format: 'May 24 12:00:00 2026 GMT' or 'May 24 12:00:00 2026 UTC'
                    # Strip out GMT/UTC and parse
                    # Remove trailing GMT or UTC or timezone info if it fails
                    try:
                        expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    except ValueError:
                        # Fallback parsing in case the timezone doesn't match %Z
                        expiry_date = datetime.strptime(not_after_str.rsplit(' ', 1)[0], '%b %d %H:%M:%S %Y')
                    
                    # Calculate days remaining relative to UTC
                    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                    days_left = (expiry_date - now_utc).days
                    valid = days_left > 0
                else:
                    valid = False
                    expiry_date = None
                    days_left = 0
                
                # Parse certificate issuer
                issuer = cert.get('issuer')
                issuer_name = "Unknown"
                if issuer:
                    for item in issuer:
                        for entry in item:
                            if entry[0] == 'commonName':
                                issuer_name = entry[1]
                                break
                            elif entry[0] == 'organizationName' and issuer_name == "Unknown":
                                issuer_name = entry[1]
                
                return {
                    "valid": valid,
                    "issuer": issuer_name,
                    "expiry_date": expiry_date.strftime('%Y-%m-%d') if expiry_date else "Unknown",
                    "days_left": max(0, days_left),
                    "warning": valid and days_left < 30,
                    "error": None
                }
    except Exception as e:
        return {
            "valid": False,
            "issuer": "None",
            "expiry_date": "N/A",
            "days_left": 0,
            "warning": False,
            "error": str(e)
        }
