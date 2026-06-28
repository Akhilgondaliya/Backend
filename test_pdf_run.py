import sys
import os

from pdf_generator import generate_pdf

data = {
    'url': 'https://paypaI.com',
    'verdict': 'PHISHING',
    'score': 70,
    'results': [
        {'name': 'Brand Impersonation', 'triggered': True, 'points': 20, 'description': 'Domain impersonates a known brand'},
        {'name': 'No HTTPS', 'triggered': True, 'points': 20, 'description': 'Insecure plain HTTP used'},
        {'name': 'Suspicious TLD', 'triggered': False, 'points': 15, 'description': ''}
    ],
    'ssl': {
        'valid': False,
        'warning': False,
        'days_left': 0,
        'expiry_date': 'N/A',
        'error': 'Broken connection'
    },
    'whois': {
        'error': False,
        'age_days': 15,
        'registrar': 'NameCheap',
        'points': 25,
        'creation_date': '2026-06-12'
    },
    'scan_duration': 0.12,
    'ip_address': '127.0.0.1',
    'confidence': 95
}

try:
    print("Generating PDF...")
    pdf_bytes = generate_pdf(data)
    with open("test_report.pdf", "wb") as f:
        f.write(pdf_bytes)
    print("Success! PDF saved to test_report.pdf, length:", len(pdf_bytes))
except Exception as e:
    import traceback
    traceback.print_exc()

