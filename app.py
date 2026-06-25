import os
import io
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import qrcode

from url_checker import check_url
from ssl_checker import check_ssl
from whois_checker import check_whois
from qr_decoder import decode_qr
from pdf_generator import generate_pdf
from mail_checker import check_mail

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure CORS dynamically from environment, supporting localhost options
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://client-jade-rho.vercel.app")
CORS(app, resources={r"/*": {
    "origins": [
        "http://localhost:5173", 
        "http://127.0.0.1:5173", 
        "https://client-jade-rho.vercel.app",
        FRONTEND_URL
    ]
}})

def perform_full_scan(url):
    """
    Orchestrates the entire scan: Heuristics, SSL certificate, and WHOIS domain age checks.
    Combines and caps the score at 100, deciding the verdict.
    """
    # 1. URL Heuristic analysis (13 checks)
    heuristic_results = check_url(url)
    
    # If the checker encounters parsing errors, use a default fallback structure
    if heuristic_results.get("error"):
        return {
            "url": url,
            "score": 0,
            "verdict": "Safe",
            "results": [],
            "ssl": {
                "valid": False, "issuer": "None", "expiry_date": "N/A", "days_left": 0, "warning": False, "error": "Invalid URL"
            },
            "whois": {
                "age_days": 0, "creation_date": "N/A", "risk_level": "Unknown", "points": 0, "error": "Invalid URL"
            }
        }
        
    # 2. SSL certificate analysis
    ssl_result = check_ssl(url)
    
    # 3. WHOIS details and domain age lookup
    whois_result = check_whois(url)
    
    # Calculate final aggregate score
    # Sum the subtotal of heuristics and any WHOIS risk points
    total_score = heuristic_results["subtotal"] + whois_result["points"]
    total_score = min(total_score, 100) # Capped at 100
    
    # Determine the verdict level
    if total_score >= 70:
        verdict = "Phishing"
    elif total_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        
    return {
        "url": url,
        "score": total_score,
        "verdict": verdict,
        "results": heuristic_results["results"],
        "ssl": ssl_result,
        "whois": whois_result
    }

@app.route('/', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({
        "status": "online",
        "app": "PhishZero Backend REST API",
        "version": "1.0.0",
        "system": "IBM CSRBOX Cybersecurity Internship 2026"
    })

@app.route('/api/scan', methods=['POST'])
def scan_url_endpoint():
    """
    Performs scan on a provided URL.
    Input JSON: { "url": "..." }
    """
    data = request.json or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "Please enter a URL"}), 400
        
    # Convert http:// to https:// and prepend https:// if missing
    if url.startswith('http://'):
        url = url.replace('http://', 'https://', 1)
    elif not url.startswith('https://'):
        url = 'https://' + url
        
    result = perform_full_scan(url)
    return jsonify(result)

@app.route('/api/scan-qr', methods=['POST'])
def scan_qr_endpoint():
    """
    Decodes an uploaded QR image (file or camera frame) and scans the extracted URL.
    Input FormData: file named "qr_image"
    """
    if 'qr_image' not in request.files:
        return jsonify({"error": "No QR code file uploaded"}), 400
        
    file = request.files['qr_image']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    # Attempt QR decode
    decode_result = decode_qr(file)
    if not decode_result["success"]:
        # Return 400 with the exact error so the frontend can intercept and alert the user
        return jsonify({"error": decode_result["error"]}), 400
        
    decoded_url = decode_result["url"]
    
    # Convert http:// to https:// and prepend https:// if missing
    if decoded_url.startswith('http://'):
        decoded_url = decoded_url.replace('http://', 'https://', 1)
    elif not decoded_url.startswith('https://'):
        decoded_url = 'https://' + decoded_url
        
    # Scan the decoded URL
    result = perform_full_scan(decoded_url)
    return jsonify(result)

@app.route('/api/scan-mail', methods=['POST'])
def scan_mail_endpoint():
    """
    Performs scan on provided email content.
    Input JSON: { "sender": "...", "subject": "...", "body": "..." }
    """
    data = request.json or {}
    sender = data.get('sender', '').strip()
    subject = data.get('subject', '').strip()
    body = data.get('body', '').strip()
    
    result = check_mail(sender, subject, body)
    return jsonify(result)

@app.route('/api/report', methods=['GET', 'POST'])
def generate_report_endpoint():
    """
    Generates and downloads a ReportLab PDF document.
    Can accept POST with JSON scan result data for instant generation,
    or fallback to GET with ?url=... which performs a scan.
    """
    scan_results = None
    if request.method == 'POST':
        scan_results = request.json
        
    if not scan_results:
        url = request.args.get('url', '').strip()
        if not url:
            return jsonify({"error": "URL parameter or scan results JSON is required"}), 400
        # Scan URL dynamically to build fresh report details
        scan_results = perform_full_scan(url)
    
    try:
        pdf_data = generate_pdf(scan_results)
        buffer = io.BytesIO(pdf_data)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='phishzero_report.pdf'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500

@app.route('/api/sample-qr', methods=['GET'])
def get_sample_qr():
    """
    Generates and returns a PNG QR code pointing to the sample phishing URL:
    http://paypal-secure-login.verify-account.tk
    """
    try:
        phish_url = "http://paypal-secure-login.verify-account.tk"
        
        # Build QR code structure
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(phish_url)
        qr.make(fit=True)
        
        # Output image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='image/png',
            as_attachment=True,
            download_name='sample_qr.png'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate sample QR: {str(e)}"}), 500

@app.route('/api/contact', methods=['POST'])
def save_contact_message():
    """
    Saves a contact message to a local JSON file: server/messages.json
    Input JSON: { "name": "...", "email": "...", "message": "..." }
    """
    import json
    from datetime import datetime
    data = request.json or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    message = data.get('message', '').strip()
    
    if not name or not email or not message:
        return jsonify({"error": "All fields (name, email, message) are required"}), 400
        
    new_message = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "name": name,
        "email": email,
        "message": message
    }
    
    # Resolve messages filepath (using /tmp on serverless environments to allow writing)
    is_serverless = os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    if is_serverless:
        messages_filepath = "/tmp/messages.json"
        # If the file doesn't exist in /tmp yet, seed it from original directory if possible
        if not os.path.exists(messages_filepath):
            orig_path = os.path.join(os.path.dirname(__file__), 'messages.json')
            if os.path.exists(orig_path):
                try:
                    import shutil
                    shutil.copy2(orig_path, messages_filepath)
                except Exception:
                    pass
    else:
        messages_filepath = os.path.join(os.path.dirname(__file__), 'messages.json')
    
    # Load existing messages
    existing_messages = []
    if os.path.exists(messages_filepath):
        try:
            with open(messages_filepath, 'r', encoding='utf-8') as f:
                existing_messages = json.load(f)
                if not isinstance(existing_messages, list):
                    existing_messages = []
        except Exception:
            existing_messages = []
            
    # Append the new message
    existing_messages.append(new_message)
    
    # Save back to file
    try:
        with open(messages_filepath, 'w', encoding='utf-8') as f:
            json.dump(existing_messages, f, indent=2, ensure_ascii=False)
    except Exception as e:
        return jsonify({"error": f"Failed to save message: {str(e)}"}), 500
        
    return jsonify({"success": True, "message": "Message saved successfully"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
