import os
import io
import json
import time
import socket
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
from file_checker import scan_apk, scan_image
from stats_store import load_stats, track_scan

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure CORS dynamically from environment, supporting localhost options
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://phishzero.vercel.app")
CORS(app, resources={r"/*": {
    "origins": [
        "http://localhost:5173", 
        "http://127.0.0.1:5173", 
        "https://client-jade-rho.vercel.app",
        "https://phishzero.vercel.app",
        FRONTEND_URL
    ]
}})

def perform_full_scan(url, scan_type="url"):
    """
    Orchestrates the entire scan: Heuristics, SSL certificate, and WHOIS domain age checks.
    Combines and caps the score at 100, deciding the verdict.
    """
    start_time = time.time()
    
    # 1. URL Heuristic analysis (13 checks)
    heuristic_results = check_url(url)
    
    # If the checker encounters parsing errors, use a default fallback structure
    if heuristic_results.get("error"):
        if scan_type in ["url", "qr"]:
            track_scan(scan_type, 0)
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
            },
            "scan_duration": 0.05,
            "ip_address": "Unavailable",
            "confidence": 50
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
        
    # Measure duration
    scan_duration = round(time.time() - start_time, 3)
    
    # Resolve IP address
    from urllib.parse import urlparse
    try:
        parsed_url = url
        if not (url.startswith('http://') or url.startswith('https://')):
            parsed_url = 'https://' + url
        hostname = urlparse(parsed_url).hostname
        if hostname:
            ip_address = socket.gethostbyname(hostname)
        else:
            ip_address = "Unavailable"
    except Exception:
        ip_address = "Unavailable"
        
    # Confidence Score Calculation
    confidence = 95
    if ssl_result.get("error"):
        confidence -= 15
    if whois_result.get("error"):
        confidence -= 15
    confidence = max(30, min(confidence, 100))
    
    # Track statistics
    if scan_type in ["url", "qr"]:
        track_scan(scan_type, total_score)
        
    return {
        "url": url,
        "score": total_score,
        "verdict": verdict,
        "results": heuristic_results["results"],
        "ssl": ssl_result,
        "whois": whois_result,
        "scan_duration": scan_duration,
        "ip_address": ip_address,
        "confidence": confidence
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

@app.route('/api/stats', methods=['GET'])
def get_stats_endpoint():
    """Returns the compiled cybersecurity statistics metrics."""
    stats = load_stats()
    return jsonify(stats)

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
        
    result = perform_full_scan(url, scan_type="url")
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
    result = perform_full_scan(decoded_url, scan_type="qr")
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
    track_scan("mail", result.get("score", 0))
    return jsonify(result)

@app.route('/api/scan-file', methods=['POST'])
def scan_file_endpoint():
    """
    Scans an uploaded file (APK or Image) for phishing threats.
    Input FormData: file named "file"
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    uploaded_file = request.files['file']
    filename = uploaded_file.filename
    if filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    try:
        file_bytes = uploaded_file.read()
        file_size = len(file_bytes)
        
        # Identify type by extension
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        
        if ext == 'apk':
            scan_data = scan_apk(file_bytes)
        elif ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
            scan_data = scan_image(file_bytes, qr_decoder_func=decode_qr)
        else:
            return jsonify({"error": "Unsupported file format. Please upload an APK or standard Image (PNG, JPG, JPEG, WEBP)"}), 400
            
        if not scan_data.get("success", False):
            return jsonify({"error": scan_data.get("error", "Failed to scan file")}), 500
            
        # 1. Run scans on extracted URLs (cap to 5 to avoid timeouts)
        extracted_urls = scan_data.get("urls", [])
        capped_urls = extracted_urls[:5]
        url_scan_results = []
        
        phishing_url_count = 0
        suspicious_url_count = 0
        
        for url in capped_urls:
            # Standardize URL
            scan_url = url
            if scan_url.startswith('http://'):
                scan_url = scan_url.replace('http://', 'https://', 1)
            elif not scan_url.startswith('https://'):
                scan_url = 'https://' + scan_url
                
            try:
                # Perform scan
                url_scan = perform_full_scan(scan_url, scan_type="file_url")
                url_scan_results.append({
                    "url": url,
                    "score": url_scan["score"],
                    "verdict": url_scan["verdict"],
                    "results": url_scan["results"]
                })
                if url_scan["verdict"] == "Phishing":
                    phishing_url_count += 1
                elif url_scan["verdict"] == "Suspicious":
                    suspicious_url_count += 1
            except Exception as e_scan:
                print(f"Failed scanning URL {url}: {e_scan}")
                
        # 2. Risk scoring calculation
        risk_score = 0
        if scan_data["type"] == "apk":
            # Add points for high risk permissions
            risk_score += len(scan_data.get("high_risk_permissions", [])) * 10
            # Add points for URLs found
            risk_score += phishing_url_count * 45
            risk_score += suspicious_url_count * 20
        else:
            # Image scanner
            if scan_data.get("qr_url"):
                # Check if QR url is phishing/suspicious
                qr_verdict = next((u for u in url_scan_results if u["url"] == scan_data["qr_url"]), None)
                if qr_verdict:
                    if qr_verdict["verdict"] == "Phishing":
                        risk_score += 80
                    elif qr_verdict["verdict"] == "Suspicious":
                        risk_score += 40
            
            # General embedded url threat additions
            risk_score += phishing_url_count * 50
            risk_score += suspicious_url_count * 25
            
            # Stego detection penalty
            if scan_data.get("stego_payload"):
                risk_score += 45
            
        risk_score = min(risk_score, 100)
        
        # Decide final file verdict
        if risk_score >= 70:
            verdict = "Phishing"
        elif risk_score >= 40:
            verdict = "Suspicious"
        else:
            verdict = "Safe"
            
        track_scan("file", risk_score)
            
        return jsonify({
            "filename": filename,
            "filesize": file_size,
            "filetype": scan_data["type"],
            "score": risk_score,
            "verdict": verdict,
            "permissions": scan_data.get("permissions", []),
            "high_risk_permissions": scan_data.get("high_risk_permissions", []),
            "qr_url": scan_data.get("qr_url"),
            "extracted_urls": extracted_urls,
            "url_scans": url_scan_results,
            "stego_payload": scan_data.get("stego_payload")
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to complete file scan: {str(e)}"}), 500

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
        logo_path = os.path.join(os.path.dirname(__file__), 'logo.png')
        pdf_data = generate_pdf(scan_results, logo_path)
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

@app.route('/api/sample-apk', methods=['GET'])
def get_sample_apk():
    """
    Generates and returns an in-memory ZIP archive representing a mock APK file.
    It contains a AndroidManifest.xml with dangerous permission tags
    and a classes.dex file containing hardcoded phishing URL strings.
    """
    try:
        import zipfile
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Write a mock AndroidManifest.xml with permissions
            manifest_content = (
                b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                b"<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
                b"    <uses-permission android:name=\"android.permission.SEND_SMS\" />\n"
                b"    <uses-permission android:name=\"android.permission.RECEIVE_SMS\" />\n"
                b"    <uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\" />\n"
                b"</manifest>"
            )
            zip_file.writestr("AndroidManifest.xml", manifest_content)
            
            # Write a mock classes.dex with hardcoded URL
            dex_content = b"classes.dex content containing mock phishing link: http://paypal-secure-login.verify-account.tk/login"
            zip_file.writestr("classes.dex", dex_content)
            
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='application/vnd.android.package-archive',
            as_attachment=True,
            download_name='sample_phish.apk'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate sample APK: {str(e)}"}), 500

@app.route('/api/sample-apk-safe', methods=['GET'])
def get_sample_apk_safe():
    """
    Generates and returns an in-memory ZIP archive representing a safe mock APK file.
    Contains standard internet permissions and a safe URL.
    """
    try:
        import zipfile
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Write a mock AndroidManifest.xml with standard safe permissions
            manifest_content = (
                b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                b"<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
                b"    <uses-permission android:name=\"android.permission.INTERNET\" />\n"
                b"</manifest>"
            )
            zip_file.writestr("AndroidManifest.xml", manifest_content)
            
            # Write a mock classes.dex with safe URL
            dex_content = b"classes.dex content containing safe link: https://google.com"
            zip_file.writestr("classes.dex", dex_content)
            
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='application/vnd.android.package-archive',
            as_attachment=True,
            download_name='sample_safe.apk'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate safe sample APK: {str(e)}"}), 500

@app.route('/api/sample-image', methods=['GET'])
def get_sample_image():
    """
    Generates and returns an in-memory PNG containing stego-appended bytes 
    with a hardcoded phishing URL: http://paypal-secure-login.verify-account.tk/login
    """
    try:
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (120, 120), color = (13, 27, 42))
        d = ImageDraw.Draw(img)
        d.text((15, 50), "PhishZero Stego", fill=(0, 212, 255))
        
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        
        # Append raw string bytes containing the phishing URL at the end of the PNG binary data
        stego_bytes = buffer.getvalue() + b"\n\nHidden URL: http://paypal-secure-login.verify-account.tk/login\n"
        buffer_stego = io.BytesIO(stego_bytes)
        
        return send_file(
            buffer_stego,
            mimetype='image/png',
            as_attachment=True,
            download_name='sample_stego.png'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate sample image: {str(e)}"}), 500

@app.route('/api/sample-image-safe', methods=['GET'])
def get_sample_image_safe():
    """
    Generates and returns an in-memory safe PNG.
    """
    try:
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (120, 120), color = (13, 27, 42))
        d = ImageDraw.Draw(img)
        d.text((15, 50), "PhishZero Safe", fill=(46, 196, 182))
        
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        
        # Append a safe link or keep it clean
        stego_bytes = buffer.getvalue() + b"\n\nInfo URL: https://google.com\n"
        buffer_stego = io.BytesIO(stego_bytes)
        
        return send_file(
            buffer_stego,
            mimetype='image/png',
            as_attachment=True,
            download_name='sample_safe.png'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate safe sample image: {str(e)}"}), 500

@app.route('/api/sample-qr-safe', methods=['GET'])
def get_sample_qr_safe():
    """
    Generates and returns a PNG QR code pointing to the safe URL: https://google.com
    """
    try:
        safe_url = "https://google.com"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(safe_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='image/png',
            as_attachment=True,
            download_name='sample_qr_safe.png'
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate safe sample QR: {str(e)}"}), 500

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
