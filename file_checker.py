import io
import re
import zipfile
from PIL import Image

def extract_urls_from_bytes(data_bytes):
    """
    Scans binary bytes for HTTP/HTTPS URLs.
    """
    try:
        # Regex to find standard HTTP/HTTPS URLs
        url_pattern = re.compile(rb'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}[a-zA-Z0-9./?=&_~#-]*')
        matches = url_pattern.findall(data_bytes)
        # Decode and uniqueify
        urls = list(set([m.decode('utf-8', errors='ignore') for m in matches]))
        return urls
    except Exception as e:
        print(f"Error extracting URLs: {e}")
        return []

def scan_apk(file_bytes):
    """
    Parses an APK in-memory to look for permissions and hardcoded URLs.
    """
    permissions = []
    extracted_urls = set()
    
    try:
        # Load the bytes as a ZIP archive
        zip_buffer = io.BytesIO(file_bytes)
        with zipfile.ZipFile(zip_buffer) as z:
            for file_info in z.infolist():
                filename = file_info.filename
                
                # Scan AndroidManifest.xml for permissions
                if filename == "AndroidManifest.xml":
                    try:
                        manifest_data = z.read(filename)
                        # Binary XML strings search for permissions
                        perm_pattern = re.compile(rb'android\.permission\.[A-Z_]+')
                        found_perms = perm_pattern.findall(manifest_data)
                        for perm in found_perms:
                            permissions.append(perm.decode('utf-8', errors='ignore'))
                    except Exception as e_manifest:
                        print(f"Error reading manifest: {e_manifest}")
                
                # Scan DEX files for hardcoded URLs
                elif filename.endswith(".dex"):
                    try:
                        dex_data = z.read(filename)
                        urls = extract_urls_from_bytes(dex_data)
                        extracted_urls.update(urls)
                    except Exception as e_dex:
                        print(f"Error reading DEX file {filename}: {e_dex}")
                
                # Scan raw resources/assets (xml, properties, json, txt) for URLs
                elif filename.endswith((".xml", ".properties", ".json", ".txt")):
                    try:
                        res_data = z.read(filename)
                        urls = extract_urls_from_bytes(res_data)
                        extracted_urls.update(urls)
                    except Exception:
                        pass # Ignore parsing failures for obscure assets

    except Exception as e:
        print(f"Error reading APK archive: {e}")
        return {
            "success": False,
            "error": f"Failed to parse APK file structure: {str(e)}"
        }

    # Post-process permissions to get unique lists
    permissions = sorted(list(set(permissions)))
    
    # Categorize high risk permissions
    high_risk_perms_map = {
        "android.permission.SEND_SMS": "Allows the app to send SMS messages without your intervention, leading to potential financial costs.",
        "android.permission.RECEIVE_SMS": "Allows the app to read incoming SMS messages (commonly used to steal 2FA OTP codes).",
        "android.permission.READ_SMS": "Allows the app to scan your SMS inbox containing personal banking alerts.",
        "android.permission.SYSTEM_ALERT_WINDOW": "Allows the app to draw overlays over other apps, facilitating credential theft through fake login panels.",
        "android.permission.RECEIVE_BOOT_COMPLETED": "Allows the app to launch malicious processes automatically as soon as the phone starts.",
        "android.permission.READ_CONTACTS": "Allows the app to steal your contacts details to spread spam or phishing links.",
        "android.permission.RECORD_AUDIO": "Allows the app to capture background sounds, risking audio surveillance.",
        "android.permission.ACCESS_FINE_LOCATION": "Allows the app to track your exact location.",
        "android.permission.ACCESS_COARSE_LOCATION": "Allows the app to track your approximate location.",
        "android.permission.CAMERA": "Allows the app to capture photos and videos, exposing your camera feed."
    }
    
    detected_high_risk = []
    for perm in permissions:
        if perm in high_risk_perms_map:
            detected_high_risk.append({
                "permission": perm,
                "description": high_risk_perms_map[perm]
            })

    return {
        "success": True,
        "type": "apk",
        "permissions": permissions,
        "high_risk_permissions": detected_high_risk,
        "urls": sorted(list(extracted_urls))
    }

def scan_image(file_bytes, qr_decoder_func=None):
    """
    Parses an Image (JPEG, PNG, etc.) to scan for QR codes and embedded/metadata URLs.
    """
    extracted_urls = set()
    qr_url = None
    
    # 1. Look for QR code
    if qr_decoder_func:
        try:
            image_buffer = io.BytesIO(file_bytes)
            qr_result = qr_decoder_func(image_buffer)
            if qr_result.get("success") and qr_result.get("url"):
                qr_url = qr_result["url"]
                extracted_urls.add(qr_url)
        except Exception as e_qr:
            print(f"QR decoding check failed: {e_qr}")

    # 2. Look for EXIF/Metadata
    try:
        image_buffer = io.BytesIO(file_bytes)
        img = Image.open(image_buffer)
        exif_data = img.getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                if isinstance(value, str):
                    found = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}[a-zA-Z0-9./?=&_~#-]*', value)
                    extracted_urls.update(found)
    except Exception as e_exif:
        print(f"EXIF parsing check failed: {e_exif}")

    # 3. Look for hidden/appended strings in raw file bytes
    try:
        raw_urls = extract_urls_from_bytes(file_bytes)
        extracted_urls.update(raw_urls)
    except Exception as e_raw:
        print(f"Raw image bytes scan failed: {e_raw}")

    return {
        "success": True,
        "type": "image",
        "qr_url": qr_url,
        "urls": sorted(list(extracted_urls))
    }
