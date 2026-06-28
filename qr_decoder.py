import cv2
import numpy as np
from PIL import Image

def decode_qr(image_file):
    """
    Decodes a QR code from a file-like image object.
    Tries pyzbar first, falls back to OpenCV's QRCodeDetector if pyzbar returns empty.
    Returns: { "success": boolean, "url": string, "error": string }
    """
    try:
        # Reset file pointer just in case
        image_file.seek(0)
        
        # Method 1: pyzbar decoding via PIL
        try:
            from pyzbar.pyzbar import decode
            pil_img = Image.open(image_file)
            decoded_objects = decode(pil_img)
            if decoded_objects:
                # Take the first detected QR code
                qr_data = decoded_objects[0].data.decode('utf-8')
                if qr_data.strip():
                    return {
                        "success": True,
                        "url": qr_data.strip(),
                        "error": None
                    }
        except Exception as e_zbar:
            # Log or print zbar exception, fallback to OpenCV
            print(f"pyzbar decoding failed: {e_zbar}")

        # Method 2: OpenCV QRCodeDetector fallback
        image_file.seek(0)
        file_bytes = np.frombuffer(image_file.read(), dtype=np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        
        if img is not None:
            detector = cv2.QRCodeDetector()
            # Detect and decode
            data, bbox, straight_qrcode = detector.detectAndDecode(img)
            if data and data.strip():
                return {
                    "success": True,
                    "url": data.strip(),
                    "error": None
                }
        
        # If both methods fail to find a QR code, return the custom warning message
        return {
            "success": False,
            "url": None,
            "error": "QR code not found Try again!"
        }

    except Exception as e:
        return {
            "success": False,
            "url": None,
            "error": f"Error decoding QR code: {str(e)}"
        }
