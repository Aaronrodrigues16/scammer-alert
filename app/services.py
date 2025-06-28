import os
import requests
import time
import uuid
# from dotenv import load_dotenv # REMOVED: load_dotenv() should be handled in your PythonAnywhere WSGI file
from twilio.rest import Client
from supabase import Client as SupabaseClient

import pytesseract
from PIL import Image
from io import BytesIO
import json

# --- Explicitly set the path to the Tesseract executable for PythonAnywhere ---
# On PythonAnywhere, Tesseract-OCR is typically pre-installed at /usr/bin/tesseract.
# This line tells pytesseract where to find the Tesseract executable.
pytesseract.tesseract_cmd = '/usr/bin/tesseract'


# Load environment variables (REMOVED from here, now handled by PythonAnywhere's WSGI file)
# load_dotenv() # This line is commented out as the WSGI file will handle it.

# --- Twilio Configuration ---
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        print("Twilio client initialized.")
    except Exception as e:
        print(f"Error initializing Twilio client: {e}")
else:
    print("WARNING: Twilio credentials not fully set. SMS alerts will not function.")

# --- Supabase Configuration ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_BUCKET_NAME = os.getenv("SUPABASE_BUCKET_NAME")

# Initialize Supabase Client globally here
supabase: SupabaseClient = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = SupabaseClient(SUPABASE_URL, SUPABASE_KEY)
        print("Supabase client initialized.")
    except Exception as e:
        print(f"Error initializing Supabase client: {e}")
else:
    print("WARNING: Supabase URL or Key not fully set. Database and storage operations will not function.")


# --- VirusTotal Configuration ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL_SCAN_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_REPORT_ENDPOINT = "https://www.virustotal.com/api/v3/analyses/{id}"

# --- AI Model Loading (Placeholder for PythonAnywhere deployment without heavy dependencies) ---
def load_whisper_model():
    print("Whisper model loaded successfully (using placeholder).")
    # This will prevent issues with missing large ML libraries on PythonAnywhere's free tier
    # if openai-whisper, torch etc. are removed from requirements.txt
    return "WhisperModel (Placeholder)"

whisper_model = load_whisper_model()

# --- Scam Detection Keywords ---
SCAM_KEYWORDS = [
    "urgent", "action required", "verify account", "account suspended", "unusual activity",
    "click this link", "security alert", "fraudulent activity", "password reset required",
    "verify your identity", "immediate attention", "suspicious login", "account locked",
    "payment failed", "update billing", "winnings", "lottery", "£", "$", "bitcoin", "crypto",
    "inheritance", "free money", "claim prize", "taxes owed", "arrest warrant", "legal action",
    "IRS", "police", "federal agent", "bail", "loved one in trouble", "grandchild in trouble",
    "relative in trouble", "send money", "gift card", "wire transfer", "secret shopper",
    "job offer", "work from home", "too good to be true", "investment opportunity", "exclusive offer",
    "one-time offer", "limited time", "act now", "confirm details", "shipping fee", "delivery problem",
    "customs duty", "reschedule delivery", "package held", "tracking number", "invoice attached",
    "invoice overdue", "refund processing", "unexpected refund", "loan approval", "debt relief",
    "credit score", "high returns", "guaranteed profit", "investment seminar", "financial advisor",
    "social security", "medicare", "health insurance", "government grant", "scholarship",
    "student loan", "tax refund", "charity donation", "emergency", "crisis", "accident",
    "hospital", "arrested", "stuck overseas", "phone broken", "new number", "lost wallet",
    "ATM", "pin", "verification code", "OTP", "login code", "security code", "your old number",
    "my old number", "my new number", "this new number", "family in distress", "help me"
]

def transcribe_audio(audio_filepath):
    print(f"Transcribing audio from: {audio_filepath} (using placeholder transcription)")
    # This placeholder is used because the actual Whisper model might not be deployed
    # or fully functional on PythonAnywhere's free tier without significant setup.
    return "Hi rose, it's urgent! Your bank account has been suspended due to suspicious activity. Click this link immediately to verify your account: http://secure-banking-alert.co/login. Enter your OTP to unlock. Do not delay, funds are at risk"

def perform_ocr(image_filepath):
    try:
        print(f"Performing OCR on image: {image_filepath}")
        image = Image.open(image_filepath)
        text = pytesseract.image_to_string(image)
        print(f"OCR extracted text: {text[:200]}...")
        return text
    except pytesseract.TesseractNotFoundError:
        print("ERROR: Tesseract is not found. On PythonAnywhere, ensure pytesseract.tesseract_cmd is set to '/usr/bin/tesseract'.")
        print("Also ensure that the Tesseract engine is installed on the PythonAnywhere system (it usually is).")
        return "" # Return empty string on OCR failure
    except Exception as e:
        print(f"ERROR: Exception during OCR: {e}")
        return "" # Return empty string on other OCR failures

def detect_scam(text_content, loved_one_name=None):
    found_keywords = []
    text_lower = text_content.lower()
    is_scam = False
    loved_one_mentioned = False

    if loved_one_name:
        if loved_one_name.lower() in text_lower:
            loved_one_mentioned = True
            found_keywords.append(f"mention of loved one's name ({loved_one_name})")

    for keyword in SCAM_KEYWORDS:
        if keyword.lower() in text_lower:
            found_keywords.append(keyword)
            is_scam = True

    print(f"Scam detection results: is_scam={is_scam}, found_keywords={found_keywords}, loved_one_mentioned={loved_one_mentioned}")
    return is_scam, found_keywords, loved_one_mentioned

# CORRECTED: upload_file_to_storage function
def upload_file_to_storage(filepath, original_filename, supabase_client: SupabaseClient, content_type="application/octet-stream"):
    try:
        if not SUPABASE_URL or not SUPABASE_KEY or not SUPABASE_BUCKET_NAME:
            print("ERROR: Supabase storage credentials or bucket name not set in environment.")
            return None
        if not supabase_client:
            print("ERROR: Supabase client is not initialized for storage operations.")
            return None

        # Generate a unique filename using UUID
        file_extension = os.path.splitext(original_filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        
        # Define the path within the bucket (e.g., 'uploads' folder)
        file_path_in_bucket = f"uploads/{unique_filename}"

        with open(filepath, 'rb') as f:
            file_bytes = f.read()

        # Perform the upload
        try:
            # The 'upload' method now typically returns a dictionary on success
            # or raises an exception on error in recent supabase-py versions.
            # It no longer returns an 'UploadResponse' object with .data or .error attributes.
            upload_result = supabase_client.storage.from_(SUPABASE_BUCKET_NAME).upload(
                file_path_in_bucket,
                file_bytes,
                {"content-type": content_type}
            )
            # If upload() succeeds without raising an exception, it implies success.
            # Then, attempt to get the public URL using the full path.
            # This is the most reliable way to get the URL after a successful upload.
            file_url = supabase_client.storage.from_(SUPABASE_BUCKET_NAME).get_public_url(file_path_in_bucket)
            
            if file_url:
                print(f"File uploaded successfully to storage. URL: {file_url}")
                return file_url
            else:
                print("Could not retrieve public URL after upload. Check bucket/file visibility or RLS policies.")
                return None

        except Exception as e:
            # Catch exceptions that might be raised directly by the upload method on failure
            print(f"Supabase storage upload failed: {e}")
            return None

    except Exception as e:
        print(f"General exception during file upload/update: {e}")
        return None

def check_url_with_virustotal(url):
    """
    Submits a URL to VirusTotal for analysis and retrieves a report.
    Returns analysis result (e.g., 'harmless', 'malicious', 'suspicious'),
    detection count, and error message.
    """
    if not VIRUSTOTAL_API_KEY:
        print("WARNING: VirusTotal API key not set. URL analysis skipped.")
        return "skipped", 0, "VirusTotal API key missing."

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {'url': url}
    
    analysis_id = None

    try:
        print(f"Submitting URL to VirusTotal for analysis: {url}")
        response = requests.post(VIRUSTOTAL_URL_SCAN_ENDPOINT, headers=headers, data=data)
        response.raise_for_status()
        
        scan_result = response.json()
        analysis_id = scan_result['data']['id']
        print(f"VirusTotal URL submitted for analysis. Analysis ID: {analysis_id}")

        max_polls = 10
        poll_interval_seconds = 3
        
        for i in range(max_polls):
            print(f"Polling VirusTotal for report... Attempt {i+1}/{max_polls}")
            time.sleep(poll_interval_seconds)
            report_response = requests.get(f"{VIRUSTOTAL_REPORT_ENDPOINT.format(id=analysis_id)}", headers=headers)
            report_response.raise_for_status()
            report_data = report_response.json()
            
            analysis_status = report_data.get('data', {}).get('attributes', {}).get('status')
            print(f"Current VirusTotal analysis status: {analysis_status}")

            if analysis_status == 'completed':
                print("\n--- VirusTotal Analysis Completed ---")
                # print(f"Full Report Data: {json.dumps(report_data, indent=2)}") # Temporarily commented for cleaner logs
                
                report_attributes = report_data.get('data', {}).get('attributes', {})
                # print(f"Report Attributes: {json.dumps(report_attributes, indent=2)}") # Temporarily commented for cleaner logs
                
                analysis_stats = report_attributes.get('stats', {})
                # print(f"Analysis Stats (from 'stats' key): {json.dumps(analysis_stats, indent=2)}") # Temporarily commented for cleaner logs

                malicious_count = analysis_stats.get('malicious', 0)
                suspicious_count = analysis_stats.get('suspicious', 0)
                harmless_count = analysis_stats.get('harmless', 0)
                
                if malicious_count > 0:
                    result = "malicious"
                elif suspicious_count > 0:
                    result = "suspicious"
                else:
                    result = "harmless"
                
                print(f"VirusTotal analysis complete: Result={result}, Malicious engines detected={malicious_count}, Suspicious engines detected={suspicious_count}, Harmless engines detected={harmless_count}")
                return result, malicious_count, None
            elif analysis_status == 'queued' or analysis_status == 'running':
                continue
            else:
                print(f"VirusTotal analysis ended with unexpected status: {analysis_status}. Full report: {report_data}")
                return "error", 0, f"Unexpected analysis status: {analysis_status}"
            
        print("VirusTotal analysis did not complete within the polling time.")
        return "pending", 0, "Analysis pending or timed out after multiple attempts."

    except requests.exceptions.RequestException as e:
        print(f"Error during VirusTotal API request for URL {url}: {e}")
        error_message = f"API request error: {e}"
        if hasattr(e, 'response') and e.response is not None:
            print(f"VirusTotal API Response Text: {e.response.text}")
            error_message += f" - Response: {e.response.text}"
        return "error", 0, error_message
    except KeyError as e:
        print(f"VirusTotal API response format unexpected for URL: {url}. Missing key: {e}. "
              f"Response from VT: {scan_result if analysis_id else 'No initial scan_result'}")
        return "error", 0, f"Unexpected API response format: Missing key {e}."
    except json.JSONDecodeError as e:
        print(f"VirusTotal JSON decode error: {e}. "
              f"Response text: {report_response.text if 'report_response' in locals() else response.text if 'response' in locals() else 'No initial response'}")
        return "error", 0, f"Invalid JSON response from VirusTotal: {e}"
    except Exception as e:
        print(f"An unexpected error occurred during VirusTotal analysis for URL {url}: {e}")
        return "error", 0, f"General error: {e}"

def save_report_to_db(report_data: dict, supabase_client: SupabaseClient):
    """
    Saves the scam report data to the Supabase database.
    """
    try:
        if not supabase_client:
            print("ERROR: Supabase client is not initialized for database operations. Cannot save report.")
            return False

        print(f"Attempting to save report to Supabase DB: {report_data}")
        response = supabase_client.table("reports").insert(report_data).execute()

        if response.data:
            print("Report saved successfully to Supabase DB.")
            return True
        else:
            error_details = response.error.message if response.error and hasattr(response.error, 'message') else "Unknown error from Supabase."
            error_code = response.error.code if response.error and hasattr(response.error, 'code') else "N/A"
            error_hint = response.error.hint if response.error and hasattr(response.error, 'hint') else "N/A"

            print(f"ERROR: Error saving to Supabase DB. Code: {error_code}, Message: {error_details}, Hint: {error_hint}")
            # IMPORTANT: If you consistently get "Could not find the 'loved_one_ph' column" error
            # after performing the Supabase schema cache refresh (in Supabase UI -> tables),
            # you will need to TEMPORARILY comment out or remove the 'loved_one_ph'
            # field from the 'report_data' dictionary *before* passing it to insert().
            # Example:
            # if 'loved_one_ph' in report_data:
            #   del report_data['loved_one_ph']
            # Then retry the insert. This is a workaround for a persistent Supabase caching bug.
            return False
    except Exception as e:
        print(f"ERROR: Exception during database save: {e}")
        return False

# CORRECTED: send_alert_messages function (shortened message)
def send_alert_messages(to_phone_number, loved_one_name, scam_text_excerpt):
    """
    Sends an SMS alert using Twilio. Message body shortened for trial accounts.
    """
    if not twilio_client or not TWILIO_PHONE_NUMBER:
        print("Twilio client or phone number not configured. SMS alerts skipped.")
        return

    try:
        # Basic E.164 formatting check - Twilio generally requires numbers to start with '+'
        if not to_phone_number.startswith('+'):
            print(f"Warning: Phone number {to_phone_number} not in E.164 format. Attempting to prepend '+91' for India by default. Please ensure this is correct for your region.")
            to_phone_number = f"+91{to_phone_number}" # Defaulting to India's country code

        # --- SHORTENED MESSAGE BODY FOR TWILIO TRIAL LIMITS ---
        # This message is designed to be concise to fit Twilio trial message length limits (typically ~160 characters for a single SMS segment).
        message_body = (
            f"SCAM ALERT: Potential scam targeting {loved_one_name}. "
            f"Msg: '{scam_text_excerpt[:50]}...' " # Truncate to first 50 chars for brevity
            "ACTION: Call them. Never click links, share OTPs, or send money for unverified requests." # Concise advice
        )
        
        message = twilio_client.messages.create(
            to=to_phone_number,
            from_=TWILIO_PHONE_NUMBER,
            body=message_body
        )
        print(f"SMS alert sent successfully to {to_phone_number}. SID: {message.sid}")
    except Exception as e:
        print(f"Error sending SMS alert to {to_phone_number}: {e}")
```
**Key Changes Made:**

1.  **Removed `load_dotenv()` import and call:** On PythonAnywhere, it's best practice to handle `load_dotenv()` within your WSGI file (`mysite_wsgi.py`) to ensure environment variables are loaded before your Flask app (and thus `app/services.py`) starts. This avoids potential issues with file paths or multiple loads.
2.  **Corrected `pytesseract.tesseract_cmd` path:** Changed the Tesseract executable path from a Windows-specific one to the standard Linux path where Tesseract is installed on PythonAnywhere servers (`/usr/bin/tesseract`).
3.  **Removed / Updated Comments:** Cleaned up the extensive comments related to Render deployment and Windows Tesseract installation, replacing them with more relevant notes for PythonAnywhere.

**To implement these changes:**

1.  **Replace the content of your `D:\scammer-alert\app\services.py` file** with the code provided above.
2.  **Update your `mysite_wsgi.py` file on PythonAnywhere** to include `load_dotenv()` as instructed in the PythonAnywhere deployment steps. This is crucial for your environment variables (Supabase, Twilio, VirusTotal) to be loaded.
3.  **Ensure `pytesseract` and `Pillow` are in your `requirements.txt`** for `pip install` on PythonAnywhere.
4.  **Upload the updated `services.py`** to your PythonAnywhere project (or re-clone if you're using Git).
5.  **Reload your web app on PythonAnywhere's "Web" tab.**

These changes should get your OCR functionality working correctly on PythonAnywhe