import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.utils import secure_filename
from functools import wraps # Ensure functools.wraps is imported for decorators

# Import the global supabase client instance
from . import supabase

from app.services import (
    transcribe_audio, detect_scam, upload_file_to_storage,
    save_report_to_db, send_alert_messages,
    perform_ocr,
    check_url_with_virustotal
)

# Define the Blueprint first
main_bp = Blueprint('main', __name__)

# --- Decorator for login required ---
# This block MUST be defined before it is used by any route functions.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'warning')
            return redirect(url_for('auth.login')) # Assuming 'auth.login' is your login route
        return f(*args, **kwargs)
    return decorated_function

# --- Public Routes ---
@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/info')
def info():
    return render_template('info.html')

# --- Protected Routes ---
@main_bp.route('/report', methods=['GET'])
@login_required # Now 'login_required' is defined when this line is read
def report_form():
    return render_template('report.html')

@main_bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    form_data = request.form
    user_id = session.get('user_id')
    
    analysis_text, transcript, file_url = "", "", ""
    original_text_input = ""
    
    # Initialize VirusTotal specific variables
    vt_result, vt_malicious_count, vt_error = None, 0, None
    keywords_from_url_scan = [] # Will hold VT related keywords

    content_type = form_data.get('content_type')

    if content_type == 'audio':
        audio_file = request.files.get('audio_file')
        if not audio_file or audio_file.filename == '':
            flash("You selected audio, but didn't upload a file.", "error")
            return redirect(url_for('main.report_form'))
        
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash("Server configuration error: UPLOAD_FOLDER is not defined.", "error")
            print("ERROR: UPLOAD_FOLDER not configured in Flask app.config")
            return redirect(url_for('main.report_form'))

        filename = secure_filename(audio_file.filename)
        filepath_to_remove = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        try:
            audio_file.save(filepath_to_remove)
            transcript = transcribe_audio(filepath_to_remove)
            analysis_text = transcript
            # Pass the supabase client here
            file_url = upload_file_to_storage(filepath_to_remove, filename, supabase, content_type="audio/mpeg")
            if not file_url: # Check if upload to Supabase failed
                flash("Failed to upload audio file to storage. Check server logs and Supabase configuration.", "error")
        except Exception as e:
            flash(f"Error processing audio: {e}", "error")
            print(f"Error processing audio file {filename}: {e}")
            return redirect(url_for('main.report_form'))
        finally:
            if filepath_to_remove and os.path.exists(filepath_to_remove):
                os.remove(filepath_to_remove)
                print(f"Cleaned up temporary file: {filepath_to_remove}")

    elif content_type == 'image':
        image_file = request.files.get('image_file')
        if not image_file or image_file.filename == '':
            flash("You selected image, but didn't upload a file.", "error")
            return redirect(url_for('main.report_form'))
        
        if 'UPLOAD_FOLDER' not in current_app.config:
            flash("Server configuration error: UPLOAD_FOLDER is not defined.", "error")
            print("ERROR: UPLOAD_FOLDER not configured in Flask app.config")
            return redirect(url_for('main.report_form'))

        filename = secure_filename(image_file.filename)
        filepath_to_remove = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        try:
            image_file.save(filepath_to_remove)
            analysis_text = perform_ocr(filepath_to_remove)
            
            # Flash message if OCR failed to extract text
            if not analysis_text:
                flash("Image uploaded, but no text could be extracted (OCR failed). Ensure Tesseract OCR is installed and the image is clear.", "warning")

            # Pass the supabase client here
            file_url = upload_file_to_storage(filepath_to_remove, filename, supabase, content_type="image/png")
            if not file_url: # Check if upload to Supabase failed
                flash("Failed to upload image file to storage. Check server logs and Supabase configuration/permissions.", "error")

        except Exception as e:
            flash(f"Error processing image: {e}", "error")
            print(f"Error processing image file {filename}: {e}")
            return redirect(url_for('main.report_form'))
        finally:
            if filepath_to_remove and os.path.exists(filepath_to_remove):
                os.remove(filepath_to_remove)
                print(f"Cleaned up temporary file: {filepath_to_remove}")

    elif content_type == 'url':
        suspicious_url = form_data.get('suspicious_url', '').strip()
        if not suspicious_url:
            flash("You selected URL, but didn't provide one.", "error")
            return redirect(url_for('main.report_form'))
        
        # For URL content, analysis_text should be the URL itself for keyword detection
        analysis_text = suspicious_url 
        original_text_input = suspicious_url
        file_url = suspicious_url

        # Perform VirusTotal analysis
        vt_result, vt_malicious_count, vt_error = check_url_with_virustotal(suspicious_url)
        
        # Provide flash messages based on VirusTotal result
        if vt_result == "malicious":
            flash(f"VirusTotal detected {vt_malicious_count} malicious engines for the URL!", "danger")
        elif vt_result == "suspicious":
            flash(f"VirusTotal flagged the URL as suspicious.", "warning")
        elif vt_result == "error" or vt_result == "skipped" or vt_result == "pending":
            flash(f"VirusTotal analysis encountered an issue or was skipped: {vt_error}", "warning")
        else: # harmless
            flash(f"VirusTotal reported the URL as harmless.", "success")
        
        # Add VirusTotal info to keywords for display/storage
        keywords_from_url_scan.append(f"VirusTotal_Status:{vt_result}")
        if vt_malicious_count > 0:
            keywords_from_url_scan.append(f"VT_Malicious_Count:{vt_malicious_count}")


    elif content_type == 'text':
        analysis_text = form_data.get('text_content', '').strip()
        original_text_input = analysis_text
    else:
        flash("Invalid content type selected. Please choose text, audio, image, or URL.", "error")
        return redirect(url_for('main.report_form'))

    # This check now runs AFTER file processing.
    # If analysis_text is still empty after OCR, it will correctly flash the "No content" error.
    if not analysis_text: 
        flash("No content could be extracted or provided for analysis. Please ensure your image is clear, or provide text/URL.", "error")
        return redirect(url_for('main.report_form'))

    # Perform general keyword-based scam detection
    is_scam, keywords, loved_one_mentioned = detect_scam(analysis_text, form_data.get('loved_one_name'))

    # Integrate VirusTotal results into the main scam detection flag and keywords
    if content_type == 'url':
        keywords.extend(keywords_from_url_scan) # Add VT-related keywords
        # If VirusTotal flags it as malicious or suspicious, it's definitely a scam
        if vt_result == "malicious" or vt_result == "suspicious":
            is_scam = True
        # You might also consider an error from VT as suspicious if you want to be very cautious
        elif vt_result == "error" or vt_result == "pending":
             pass # Keeping current logic, where an error doesn't automatically mark as scam unless keywords are found

    report_data = {
        "user_id": str(user_id) if user_id else None, # Ensure user_id is string (UUID)
        "input_text": original_text_input if original_text_input else analysis_text, # Use original input if available, else analysis_text
        "transcript": transcript if transcript else analysis_text, # Use transcript if available, else analysis_text (for images with OCR)
        "file_url": file_url, # URL of uploaded file or the provided suspicious URL
        "loved_one_name": form_data.get('loved_one_name'),
        "loved_one_phone": form_data.get('loved_one_phone'), # <<-- CORRECTED COLUMN NAME based on Supabase schema
        "is_scam_detected": is_scam,
        "found_keywords": ", ".join(keywords), # <<-- CONVERTED LIST to COMMA-SEPARATED STRING
        # Add explicit VirusTotal fields for better reporting/analysis
        "virustotal_scan_result": vt_result,
        "virustotal_malicious_count": vt_malicious_count, # <<-- CORRECTED COLUMN NAME based on Supabase schema
        "virustotal_error": vt_error
    }

    report_saved = save_report_to_db(report_data, supabase)
    if not report_saved:
        flash("We're sorry, there was a server error trying to save your report to the database. Please check server logs.", "error")
        return render_template('result.html',
                                result_title="Analysis Complete (Database Error)",
                                result_message="Your report was analyzed, but could not be saved to the database. "
                                               "Please inform support if this issue persists. "
                                               "Analysis result: " + ("Potential Scam!" if is_scam else "Looks Safe."),
                                transcript=transcript,
                                original_text_input=original_text_input,
                                is_scam_detected=is_scam,
                                found_keywords=keywords,
                                file_url=file_url # Pass file_url to result page
                               )

    # --- Start of refined alert sending logic ---
    alert_sent_successfully = False
    alert_message_detail = ""

    if is_scam:
        if form_data.get('loved_one_phone'):
            try:
                send_alert_messages(
                    form_data.get('loved_one_phone'),
                    form_data.get('loved_one_name', 'your loved one'),
                    original_text_input if original_text_input else analysis_text # Use original input for the excerpt
                )
                alert_sent_successfully = True
                alert_message_detail = f"We've started sending alerts to {form_data.get('loved_one_name', 'your loved one')} " \
                                       f"at {form_data.get('loved_one_phone')}."
            except Exception as e:
                print(f"ERROR sending SMS alert: {e}")
                alert_message_detail = "Failed to send SMS alert. Please check server logs."
                flash("Scam detected, but failed to send SMS alert. Please check server logs.", "warning")
        else:
            alert_message_detail = "No SMS alerts were sent as no phone number was provided."

        result_title = "🚨 Potential Scam Detected!"
        result_message = f"Suspicious keywords found: {', '.join(keywords)}. {alert_message_detail}"

        # Adjust the flash message for the overall result page based on alert status
        if alert_sent_successfully:
            flash("Scam detected and alerts initiated!", "success")
        else:
            flash("Scam detected, but alerts could not be sent or phone number was missing.", "warning")

    else:
        result_title = "✅ Looks Safe For Now"
        result_message = "Our analysis found no common scam keywords. Always remain cautious."
        flash("Analysis complete: Content appears safe.", "info")
    # --- End of refined alert sending logic ---

    return render_template('result.html',
                            result_title=result_title,
                            result_message=result_message,
                            transcript=transcript,
                            original_text_input=original_text_input,
                            is_scam_detected=is_scam,
                            found_keywords=keywords,
                            file_url=file_url, # Pass file_url to result page
                            virustotal_scan_result=vt_result, # Pass VT result for display
                            virustotal_malicious_count=vt_malicious_count, # Pass VT count for display
                            virustotal_error=vt_error # Pass VT error for display
                           )