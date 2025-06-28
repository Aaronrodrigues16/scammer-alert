# app/auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from . import supabase # CORRECTED: Import from the app package context

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles user registration.
    - On GET, displays the signup form.
    - On POST, attempts to create a new user via Supabase.
    """
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Email and password are required!', 'error')
            return render_template('signup.html', email=email)

        try:
            # Attempt to sign up the user with Supabase
            response = supabase.auth.sign_up({"email": email, "password": password})
            
            print(f"Supabase signup raw response: {response}")

            if response.user:
                if response.session:
                    # User is created AND logged in immediately (email confirmation likely off)
                    session['user_id'] = response.user.id
                    session['user_email'] = response.user.email
                    
                    # --- NEW ADDITION HERE ---
                    # Set the global Supabase client's session to the newly created user's session
                    # This is crucial for subsequent authenticated Supabase API calls from this server instance
                    supabase.auth.set_session(response.session.access_token, response.session.refresh_token)
                    # --- END NEW ADDITION ---

                    flash('Signup successful! You are now logged in.', 'success')
                    print(f"User {email} signed up and logged in.")
                    return redirect(url_for('main.report_form')) # Redirect to a protected page after successful login
                else:
                    # User is created, but email confirmation is pending
                    flash('Signup successful! Please check your email to verify your account before logging in.', 'success')
                    print(f"User {email} signed up, pending email verification.")
                    return redirect(url_for('auth.login')) # Redirect to login page to await verification

            else:
                error_message = "Signup failed. Please try again."
                if hasattr(response, 'error') and response.error and response.error.message:
                    error_message = response.error.message
                    if "User already registered" in error_message:
                        error_message = "This email is already registered. Please try logging in instead."
                        flash(error_message, 'warning')
                        return render_template('login.html', email=email)
                    elif "Password should be at least 6 characters" in error_message:
                        error_message = "Password must be at least 6 characters long."
                    elif "AuthApiError: Email rate limit exceeded" in error_message:
                         error_message = "Too many signup attempts from this IP. Please wait a few minutes and try again."
                
                print(f"Supabase signup failed for {email}: {error_message}")
                flash(f'Error: {error_message}', 'error')
                return render_template('signup.html', email=email)

        except Exception as e:
            print(f"CRITICAL ERROR during Supabase signup for {email}: {e}")
            flash(f'An unexpected server error occurred during signup. Please try again or contact support.', 'error')
            return render_template('signup.html', email=email)
    
    return render_template('signup.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    - On GET, displays the login form.
    - On POST, attempts to authenticate the user via Supabase.
    """
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Email and password are required!', 'error')
            return render_template('login.html', email=email)

        try:
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            
            print(f"Supabase login raw response: {response}")

            if response.user and response.session:
                # Login successful
                session['user_id'] = response.user.id
                session['user_email'] = response.user.email
                
                # --- NEW ADDITION HERE ---
                # Set the global Supabase client's session to the newly logged-in user's session
                # This makes subsequent API calls from the 'supabase' client instance authenticated
                supabase.auth.set_session(response.session.access_token, response.session.refresh_token)
                # --- END NEW ADDITION ---

                flash('You have been successfully logged in.', 'success')
                print(f"User {email} logged in successfully.")
                return redirect(url_for('main.report_form'))

            else:
                error_message = "Invalid credentials. Please check your email and password."
                if hasattr(response, 'error') and response.error and response.error.message:
                    error_message = response.error.message
                    if "Email not confirmed" in error_message:
                        error_message = "Your email has not been confirmed. Please check your inbox for a verification link."
                    elif "Invalid login credentials" in error_message or "Invalid email or password" in error_message:
                        error_message = "Invalid email or password. Please try again."
                
                print(f"Supabase login failed for {email}: {error_message}")
                flash(f'Error: {error_message}', 'error')
                return render_template('login.html', email=email)

        except Exception as e:
            print(f"CRITICAL ERROR during Supabase login for {email}: {e}")
            flash(f'An unexpected server error occurred during login. Please try again or contact support.', 'error')
            return render_template('login.html', email=email)
    
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """
    Handles user logout.
    Clears the Flask session and calls Supabase sign_out.
    """
    session.pop('user_id', None)
    session.pop('user_email', None)
    
    try:
        # Clear the global Supabase client's session
        supabase.auth.sign_out()
        print("Supabase session signed out.")
    except Exception as e:
        print(f"Error signing out from Supabase: {e}")
    
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))