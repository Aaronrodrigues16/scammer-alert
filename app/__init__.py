import os
from flask import Flask
from dotenv import load_dotenv # Keep this here for the current structure
from supabase import create_client, Client

# --- IMPORTANT: load_dotenv() can stay here if run.py doesn't call it,
# or you can move it to run.py and remove it here.
# For now, let's keep it here assuming this is the primary entry for imports.
load_dotenv()


def create_app():
    app = Flask(__name__)

    # Get Supabase credentials from environment
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")

    # Add checks to ensure these are not None
    if not supabase_url:
        raise ValueError("SUPABASE_URL environment variable is not set.")
    if not supabase_key:
        raise ValueError("SUPABASE_KEY environment variable is not set.")

    # Initialize Supabase client INSIDE the factory
    # This ensures the client is created with the app context
    global supabase # Declare global if you intend to access it outside this function globally
    supabase = create_client(supabase_url, supabase_key) # Now this line is inside create_app

    # IMPORTANT: Make sure you have this in your .env file
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "a-very-secret-key-for-dev")

    # Make the UPLOAD_FOLDER
    UPLOAD_FOLDER = 'uploads'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Register blueprints (our routes)
    from .routes import main_bp
    from .auth import auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    print("Flask app created and configured.")
    return app

# If you need a global 'supabase' client for other modules,
# it will be set by the first call to create_app()
# You might need to adjust how other modules import/access 'supabase' if they do so globally.
# For example, they might need to import 'app' and then access app.supabase (if you attached it to app instance)
# or ensure create_app() is called before they access the global 'supabase' variable.
