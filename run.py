# run.py
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Use debug=False in production!
    app.run(debug=True, port=5001)
