    # Use an official Python runtime as a parent image
    FROM python:3.13-slim-bullseye

    # Set the working directory in the container
    WORKDIR /app

    # Install system dependencies for Tesseract OCR
    # This updates packages, then installs tesseract and its libraries
    RUN apt-get update && \
        apt-get install -y tesseract-ocr libtesseract-dev libleptonica-dev && \
        rm -rf /var/lib/apt/lists/*

    # Copy requirements.txt and install Python dependencies
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    # Copy the rest of your application code
    COPY . .

    # Ensure the 'uploads' directory exists (if you need to write files there)
    RUN mkdir -p uploads

    # Expose the port Gunicorn will run on
    EXPOSE 10000

    # Define the command to run your application
    # This matches your Procfile for gunicorn run:app
    CMD ["gunicorn", "run:app", "--bind", "0.0.0.0:10000"]
    