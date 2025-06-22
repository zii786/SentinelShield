# Use an official Python image
FROM python:3.11-slim

WORKDIR /app

# Copy the backend application code
COPY ./backend/ /app/

# Install docker client to allow this container to reload nginx
RUN apt-get update && apt-get install -y --no-install-recommends docker.io && rm -rf /var/lib/apt/lists/*

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define environment variables for Gunicorn
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Run the app. The Gunicorn server will bind to 0.0.0.0:8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]