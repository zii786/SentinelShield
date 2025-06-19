# Use an official Python image
FROM python:3.11-slim

WORKDIR /app

COPY backend/ /app/
RUN pip install --no-cache-dir flask

# If you have a requirements.txt, use:
# COPY backend/requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]