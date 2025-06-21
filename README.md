# SentinelShield

SentinelShield is a real-time web dashboard for monitoring simulated security events like network traffic, suspicious requests, and system alerts. It's built with Flask and runs with Gunicorn in a Docker container.

## Features

- **Real-Time Dashboard:** Live updates for traffic, alerts, and uptime.
- **Suspicious Activity Detection:** Detects and logs rate limiting, suspicious headers, and traffic spikes.
- **Data Persistence:** Uses simple JSON files for logging, with automatic log rotation.
- **Interactive UI:** Filter events by type and search by IP address.
- **Secure Configuration:** All secrets and configurations are managed via an environment file (`.env`).
- **Containerized:** Ships with a production-ready Docker setup using Gunicorn.

## Prerequisites

- [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/install/)
- [Python 3.10+](https://www.python.org/downloads/) and `pip` (for local development)

## How to Run

There are two ways to run the application:

### 1. Using Docker (Recommended)

This is the easiest and most reliable way to run SentinelShield in a production-like environment.

**Step 1: Create the Environment File**

Create a file named `.env` inside the `SentinelShield/backend/` directory and add the following content. Replace the placeholder values with your own secure secrets.

```env
# A strong, random string for Flask session management
SECRET_KEY=your_very_strong_and_random_secret_key_here

# Credentials for the dashboard login
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password

# Optional: Email settings for alerts
EMAIL_ALERTS_ENABLED=False
SMTP_SERVER=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
EMAIL_FROM=
EMAIL_TO=
```

**Step 2: Build and Run the Container**

Open your terminal in the root `SentinelShield` directory and run:

```bash
docker-compose up --build
```

**Step 3: Access the Application**

The application will be available at [http://localhost](http://localhost).

### 2. Running Locally (for Development)

**Step 1: Set Up Environment**

Follow "Step 1" from the Docker instructions to create your `.env` file.

**Step 2: Install Dependencies**

Navigate to the backend directory and install the required Python packages:

```bash
cd SentinelShield/backend
pip install -r requirements.txt
```

**Step 3: Run the Flask Development Server**

From the `SentinelShield/backend` directory, run:

```bash
python app.py
```

**Step 4: Access the Application**

The application will be available at [http://localhost:5000](http://localhost:5000).