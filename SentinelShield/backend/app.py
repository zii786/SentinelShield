from flask import Flask, render_template, request, redirect, session, jsonify
import json, threading, time, random
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATA_FILE = 'data.json'
LOG_FILE = 'logs.json'
USER_CREDENTIALS = {'admin': 'password123'}

# In-memory store for request counts (reset periodically)
ip_request_counts = defaultdict(list)  # {ip: [timestamps]}
REQUEST_LIMIT = 20  # max requests per minute per IP
SUSPICIOUS_HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'Referer']
TRAFFIC_WINDOW = 60  # seconds

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Email alert function (settings loaded from .env)
EMAIL_ALERTS_ENABLED = os.getenv('EMAIL_ALERTS_ENABLED', 'True') == 'True'
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
EMAIL_FROM = os.getenv('EMAIL_FROM')
EMAIL_TO = os.getenv('EMAIL_TO')
# DO NOT commit .env to version control!

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return wrapper

def update_data():
    while True:
        new_data = {
            "traffic": f"{random.randint(1000, 2000)} users online",
            "alerts": f"{random.randint(0, 5)} critical alerts",
            "uptime": f"{random.uniform(99.90, 100.00):.2f}%",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        with open(DATA_FILE, 'w') as f:
            json.dump(new_data, f, indent=4)

        try:
            with open(LOG_FILE, 'r') as f:
                content = f.read().strip()
                log_data = json.loads(content) if content else []
        except (FileNotFoundError, json.JSONDecodeError):
            log_data = []

        log_data.append(new_data)

        with open(LOG_FILE, 'w') as f:
            json.dump(log_data, f, indent=4)

        time.sleep(5)

# Helper to log suspicious events
def log_suspicious_event(event):
    try:
        with open(LOG_FILE, 'r') as f:
            content = f.read().strip()
            log_data = json.loads(content) if content else []
    except (FileNotFoundError, json.JSONDecodeError):
        log_data = []
    log_data.append(event)
    with open(LOG_FILE, 'w') as f:
        json.dump(log_data, f, indent=4)

@app.before_request
def detect_suspicious_activity():
    ip = request.remote_addr
    now = datetime.utcnow()
    # Track requests per IP
    ip_request_counts[ip] = [t for t in ip_request_counts[ip] if (now - t).total_seconds() < TRAFFIC_WINDOW]
    ip_request_counts[ip].append(now)
    # 1. Rate limiting detection
    if len(ip_request_counts[ip]) > REQUEST_LIMIT:
        event = {
            'type': 'Rate Limit Exceeded',
            'ip': ip,
            'count': len(ip_request_counts[ip]),
            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
            'details': 'Too many requests from this IP in a short time.'
        }
        log_suspicious_event(event)
    # 2. Suspicious headers detection
    for header in SUSPICIOUS_HEADERS:
        if header in request.headers:
            event = {
                'type': 'Suspicious Header',
                'ip': ip,
                'header': header,
                'value': request.headers[header],
                'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
                'details': f'Suspicious header detected: {header}'
            }
            log_suspicious_event(event)
    # 3. Simple traffic spike detection (all requests in window)
    total_requests = sum(len(times) for times in ip_request_counts.values())
    if total_requests > 100:  # arbitrary threshold for demo
        event = {
            'type': 'Traffic Spike',
            'total_requests': total_requests,
            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
            'details': 'Sudden spike in total traffic.'
        }
        log_suspicious_event(event)
        # Send email alert for critical event
        subject = '[SentinelShield] Traffic Spike Detected'
        body = f"A traffic spike was detected at {event['timestamp']} with {total_requests} requests in the last minute.\nDetails: {event['details']}"
        send_email_alert(subject, body)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if USER_CREDENTIALS.get(request.form['username']) == request.form['password']:
            session['username'] = request.form['username']
            return redirect('/dashboard')
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/dashboard')
@login_required
def dashboard():
    # Load recent suspicious events
    try:
        with open(LOG_FILE) as f:
            logs = json.load(f)
    except:
        logs = []
    recent_events = logs[-20:][::-1]  # last 20, most recent first
    return render_template('dashboard.html', recent_events=recent_events)

@app.route('/logs')
@login_required
def logs():
    try:
        with open(LOG_FILE) as f:
            logs = json.load(f)
    except:
        logs = []
    return render_template('logs.html', logs=logs)

@app.route('/history')
@login_required
def history():
    return render_template('history.html')

@app.route('/data')
@login_required
def get_data():
    with open(DATA_FILE) as f:
        return jsonify(json.load(f))

@app.route('/history-data')
@login_required
def history_data():
    with open(LOG_FILE) as f:
        return jsonify(json.load(f))

@app.route('/recent-events')
@login_required
def recent_events():
    try:
        with open(LOG_FILE) as f:
            logs = json.load(f)
    except:
        logs = []
    recent_events = logs[-20:][::-1]  # last 20, most recent first
    return jsonify(recent_events)

def send_email_alert(subject, body):
    if not EMAIL_ALERTS_ENABLED:
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
    except Exception as e:
        print(f"Failed to send alert email: {e}")

if __name__ == '__main__':
    threading.Thread(target=update_data, daemon=True).start()
    app.run(debug=True)
