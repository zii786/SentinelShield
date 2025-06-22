from flask import Flask, render_template, request, redirect, session, jsonify, make_response
import json, threading, time, re
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

# Load environment variables from .env file first
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(__name__)
# Load secret key from environment variable
app.secret_key = os.getenv('SECRET_KEY', 'a_default_fallback_secret_key')

DATA_FILE = 'data.json'
LOG_FILE = 'logs.json'
EVENTS_FILE = 'events.json'  # New file for suspicious events

# Load user credentials from environment variables
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'password123')
USER_CREDENTIALS = {ADMIN_USERNAME: ADMIN_PASSWORD}

# New global state for real-time analytics from Nginx logs
APP_STATS = {
    "total_requests": 0,
    "unique_visitors": set(),
    "http_status_counts": defaultdict(int),
    "requests_per_minute": 0,
    "last_updated": "Never",
    "requests_per_minute_history": [],  # Store last 60 seconds of request counts
    "current_minute_requests": 0,
    "last_minute_reset": datetime.now(timezone.utc)
}

# In-memory store for request counts (reset periodically)
ip_request_counts = defaultdict(list)  # {ip: [timestamps]}
REQUEST_LIMIT = 20  # max requests per minute per IP
SUSPICIOUS_HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'Referer']
TRAFFIC_WINDOW = 60  # seconds

# Email alert function (settings loaded from .env)
EMAIL_ALERTS_ENABLED = os.getenv('EMAIL_ALERTS_ENABLED', 'True') == 'True'
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
EMAIL_FROM = os.getenv('EMAIL_FROM')
EMAIL_TO = os.getenv('EMAIL_TO')

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return wrapper

def load_events():
    """Load events from JSON file"""
    try:
        with open(EVENTS_FILE, 'r') as f:
            content = f.read().strip()
            return json.loads(content) if content else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_events(events):
    """Save events to JSON file"""
    with open(EVENTS_FILE, 'w') as f:
        json.dump(events, f, indent=4)

def manage_logs():
    """Periodically trims log files to prevent them from growing too large."""
    MAX_LOG_ENTRIES = 1000  # Max number of entries to keep
    while True:
        time.sleep(3600)  # Run once every hour
        for log_file in [LOG_FILE, EVENTS_FILE]:
            try:
                with open(log_file, 'r') as f:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
                
                if isinstance(data, list) and len(data) > MAX_LOG_ENTRIES:
                    # Keep the most recent entries
                    trimmed_data = data[-MAX_LOG_ENTRIES:]
                    with open(log_file, 'w') as f:
                        json.dump(trimmed_data, f, indent=4)
                    print(f"Log file {log_file} trimmed to {MAX_LOG_ENTRIES} entries.")

            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"Could not process log file {log_file}: {e}")
            except Exception as e:
                print(f"An unexpected error occurred during log management: {e}")

def process_logs():
    """
    Reads the Nginx access log in real-time, parses new entries,
    and updates application statistics.
    """
    log_file_path = '/var/log/nginx/access.log'
    log_pattern = re.compile(
        r'(?P<ip>\S+) - .* \[(?P<time>.*?)\] "(?P<request>.*?)" '
        r'(?P<status>\d{3}) (?P<size>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)" "(?P<x_forwarded_for>.*?)"'
    )
    
    # Wait for the log file to be created by Nginx
    print("Log processing thread started. Waiting for Nginx log file...")
    while not os.path.exists(log_file_path):
        time.sleep(2)
    print(f"Nginx log file found at {log_file_path}. Starting to monitor.")

    try:
        with open(log_file_path, 'r') as file:
            file.seek(0, 2)  # Go to the end of the file
            while True:
                new_lines = file.readlines()
                if not new_lines:
                    time.sleep(1)  # Wait for new entries
                    continue

                for line in new_lines:
                    try:
                        match = log_pattern.match(line)
                        if not match:
                            print(f"Log line did not match pattern: {line.strip()}")
                            continue
                        
                        log_entry = match.groupdict()
                        analyze_log_entry(log_entry)
                    except Exception as e:
                        print(f"Error processing log line: {line.strip()}. Error: {e}")
                        
    except FileNotFoundError:
        print(f"FATAL: Log file {log_file_path} was not found after initial check. Thread is stopping.")
    except Exception as e:
        print(f"A fatal error occurred in the log processing thread: {e}. Thread is stopping.")

# Helper to log suspicious events to JSON file
def log_suspicious_event(event):
    events = load_events()
    events.append(event)
    save_events(events)

def analyze_log_entry(log_entry):
    """
    Analyzes a single log entry for suspicious patterns.
    This replaces the old @app.before_request decorator.
    """
    ip = log_entry.get('ip')
    if not ip:
        return

    now = datetime.now(timezone.utc)
    
    # Update real-time statistics
    APP_STATS["total_requests"] += 1
    APP_STATS["unique_visitors"].add(ip)
    APP_STATS["http_status_counts"][log_entry.get('status', '0')] += 1
    APP_STATS["last_updated"] = now.strftime('%Y-%m-%d %H:%M:%S')
    
    # Calculate requests per minute
    APP_STATS["current_minute_requests"] += 1
    
    # Reset minute counter if a minute has passed
    if (now - APP_STATS["last_minute_reset"]).total_seconds() >= 60:
        APP_STATS["requests_per_minute"] = APP_STATS["current_minute_requests"]
        APP_STATS["current_minute_requests"] = 0
        APP_STATS["last_minute_reset"] = now
        
        # Keep history for the last 10 minutes
        APP_STATS["requests_per_minute_history"].append({
            "timestamp": now.strftime('%Y-%m-%d %H:%M:%S'),
            "requests": APP_STATS["requests_per_minute"]
        })
        if len(APP_STATS["requests_per_minute_history"]) > 10:
            APP_STATS["requests_per_minute_history"].pop(0)
    
    # --- 1. Rate Limiting Detection ---
    ip_request_counts[ip] = [t for t in ip_request_counts[ip] if (now - t).total_seconds() < TRAFFIC_WINDOW]
    ip_request_counts[ip].append(now)
    if len(ip_request_counts[ip]) > REQUEST_LIMIT:
        event = {
            'type': 'Rate Limit Exceeded',
            'ip': ip,
            'count': len(ip_request_counts[ip]),
            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
            'details': f"IP exceeded {REQUEST_LIMIT} requests in {TRAFFIC_WINDOW} seconds."
        }
        log_suspicious_event(event)

    # --- 2. Suspicious User-Agent Detection (Example) ---
    user_agent = log_entry.get('user_agent', '').lower()
    suspicious_agents = ['sqlmap', 'nmap', 'nikto', 'curl', 'wget', 'python-requests']
    for agent in suspicious_agents:
        if agent in user_agent:
            event = {
                'type': 'Suspicious User-Agent',
                'ip': ip,
                'user_agent': log_entry.get('user_agent'),
                'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
                'details': f"Detected suspicious user-agent: {agent}"
            }
            log_suspicious_event(event)
            break # Log only once per entry

    # --- 3. HTTP Status Code Monitoring ---
    status = log_entry.get('status', '0')
    if status.startswith('4') or status.startswith('5'):
        event = {
            'type': 'HTTP Error',
            'ip': ip,
            'status': status,
            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
            'details': f"HTTP {status} error detected"
        }
        log_suspicious_event(event)

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
    # Load recent suspicious events from JSON file
    events = load_events()
    recent_events = sorted(events, key=lambda x: x.get('timestamp', ''), reverse=True)[:20]
    
    # Create the response object
    response = make_response(render_template('dashboard.html', recent_events=recent_events))
    
    # Add headers to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/logs')
@login_required
def logs():
    try:
        events = load_events()
        logs = sorted(events, key=lambda x: x.get('timestamp', ''), reverse=True)
    except Exception:
        logs = []
    return render_template('logs.html', logs=logs)

@app.route('/events')
@login_required
def events():
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Number of events per page
    try:
        all_events = load_events()
        sorted_events = sorted(all_events, key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Paginate the sorted events
        start = (page - 1) * per_page
        end = start + per_page
        paginated_events = sorted_events[start:end]
        
        # Calculate total pages
        total_pages = (len(sorted_events) + per_page - 1) // per_page
        
    except Exception as e:
        print(f"Error loading events: {e}")
        paginated_events = []
        total_pages = 0

    return render_template('events.html', events=paginated_events, page=page, total_pages=total_pages)

@app.route('/history')
@login_required
def history():
    return render_template('history.html')

@app.route('/data')
@login_required
def get_data():
    # Return a copy of the stats, converting set to a simple count for JSON
    stats_copy = APP_STATS.copy()
    stats_copy["unique_visitors"] = len(stats_copy["unique_visitors"])
    
    # Add current minute requests for real-time display
    stats_copy["current_minute_requests"] = APP_STATS["current_minute_requests"]
    
    # Add HTTP status breakdown
    stats_copy["http_status_breakdown"] = dict(APP_STATS["http_status_counts"])
    
    # Calculate average requests per minute from history
    if APP_STATS["requests_per_minute_history"]:
        avg_rpm = sum(item["requests"] for item in APP_STATS["requests_per_minute_history"]) / len(APP_STATS["requests_per_minute_history"])
        stats_copy["average_requests_per_minute"] = round(avg_rpm, 2)
    else:
        stats_copy["average_requests_per_minute"] = 0
    
    return jsonify(stats_copy)

@app.route('/history-data')
@login_required
def history_data():
    """Provides aggregated data for historical charts."""
    # This now returns real, aggregated data instead of old log files.
    stats = {
        "requests_per_minute_history": APP_STATS["requests_per_minute_history"],
        "http_status_counts": dict(APP_STATS["http_status_counts"]),
        "unique_visitor_count": len(APP_STATS["unique_visitors"])
    }
    return jsonify(stats)

@app.route('/recent-events')
@login_required
def recent_events():
    events = load_events()
    recent_events = sorted(events, key=lambda x: x.get('timestamp', ''), reverse=True)[:20]
    return jsonify(recent_events)

@app.route('/real-time-logs')
@login_required
def real_time_logs():
    """Return real-time traffic logs for the logs page"""
    log_file_path = '/var/log/nginx/access.log'
    parsed_logs = []

    if not os.path.exists(log_file_path):
        return jsonify([])

    try:
        with open(log_file_path, 'r') as f:
            lines = f.readlines()
            # Get last 50 lines and parse them
            recent_lines = lines[-50:]

            log_pattern = re.compile(
                r'(?P<ip>\S+) - .* \[(?P<time>.*?)\] "(?P<request>.*?)" '
                r'(?P<status>\d{3}) (?P<size>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)" "(?P<x_forwarded_for>.*?)"'
            )

            for line in reversed(recent_lines): # Show newest first immediately
                match = log_pattern.match(line)
                if match:
                    log_entry = match.groupdict()
                    parsed_logs.append({
                        'timestamp': log_entry['time'],
                        'ip': log_entry['ip'],
                        'request': log_entry['request'],
                        'status': log_entry['status'],
                        'size': log_entry['size'],
                        'user_agent': log_entry['user_agent'][:70] + '...' if len(log_entry['user_agent']) > 70 else log_entry['user_agent']
                    })
            
        return jsonify(parsed_logs)

    except Exception as e:
        print(f"Error reading real-time logs: {e}")
        # In case of any error (e.g., file lock, malformed line), return an empty list
        # This prevents the 500 Internal Server Error.
        return jsonify([])

@app.route('/block/<ip>', methods=['POST'])
@login_required
def block_ip(ip):
    # Basic IP validation to prevent command injection
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({"status": "error", "message": "Invalid IP address format."}), 400

    blacklist_path = '/etc/nginx/blacklist.conf'
    nginx_container_name = 'sentinelshield-nginx-waf'
    
    try:
        # Check if IP is already blocked to prevent duplicates
        with open(blacklist_path, 'r') as f:
            if f"deny {ip};" in f.read():
                return jsonify({"status": "already_blocked", "ip": ip})

        # 1. Add the IP to the blacklist file
        with open(blacklist_path, 'a') as f:
            f.write(f"deny {ip};\n")
            
        # 2. Reload Nginx configuration
        # This command is executed from the sentinelshield-app container, which has docker client installed
        # and the docker socket mounted.
        reload_command = f"docker exec {nginx_container_name} nginx -s reload"
        result = os.system(reload_command)
        
        if result == 0:
            log_suspicious_event({
                'type': 'IP Blocked',
                'ip': ip,
                'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                'details': f"IP {ip} was manually blocked by an administrator."
            })
            return jsonify({"status": "blocked", "ip": ip})
        else:
            return jsonify({
                "status": "error", 
                "message": f"IP {ip} was added to the blacklist, but the Nginx reload command failed. " \
                           f"Exit code: {result}"
            }), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/blacklist')
@login_required
def blacklist_manager():
    blacklist_path = '/etc/nginx/blacklist.conf'
    blocked_ips = []
    try:
        with open(blacklist_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                # Basic parsing for "deny 1.2.3.4;"
                match = re.search(r"deny\s+([^;]+);", line)
                if match:
                    blocked_ips.append(match.group(1).strip())
    except FileNotFoundError:
        # If the file doesn't exist, it's fine, no IPs are blocked.
        pass
    except Exception as e:
        # Handle other potential errors, maybe log them
        print(f"Error reading blacklist file: {e}")

    return render_template('blacklist.html', blocked_ips=blocked_ips)

@app.route('/unblock/<ip>', methods=['POST'])
@login_required
def unblock_ip(ip):
    # Basic IP validation
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({"status": "error", "message": "Invalid IP address format."}), 400

    blacklist_path = '/etc/nginx/blacklist.conf'
    nginx_container_name = 'sentinelshield-nginx-waf'
    ip_unblocked = False

    try:
        with open(blacklist_path, 'r') as f:
            lines = f.readlines()
        
        # Filter out the line with the IP to unblock
        new_lines = []
        for line in lines:
            if f"deny {ip};" not in line:
                new_lines.append(line)
            else:
                ip_unblocked = True
        
        if not ip_unblocked:
            return jsonify({"status": "not_found", "message": f"IP {ip} was not found in the blacklist."})

        with open(blacklist_path, 'w') as f:
            f.writelines(new_lines)

        # Reload Nginx
        reload_command = f"docker exec {nginx_container_name} nginx -s reload"
        result = os.system(reload_command)

        if result == 0:
            log_suspicious_event({
                'type': 'IP Unblocked',
                'ip': ip,
                'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                'details': f"IP {ip} was manually unblocked by an administrator."
            })
            return jsonify({"status": "unblocked", "ip": ip})
        else:
            return jsonify({
                "status": "error",
                "message": f"IP {ip} was removed from the blacklist file, but Nginx reload failed."
            }), 500

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

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

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check if log file exists and is readable
        log_file_path = '/var/log/nginx/access.log'
        log_file_ok = os.path.exists(log_file_path) and os.access(log_file_path, os.R_OK)
        
        # Check if blacklist file is writable
        blacklist_path = '/etc/nginx/blacklist.conf'
        blacklist_ok = os.access(os.path.dirname(blacklist_path), os.W_OK)
        
        status = {
            'status': 'healthy' if log_file_ok and blacklist_ok else 'degraded',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'services': {
                'log_processing': log_file_ok,
                'blacklist_management': blacklist_ok,
                'total_requests': APP_STATS["total_requests"],
                'unique_visitors': len(APP_STATS["unique_visitors"])
            }
        }
        
        return jsonify(status), 200 if status['status'] == 'healthy' else 503
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    threading.Thread(target=process_logs, daemon=True).start()
    threading.Thread(target=manage_logs, daemon=True).start()
    # Note: For production, this is run via Gunicorn from the Dockerfile
    app.run(host='0.0.0.0', port=8000, debug=True)
