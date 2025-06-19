from flask import Flask, render_template, request, redirect, session, jsonify
import json, threading, time, random
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATA_FILE = 'data.json'
LOG_FILE = 'logs.json'
USER_CREDENTIALS = {'admin': 'password123'}

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
    return render_template('dashboard.html')

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

if __name__ == '__main__':
    threading.Thread(target=update_data, daemon=True).start()
    app.run(debug=True)
