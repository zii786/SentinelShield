from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    # Running on port 5001 to avoid conflict with SentinelShield
    app.run(host='0.0.0.0', port=5001, debug=True) 