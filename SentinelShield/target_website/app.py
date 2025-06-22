from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how-it-works.html')

@app.route('/use-cases')
def use_cases():
    return render_template('use-cases.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    # Running on port 8080 to avoid conflict with SentinelShield
    app.run(host='0.0.0.0', port=8080, debug=True) 