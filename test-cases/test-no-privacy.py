# No Privacy Policy Test Case — DPDP Act Sec 5 + IT Act 43A Violation
# This file contains an INTENTIONAL compliance violation for testing.

from flask import Flask, request, jsonify

app = Flask(__name__)

# VIOLATION: App collects user data but has NO privacy policy route
# No /privacy, /privacy-policy, or /terms endpoint exists

@app.route('/api/signup', methods=['POST'])
def signup():
    """Collects PII without any privacy policy page existing"""
    data = request.json
    name = data['name']
    email = data['email']
    phone = data['phone']
    # Storing SPDI without informing user of privacy practices
    save_user(name, email, phone)
    return jsonify({"status": "created"})

@app.route('/api/users/<user_id>')
def get_user(user_id):
    """Returns user data — no access control, no privacy notice"""
    return jsonify(get_user_from_db(user_id))

@app.route('/')
def index():
    return "Welcome to our app!"

@app.route('/about')
def about():
    return "About us page"

@app.route('/contact')
def contact():
    return "Contact us page"

# MISSING: /privacy or /privacy-policy route
# MISSING: /terms or /terms-of-service route
# MISSING: /data-deletion or /delete-account route
# MISSING: /consent-withdraw route

# VIOLATION: No data erasure mechanism (DPDP Sec 12(3))
# VIOLATION: No consent withdrawal (DPDP Sec 6(6))
# VIOLATION: No grievance redressal (DPDP Sec 13)

if __name__ == '__main__':
    app.run(debug=True)  # BONUS: Debug mode in production
