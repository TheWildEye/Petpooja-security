# SSRF Test Case — CWE-918, OWASP A10:2021
# This file contains INTENTIONAL vulnerabilities for testing the security scanner.

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/fetch-url')
def fetch_url():
    """VULNERABLE: SSRF via user-controlled URL"""
    # VULNERABILITY: User input directly used as URL
    url = request.args.get('url')
    response = requests.get(url)
    return response.text

@app.route('/proxy')
def proxy_request():
    """VULNERABLE: SSRF proxy with no validation"""
    # VULNERABILITY: Acting as an open proxy
    target = request.args.get('target')
    resp = requests.get(target, headers=dict(request.headers))
    return jsonify({"status": resp.status_code, "body": resp.text})

@app.route('/webhook')
def process_webhook():
    """VULNERABLE: SSRF via webhook URL"""
    # VULNERABILITY: Webhook URL not validated
    webhook_url = request.json.get('callback_url')
    # Attacker could set callback_url to http://169.254.169.254/latest/meta-data/
    requests.post(webhook_url, json={"status": "completed"})
    return "OK"

import urllib.request

def download_image(image_url):
    """VULNERABLE: SSRF via urllib"""
    # VULNERABILITY: No URL validation
    response = urllib.request.urlopen(image_url)
    return response.read()

# SAFE EXAMPLE:
# from urllib.parse import urlparse
# parsed = urlparse(url)
# if parsed.hostname not in ALLOWED_HOSTS:
#     return "Forbidden", 403
