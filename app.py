"""
app.py - Web Application for Fake Form Detector ("Is This Website Safe?")
Event: BUILD SECURE 2026 - Cybersecurity Competition
"""

import os
import json
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, flash
import scanner

app = Flask(__name__)
app.secret_key = "build-secure-2026-fake-form-detector-educational-key"

# In-memory store for recent scan result to support print/export without storing credentials
LAST_SCAN_RESULT = None

@app.route("/")
def index():
    """Home landing page."""
    return render_template("index.html")

@app.route("/scan", methods=["GET", "POST"])
def scan():
    """
    Main URL Analysis endpoint.
    Handles submission from form or query param 'url'.
    """
    global LAST_SCAN_RESULT
    
    if request.method == "POST":
        target_url = request.form.get("url", "").strip()
    else:
        target_url = request.args.get("url", "").strip()

    if not target_url:
        flash("Please enter a website URL to analyze.", "warning")
        return redirect(url_for("index"))

    # Execute passive scan
    result = scanner.run_full_scan(target_url)
    
    if not result.get("success"):
        return render_template("report.html", error=result, target_url=target_url)

    LAST_SCAN_RESULT = result
    return render_template("report.html", report=result, target_url=target_url)


@app.route("/demo/insecure")
def demo_insecure():
    """
    Intentionally insecure training target page.
    Demonstrates missing security headers, credentials over HTTP/GET,
    file upload risks, and missing CSRF tokens.
    """
    resp = make_response(render_template("demo_insecure.html"))
    # Explicitly ensure NO security headers are attached
    for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", 
              "Referrer-Policy", "Permissions-Policy", "X-Frame-Options"]:
        if h in resp.headers:
            del resp.headers[h]
    return resp


@app.route("/demo/secure")
def demo_secure():
    """
    Secured, hardened training target page.
    Demonstrates proper security headers, HTTPS-ready POST form,
    CSRF token, and hardened input specifications.
    """
    resp = make_response(render_template("demo_secure.html"))
    # Attach industry-standard defense-in-depth headers
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/demo/run/<mode>")
def demo_run(mode):
    """
    Directly triggers analysis of the internal demo targets.
    """
    host = request.host
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    if mode == "insecure":
        target = f"http://{host}/demo/insecure"
    elif mode == "secure":
        target = f"{scheme}://{host}/demo/secure"
    else:
        return redirect(url_for("index"))

    return redirect(url_for("scan", url=target))


@app.route("/compare")
def compare():
    """
    Before vs After comparison page.
    Analyzes or showcases the difference between insecure and secured architectures.
    Demonstrates: BUILD -> DEPLOY -> SECURE -> ANALYZE
    """
    # Sample comparison data based on our demo environments
    before_data = {
        "title": "BEFORE SECURITY FIXES",
        "subtitle": "Default Insecure Configuration",
        "score": 15,
        "risk_level": "HIGH",
        "risk_color": "danger",
        "passed": 1,
        "warnings": 4,
        "risks": 2,
        "issues": [
            {"title": "Plaintext Password Exposure", "detail": "Password field transmitted via HTTP GET; visible in proxy logs and browser history.", "severity": "HIGH RISK"},
            {"title": "Missing Security Headers", "detail": "CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy absent.", "severity": "WARNING"},
            {"title": "Missing Anti-CSRF Token", "detail": "Forms lack state-changing validation tokens, vulnerable to cross-origin abuse.", "severity": "WARNING"},
            {"title": "Unrestricted File Upload Surface", "detail": "File upload endpoint lacks client-side specifications and visible restrictions.", "severity": "WARNING"},
            {"title": "Unvalidated Input Entry Points", "detail": "User input inputs accept raw text without explicit schema constraints.", "severity": "WARNING"}
        ]
    }

    after_data = {
        "title": "AFTER SECURITY FIXES",
        "subtitle": "Hardened Defensive Configuration",
        "score": 94,
        "risk_level": "LOW",
        "risk_color": "success",
        "passed": 8,
        "warnings": 1,
        "risks": 0,
        "issues": [
            {"title": "Encrypted Transport Enforced", "detail": "Credentials submitted via HTTP POST over TLS with HTTPS action.", "severity": "RESOLVED"},
            {"title": "Comprehensive Security Headers", "detail": "Strict CSP, HSTS, X-Content-Type-Options: nosniff, and Permissions-Policy deployed.", "severity": "RESOLVED"},
            {"title": "Anti-CSRF Synchronization Token", "detail": "Hidden cryptographic nonce protects against cross-site request forgery.", "severity": "RESOLVED"},
            {"title": "Guarded File Upload Specifications", "detail": "File type restrictions, size bounds, and secure storage advisory implemented.", "severity": "RESOLVED"},
            {"title": "Input Defense & Context Encoding", "detail": "Input allowlisting and parameterization principles integrated.", "severity": "RESOLVED"}
        ]
    }

    return render_template("compare.html", before=before_data, after=after_data)


@app.route("/methodology")
def methodology():
    """
    Methodology, ethics, limitations, and OWASP Top 10 alignment guide.
    """
    return render_template("methodology.html")


@app.route("/export/json")
def export_json():
    """
    Exports the most recent scan report as downloadable JSON.
    """
    global LAST_SCAN_RESULT
    if not LAST_SCAN_RESULT:
        return jsonify({"error": "No scan results available to export. Run an analysis first."}), 404

    # Sanitize for export (no HTML string blobs in JSON export for clean readability)
    export_payload = {
        "project": "Fake Form Detector",
        "competition": "BUILD SECURE 2026",
        "target_url": LAST_SCAN_RESULT.get("scanned_url"),
        "final_url": LAST_SCAN_RESULT.get("final_url"),
        "timestamp": LAST_SCAN_RESULT.get("timestamp"),
        "http_status": LAST_SCAN_RESULT.get("status_code"),
        "is_https": LAST_SCAN_RESULT.get("is_https"),
        "score_summary": LAST_SCAN_RESULT.get("summary"),
        "statistics": LAST_SCAN_RESULT.get("stats"),
        "forms_detected": LAST_SCAN_RESULT.get("forms"),
        "security_findings": LAST_SCAN_RESULT.get("findings")
    }

    response = make_response(json.dumps(export_payload, indent=2))
    response.headers["Content-Disposition"] = "attachment; filename=security-report-card.json"
    response.headers["Content-Type"] = "application/json"
    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print(" FAKE FORM DETECTOR - BUILD SECURE 2026")
    print(" Is This Website Safe? Passive Web Security Scanner")
    print(f" Server running at: http://0.0.0.0:{port}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=False)
