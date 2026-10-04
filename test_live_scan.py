"""
test_live_scan.py - Tests end-to-end scanning and report rendering
Event: BUILD SECURE 2026
"""

import threading
import time
import requests
from app import app
import scanner

def run_server():
    app.run(host="127.0.0.1", port=5055, debug=False, use_reloader=False)

def test_full_pipeline():
    print("Testing live end-to-end scanning pipeline...")
    # Start app in background thread on test port 5055
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)  # wait for server to bind

    # 1. Test Insecure Demo Analysis
    insecure_url = "http://127.0.0.1:5055/demo/insecure"
    res_insecure = scanner.run_full_scan(insecure_url)
    assert res_insecure["success"] is True, f"Scan failed: {res_insecure}"
    print(f"[PASS] Insecure Demo Scored: {res_insecure['summary']['score']}/100 | Risk: {res_insecure['summary']['risk_level']}")
    assert res_insecure["summary"]["risk_level"] in ("HIGH", "NEEDS ATTENTION"), "Insecure demo should have high risk or need attention"
    assert res_insecure["stats"]["has_file_upload"] is True, "File upload should be detected"
    assert res_insecure["stats"]["has_password"] is True, "Password field should be detected"
    assert res_insecure["stats"]["has_plaintext_password"] is True, "Password over HTTP/GET must be flagged"

    # 2. Test Secure Demo Analysis
    secure_url = "http://127.0.0.1:5055/demo/secure"
    res_secure = scanner.run_full_scan(secure_url)
    assert res_secure["success"] is True, f"Scan failed: {res_secure}"
    print(f"[PASS] Secure Demo Scored: {res_secure['summary']['score']}/100 | Risk: {res_secure['summary']['risk_level']}")
    assert res_secure["summary"]["score"] > res_insecure["summary"]["score"], "Secure demo score must exceed insecure demo"
    assert res_secure["stats"]["has_csrf_indicator"] is True, "CSRF indicator should be detected"

    # 3. Test HTTP Web Request to /scan for Insecure Demo
    web_res = requests.post("http://127.0.0.1:5055/scan", data={"url": insecure_url})
    assert web_res.status_code == 200
    assert "SECURITY REPORT CARD" in web_res.text
    assert "Insecure Credential Transmission" in web_res.text
    assert "File upload detected" in web_res.text or "File Upload Endpoint Detected" in web_res.text
    print("[PASS] Full web report rendering validated successfully.")

    # 4. Test Export JSON
    json_res = requests.get("http://127.0.0.1:5055/export/json")
    assert json_res.status_code == 200
    data = json_res.json()
    assert data["project"] == "Fake Form Detector"
    assert "score_summary" in data
    print("[PASS] JSON report export validated successfully.")

    print("\nALL END-TO-END AUDIT TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_full_pipeline()
