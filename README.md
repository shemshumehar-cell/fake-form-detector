# 🛡️ FAKE FORM DETECTOR
> **Tagline:** *"Is This Website Safe?"*  
> **Event:** BUILD SECURE 2026 — Cybersecurity Competition  
> **Project Type:** Defensive, Non-Destructive Passive Web Security & Form Inspector  

---

## 📌 1. Project Purpose

The **Fake Form Detector** is a defensive cybersecurity web application built for **BUILD SECURE 2026**. It allows users, students, and competition judges to passively inspect any website URL or form endpoint to evaluate transport security, HTTP response defense headers, HTML form configurations, credential handling hygiene, and file upload risks.

### 🔒 Passive & Ethical Security Guarantee
This application is strictly **passive and non-destructive**. It:
- **Never** executes brute-force or credential-stuffing attacks.
- **Never** injects SQL injection or XSS payloads into external servers.
- **Never** submits forms or uploads files to target websites.
- **Never** performs destructive penetration testing or denial-of-service attempts.
- **Never** collects, stores, or logs sensitive user passwords or session tokens.

All analysis is derived entirely from non-destructive HTTP GET requests, standard header inspection, and HTML parsing with BeautifulSoup4.

---

## 🚀 2. Features

1. **Cybersecurity-Themed Landing Page**:
   - Modern dark UI theme with high-contrast neon orange accents.
   - One-click URL input and instant local demo triggers.
2. **Transport Security (HTTPS/TLS) Verification**:
   - Checks TLS enforcement, redirects, and flags plaintext HTTP downgrade risks.
3. **HTTP Security Headers Audit**:
   - Analyzes 5 critical browser defense headers:
     - `Content-Security-Policy` (CSP)
     - `Strict-Transport-Security` (HSTS)
     - `X-Content-Type-Options` (nosniff)
     - `Referrer-Policy`
     - `Permissions-Policy`
     - *Bonus:* `X-Frame-Options` (Clickjacking defense)
   - Evaluates each as `PASS`, `WARNING`, or `UNVERIFIED` (e.g. HSTS over plain HTTP).
4. **HTML Form & Action Surface Analysis**:
   - Form method audit (`POST` vs `GET`).
   - Mixed-content detection (forms on HTTPS posting to insecure HTTP).
   - Anti-CSRF token heuristic discovery.
5. **Authentication & Password Exposure Detection**:
   - Identifies password inputs (`<input type="password">`).
   - Flags plaintext transmission risks (passwords sent over HTTP or GET).
6. **File Upload Surface Advisory**:
   - Discovers `<input type="file">` and displays defense-in-depth guidance covering server-side MIME verification, file size bounds, random filename hashing, and isolated cloud storage.
7. **Input Handling & Safe Injection Risk Education**:
   - Contextualizes user-controllable input fields.
   - Highlights that static HTML inspection cannot verify server-side parameterized queries or output sanitization, avoiding false vulnerability claims.
8. **Transparent 0–100 Security Score**:
   - Deterministic, category-weighted scoring formula based strictly on checks performed.
   - Categorizes risk as `LOW` (80–100), `NEEDS ATTENTION` (50–79), or `HIGH` (0–49).
9. **Interactive Visual Security Report Card**:
   - Circular score gauge with animated severity indicators.
   - Real-time finding filters (`All`, `High Risk`, `Warning`, `Pass`, `Unverified`).
   - Detailed remediation recommendations for every detected item.
10. **Built-in Local Demo Modes**:
    - **Insecure Demo (`/demo/insecure`)**: Demonstrates missing headers, passwords sent via HTTP GET, unrestricted file uploads, and missing CSRF tokens (Scores ~5/100).
    - **Secure Demo (`/demo/secure`)**: Demonstrates strict headers, HTTPS-ready POST forms, CSRF tokens, and input constraints (Scores ~100/100).
11. **Before vs After Hardening Comparison**:
    - Side-by-side case study illustrating the complete lifecycle:  
      **BUILD → DEPLOY → SECURE → ANALYZE**
12. **Printable Report & JSON Export**:
    - Print-optimized CSS (`@media print`) for clean paper/PDF reports.
    - Downloadable JSON audit file (`/export/json`).
13. **Methodology & OWASP Framework Alignment**:
    - Detailed documentation mapping findings to OWASP Top 10 categories (A01, A02, A03, A04, A05).
14. **Fault-Tolerant Error Handling**:
    - Gracefully handles unreachable domains, timeouts, DNS errors, and invalid schemes without application crashes.

---

## 🛠️ 3. Technology Stack

- **Backend**: Python 3.11+ with **Flask**
- **Passive HTTP Client**: `requests` & `urllib3`
- **HTML Parsing**: `BeautifulSoup4` (`bs4`)
- **Frontend**: HTML5, Vanilla JavaScript, Modern CSS (Cyber Dark Theme with Orange Accents)
- **Zero Heavy Frameworks**: Easy to run on any computer with minimal setup.

---

## 📦 4. Installation & Setup

### Prerequisites
- Python 3.8+ installed on your computer.

### Step 1: Open Terminal in Project Directory
```powershell
cd "C:\Users\Shemshu mehar\.gemini\antigravity\scratch\fake_form_detector"
```

### Step 2: Install Required Dependencies
```powershell
python -m pip install -r requirements.txt
```
*(Dependencies: `flask`, `requests`, `beautifulsoup4`)*

---

## ▶️ 5. How to Run the Application

Start the Flask local development server:
```powershell
python app.py
```

You will see output in the terminal:
```text
============================================================
 FAKE FORM DETECTOR - BUILD SECURE 2026
 Is This Website Safe? Passive Web Security Scanner
 Server running locally at: http://127.0.0.1:5000
============================================================
 * Running on http://127.0.0.1:5000
```

Open your web browser and navigate to:  
👉 **`http://127.0.0.1:5000`**

---

## 🧪 6. Automated Testing

To run the automated unit and integration tests:
```powershell
python test_app.py
```

To run the live server pipeline and demo audit tests:
```powershell
python test_live_scan.py
```

All tests run locally in under 2 seconds and verify URL validation, header analysis, form parsing, demo routes, and scoring integrity.

---

## 🎯 7. How to Demonstrate for Competition Judges

Follow this script during your **BUILD SECURE 2026** presentation:

### Phase 1: Landing Page & Philosophy (1 min)
1. Open `http://127.0.0.1:5000`.
2. Highlight the title **FAKE FORM DETECTOR** and tagline *"Is This Website Safe?"*.
3. Point out the **Passive & Non-Destructive banner**: explain to the judges that this scanner complies with ethical hacking and cybersecurity laws by avoiding aggressive exploit traffic.

### Phase 2: Auditing the Insecure Demo (2 mins)
1. On the home page, click the red button **"⚠️ Test Insecure Demo"**.
2. Notice the resulting **Security Report Card**:
   - Score: **5/100 (HIGH RISK)**
   - Plaintext password transmission flagged (submitted via GET to HTTP).
   - Missing security headers (CSP, HSTS, X-Content-Type-Options).
   - Unrestricted file upload endpoint detected.
   - Missing anti-CSRF token detected.
3. Show the **"Recommended Fix"** box on each card demonstrating how developers can remediate the issue.

### Phase 3: Auditing the Secure Demo (2 mins)
1. Navigate back to Home and click the green button **"✅ Test Secure Demo"**.
2. Notice the transformed **Security Report Card**:
   - Score: **100/100 (LOW RISK)**
   - All five security headers properly configured (`nosniff`, strict CSP, HSTS).
   - Form submitted via POST over encrypted HTTPS.
   - Anti-CSRF synchronization token identified.
   - File upload constraints (MIME restrictions and size boundaries) specified.

### Phase 4: Before vs After & Cybersecurity Lifecycle (1 min)
1. Click **"Before vs After"** in the top navigation bar.
2. Walk the judges through the visual lifecycle:  
   **BUILD → DEPLOY → SECURE → ANALYZE**
3. Show how security posture jumps from a 15/100 vulnerable baseline to a 94–100/100 hardened defense.

### Phase 5: Exporting & Methodology (1 min)
1. On any report card, click **"🖨️ Download / Print Report"** to show the clean print-ready stylesheet.
2. Click **"💾 Export JSON"** to show machine-readable security data for SIEM/logging integration.
3. Click **"Methodology"** in the navigation bar to discuss OWASP Top 10 alignment and passive testing limitations.

---

## ⚠️ 8. Limitations & Scope

- **Passive Analysis Limitation**: Static HTML analysis cannot execute backend database queries or inspect compiled server code. Therefore, SQL Injection and Cross-Site Scripting (XSS) are categorized as **"Potential injection risk — requires controlled security testing"**, avoiding unsubstantiated vulnerability claims.
- **Client-Side Frameworks**: Websites that render 100% of their forms dynamically via client-side JavaScript Single Page Applications (SPAs) without pre-rendered HTML will show 0 forms discovered.
- **Educational Indicator**: The 0–100 score is an educational metric designed for security hygiene awareness, not a substitute for a full manual penetration test.

---

## 📁 9. Project Structure

```text
fake_form_detector/
│
├── app.py                   # Flask server, route controllers, and demo endpoints
├── scanner.py               # Passive inspection engine, header & form auditor, scoring
├── requirements.txt         # Project dependencies (Flask, requests, beautifulsoup4)
├── test_app.py              # Unit tests for scanner, validation, and Flask routes
├── test_live_scan.py        # End-to-end integration test of live demo audits
├── README.md                # Competition documentation & user guide
│
├── static/
│   ├── css/
│   │   └── style.css        # Dark cybersecurity stylesheet, orange accents, print styles
│   └── js/
│       └── main.js          # Interactive UI filters, loading states, print handler
│
└── templates/
    ├── base.html            # Core layout with cyber navigation and footer
    ├── index.html           # Landing page with URL input & quick demo buttons
    ├── report.html          # Visual Security Report Card with gauge & findings
    ├── compare.html         # Before vs After security hardening comparison
    ├── methodology.html     # Methodology, ethics, and OWASP framework guide
    ├── demo_insecure.html   # Intentionally insecure educational mock portal
    └── demo_secure.html     # Hardened educational mock portal
```

---

*Created for **BUILD SECURE 2026** — Advancing defensive cybersecurity education through safe, non-destructive web inspection.*
