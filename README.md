# Phishinator

#### Video Demo: https://youtu.be/Zz8wpisrgcA 

#### Description:

Phishinator is a web-based email security inspection platform built with Python (Flask), HTML5, Tailwind CSS, and JavaScript. It allows security analysts, defenders, and everyday users to inspect suspicious email files (`.eml`), analyze header anomalies, query VirusTotal threat intelligence feeds for embedded links, evaluate social engineering urgency cues, and receive an instant AI executive threat summary powered by OpenRouter LLM.

Phishinator was developed as a practical cybersecurity tool designed to solve a real-world problem: helping users safely evaluate whether an unexpected email message is legitimate or a malicious phishing attempt. Email remains the primary entry vector for cyber attacks, credential theft, and malware delivery. Many non-technical users struggle to read raw email headers or determine if a link leads to a credential harvester. Phishinator bridge this gap by automating header parsing, link extraction, threat intelligence lookups, and rule-based risk scoring into a clean, responsive "Bento Box" dashboard interface.

---

### Key Features & Workflow

1. **Email Parsing & Header Dissection**: Extracts subject, display name, sender email, recipient, MIME body content, attachments, Return-Path, and envelope headers using Python's `email` package and custom regex matchers.
2. **Multi-Link Threat Intelligence**: Extracts all unique clickable URLs from the message body and headers and queries the VirusTotal v3 API (using base64url encoding) to verify whether any domain is flagged by security vendors worldwide.
3. **Rule-Based Heuristic Engine**: Scores email threats from 0 to 100 based on weighted indicators, such as urgency/password-reset language, mismatched sender display names, attachment presence, and VirusTotal threat flags.
4. **AI Executive Summary**: Integrates with OpenRouter API (Gemini/Llama LLM endpoints) to synthesize an executive risk summary that translates technical header anomalies and VirusTotal flags into plain-English security guidance.
5. **Rate Limiting & Protection**: Protects backend API endpoints against abuse using `Flask-Limiter` with custom 429 error handling pages.
6. **Bundled Sample Corpus**: Includes a sample dataset page to evaluate sample `.eml` files without requiring manual file uploads during demonstration or testing.

---

### Project Structure & File Overview

- **`app/app.py`**: The entry point for the Flask web application. Registers application blueprints (`index_bp`, `uploader_bp`), configures `Flask-Limiter` for IP-based rate limiting, and defines custom error handlers for 404 (Not Found) and 429 (Rate Limit Exceeded).
- **`app/config.py`**: Handles environment configurations and application setting parameters.
- **`app/routes/index.py`**: Defines standard page navigation routes for the Home (`/`), About (`/about`), Glossary (`/glossary`), and Sample Dataset (`/samples`) pages.
- **`app/routes/analyser.py`**: Manages the upload route (`/upload`), file validation (file size limits, `.eml` extension checks), temporary file storage, and coordinates parser, VirusTotal, scoring, and LLM services.
- **`app/services/parser_service.py`**: Parses raw email bytes into structured Python dictionaries. Extracts plain text and HTML bodies, handles character set encoding, extracts links, and checks attachment states.
- **`app/services/scorer_service.py`**: Implements heuristic threat rules and assigns a risk score (0–100) along with a verdict (`likely legitimate`, `suspicious but not conclusive`, or `high-risk phishing`).
- **`app/services/virustotal_service.py`**: Interacts with VirusTotal API v3. Encodes URLs to VT base64url identifiers and returns aggregated security vendor verdicts (`clean`, `suspicious`, `malicious`, `submitted`, `rate_limited`, or `disabled`).
- **`app/services/llm_service.py`**: Communicates with OpenRouter LLM API to generate concise executive threat summaries explaining the findings, with local fallback handling.
- **`app/templates/`**: Contains HTML templates built with Jinja2 inheritance (`base.html`), adhering to a modern, responsive Bento Grid UI design system:
  - `base.html`: Common layout wrapper with standardized container alignment (`container mx-auto px-4`), navigation header, and footer.
  - `index.html`: Home page featuring hero banner, file upload dropzone, analysis capabilities grid, and interactive FAQs.
  - `result.html`: Security report page displaying executive AI summary, threat risk gauge, key findings list, email header breakdown, VirusTotal multi-link intelligence table, and message body preview.
  - `about.html`, `glossary.html`, `samples.html`, `processing.html`, `404.html`, `error.html`: Utility and information pages styled with transparent bento card borders.
- **`tests/`**: Automated test suite powered by `pytest` covering MIME parsing (`test_parser.py`), heuristic scoring (`test_rules.py`), file uploads (`test_upload.py`), and VirusTotal API integration paths (`test_virustotal.py`).
- **`sample/phishing_pot/`**: Synthetic and sample `.eml` files used for demonstration and automated heuristic testing.

---

### Design Decisions

1. **Rule-Based Heuristics vs. Pure Machine Learning**: I chose a rule-based scoring architecture combined with deterministic threat intelligence (VirusTotal) because security analysts require transparent, explainable logic. Users can see exactly which indicators triggered the risk score.
2. **AI Executive Summary Integration**: While heuristic rules assign numerical scores, non-technical users often need plain-English context. Adding OpenRouter LLM summarization bridges this gap by describing *why* an email is dangerous and what specific action to take.
3. **Bento Card Styling & UX**: Replaced dense default tables with a modern "Bento Box" visual grid featuring transparent backgrounds, dark border highlights (`border-gray-700`), and consistent margin alignment across all viewports.
4. **Privacy & Temporary Storage**: Uploaded `.eml` files are parsed in memory / temporary server storage and immediately deleted after report generation to safeguard user privacy.

---

### AI Tool Citation (CS50x Policy Compliance)

In accordance with CS50x policy on the use of AI tools for the Final Project:
- **AI Tool Used**: Google Antigravity AI pair programming assistant.
- **Usage Scope**: Assisted as a productivity helper for code refactoring, Tailwind CSS UI Bento card grid alignment, VirusTotal v3 URL base64url encoding logic, Flask-Limiter integration, and unit test discovery.
- **Citation in Source Code**: Code files (`app/app.py`, `app/routes/analyser.py`, `app/services/virustotal_service.py`, `app/services/llm_service.py`, etc.) contain explicit header comments citing the use of AI tools as required by CS50x guidelines. The core application design, architectural decisions, and project implementation reflect my own work and learning from the course.

---

### How to Run the Project

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Environment Setup**:
   Create or verify `.env` file in project root:
   ```env
   SECRET_KEY=your-flask-secret
   VIRUS_TOTAL_API=your-virustotal-v3-api-key
   OPENROUTER_API_KEY=your-openrouter-api-key
   ```
3. **Compile CSS Assets**:
   ```bash
   ./tailwindcss -i app/static/css/input.css -o app/static/css/output.css
   ```
4. **Launch Application**:
   ```bash
   export FLASK_APP=app.app
   honcho start
   ```
   Open `http://127.0.0.1:5000` in your web browser.

---

### Testing

Run the automated `pytest` test suite:
```bash
pytest
```
Or with unittest runner:
```bash
python -m unittest discover -s tests -v
```
