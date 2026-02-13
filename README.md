# SecureMCP

**AI‑assisted security scanner and remediation platform for modern codebases.**
SecureMCP helps developers and students **detect, understand, fix, and report security issues** with clarity and confidence. It combines offline static analysis with optional AI enrichment powered by **Groq‑hosted Llama 3.3**, producing **professional‑grade PDF/HTML reports** suitable for coursework, audits, and production hardening.

> 🔗 Repository: [https://github.com/mrvoidx/SecureMCP](https://github.com/mrvoidx/SecureMCP)

---

## Table of Contents

* [Why SecureMCP?](#why-securemcp)
* [Key Capabilities](#key-capabilities)
* [How It Works](#how-it-works)
* [Technology Stack](#technology-stack)
* [Vulnerability Coverage](#vulnerability-coverage)
* [Installation](#installation)
* [Configuration](#configuration)
* [Usage Guide](#usage-guide)
* [API Reference](#api-reference)
* [Project Architecture](#project-architecture)
* [Report Generation](#report-generation)
* [Use Cases](#use-cases)
* [Contributing](#contributing)
* [License](#license)

---

## Why SecureMCP?

Many student and early‑stage projects unintentionally ship with insecure defaults: exposed secrets, weak authentication, unsafe file handling, or missing protections. These issues are often:

* Easy to miss during feature‑focused development
* Hard to explain to non‑security teammates
* Poorly documented in final reports

**SecureMCP bridges that gap** by scanning codebases, explaining risks in plain language, proposing concrete fixes, and turning results into **clear, visual, professional reports**.

---

## Key Capabilities

### 🔍 Static Security Scanning (Offline)

* Detects **70+ vulnerability patterns** across web and backend projects
* Works fully offline for scanning and reporting
* Supports ZIP uploads or direct project path scanning

### 🤖 AI‑Enhanced Explanations & Fixes (Optional)

* Uses **Groq‑hosted Llama 3.3** to:

  * Explain vulnerabilities in human‑readable terms
  * Assess risk severity and impact
  * Propose safe, minimal fix suggestions
  * Generate **full‑file AI repair drafts** when needed
* Automatic fallback to heuristic fixes if no API key is configured

### 🛠 Apply / Skip Workflow

* Review findings with surrounding code context
* Apply automatic fixes or mark issues as skipped/manual
* Download AI‑generated fixed files before committing changes

### 📊 Professional Reporting

* Export **PDF or HTML reports** with:

  * Severity distribution charts
  * Category breakdowns
  * Applied / skipped / remaining issue counts
  * Executive summary and recommendations

---

## How It Works

1. **Upload or select a project** (ZIP or local path)
2. **Static scan** identifies risky patterns
3. **AI enrichment** adds explanations and fixes (if enabled)
4. **User review**: apply, skip, or inspect fixes
5. **Generate report** for documentation or submission

---

## Technology Stack

**Backend**

* Flask 3.1, Werkzeug, Jinja2

**AI**

* Groq API – Llama 3.3 (versatile model)

**Reporting & Visualization**

* ReportLab (PDF)
* Matplotlib (charts)
* Jinja2 (HTML reports)

**Parsing & Utilities**

* PyYAML, markdown2

**Frontend**

* Vanilla HTML / CSS / JavaScript (SPA‑style UI)

---

## Vulnerability Coverage

SecureMCP detects common real‑world security mistakes, including:

* Hardcoded secrets & API keys
* Insecure HTTP usage
* SQL injection
* Cross‑Site Scripting (XSS)
* Command injection
* Weak or missing authentication
* Weak password storage
* Insecure file uploads
* Path traversal
* Sensitive data exposure
* Missing input validation
* Missing security headers
* Over‑permissive configurations
* Exposed configuration files
* Missing rate limiting
* Insecure API endpoints

…and multiple variants of each category.

---

## Installation

### 🚀 Quick Start (Windows – Recommended)

```bash
run.bat
```

* Creates a virtual environment (`.venv`)
* Upgrades pip and installs dependencies
* Launches SecureMCP at **[http://localhost:5000](http://localhost:5000)**

Reuse existing dependencies:

```bash
run.bat --skip-install
```

### 🧰 Manual Setup (Any OS)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

**Requirements**

* Python 3.10+
* pip
* (Optional) Groq API key for AI features

---

## Configuration

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key
SESSION_SECRET=change_me_in_production
```

* `GROQ_API_KEY` → Enables AI explanations and fix generation
* `SESSION_SECRET` → Secures Flask sessions (required for production)

---

## Usage Guide

1. Open **[http://localhost:5000](http://localhost:5000)**
2. Upload a ZIP project or select a local path
3. Review detected findings with explanations and severity
4. Apply or skip fixes as appropriate
5. Generate a **PDF or HTML report** from the UI
6. Find reports in the `reports/` directory

---

## API Reference (Selected)

* `POST /api/upload` – Upload and extract a ZIP project
* `POST /api/scan` – Start scanning a project path
* `GET /api/findings` – List unresolved findings
* `POST /api/apply-fix/<index>` – Apply or mark fix as resolved
* `POST /api/skip-fix/<index>` – Skip a finding
* `GET /api/fix-preview/<index>` – View original vs replacement code
* `POST /api/generate-ai-fix/<index>` – Generate AI full‑file fix
* `POST /api/generate-report` – Create PDF or HTML report
* `GET /api/download-report/<filename>` – Download a generated report

---

## Project Architecture

* `app.py` – Flask app, routing, uploads, orchestration
* `src/scanner.py` – Static detection patterns & metrics
* `src/controller.py` – Scan lifecycle, apply/skip logic
* `src/auto_fixer.py` – Heuristic fix generation
* `src/llm_engine.py` – Groq client and AI enrichment
* `src/enhanced_report_generator.py` – PDF/HTML report builder
* `templates/` – Jinja2 views
* `static/` – Frontend assets
* `reports/` – Generated reports

---

## Report Generation

**Formats**: PDF, HTML
**Contents**:

* Executive summary
* Severity and category charts
* Applied / skipped / failed fix counts
* Remaining vulnerabilities
* Security recommendations

Reports are saved as:

```
reports/security_report_YYYYMMDD_HHMMSS.pdf|html
```

---

## Use Cases

* 🎓 University security or software engineering projects
* 🧪 Secure code reviews for side projects
* 🧱 Baseline security hardening before production
* 📄 Generating audit‑ready documentation

---

## Contributing

Contributions are welcome and encouraged.

Ideas:

* New vulnerability patterns
* Improved fix accuracy
* UI/UX enhancements
* Performance optimizations
* Documentation and examples

Workflow:

1. Fork the repository
2. Create a feature branch (`feature/your-feature`)
3. Keep `requirements.txt` updated if dependencies change
4. Submit a pull request to `main`

---

## License

MIT License – see `LICENSE` for details.

---

Built by **mrvoidx**.
AI assistance powered by **Groq‑hosted Llama 3.3**.
