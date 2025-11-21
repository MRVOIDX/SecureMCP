# 🛡️ SecureMCP - AI-Powered Security Analysis Tool

A comprehensive security vulnerability scanner powered by Google Gemini AI that analyzes project codebases for 20+ types of security vulnerabilities, provides intelligent explanations, and generates professional security reports in multiple formats.

> **Project Type:** University Project | **Status:** Production Ready | **License:** MIT

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Vulnerability Detection](#vulnerability-detection)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)
- [Report Generation](#report-generation)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

SecureMCP is an intelligent security analysis platform designed to help developers identify and fix security vulnerabilities in their projects automatically. Using advanced pattern recognition and AI-powered analysis via Google Gemini, SecureMCP scans your entire codebase and provides:

- ✅ **Automated Detection** of 81+ security patterns
- ✅ **AI-Powered Explanations** for each vulnerability
- ✅ **Intelligent Fix Suggestions** with code examples
- ✅ **Security Scoring** system (0-100 scale)
- ✅ **Multi-Format Reports** (PDF, HTML, Markdown)
- ✅ **Multi-Page Dashboard** with professional UI

Perfect for university projects, open-source contributions, and production applications.

---

## ✨ Features

### Core Functionality
- **ZIP Upload Support** - Upload your entire project as a ZIP file for scanning
- **Comprehensive Scanning** - Analyzes 28+ file types including Python, JavaScript, Java, C++, etc.
- **Real-Time Analysis** - Instant vulnerability detection and AI analysis
- **Interactive Dashboard** - Accept or skip fixes with real-time UI updates
- **Security Scoring** - Automatic security score calculation (0-100)

### Report Generation
- 📄 **Professional Reports** with 8-section template
- 🎨 **Beautiful PDF Output** with styled tables and formatted findings
- 🌐 **HTML Reports** with embedded styles and print support
- 📝 **Markdown Reports** for version control integration
- 📊 **Detailed Metrics** including severity breakdown and security statistics

### Intelligence
- 🤖 **AI-Powered Analysis** using Google Gemini 1.5 Flash
- 💡 **Smart Suggestions** for each vulnerability
- 📚 **Security Best Practices** recommendations
- 🎯 **Risk Assessment** with severity levels (Critical, High, Medium, Low)

---

## 🛠️ Tech Stack

### Backend
- **Framework:** Flask 3.1.2
- **AI Engine:** Google Generative AI (Gemini 1.5 Flash)
- **PDF Generation:** ReportLab 4.0.9
- **Markdown Processing:** markdown2 2.5.4
- **Config Management:** PyYAML 6.0.3

### Frontend
- **HTML5 / CSS3** - Responsive, modern UI
- **Vanilla JavaScript** - Interactive scanner experience
- **Bootstrap-inspired Design** - Professional styling

### Deployment
- **Runtime:** Python 3.10+
- **Server:** Werkzeug WSGI server
- **Platform:** Replit (Cloud-based)

---

## 🔐 Vulnerability Detection

SecureMCP detects **81+ patterns across 17 security categories:**

### 1. **Hardcoded Secrets** 🔑
   - API keys, passwords, tokens
   - Database credentials
   - Private keys

### 2. **Insecure HTTP** 🌐
   - Unencrypted connections
   - Missing HTTPS enforcement

### 3. **SQL Injection** 💾
   - String concatenation in queries
   - Unsanitized user input

### 4. **Cross-Site Scripting (XSS)** ⚠️
   - DOM-based XSS
   - Unescaped HTML rendering

### 5. **Sensitive Data Storage** 📱
   - localStorage/sessionStorage misuse
   - Client-side secrets

### 6. **Weak Permissions** 🚪
   - Overly broad file permissions
   - World-readable sensitive files

### 7. **Debug Mode Enabled** 🐛
   - Development mode in production
   - Verbose error messages

### 8. **Missing Security Headers** 🛑
   - X-Frame-Options
   - Content-Security-Policy
   - X-Content-Type-Options

### 9. **Unsafe User Input** 📥
   - Missing input validation
   - Command injection vectors

### 10. **Weak Authentication** 🔓
   - Disabled auth mechanisms
   - Weak password policies

### 11. **Unrestricted File Upload** 📤
   - No file type validation
   - Arbitrary file execution

### 12. **Insecure Defaults** ⚙️
   - Debug mode on
   - Default credentials

### 13. **Path Traversal** 🗂️
   - Directory traversal vulnerabilities
   - Unsafe file operations

### 14. **Command Injection** 💣
   - System command execution
   - Unsafe shell operations

### 15. **Missing Input Validation** ✔️
   - Unvalidated parameters
   - Type confusion attacks

### 16. **Weak Password Storage** 🔐
   - MD5/SHA1 hashing
   - No salt usage

### 17. **No Rate Limiting** ⏱️
   - Brute force exposure
   - API abuse vectors

### Additional Detections
- Exposed configuration files
- Insecure API endpoints
- Excessive permissions
- Hardcoded test data

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)
- Google Generative AI API key

### Setup Steps

1. **Clone the Repository**
```bash
git clone https://github.com/mrvoidx/securemcp.git
cd securemcp
```

2. **Create Virtual Environment** (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Set Up Environment Variables**
```bash
cp .env.example .env
# Edit .env and add your Google Generative AI API key
```

5. **Configure API Key**
Add your Google Generative AI API key to `.env`:
```
GOOGLE_API_KEY=your_api_key_here
```

Get your API key from: https://makersuite.google.com/app/apikey

6. **Run the Application**
```bash
python app.py
```

The application will be available at `http://localhost:5000`

---

## 🚀 Usage

### Web Interface

1. **Open the Application**
   - Navigate to `http://localhost:5000` in your browser

2. **Home Page Features**
   - Project overview
   - Key features showcase
   - Call-to-action buttons

3. **Scanner Page**
   - Click "Choose File" to upload a ZIP file
   - Wait for automated scanning
   - Review detected vulnerabilities
   - Accept or skip fixes for each finding
   - Generate and download report

4. **View Reports**
   - Download as PDF (professionally formatted)
   - Download as HTML (interactive)
   - Download as Markdown (version control friendly)

### Workflow

```
Upload ZIP → Extract Files → Scan → Analyze with AI → Display Findings
    ↓
Review Results → Accept/Skip Fixes → Generate Report → Download
```

---

## 🔌 API Endpoints

### File Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload ZIP file for scanning |

### Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start security scan on project |
| GET | `/api/findings` | Get detected vulnerabilities |
| GET | `/api/summary` | Get scan summary statistics |

### Fix Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/apply-fix/<id>` | Apply fix to vulnerable code |
| POST | `/api/skip-fix/<id>` | Skip fix for vulnerability |

### Report Generation
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/generate-report` | Generate security report |
| GET | `/api/download-report/<filename>` | Download generated report |

### Pages
| Method | Endpoint | Page |
|--------|----------|------|
| GET | `/` | Home page |
| GET | `/scanner` | Scanner interface |
| GET | `/about` | Vulnerability types |
| GET | `/documentation` | User documentation |

---

## 📁 Project Structure

```
securemcp/
├── app.py                      # Flask application entry point
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore rules
│
├── src/
│   ├── scanner.py             # Main vulnerability scanner
│   ├── controller.py          # Business logic controller
│   ├── report_generator.py    # Report generation (PDF, HTML, MD)
│   └── llm_engine.py          # Google Gemini AI integration
│
├── templates/
│   ├── base.html              # Base template with navigation
│   ├── index.html             # Home page
│   ├── scanner.html           # Scanner interface
│   ├── about.html             # Vulnerability documentation
│   └── documentation.html     # User guides
│
├── static/
│   ├── style.css              # Main stylesheet
│   ├── script.js              # Shared utilities
│   └── scanner.js             # Scanner-specific scripts
│
└── reports/                   # Generated reports directory
    └── security_report_*.pdf  # Example reports
```

---

## 📊 Report Generation

### Security Score Calculation

```
Score = 100 - (CRITICAL×15 + HIGH×10 + MEDIUM×5 + LOW×2) + (Fixed Issues Bonus)
Range: 0-100
```

### Score Interpretation
- **90-100:** Excellent security practices
- **75-89:** Good foundation, minor issues
- **60-74:** Fair, needs attention
- **40-59:** Poor, significant risks
- **0-39:** Critical, immediate action required

### Report Sections
1. 📄 **Overview** - Project summary and scan statistics
2. 🛑 **Finding Summary** - Vulnerability breakdown by severity
3. 🔍 **Detailed Risks** - Each finding with explanations
4. 📈 **Security Score** - Overall rating and assessment
5. 🛠️ **Applied Fixes** - Accepted automatic fixes
6. ⚡ **Remaining Risks** - Unfixed vulnerabilities
7. 📘 **Next Steps** - Recommendations
8. 🧾 **Appendix** - Technical details

---

## 🎨 Features in Action

### Scanner Interface
- Clean, intuitive design
- Real-time scan progress
- Interactive finding cards
- One-click fix acceptance
- Instant UI updates

### Report Dashboard
- Security score visualization
- Severity breakdown charts
- Detailed finding cards
- Color-coded severity levels
- Export options

### AI Analysis
- Explains each vulnerability
- Provides fix recommendations
- Suggests best practices
- Generates code examples

---

## 🧪 Testing

To test the application:

1. **Use Sample Project**
   - Create a test ZIP file with vulnerable code
   - Upload to scanner
   - Verify vulnerability detection

2. **API Testing**
   ```bash
   curl -X POST http://localhost:5000/api/upload -F "file=@project.zip"
   curl -X GET http://localhost:5000/api/summary
   ```

3. **Report Generation**
   - Scan project
   - Generate PDF/HTML/Markdown reports
   - Verify formatting and content

---

## 📚 Documentation

### User Guide
Visit `/documentation` page for:
- Step-by-step scanning guide
- Understanding vulnerability types
- Best practices
- FAQ

### API Documentation
Detailed endpoint documentation available in `/documentation` page

### Security Best Practices
- Use environment variables for secrets
- Enable HTTPS in production
- Regular security audits
- Keep dependencies updated

---

## 🤝 Contributing

We welcome contributions! Here's how:

### Development Setup
```bash
git clone https://github.com/mrvoidx/securemcp.git
cd securemcp
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Making Changes
1. Create a feature branch: `git checkout -b feature/YourFeature`
2. Make your changes
3. Test thoroughly
4. Commit with clear messages: `git commit -m 'Add YourFeature'`
5. Push to branch: `git push origin feature/YourFeature`
6. Open a Pull Request

### Contribution Areas
- [ ] Additional vulnerability patterns
- [ ] Language/framework support
- [ ] UI/UX improvements
- [ ] Documentation enhancements
- [ ] Performance optimizations
- [ ] Bug fixes and testing

---

## 🐛 Known Limitations

- File size limit: 50MB per upload
- Supported formats: ZIP archives only
- Requires active internet for AI analysis
- Requires valid Google Generative AI API key

---

## 🚀 Deployment

### On Replit
1. Import this repository
2. Set environment variables in Secrets
3. Install dependencies (automatic)
4. Run `python app.py`
5. Access via Replit URL

### On Local Server
```bash
pip install -r requirements.txt
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### On Docker
```bash
docker build -t securemcp .
docker run -p 5000:5000 -e GOOGLE_API_KEY=your_key securemcp
```

---

## 📈 Performance

- **Scan Speed:** ~5-30 seconds (depends on project size)
- **AI Analysis:** ~2-5 seconds per finding
- **Report Generation:** ~1-2 seconds
- **Supported File Types:** 28+ languages/formats
- **Max Files Scanned:** Unlimited

---

## 📞 Support & Contact

- **Email:** your.email@university.edu
- **Issues:** Create an issue on GitHub
- **Questions:** Check documentation page
- **University Project:** Submitted as coursework

---

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

**MIT License Summary:**
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use
- ⚠️ Patent claims not granted
- ⚠️ Liability limited

---

## 🎓 Academic Information

**Institution:** [Warsaw Management University]  
**Course:** [Software Engineering]  
**Semester:** [Semester 5 - 2025/2026]  
**Project Type:** Assignment  
**Team:** [Group 4]  

---

## 🙏 Acknowledgments

- Google Generative AI (Gemini) for AI analysis
- Flask team for excellent web framework
- ReportLab for PDF generation
- Open source community

---

## 🔐 Security & Privacy

- No code is stored permanently on servers
- Reports are stored temporarily in `reports/` directory
- API keys should never be committed to git
- Use `.env` files for sensitive data
- Scan only your own projects

---

## 📊 Project Statistics

- **Total Vulnerability Patterns:** 81+
- **Detection Categories:** 17
- **Supported File Types:** 28+
- **Report Formats:** 3 (PDF, HTML, Markdown)
- **Lines of Code:** 2,000+
- **Response Time:** <5 seconds average

---

## 🔄 Version History

### v1.0.0 (Current)
- ✅ Initial release
- ✅ 81 detection patterns
- ✅ PDF/HTML/Markdown reports
- ✅ Google Gemini AI integration
- ✅ Professional web interface
- ✅ Auto-fix suggestions

---

## 📋 Checklist for Users

- [ ] Read the documentation
- [ ] Prepare ZIP file with project
- [ ] Upload project for scanning
- [ ] Review detected vulnerabilities
- [ ] Accept/skip suggested fixes
- [ ] Generate comprehensive report
- [ ] Review security score
- [ ] Implement recommendations

---

**Built with ❤️ for secure code**

---

*Last Updated: November 2025*  
*For questions or feedback, please create an issue on GitHub.*
