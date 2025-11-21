from datetime import datetime
from typing import List, Dict, Any
import markdown2
import os
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from io import BytesIO

class ReportGenerator:
    def __init__(self, project_path: str, findings: List[Dict[str, Any]], 
                 applied_fixes: List[Dict[str, Any]], summary: Dict[str, Any]):
        self.project_path = project_path
        self.findings = findings
        self.applied_fixes = applied_fixes
        self.summary = summary
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_date_formatted = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    
    def generate_markdown(self) -> str:
        project_name = os.path.basename(self.project_path) or "Unknown Project"
        severity_summary = self.summary.get('summary', {}).get('by_severity', {})
        
        critical_count = severity_summary.get('CRITICAL', 0)
        high_count = severity_summary.get('HIGH', 0)
        medium_count = severity_summary.get('MEDIUM', 0)
        low_count = severity_summary.get('LOW', 0)
        
        security_score = self._calculate_security_score()
        
        md_content = f"""# 🔐 SecureMCP — Security Risk Report By Group 4

## 📌 Project Name:

**{project_name}**

## 📁 Scan Date:

**{self.scan_date_formatted}**

## 👥 Scanned By:

**SecureMCP Automated Security Checker (LLM-Powered)**

Credit:
1/ Oussama Lakhtiri - 78704
2/ Bersun Ece Yılmaz-78866
3/ Abdelmounaim bounnou - 78763
4/ Yacine Doumer billel - 78743

---

## 1. 📄 Overview

SecureMCP analyzed the project's structure, codebase, and configuration files to identify potential security weaknesses.

This report summarizes:

- Detected issues
- Their severity
- Suggested improvements
- Which fixes were accepted or skipped

**Total Files Scanned:** {self.summary.get('total_files_scanned', 'N/A')}  
**Total Findings:** {self.summary.get('total_findings', 0)}  
**Applied Fixes:** {self.summary.get('applied_fixes', 0)}  
**Skipped Fixes:** {self.summary.get('skipped_fixes', 0)}  
**Remaining Issues:** {self.summary.get('remaining_issues', 0)}

---

## 2. 🛑 Summary of Findings

| Severity | Count |
|----------|-------|
| 🟥 Critical | {critical_count} |
| 🟧 High | {high_count} |
| 🟨 Medium | {medium_count} |
| 🟩 Low | {low_count} |

---

## 3. 🚨 Detailed Risk Findings

"""
        
        if not self.findings:
            md_content += "✅ **Excellent!** No security issues were detected in your project.\n\n"
        else:
            for idx, finding in enumerate(self.findings, 1):
                severity = finding.get('risk_level', finding.get('severity', 'MEDIUM'))
                severity_emoji = self._get_severity_emoji(severity)
                
                md_content += f"""### Finding #{idx} — {finding['description']}

**Severity:** {severity_emoji} {severity}  
**File:** `{finding['file']}`  
**Line(s):** {finding['line']}  
**Category:** {finding.get('category', 'unknown').replace('_', ' ').title()}

#### 🔍 Description

{finding.get('explanation', 'This security issue was detected in your code.')}

#### ⚠️ Why This Is Dangerous

{finding.get('impact', self._get_default_impact(finding.get('category', 'unknown')))}

#### 💡 Suggested Fix

{finding.get('suggested_fix', 'Manual review and correction recommended. Consult security best practices for this issue type.')}

#### 🧪 Proposed Code Change

**Current Code:**
```
{finding.get('snippet', 'N/A')}
```

**Matched Pattern:**
```
{finding.get('matched_text', 'N/A')}
```

#### ✔ User Decision:

{self._get_fix_status(idx - 1)}

---

"""
        
        md_content += """## 4. 🛠 Auto-Fixes Applied

"""
        
        if not self.applied_fixes:
            md_content += "No fixes were applied during this scan. All issues may require manual review.\n\n"
        else:
            applied_count = 0
            for fix in self.applied_fixes:
                if fix['status'] == 'applied':
                    applied_count += 1
                    finding = fix['finding']
                    md_content += f"""### ✅ Fix #{applied_count}: {finding['description']}

**File:** `{finding['file']}`  
**Line:** {finding['line']}

**Original Code:**
```
{fix.get('original_code', finding.get('snippet', 'N/A')).strip()}
```

**Replacement Code:**
```
{fix.get('replacement_code', 'Applied fix').strip()}
```

---

"""
            
            if applied_count == 0:
                md_content += "No auto-fixes were applied. All issues require manual review.\n\n"
        
        md_content += """## 5. ⚡ Remaining Risks (Not Fixed)

"""
        
        remaining = self.summary.get('remaining_issues', 0)
        if remaining == 0:
            md_content += "✅ **All identified issues have been addressed!**\n\n"
        else:
            md_content += f"These **{remaining} issue(s)** should be reviewed before release:\n\n"
            
            unresolved_num = 1
            for idx, finding in enumerate(self.findings):
                if not self._is_fixed(idx):
                    severity_emoji = self._get_severity_emoji(finding.get('risk_level', finding.get('severity', 'MEDIUM')))
                    md_content += f"{unresolved_num}. {severity_emoji} **{finding['description']}** in `{finding['file']}` (Line {finding['line']})\n"
                    unresolved_num += 1
        
        md_content += f"""
---

## 6. 📈 Overall Security Score

**Score:** {security_score} / 100

**General Assessment:**

{self._get_overall_feedback(security_score, remaining)}

---

## 7. 📘 Next Steps

SecureMCP recommends:

"""
        
        next_steps = self._generate_next_steps(remaining, critical_count, high_count)
        for i, step in enumerate(next_steps, 1):
            md_content += f"{i}. {step}\n"
        
        total_files = self.summary.get('total_files_scanned', 'N/A')
        
        md_content += f"""
---

## 8. 🧾 Appendix (Optional)

### Full Scanned File List

Total files scanned: {total_files}

### Configuration Details

- **Project Path:** `{self.project_path}`
- **Scan Timestamp:** {self.timestamp}
- **Scanner Version:** SecureMCP v1.0
- **LLM Engine:** Google Gemini 1.5 Flash

### Security Categories Checked

- Hardcoded Secrets
- Insecure HTTP
- SQL Injection
- Cross-Site Scripting (XSS)
- Sensitive Data in localStorage
- Overly Broad File Permissions
- Debug Mode Enabled
- Missing Security Headers
- Unsafe User Input
- Weak Authentication
- Unrestricted File Upload
- Insecure Default Configurations
- Path Traversal
- Command Injection
- Missing Input Validation
- Weak Password Storage
- No Rate Limiting
- Insecure API Endpoints
- Excessive Permissions
- Exposed Config Files

---

*Report generated by SecureMCP - LLM-Powered Security Checker*  
*Scan completed at {self.timestamp}*
"""
        
        return md_content
    
    def _get_severity_emoji(self, severity: str) -> str:
        emoji_map = {
            'CRITICAL': '🟥',
            'HIGH': '🟧',
            'MEDIUM': '🟨',
            'LOW': '🟩'
        }
        return emoji_map.get(severity, '⚪')
    
    def _get_fix_status(self, finding_index: int) -> str:
        if finding_index < len(self.applied_fixes):
            fix = self.applied_fixes[finding_index]
            if fix['status'] == 'applied':
                return '✅ **Accepted** - Fix has been applied to the codebase'
            elif fix['status'] == 'skipped':
                return '⏭️ **Skipped** - User chose not to apply this fix'
        return '⏳ **Pending Review** - Requires manual attention'
    
    def _is_fixed(self, finding_index: int) -> bool:
        if finding_index < len(self.applied_fixes):
            return self.applied_fixes[finding_index]['status'] == 'applied'
        return False
    
    def _calculate_security_score(self) -> int:
        total_findings = self.summary.get('total_findings', 0)
        
        if total_findings == 0:
            return 100
        
        severity_summary = self.summary.get('summary', {}).get('by_severity', {})
        
        critical_count = severity_summary.get('CRITICAL', 0)
        high_count = severity_summary.get('HIGH', 0)
        medium_count = severity_summary.get('MEDIUM', 0)
        low_count = severity_summary.get('LOW', 0)
        
        deduction = (critical_count * 15) + (high_count * 10) + (medium_count * 5) + (low_count * 2)
        
        applied_fixes = self.summary.get('applied_fixes', 0)
        if total_findings > 0:
            fix_bonus = int((applied_fixes / total_findings) * 20)
        else:
            fix_bonus = 0
        
        score = max(0, min(100, 100 - deduction + fix_bonus))
        
        return score
    
    def _get_default_impact(self, category: str) -> str:
        impact_descriptions = {
            'hardcoded_secrets': 'Hardcoded secrets can be easily discovered by attackers who gain access to your source code or repository. This can lead to unauthorized access to external services, data breaches, and potential financial losses.',
            'insecure_http': 'Using HTTP instead of HTTPS exposes data transmission to man-in-the-middle attacks, allowing attackers to intercept and read sensitive information like passwords, tokens, and personal data.',
            'sql_injection': 'SQL injection vulnerabilities allow attackers to manipulate database queries, potentially leading to unauthorized data access, data deletion, or complete database compromise.',
            'xss_vulnerabilities': 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts that execute in users\' browsers, potentially stealing session tokens, credentials, or performing actions on behalf of users.',
            'sensitive_data_storage': 'Storing sensitive data in localStorage or sessionStorage makes it vulnerable to XSS attacks and accessible to any JavaScript code running in the browser.',
            'insecure_configs': 'Insecure configurations can expose internal information, disable security features, and create attack vectors that compromise the entire application.',
            'weak_permissions': 'Overly permissive file permissions allow unauthorized users to read, modify, or execute sensitive files, potentially leading to system compromise.',
            'missing_security_headers': 'Missing security headers leave applications vulnerable to clickjacking, MIME-sniffing attacks, and other browser-based vulnerabilities.',
            'weak_authentication': 'Weak or disabled authentication mechanisms allow unauthorized access to protected resources and user accounts.',
            'file_upload_vulnerabilities': 'Unrestricted file uploads can allow attackers to upload malicious files, potentially leading to remote code execution or stored XSS attacks.',
            'path_traversal': 'Path traversal vulnerabilities allow attackers to access files outside the intended directory, potentially exposing sensitive configuration files, source code, or system files.',
            'command_injection': 'Command injection allows attackers to execute arbitrary system commands, potentially leading to complete server compromise.',
            'missing_input_validation': 'Lack of input validation allows attackers to inject malicious data, leading to various attacks including injection flaws and data corruption.',
            'weak_password_storage': 'Using weak hashing algorithms like MD5 or SHA1 for passwords makes them vulnerable to rainbow table attacks and brute-force cracking.',
            'no_rate_limiting': 'Without rate limiting, APIs are vulnerable to brute-force attacks, credential stuffing, and denial-of-service attacks.',
            'insecure_api_endpoints': 'Insecure API endpoints without proper protection can be exploited for unauthorized data access, modification, or deletion.',
            'exposed_config_files': 'Exposed configuration files can reveal sensitive credentials, API keys, and system architecture information to attackers.',
        }
        return impact_descriptions.get(category, 'This security issue could potentially be exploited by attackers to compromise the security and integrity of your application.')
    
    def _get_overall_feedback(self, score: int, remaining_issues: int) -> str:
        if score >= 90:
            return "🎉 **Excellent!** Your project demonstrates strong security practices. Continue maintaining these standards as you develop new features."
        elif score >= 75:
            return "👍 **Good!** Your project has a solid security foundation. Address the remaining issues to further strengthen your security posture."
        elif score >= 60:
            return "⚠️ **Fair.** Your project has some security concerns that should be addressed. Review and fix the critical and high-severity issues as a priority."
        elif score >= 40:
            return "🔴 **Needs Improvement.** Your project has significant security vulnerabilities. Immediate attention is required to address critical issues before deployment."
        else:
            return "🚨 **Critical!** Your project has severe security vulnerabilities that must be fixed immediately. Do not deploy this application until all critical and high-severity issues are resolved."
    
    def _generate_next_steps(self, remaining_issues: int, critical_count: int, high_count: int) -> List[str]:
        steps = []
        
        if critical_count > 0:
            steps.append("🚨 **Address Critical Issues Immediately** - Fix all critical-severity findings before proceeding with development or deployment")
        
        if high_count > 0:
            steps.append("⚠️ **Resolve High-Priority Risks** - Address high-severity vulnerabilities that pose significant security threats")
        
        if remaining_issues > 0:
            steps.append("📋 **Review Remaining Issues** - Carefully examine all unfixed security findings and create a remediation plan")
            steps.append("🧪 **Test After Fixes** - Ensure your application functions correctly after applying security patches")
        else:
            steps.append("✅ **Maintain Security Standards** - Continue following secure coding practices in future development")
        
        steps.append("🔄 **Regular Security Scans** - Run SecureMCP scans regularly, especially before releases and after major changes")
        steps.append("📚 **Security Training** - Keep your team updated on the latest security best practices and common vulnerabilities")
        steps.append("👥 **Code Reviews** - Implement peer reviews for security-critical code sections")
        steps.append("🔐 **Secrets Management** - Use environment variables and secret management tools instead of hardcoding credentials")
        
        if remaining_issues == 0:
            steps.append("🎯 **Penetration Testing** - Consider professional security testing for production applications")
        
        return steps
    
    def generate_pdf(self) -> bytes:
        """Generate a PDF report and return as bytes"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
        
        styles = getSampleStyleSheet()
        custom_styles = {
            'title': ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=12,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'heading2': ParagraphStyle(
                'CustomHeading2',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=10,
                spaceBefore=10,
                fontName='Helvetica-Bold',
                borderPadding=5,
                borderColor=colors.HexColor('#3498db'),
                borderWidth=1,
                borderRadius=3
            ),
            'heading3': ParagraphStyle(
                'CustomHeading3',
                parent=styles['Heading3'],
                fontSize=12,
                textColor=colors.HexColor('#34495e'),
                spaceAfter=8,
                spaceBefore=8,
                fontName='Helvetica-Bold'
            ),
            'normal': ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=10,
                alignment=TA_JUSTIFY,
                spaceAfter=6
            ),
            'code': ParagraphStyle(
                'Code',
                parent=styles['Normal'],
                fontSize=8,
                fontName='Courier',
                textColor=colors.HexColor('#d63384'),
                spaceAfter=6,
                leftIndent=10,
                rightIndent=10,
                backColor=colors.HexColor('#f8f9fa')
            )
        }
        
        story = []
        project_name = os.path.basename(self.project_path) or "Unknown Project"
        severity_summary = self.summary.get('summary', {}).get('by_severity', {})
        
        critical_count = severity_summary.get('CRITICAL', 0)
        high_count = severity_summary.get('HIGH', 0)
        medium_count = severity_summary.get('MEDIUM', 0)
        low_count = severity_summary.get('LOW', 0)
        
        security_score = self._calculate_security_score()
        
        # Title
        story.append(Paragraph("🔐 SecureMCP — Security Risk Report", custom_styles['title']))
        story.append(Spacer(1, 0.2*inch))
        
        # Project Info
        story.append(Paragraph(f"<b>Project Name:</b> {project_name}", custom_styles['normal']))
        story.append(Paragraph(f"<b>Scan Date:</b> {self.scan_date_formatted}", custom_styles['normal']))
        story.append(Paragraph(f"<b>Scanned By:</b> SecureMCP Automated Security Checker (LLM-Powered)", custom_styles['normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Overview
        story.append(Paragraph("1. Overview", custom_styles['heading2']))
        story.append(Paragraph("SecureMCP analyzed the project's structure, codebase, and configuration files to identify potential security weaknesses.", custom_styles['normal']))
        story.append(Spacer(1, 0.1*inch))
        
        overview_data = [
            ['Metric', 'Value'],
            ['Total Files Scanned', str(self.summary.get('total_files_scanned', 'N/A'))],
            ['Total Findings', str(self.summary.get('total_findings', 0))],
            ['Applied Fixes', str(self.summary.get('applied_fixes', 0))],
            ['Skipped Fixes', str(self.summary.get('skipped_fixes', 0))],
            ['Remaining Issues', str(self.summary.get('remaining_issues', 0))]
        ]
        
        overview_table = Table(overview_data, colWidths=[2.5*inch, 2*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ecf0f1'))
        ]))
        story.append(overview_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Summary of Findings
        story.append(Paragraph("2. Summary of Findings", custom_styles['heading2']))
        
        summary_data = [
            ['Severity', 'Count'],
            ['🟥 Critical', str(critical_count)],
            ['🟧 High', str(high_count)],
            ['🟨 Medium', str(medium_count)],
            ['🟩 Low', str(low_count)]
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ecf0f1'))
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Detailed Findings
        story.append(Paragraph("3. Detailed Risk Findings", custom_styles['heading2']))
        
        if not self.findings:
            story.append(Paragraph("✅ <b>Excellent!</b> No security issues were detected in your project.", custom_styles['normal']))
        else:
            for idx, finding in enumerate(self.findings, 1):
                story.append(Paragraph(f"Finding #{idx}: {finding['description']}", custom_styles['heading3']))
                
                severity = finding.get('risk_level', finding.get('severity', 'MEDIUM'))
                severity_emoji = self._get_severity_emoji(severity)
                
                story.append(Paragraph(f"<b>Severity:</b> {severity_emoji} {severity}", custom_styles['normal']))
                story.append(Paragraph(f"<b>File:</b> {finding['file']}", custom_styles['normal']))
                story.append(Paragraph(f"<b>Line(s):</b> {finding['line']}", custom_styles['normal']))
                story.append(Paragraph(f"<b>Category:</b> {finding.get('category', 'unknown').replace('_', ' ').title()}", custom_styles['normal']))
                
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph("<b>Description:</b>", custom_styles['heading3']))
                story.append(Paragraph(finding.get('explanation', 'This security issue was detected in your code.'), custom_styles['normal']))
                
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph("<b>Why This Is Dangerous:</b>", custom_styles['heading3']))
                story.append(Paragraph(finding.get('impact', self._get_default_impact(finding.get('category', 'unknown'))), custom_styles['normal']))
                
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph("<b>Suggested Fix:</b>", custom_styles['heading3']))
                story.append(Paragraph(finding.get('suggested_fix', 'Manual review and correction recommended.'), custom_styles['normal']))
                
                story.append(Spacer(1, 0.1*inch))
                story.append(PageBreak())
        
        # Overall Security Score
        story.append(Paragraph("4. Overall Security Score", custom_styles['heading2']))
        story.append(Paragraph(f"<b>Score:</b> {security_score} / 100", custom_styles['normal']))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(f"<b>Assessment:</b> {self._get_overall_feedback(security_score, self.summary.get('remaining_issues', 0))}", custom_styles['normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Next Steps
        story.append(Paragraph("5. Next Steps", custom_styles['heading2']))
        next_steps = self._generate_next_steps(self.summary.get('remaining_issues', 0), critical_count, high_count)
        for i, step in enumerate(next_steps, 1):
            story.append(Paragraph(f"{i}. {step}", custom_styles['normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Appendix
        story.append(Paragraph("6. Appendix", custom_styles['heading2']))
        story.append(Paragraph(f"<b>Project Path:</b> {self.project_path}", custom_styles['normal']))
        story.append(Paragraph(f"<b>Scan Timestamp:</b> {self.timestamp}", custom_styles['normal']))
        story.append(Paragraph(f"<b>Scanner Version:</b> SecureMCP v1.0", custom_styles['normal']))
        story.append(Paragraph(f"<b>LLM Engine:</b> Google Gemini 1.5 Flash", custom_styles['normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def generate_html(self) -> str:
        markdown_content = self.generate_markdown()
        html_body = markdown2.markdown(markdown_content, extras=['fenced-code-blocks', 'tables'])
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMCP Security Report - {os.path.basename(self.project_path)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.7;
            color: #1a1a1a;
            max-width: 1000px;
            margin: 0 auto;
            padding: 30px 20px;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }}
        .container {{
            background-color: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }}
        h1 {{ 
            color: #2c3e50; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 15px;
            font-size: 2.2em;
            margin-top: 0;
        }}
        h2 {{ 
            color: #2c3e50; 
            margin-top: 40px; 
            border-bottom: 2px solid #ecf0f1; 
            padding-bottom: 10px;
            font-size: 1.8em;
        }}
        h3 {{ 
            color: #34495e; 
            margin-top: 25px;
            font-size: 1.4em;
        }}
        h4 {{
            color: #546e7a;
            margin-top: 20px;
            font-size: 1.1em;
        }}
        code {{ 
            background-color: #f8f9fa; 
            padding: 3px 8px; 
            border-radius: 4px; 
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            color: #d63384;
        }}
        pre {{ 
            background-color: #282c34; 
            color: #abb2bf;
            padding: 20px; 
            border-radius: 8px; 
            overflow-x: auto; 
            border: 1px solid #3e4451;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
        }}
        pre code {{
            background-color: transparent;
            color: #abb2bf;
            padding: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}
        th {{
            background-color: #3498db;
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #f39c12; font-weight: bold; }}
        .severity-medium {{ color: #f1c40f; font-weight: bold; }}
        .severity-low {{ color: #2ecc71; font-weight: bold; }}
        strong {{ color: #2c3e50; font-weight: 600; }}
        hr {{ 
            border: none; 
            border-top: 2px solid #ecf0f1; 
            margin: 40px 0; 
        }}
        blockquote {{
            border-left: 4px solid #3498db;
            padding-left: 20px;
            margin-left: 0;
            color: #546e7a;
            font-style: italic;
        }}
        ul, ol {{
            padding-left: 25px;
        }}
        li {{
            margin: 8px 0;
        }}
        .score-badge {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 1.2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .score-excellent {{ background-color: #d4edda; color: #155724; }}
        .score-good {{ background-color: #d1ecf1; color: #0c5460; }}
        .score-fair {{ background-color: #fff3cd; color: #856404; }}
        .score-poor {{ background-color: #f8d7da; color: #721c24; }}
        .finding-block {{
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 6px;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        {html_body}
    </div>
</body>
</html>"""
        
        return html_template
