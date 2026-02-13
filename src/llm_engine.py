import os
from groq import Groq
from typing import Dict, List, Any
import json

class LLMReasoningEngine:
    def __init__(self):
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            raise ValueError("GROQ_API_KEY environment variable is required")
        
        self.client = Groq(api_key=api_key)
        self.model_name = 'llama-3.3-70b-versatile'
    
    def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched_findings = []
        
        for finding in findings:
            try:
                analysis = self._get_llm_analysis(finding)
                enriched_finding = {**finding, **analysis}
                enriched_findings.append(enriched_finding)
            except Exception as e:
                enriched_finding = {
                    **finding,
                    'explanation': f"Security issue detected: {finding['description']}",
                    'risk_level': finding['severity'],
                    'suggested_fix': "Manual review recommended",
                    'auto_fixable': False
                }
                enriched_findings.append(enriched_finding)
        
        return enriched_findings
    
    def _get_llm_analysis(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        prompt = f"""You are a security expert analyzing code vulnerabilities for student projects.

Finding Details:
- File: {finding['file']}
- Line: {finding['line']}
- Severity: {finding['severity']}
- Category: {finding['category']}
- Description: {finding['description']}
- Code Snippet:
{finding['snippet']}

Please provide:
1. A clear, student-friendly explanation (2-3 sentences) of why this is a security risk
2. The risk level (CRITICAL, HIGH, MEDIUM, or LOW)
3. A specific, actionable fix suggestion
4. Whether this can be auto-fixed (true/false)
5. If auto-fixable, provide the exact replacement code

Respond in this exact JSON format:
{{
  "explanation": "your explanation here",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "suggested_fix": "your fix suggestion here",
  "auto_fixable": true or false,
  "replacement_code": "exact code to replace the problematic line (if auto_fixable)"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1024
            )
            content = response.choices[0].message.content or "{}"
            
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                json_str = content[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                analysis = {}
            
            return {
                'explanation': analysis.get('explanation', ''),
                'risk_level': analysis.get('risk_level', finding['severity']),
                'suggested_fix': analysis.get('suggested_fix', ''),
                'auto_fixable': analysis.get('auto_fixable', False),
                'replacement_code': analysis.get('replacement_code', '')
            }
        except Exception as e:
            return {
                'explanation': f"Security issue: {finding['description']}. This could expose sensitive data or create vulnerabilities in your application.",
                'risk_level': finding['severity'],
                'suggested_fix': "Review this code and consider removing hardcoded values, enabling security features, or restricting permissions.",
                'auto_fixable': False,
                'replacement_code': ''
            }
    
    def generate_summary_insights(self, findings: List[Dict[str, Any]], applied_fixes: List[Dict[str, Any]]) -> str:
        if not findings:
            return "Great job! No significant security issues were found in your project."
        
        prompt = f"""You are a security advisor for student developers. 

Scan Results:
- Total findings: {len(findings)}
- Applied fixes: {len(applied_fixes)}
- Remaining issues: {len(findings) - len(applied_fixes)}

Severity breakdown:
{self._get_severity_breakdown(findings)}

Please provide a brief, encouraging summary (3-4 sentences) that:
1. Highlights the overall security posture
2. Praises fixes that were applied
3. Emphasizes the importance of addressing remaining issues
4. Offers next steps

Keep the tone positive and educational, suitable for students learning about security."""

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=512
            )
            content = response.choices[0].message.content
            return content.strip() if content else "Your scan is complete."
        except:
            return "Your scan is complete. Review the findings above and apply the suggested fixes to improve your project's security posture."
    
    def _get_severity_breakdown(self, findings: List[Dict[str, Any]]) -> str:
        severity_counts = {}
        for finding in findings:
            severity = finding.get('risk_level', finding.get('severity', 'MEDIUM'))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return '\n'.join([f"- {severity}: {count}" for severity, count in severity_counts.items()])
    
    def generate_fixed_file(self, file_content: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Use Groq AI to generate a complete fixed version of the file."""
        
        prompt = f"""You are a security expert fixing vulnerabilities in student code projects. Your task is to FIX the security issue and return the corrected code.

=== ORIGINAL FILE CONTENT ===
{file_content}
=== END OF FILE ===

=== SECURITY VULNERABILITY DETAILS ===
- Line Number: {finding.get('line', 'Unknown')}
- Severity: {finding.get('severity', 'MEDIUM')}
- Category: {finding.get('category', 'Unknown')}
- Problem Description: {finding.get('description', 'Security issue')}
- Vulnerable Code Snippet: {finding.get('snippet', '')}

=== YOUR TASK ===
You MUST fix this security vulnerability. Here's what to do based on the category:

1. For HARDCODED SECRETS (api keys, passwords, tokens):
   - Replace hardcoded values with environment variable usage
   - For Python: Use os.getenv('VARIABLE_NAME', '') and add 'import os' if needed
   - For JavaScript: Use process.env.VARIABLE_NAME

2. For SQL INJECTION:
   - Replace string concatenation with parameterized queries
   - Use placeholders (?, %s) instead of f-strings or .format()

3. For XSS (Cross-Site Scripting):
   - Sanitize user input before rendering
   - Use textContent instead of innerHTML when possible

4. For INSECURE HTTP:
   - Change http:// to https://

5. For WEAK PASSWORD HASHING:
   - Replace MD5/SHA1 with bcrypt or argon2

6. For COMMAND INJECTION:
   - Use subprocess with shell=False and list arguments
   - Avoid os.system()

=== OUTPUT REQUIREMENTS ===
Return ONLY the complete fixed file. No markdown formatting, no code blocks (```), no explanations.
The output must be valid code that can be saved directly to a file and will work correctly.
Make sure to preserve all indentation, line breaks, and formatting from the original file."""

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=4096
            )
            fixed_content = response.choices[0].message.content or file_content
            
            fixed_content = fixed_content.strip()
            if fixed_content.startswith('```'):
                lines = fixed_content.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                fixed_content = '\n'.join(lines)
            
            if fixed_content.endswith('```'):
                fixed_content = fixed_content[:-3].rstrip()
            
            if fixed_content == file_content:
                fixed_content = self._apply_basic_fix(file_content, finding)
            
            return {
                'success': True,
                'fixed_content': fixed_content,
                'original_content': file_content,
                'finding': finding
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'original_content': file_content
            }
    
    def _apply_basic_fix(self, file_content: str, finding: Dict[str, Any]) -> str:
        """Apply a basic fix if the AI didn't make changes."""
        import re
        
        category = finding.get('category', '')
        snippet = finding.get('snippet', '')
        line_num = finding.get('line', 0)
        file_path = finding.get('file', '')
        
        is_python = file_path.endswith('.py')
        is_javascript = any(file_path.endswith(ext) for ext in ['.js', '.jsx', '.ts', '.tsx', '.mjs'])
        
        lines = file_content.split('\n')
        
        if category == 'insecure_http' and line_num > 0 and line_num <= len(lines):
            lines[line_num - 1] = lines[line_num - 1].replace('http://', 'https://')
            return '\n'.join(lines)
        
        if category == 'hardcoded_secrets' and line_num > 0 and line_num <= len(lines):
            line = lines[line_num - 1]
            
            if is_python:
                secret_patterns = [
                    (r'["\']([a-zA-Z0-9_-]{20,})["\']', 'os.getenv("SECRET_KEY", "")'),
                    (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'api_key = os.getenv("API_KEY", "")'),
                    (r'password\s*=\s*["\'][^"\']+["\']', 'password = os.getenv("PASSWORD", "")'),
                ]
                for pattern, replacement in secret_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        lines[line_num - 1] = re.sub(pattern, replacement, line, flags=re.IGNORECASE)
                        if 'import os' not in file_content:
                            lines.insert(0, 'import os')
                        return '\n'.join(lines)
            
            elif is_javascript:
                js_patterns = [
                    (r'["\']([a-zA-Z0-9_-]{20,})["\']', 'process.env.SECRET_KEY'),
                    (r'(api[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', r'\1: process.env.API_KEY'),
                    (r'(password)\s*[:=]\s*["\'][^"\']+["\']', r'\1: process.env.PASSWORD'),
                ]
                for pattern, replacement in js_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        lines[line_num - 1] = re.sub(pattern, replacement, line, flags=re.IGNORECASE)
                        return '\n'.join(lines)
        
        return file_content
    
    def generate_fix_explanation(self, finding: Dict[str, Any], original_code: str, fixed_code: str) -> str:
        """Generate a brief explanation of what was fixed."""
        
        prompt = f"""Explain in 1-2 sentences what security fix was applied:

Original code: {original_code}
Fixed code: {fixed_code}
Issue: {finding.get('description', 'Security issue')}

Keep the explanation simple and clear for a student developer."""

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5,
                max_tokens=256
            )
            return response.choices[0].message.content.strip() if response.choices[0].message.content else "Security fix applied."
        except:
            return f"Fixed: {finding.get('description', 'Security issue')}"
