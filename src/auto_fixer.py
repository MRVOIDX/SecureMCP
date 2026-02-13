import re
from typing import Dict, Any, Optional

class AutoFixer:
    def __init__(self):
        self.fix_strategies = {
            'hardcoded_secrets': self._fix_hardcoded_secret,
            'insecure_http': self._fix_insecure_http,
            'sql_injection': self._fix_sql_injection,
            'xss_vulnerabilities': self._fix_xss,
            'sensitive_data_storage': self._fix_sensitive_storage,
            'insecure_configs': self._fix_insecure_config,
            'weak_permissions': self._fix_weak_permissions,
            'weak_authentication': self._fix_weak_auth,
            'command_injection': self._fix_command_injection,
            'weak_password_storage': self._fix_weak_password_storage,
        }
        
        self.python_extensions = ['.py']
        self.js_extensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs']
        self.config_extensions = ['.yml', '.yaml', '.json', '.env', '.ini', '.cfg', '.toml']
        
        self.explanations = {
            'hardcoded_secrets': "Hardcoded secrets in code are dangerous because anyone who sees your code can access those secrets. This could lead to unauthorized access to your systems, data breaches, or financial losses.",
            'insecure_http': "Using HTTP instead of HTTPS means data is sent unencrypted. Attackers on the same network could intercept sensitive information like passwords, tokens, or personal data.",
            'sql_injection': "SQL injection allows attackers to manipulate your database queries. They could steal all your data, delete your database, or gain unauthorized access to your application.",
            'xss_vulnerabilities': "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into your web pages. This can steal user cookies, hijack sessions, or redirect users to malicious sites.",
            'sensitive_data_storage': "Storing sensitive data in browser storage (localStorage/sessionStorage) is risky because any JavaScript on the page can access it, including malicious scripts.",
            'insecure_configs': "Insecure configurations can expose your application to attacks. Debug mode in production reveals sensitive information, disabled SSL verification allows man-in-the-middle attacks.",
            'weak_permissions': "Overly permissive file permissions (like 777) allow any user on the system to read, write, and execute files. This is a major security risk on shared systems.",
            'weak_authentication': "Weak authentication mechanisms make it easy for attackers to bypass security and gain unauthorized access to your application or user accounts.",
            'command_injection': "Command injection allows attackers to execute arbitrary commands on your server. This could lead to complete system compromise, data theft, or service destruction.",
            'weak_password_storage': "Using weak hashing algorithms like MD5 or SHA1 for passwords makes them easy to crack. Attackers with a leaked database can quickly recover user passwords.",
        }
    
    def _get_file_extension(self, finding: Dict[str, Any]) -> str:
        file_path = finding.get('file', '')
        if '.' in file_path:
            return '.' + file_path.split('.')[-1].lower()
        return ''
    
    def _is_python_file(self, finding: Dict[str, Any]) -> bool:
        return self._get_file_extension(finding) in self.python_extensions
    
    def _is_js_file(self, finding: Dict[str, Any]) -> bool:
        return self._get_file_extension(finding) in self.js_extensions
    
    def _is_config_file(self, finding: Dict[str, Any]) -> bool:
        return self._get_file_extension(finding) in self.config_extensions

    def generate_fix(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        category = finding.get('category', '')
        snippet = finding.get('snippet', '')
        matched_text = finding.get('matched_text', '')
        description = finding.get('description', '')
        
        fix_strategy = self.fix_strategies.get(category)
        
        if fix_strategy:
            result = fix_strategy(finding, snippet, matched_text)
            if result:
                return {
                    'explanation': self.explanations.get(category, f"This is a security vulnerability: {description}"),
                    'risk_level': finding.get('severity', 'MEDIUM'),
                    'suggested_fix': result['suggested_fix'],
                    'auto_fixable': result['auto_fixable'],
                    'replacement_code': result.get('replacement_code', '')
                }
        
        return {
            'explanation': self.explanations.get(category, f"Security issue detected: {description}. This could potentially be exploited by attackers."),
            'risk_level': finding.get('severity', 'MEDIUM'),
            'suggested_fix': self._get_generic_fix(category, description),
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_hardcoded_secret(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        is_python = self._is_python_file(finding)
        is_js = self._is_js_file(finding)
        
        env_var_match = re.search(r'(api[_-]?key|apikey|password|passwd|pwd|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|private[_-]?key|aws[_-]?secret|aws[_-]?access[_-]?key|database[_-]?url|db[_-]?url|connection[_-]?string)', matched_text, re.IGNORECASE)
        
        if env_var_match:
            var_name = env_var_match.group(1).upper().replace('-', '_')
        else:
            var_name = 'SECRET_VALUE'
        
        if is_python:
            return {
                'suggested_fix': f'Replace the hardcoded value with an environment variable. Add "import os" at the top of your file, then use: os.getenv("{var_name}", "")',
                'auto_fixable': False,
                'replacement_code': ''
            }
        elif is_js:
            return {
                'suggested_fix': f'Replace the hardcoded value with an environment variable: process.env.{var_name}',
                'auto_fixable': False,
                'replacement_code': ''
            }
        else:
            return {
                'suggested_fix': 'Move this secret to an environment variable. Never commit secrets to version control.',
                'auto_fixable': False,
                'replacement_code': ''
            }
    
    def _fix_insecure_http(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        return {
            'suggested_fix': 'Use HTTPS instead of HTTP for secure communication. Verify that the target server supports TLS/SSL with a valid certificate before changing the URL.',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_sql_injection(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        return {
            'suggested_fix': 'Use parameterized queries instead of string formatting. Example: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_xss(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        is_js = self._is_js_file(finding)
        
        if 'innerHTML' in matched_text or 'innerHTML' in snippet:
            return {
                'suggested_fix': 'If you need to display plain text, use textContent instead of innerHTML. If you need HTML, sanitize it first using a library like DOMPurify: element.innerHTML = DOMPurify.sanitize(userInput)',
                'auto_fixable': False,
                'replacement_code': ''
            }
        
        if 'eval(' in matched_text or 'eval(' in snippet:
            return {
                'suggested_fix': 'Remove eval() and use JSON.parse() for parsing JSON data, or restructure code to avoid dynamic execution',
                'auto_fixable': False,
                'replacement_code': ''
            }
        
        if 'document.write' in matched_text or 'document.write' in snippet:
            return {
                'suggested_fix': 'Avoid document.write(). Use DOM methods like createElement() and appendChild() instead',
                'auto_fixable': False,
                'replacement_code': ''
            }
        
        return {
            'suggested_fix': 'Sanitize all user input before rendering in the DOM. Use textContent for plain text, or a sanitization library like DOMPurify for HTML',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_sensitive_storage(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        return {
            'suggested_fix': 'Do not store sensitive data in localStorage or sessionStorage. Use httpOnly cookies with secure flag, or store tokens in memory only',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_insecure_config(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        lower_snippet = snippet.lower()
        
        if 'debug' in lower_snippet and 'true' in lower_snippet:
            return {
                'suggested_fix': 'Set DEBUG = False for production environments to prevent sensitive information from being exposed in error messages.',
                'auto_fixable': False,
                'replacement_code': ''
            }
        
        if 'verify' in lower_snippet and 'false' in lower_snippet:
            return {
                'suggested_fix': 'Enable SSL/TLS certificate verification (verify=True) to prevent man-in-the-middle attacks. If using a self-signed certificate, configure a custom CA bundle instead of disabling verification.',
                'auto_fixable': False,
                'replacement_code': ''
            }
        
        return {
            'suggested_fix': 'Review and fix insecure configuration settings. Enable security features for production environments.',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_weak_permissions(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        return {
            'suggested_fix': 'Use more restrictive file permissions. Recommended: 755 for directories (owner rwx, others rx), 644 for files (owner rw, others r). Avoid 777 which allows everyone full access.',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_weak_auth(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        return {
            'suggested_fix': 'Implement proper authentication. Never hardcode credentials or disable authentication in production.',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_command_injection(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        is_python = self._is_python_file(finding)
        
        if is_python:
            if 'shell=True' in matched_text or 'shell=True' in snippet:
                return {
                    'suggested_fix': 'Set shell=False and pass command as a list. Example: subprocess.run(["ls", "-la"]) instead of subprocess.run("ls -la", shell=True)',
                    'auto_fixable': False,
                    'replacement_code': ''
                }
            elif 'os.system' in matched_text or 'os.system' in snippet:
                return {
                    'suggested_fix': 'Replace os.system() with subprocess.run() using a list of arguments. Example: subprocess.run(["ls", "-la"]) instead of os.system("ls -la")',
                    'auto_fixable': False,
                    'replacement_code': ''
                }
        
        return {
            'suggested_fix': 'Avoid using shell commands with user input. Use safe APIs or validate/sanitize all inputs before use.',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _fix_weak_password_storage(self, finding: Dict, snippet: str, matched_text: str) -> Optional[Dict]:
        return {
            'suggested_fix': 'Use bcrypt, argon2, or PBKDF2 for password hashing instead of MD5 or SHA1. Example: from bcrypt import hashpw, gensalt; hashed = hashpw(password.encode(), gensalt())',
            'auto_fixable': False,
            'replacement_code': ''
        }
    
    def _get_generic_fix(self, category: str, description: str) -> str:
        generic_fixes = {
            'exposed_config_files': 'Add sensitive files to .gitignore and remove from version control. Use environment variables for secrets.',
            'sensitive_files': 'Add this file to .gitignore and store secrets in environment variables instead.',
            'missing_security_headers': 'Add security headers like X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy.',
            'file_upload_vulnerabilities': 'Validate file types, use secure_filename(), and store uploads outside web root.',
            'path_traversal': 'Validate and sanitize file paths. Use os.path.realpath() to resolve paths and verify they stay within allowed directories.',
            'missing_input_validation': 'Validate and sanitize all user input before processing. Use a validation library.',
            'no_rate_limiting': 'Implement rate limiting to prevent abuse. Use libraries like flask-limiter or express-rate-limit.',
            'insecure_api_endpoints': 'Enable CSRF protection and restrict CORS origins to trusted domains only.',
        }
        
        return generic_fixes.get(category, f'Review and fix this security issue: {description}')
