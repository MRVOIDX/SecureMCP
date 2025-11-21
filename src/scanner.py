import os
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any

class SecurityScanner:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.findings = []
        
        self.security_patterns = {
            'hardcoded_secrets': [
                (r'(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']+)["\']', 'CRITICAL', 'Hardcoded API Key'),
                (r'(password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']', 'CRITICAL', 'Hardcoded Password'),
                (r'(secret[_-]?key|secret)\s*[:=]\s*["\']([^"\']+)["\']', 'CRITICAL', 'Hardcoded Secret Key'),
                (r'(access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([^"\']+)["\']', 'CRITICAL', 'Hardcoded Access Token'),
                (r'(private[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']', 'CRITICAL', 'Hardcoded Private Key'),
                (r'(aws[_-]?secret|aws[_-]?access[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']', 'CRITICAL', 'Hardcoded AWS Credentials'),
                (r'(database[_-]?url|db[_-]?url|connection[_-]?string)\s*[:=]\s*["\'][^"\']*://[^"\']+["\']', 'CRITICAL', 'Hardcoded Database Connection String'),
                (r'(bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)', 'CRITICAL', 'Hardcoded JWT Token'),
            ],
            'insecure_http': [
                (r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)', 'HIGH', 'Insecure HTTP Protocol (Use HTTPS)'),
                (r'(url|endpoint|api[_-]?url)\s*[:=]\s*["\']http://[^"\']+["\']', 'HIGH', 'HTTP URL in Configuration'),
                (r'fetch\s*\(\s*["\']http://[^"\']+["\']', 'HIGH', 'HTTP Request in Code'),
                (r'requests\.(get|post|put|delete)\s*\(\s*["\']http://[^"\']+["\']', 'HIGH', 'HTTP Request in Python'),
            ],
            'sql_injection': [
                (r'execute\s*\(\s*["\'].*%s.*["\'].*%', 'CRITICAL', 'Potential SQL Injection (String Formatting)'),
                (r'execute\s*\(\s*f["\'].*\{.*\}.*["\']', 'CRITICAL', 'Potential SQL Injection (F-string)'),
                (r'execute\s*\(\s*["\'].*\+.*\+.*["\']', 'CRITICAL', 'Potential SQL Injection (String Concatenation)'),
                (r'query\s*\(\s*["\'].*\+.*["\']', 'CRITICAL', 'Potential SQL Injection in Query'),
                (r'(SELECT|INSERT|UPDATE|DELETE).*\+.*\+', 'HIGH', 'SQL Query with String Concatenation'),
                (r'raw\s*\(\s*f["\']', 'HIGH', 'Raw SQL with F-string'),
                (r'\.query\s*\(\s*[\'"].*\$\{', 'CRITICAL', 'SQL Injection via Template Literal'),
            ],
            'xss_vulnerabilities': [
                (r'innerHTML\s*=\s*[^"\';\n]*(?<!\.textContent)', 'HIGH', 'Cross-Site Scripting (XSS) via innerHTML'),
                (r'outerHTML\s*=', 'HIGH', 'Cross-Site Scripting (XSS) via outerHTML'),
                (r'document\.write\s*\(', 'HIGH', 'Cross-Site Scripting (XSS) via document.write'),
                (r'eval\s*\(', 'CRITICAL', 'Code Injection via eval()'),
                (r'dangerouslySetInnerHTML', 'HIGH', 'Potential XSS via dangerouslySetInnerHTML'),
                (r'v-html\s*=', 'HIGH', 'Potential XSS via Vue v-html'),
                (r'\$\(.*\)\.html\(', 'HIGH', 'Potential XSS via jQuery html()'),
            ],
            'sensitive_data_storage': [
                (r'localStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|password|secret|key|auth)[^"\']*["\']', 'HIGH', 'Sensitive Data in localStorage'),
                (r'sessionStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|password|secret|key)[^"\']*["\']', 'MEDIUM', 'Sensitive Data in sessionStorage'),
                (r'localStorage\[["\'][^"\']*(?:token|password|secret|key)[^"\']*["\']\]', 'HIGH', 'Sensitive Data Stored in localStorage'),
                (r'document\.cookie\s*=\s*["\'][^"\']*(?:token|password|auth)[^"\']*["\']', 'HIGH', 'Sensitive Data in Cookie without Secure Flag'),
            ],
            'insecure_configs': [
                (r'debug\s*[:=]\s*[Tt]rue', 'HIGH', 'Debug Mode Enabled in Production'),
                (r'DEBUG\s*=\s*True', 'HIGH', 'Django Debug Mode Enabled'),
                (r'ssl[_-]?verify\s*[:=]\s*[Ff]alse', 'CRITICAL', 'SSL Verification Disabled'),
                (r'allow[_-]?origins\s*[:=]\s*["\']?\*["\']?', 'HIGH', 'CORS Allows All Origins'),
                (r'session[_-]?cookie[_-]?secure\s*[:=]\s*[Ff]alse', 'HIGH', 'Insecure Session Cookie'),
                (r'SECURE_SSL_REDIRECT\s*=\s*False', 'HIGH', 'SSL Redirect Disabled'),
                (r'X_FRAME_OPTIONS\s*=\s*["\']ALLOW', 'MEDIUM', 'Clickjacking Protection Disabled'),
                (r'verify\s*[:=]\s*False', 'HIGH', 'Certificate Verification Disabled'),
            ],
            'weak_permissions': [
                (r'chmod\s+777', 'CRITICAL', 'Overly Permissive File Permissions (777)'),
                (r'os\.chmod\([^,]+,\s*0o777\)', 'CRITICAL', 'Overly Permissive File Permissions (777)'),
                (r'chmod\s+[4-7][4-7]7', 'HIGH', 'Overly Permissive File Permissions (World Writable)'),
                (r'umask\s*\(\s*0+\s*\)', 'HIGH', 'Insecure umask (0000)'),
            ],
            'missing_security_headers': [
                (r'(?<!X-Frame-Options)(?<!X-Content-Type-Options)(?<!Strict-Transport-Security)@app\.route', 'LOW', 'Missing Security Headers in Route'),
                (r'app\.config\[["\']SECRET_KEY["\']\]\s*=\s*["\'][^"\']{1,16}["\']', 'HIGH', 'Weak Flask Secret Key'),
            ],
            'weak_authentication': [
                (r'auth\s*=\s*None', 'HIGH', 'Authentication Disabled'),
                (r'authenticate\s*=\s*False', 'HIGH', 'Authentication Bypass'),
                (r'skip[_-]?auth\s*[:=]\s*[Tt]rue', 'HIGH', 'Authentication Skipped'),
                (r'(?:password|passwd)\s*==\s*["\'][^"\']+["\']', 'CRITICAL', 'Hardcoded Password Comparison'),
                (r'basicAuth\s*\(\s*["\'][^"\']+["\'],\s*["\'][^"\']+["\']\s*\)', 'CRITICAL', 'Hardcoded Basic Auth Credentials'),
            ],
            'file_upload_vulnerabilities': [
                (r'\.save\s*\(\s*(?!.*(?:secure_filename|sanitize))', 'HIGH', 'Unrestricted File Upload'),
                (r'request\.files\[.*\]\.filename', 'MEDIUM', 'Unsanitized Filename Usage'),
                (r'UPLOAD_FOLDER.*(?!.*allowed_extensions)', 'MEDIUM', 'File Upload without Extension Validation'),
            ],
            'path_traversal': [
                (r'open\s*\(\s*.*\+.*\)', 'HIGH', 'Potential Path Traversal in File Open'),
                (r'os\.path\.join\s*\(\s*[^,]+,\s*(?!.*secure_filename)', 'MEDIUM', 'Path Traversal Risk in os.path.join'),
                (r'readFile\s*\(\s*.*\+', 'HIGH', 'Path Traversal in File Read'),
                (r'\.\./', 'MEDIUM', 'Directory Traversal Pattern Detected'),
                (r'sendFile\s*\(.*request\.(query|params|body)', 'CRITICAL', 'Path Traversal in sendFile'),
            ],
            'command_injection': [
                (r'os\.system\s*\(.*\+', 'CRITICAL', 'Command Injection via os.system'),
                (r'subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True', 'CRITICAL', 'Command Injection via subprocess with shell=True'),
                (r'exec\s*\(', 'CRITICAL', 'Code Injection via exec()'),
                (r'eval\s*\(.*request', 'CRITICAL', 'Code Injection - eval with User Input'),
                (r'child_process\.(exec|spawn)\s*\(', 'HIGH', 'Potential Command Injection in Node.js'),
            ],
            'missing_input_validation': [
                (r'request\.(args|form|json)\[.*\](?!.*(?:validate|sanitize|escape))', 'MEDIUM', 'Missing Input Validation'),
                (r'request\.GET\[.*\](?!.*clean)', 'MEDIUM', 'Unvalidated GET Parameter'),
                (r'request\.POST\[.*\](?!.*clean)', 'MEDIUM', 'Unvalidated POST Parameter'),
                (r'req\.(query|body|params)\.[a-zA-Z_]+(?!.*(?:validate|sanitize))', 'MEDIUM', 'Unvalidated User Input'),
            ],
            'weak_password_storage': [
                (r'hashlib\.(md5|sha1)\s*\(.*password', 'CRITICAL', 'Weak Password Hashing Algorithm (MD5/SHA1)'),
                (r'password\s*=\s*hashlib\.(md5|sha1)', 'CRITICAL', 'Insecure Password Storage'),
                (r'md5\s*\(.*password', 'CRITICAL', 'MD5 Used for Password Hashing'),
                (r'sha1\s*\(.*password', 'CRITICAL', 'SHA1 Used for Password Hashing'),
                (r'password.*encode\(\)(?!.*(?:bcrypt|scrypt|argon2|pbkdf2))', 'HIGH', 'Password Stored Without Proper Hashing'),
            ],
            'no_rate_limiting': [
                (r'@app\.route.*(?!.*limiter|rate_limit)', 'LOW', 'API Endpoint Without Rate Limiting'),
                (r'@router\.(get|post|put|delete).*(?!.*throttle|rate)', 'LOW', 'No Rate Limiting on Endpoint'),
            ],
            'insecure_api_endpoints': [
                (r'@app\.route\(["\']\/api\/.*["\'].*methods\s*=\s*\[[^\]]*["\']DELETE["\']', 'MEDIUM', 'DELETE Endpoint May Need Protection'),
                (r'csrf[_-]?exempt', 'HIGH', 'CSRF Protection Disabled'),
                (r'@csrf_exempt', 'HIGH', 'CSRF Exempt Decorator'),
                (r'cors\(.*origins?\s*=\s*\*', 'HIGH', 'CORS Allows All Origins on API'),
            ],
            'exposed_config_files': [
                (r'\.env(?!\.example)', 'HIGH', 'Environment File Exposed'),
                (r'config\.(json|yml|yaml|xml)(?!\.example)', 'MEDIUM', 'Configuration File May Be Exposed'),
                (r'\.git/config', 'HIGH', 'Git Config Exposed'),
                (r'\.aws/credentials', 'CRITICAL', 'AWS Credentials File Exposed'),
            ],
        }
        
        self.sensitive_extensions = ['.env', '.config', '.yml', '.yaml', '.json', '.xml', '.properties', '.ini', '.conf', '.cfg', '.toml']
        self.code_extensions = ['.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c', '.h', '.html', '.htm', '.vue', '.svelte']
    
    def scan(self) -> Dict[str, Any]:
        if not self.project_path.exists():
            return {'error': 'Project path does not exist', 'findings': []}
        
        self.findings = []
        self._scan_directory(self.project_path)
        
        return {
            'project_path': str(self.project_path),
            'total_files_scanned': len(self._get_all_files()),
            'findings': self.findings,
            'summary': self._generate_summary()
        }
    
    def _scan_directory(self, directory: Path):
        for item in directory.rglob('*'):
            if item.is_file() and not self._should_ignore(item):
                self._scan_file(item)
    
    def _scan_file(self, file_path: Path):
        if file_path.suffix in self.code_extensions or file_path.suffix in self.sensitive_extensions:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    self._check_patterns(file_path, content)
                    
                    if file_path.name == '.env' or file_path.name.startswith('.env.'):
                        self._check_env_file(file_path, content)
                    elif file_path.suffix in ['.yml', '.yaml']:
                        self._check_yaml_file(file_path, content)
                    
                    self._check_exposed_configs(file_path)
            except Exception as e:
                pass
    
    def _check_exposed_configs(self, file_path: Path):
        exposed_files = {
            '.env': ('CRITICAL', 'Environment file should not be committed'),
            '.aws/credentials': ('CRITICAL', 'AWS credentials file exposed'),
            '.aws/config': ('HIGH', 'AWS configuration file exposed'),
            '.npmrc': ('HIGH', 'NPM configuration with potential tokens'),
            '.pypirc': ('HIGH', 'PyPI configuration with potential credentials'),
            'id_rsa': ('CRITICAL', 'SSH private key exposed'),
            'id_dsa': ('CRITICAL', 'SSH private key exposed'),
            '.pgpass': ('CRITICAL', 'PostgreSQL password file exposed'),
            'shadow': ('CRITICAL', 'Shadow password file exposed'),
            'passwd': ('HIGH', 'Password file exposed'),
        }
        
        file_name = file_path.name
        for sensitive_name, (severity, description) in exposed_files.items():
            if sensitive_name in str(file_path) and not file_path.name.endswith('.example'):
                self.findings.append({
                    'file': str(file_path.relative_to(self.project_path)),
                    'line': 0,
                    'severity': severity,
                    'category': 'exposed_config_files',
                    'description': description,
                    'snippet': f"Sensitive file: {file_path.name}",
                    'matched_text': file_name
                })
    
    def _check_patterns(self, file_path: Path, content: str):
        for category, patterns in self.security_patterns.items():
            for pattern, severity, description in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    self.findings.append({
                        'file': str(file_path.relative_to(self.project_path)),
                        'line': line_number,
                        'severity': severity,
                        'category': category,
                        'description': description,
                        'snippet': self._get_code_snippet(content, match.start()),
                        'matched_text': match.group(0)
                    })
    
    def _check_env_file(self, file_path: Path, content: str):
        if not file_path.name.startswith('.env.example'):
            self.findings.append({
                'file': str(file_path.relative_to(self.project_path)),
                'line': 1,
                'severity': 'HIGH',
                'category': 'sensitive_files',
                'description': 'Environment File May Contain Secrets',
                'snippet': f"File: {file_path.name}",
                'matched_text': '.env file detected'
            })
    
    def _check_yaml_file(self, file_path: Path, content: str):
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                self._check_yaml_structure(file_path, data)
        except:
            pass
    
    def _check_yaml_structure(self, file_path: Path, data: dict, path=''):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            if isinstance(value, dict):
                self._check_yaml_structure(file_path, value, current_path)
            elif isinstance(value, str):
                if any(term in key.lower() for term in ['password', 'secret', 'key', 'token']):
                    if value and not value.startswith('${'):
                        self.findings.append({
                            'file': str(file_path.relative_to(self.project_path)),
                            'line': 0,
                            'severity': 'MEDIUM',
                            'category': 'insecure_configs',
                            'description': f'Potential Secret in Config: {current_path}',
                            'snippet': f"{current_path}: {value[:20]}...",
                            'matched_text': f"{key}: {value}"
                        })
    
    def _get_code_snippet(self, content: str, position: int, context_lines: int = 2) -> str:
        lines = content.split('\n')
        line_num = content[:position].count('\n')
        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines + 1)
        return '\n'.join(lines[start:end])
    
    def _should_ignore(self, path: Path) -> bool:
        ignore_patterns = [
            'node_modules', '__pycache__', '.git', 'venv', 'env',
            '.venv', 'dist', 'build', '.pytest_cache', 'coverage'
        ]
        return any(pattern in str(path) for pattern in ignore_patterns)
    
    def _get_all_files(self) -> List[Path]:
        return [f for f in self.project_path.rglob('*') if f.is_file() and not self._should_ignore(f)]
    
    def _generate_summary(self) -> Dict[str, Any]:
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        category_counts = {}
        
        for finding in self.findings:
            severity = finding.get('severity', 'MEDIUM')
            category = finding.get('category', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'by_severity': severity_counts,
            'by_category': category_counts
        }
