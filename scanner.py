import os
import re
import json
from datetime import datetime
from typing import List, Dict, Any

print("--- Scanner Initializing ---")

class ProjectScanner:
    """
    Backend module to scan student project directories for security risks.
    """

    # CRITICAL: Make sure this line has TWO underscores on each side!
    # def _init_(self):
    def __init__(self):
        # 1. Directories to ignore
        self.IGNORE_DIRS = {
            '.git', 'node_modules', '_pycache_', 'venv', 'env', 
            '.idea', '.vscode', 'dist', 'build'
        }
        # 2. Extensions to ignore
        self.IGNORE_EXTENSIONS = {
            '.png', '.jpg', '.jpeg', '.gif', '.pdf', 
            '.exe', '.bin', '.pyc', '.zip', '.tar'
        }
        
        # 3. Risk Patterns (Heuristics)
        self.RISK_PATTERNS = [
            {
                "id": "AWS_KEY_DETECTED",
                "pattern": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", 
                "description": "Possible AWS Access Key ID found.",
                "severity": "HIGH"
            },
            {
                "id": "GENERIC_SECRET",
                "pattern": r"(?i)(api_key|secret|password|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{8,}['\"]",
                "description": "Hardcoded secret detected.",
                "severity": "HIGH"
            },
            {
                "id": "PRIVATE_KEY",
                "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                "description": "Private Key file content detected.",
                "severity": "CRITICAL"
            },
            {
                "id": "DANGEROUS_FUNCTION",
                "pattern": r"eval\(|exec\(",
                "description": "Use of 'eval()' or 'exec()' detected.",
                "severity": "MEDIUM"
            },
            {
                "id": "HARDCODED_IP",
                "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                "description": "Hardcoded IP address found.",
                "severity": "LOW"
            }
        ]

        # 4. Files that provide context
        self.RELEVANT_FILES = {
            'Dockerfile', 'docker-compose.yml', '.env', 'package.json', 
            'requirements.txt', 'pom.xml', 'settings.py', 'config.js', 
            'manifest.json', 'manifest.xml'
        }

    def _is_ignored(self, file_path: str) -> bool:
        parts = file_path.split(os.sep)
        if any(part in self.IGNORE_DIRS for part in parts):
            return True
        _, ext = os.path.splitext(file_path)
        return ext.lower() in self.IGNORE_EXTENSIONS

    def _scan_file_content(self, content: str, file_path: str) -> List[Dict]:
        findings = []
        for risk in self.RISK_PATTERNS:
            matches = re.finditer(risk['pattern'], content)
            for match in matches:
                line_num = content.count('\n', 0, match.start()) + 1
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                snippet = content[start:end].strip()

                findings.append({
                    "type": "security_risk",
                    "risk_id": risk['id'],
                    "description": risk['description'],
                    "severity": risk['severity'],
                    "file": file_path,
                    "line": line_num,
                    "snippet": snippet
                })
        return findings

    def scan_project(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {"error": f"Path '{path}' does not exist."}

        scan_output = {
            "project_path": path,
            "scan_time": datetime.now().isoformat(),
            "summary": {"files_scanned": 0, "issues_found": 0},
            "findings": [],
            "project_context": []
        }

        for root, dirs, files in os.walk(path):
            # Modify dirs in-place to skip ignored folders
            # If this fails, _init_ likely didn't run.
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]

            for file in files:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, path)

                if self._is_ignored(full_path):
                    continue

                scan_output["summary"]["files_scanned"] += 1

                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    risks = self._scan_file_content(content, relative_path)
                    if risks:
                        scan_output["findings"].extend(risks)
                        scan_output["summary"]["issues_found"] += len(risks)

                    if file in self.RELEVANT_FILES or relative_path.endswith(('.conf', '.ini')):
                        scan_output["project_context"].append({
                            "file": relative_path,
                            "type": "configuration",
                            "content_preview": content[:2000]
                        })

                except Exception:
                    pass

        return scan_output

# --- EXECUTION BLOCK ---
if __name__ == "__main__":
    try:
        # 1. Initialize Scanner
        scanner = ProjectScanner()
        
        # 2. Run Scan on Current Directory
        print(f"Scanning current directory: {os.getcwd()} ...")
        results = scanner.scan_project(".")
        
        # 3. Print Results
        print(json.dumps(results, indent=4))
        
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")