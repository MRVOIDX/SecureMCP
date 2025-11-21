from pathlib import Path
from typing import Dict, List, Any
from src.scanner import SecurityScanner
from src.llm_engine import LLMReasoningEngine
import json
import os

class SecurityController:
    def __init__(self):
        self.scanner = None
        self.llm_engine = None
        self.scan_results = None
        self.enriched_findings = []
        self.applied_fixes = []
        
    def initialize_scan(self, project_path: str) -> Dict[str, Any]:
        try:
            self.scanner = SecurityScanner(project_path)
            self.scan_results = self.scanner.scan()
            
            if 'error' in self.scan_results:
                return {
                    'success': False,
                    'error': self.scan_results['error']
                }
            
            try:
                self.llm_engine = LLMReasoningEngine()
                self.enriched_findings = self.llm_engine.analyze_findings(self.scan_results['findings'])
            except ValueError as e:
                self.enriched_findings = []
                for finding in self.scan_results['findings']:
                    self.enriched_findings.append({
                        **finding,
                        'explanation': f"Security issue: {finding['description']}",
                        'risk_level': finding['severity'],
                        'suggested_fix': 'Manual review recommended',
                        'auto_fixable': False
                    })
            
            return {
                'success': True,
                'project_path': self.scan_results['project_path'],
                'total_files_scanned': self.scan_results['total_files_scanned'],
                'findings': self.enriched_findings,
                'summary': self.scan_results['summary']
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def apply_fix(self, finding_index: int) -> Dict[str, Any]:
        if finding_index >= len(self.enriched_findings):
            return {
                'success': False,
                'error': 'Invalid finding index'
            }
        
        finding = self.enriched_findings[finding_index]
        
        if not finding.get('auto_fixable', False):
            return {
                'success': False,
                'error': 'This finding cannot be auto-fixed'
            }
        
        try:
            if not self.scan_results:
                return {
                    'success': False,
                    'error': 'No scan results available'
                }
            
            file_path = Path(self.scan_results['project_path']) / finding['file']
            
            if not file_path.exists():
                return {
                    'success': False,
                    'error': 'File not found'
                }
            
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if finding['line'] > 0 and finding['line'] <= len(lines):
                original_line = lines[finding['line'] - 1]
                replacement = finding.get('replacement_code', '')
                
                if replacement:
                    lines[finding['line'] - 1] = replacement + '\n'
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    
                    self.applied_fixes.append({
                        'finding': finding,
                        'original_code': original_line,
                        'replacement_code': replacement,
                        'status': 'applied'
                    })
                    
                    return {
                        'success': True,
                        'message': 'Fix applied successfully',
                        'file': finding['file'],
                        'line': finding['line']
                    }
            
            return {
                'success': False,
                'error': 'Unable to apply fix'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def skip_fix(self, finding_index: int) -> Dict[str, Any]:
        if finding_index >= len(self.enriched_findings):
            return {
                'success': False,
                'error': 'Invalid finding index'
            }
        
        finding = self.enriched_findings[finding_index]
        
        self.applied_fixes.append({
            'finding': finding,
            'status': 'skipped'
        })
        
        return {
            'success': True,
            'message': 'Fix skipped'
        }
    
    def get_findings(self) -> List[Dict[str, Any]]:
        return self.enriched_findings
    
    def get_applied_fixes(self) -> List[Dict[str, Any]]:
        return self.applied_fixes
    
    def get_summary(self) -> Dict[str, Any]:
        if not self.scan_results:
            return {}
        
        return {
            'total_findings': len(self.enriched_findings),
            'applied_fixes': len([f for f in self.applied_fixes if f['status'] == 'applied']),
            'skipped_fixes': len([f for f in self.applied_fixes if f['status'] == 'skipped']),
            'remaining_issues': len(self.enriched_findings) - len(self.applied_fixes),
            'summary': self.scan_results['summary']
        }
