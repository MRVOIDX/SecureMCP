from pathlib import Path
from typing import Dict, List, Any
from src.scanner import SecurityScanner
from src.llm_engine import LLMReasoningEngine
from src.auto_fixer import AutoFixer
import json
import os

class SecurityController:
    def __init__(self):
        self.scanner = None
        self.llm_engine = None
        self.auto_fixer = AutoFixer()
        self.scan_results = None
        self.enriched_findings = []
        self.original_findings = []  # Store original findings for reporting
        self.applied_fixes = []
        
    def initialize_scan(self, project_path: str) -> Dict[str, Any]:
        try:
            # Reset applied fixes for new scan
            self.applied_fixes = []
            
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
                    fix_info = self.auto_fixer.generate_fix(finding)
                    self.enriched_findings.append({
                        **finding,
                        **fix_info
                    })
            
            # Store original findings for reporting (deep copy to prevent modifications)
            import copy
            self.original_findings = copy.deepcopy(self.enriched_findings)
            
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
        
        # If not auto-fixable, mark as manually resolved so the card is removed and reporting counts it
        if not finding.get('auto_fixable', False):
            finding['status'] = 'applied'
            self.applied_fixes.append({
                'finding': finding,
                'original_code': finding.get('snippet', ''),
                'replacement_code': finding.get('replacement_code', '') or finding.get('suggested_fix', ''),
                'status': 'applied',
                'index': finding_index,
                'note': 'Marked as resolved (manual)'
            })
            return {
                'success': True,
                'message': 'Marked as resolved (manual)',
                'file': finding.get('file'),
                'line': finding.get('line', 0)
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
            
            original_line = None
            if finding['line'] > 0 and finding['line'] <= len(lines):
                original_line = lines[finding['line'] - 1]
                replacement = finding.get('replacement_code', '')

                if replacement:
                    lines[finding['line'] - 1] = replacement + '\n'

                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines)

            # Mark as applied when the target line exists (even if replacement is empty),
            # so the finding is removed from the list once handled.
            if original_line is not None:
                # Mark finding as applied in-place so remaining list hides it immediately
                finding['status'] = 'applied'
                self.applied_fixes.append({
                    'finding': finding,
                    'original_code': original_line,
                    'replacement_code': finding.get('replacement_code', ''),
                    'status': 'applied',
                    'index': finding_index
                })

                return {
                    'success': True,
                    'message': 'Fix applied successfully',
                    'file': finding['file'],
                    'line': finding['line']
                }

            # If we reach here, we could not apply the fix
            finding['status'] = 'failed'
            self.applied_fixes.append({
                'finding': finding,
                'status': 'failed',
                'index': finding_index
            })

            return {
                'success': False,
                'error': 'Unable to apply fix'
            }
        except Exception as e:
            self.applied_fixes.append({
                'finding': finding,
                'status': 'failed',
                'index': finding_index,
                'error': str(e)
            })
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
        
        finding['status'] = 'skipped'
        self.applied_fixes.append({
            'finding': finding,
            'status': 'skipped',
            'index': finding_index
        })
        
        # Don't remove from enriched_findings - keep consistent with apply_fix
        # This preserves the original findings list for accurate reporting
        
        return {
            'success': True,
            'message': 'Fix skipped'
        }
    
    def get_findings(self) -> List[Dict[str, Any]]:
        return self.enriched_findings
    
    def get_original_findings(self) -> List[Dict[str, Any]]:
        """Get original findings for accurate reporting (before any apply/skip modifications)."""
        return self.original_findings
    
    def get_remaining_findings(self) -> List[Dict[str, Any]]:
        """Get findings that haven't been applied or skipped yet."""
        # Get indices of findings that have been processed (applied or skipped)
        processed_indices = set()
        for fix in self.applied_fixes:
            finding_data = fix.get('finding', {})
            status = fix.get('status')

            # Allow retry for failed applies
            if status == 'failed':
                continue

            # Prefer the stored index if available for an exact match
            if 'index' in fix:
                processed_indices.add(fix['index'])
                continue

            # Fallback to matching by file and normalized line number
            for idx, f in enumerate(self.enriched_findings):
                file_match = f.get('file') == finding_data.get('file')
                try:
                    line_match = int(f.get('line', 0)) == int(finding_data.get('line', 0))
                except Exception:
                    line_match = f.get('line') == finding_data.get('line')
                if file_match and line_match:
                    processed_indices.add(idx)
                    break
        
        # Return findings that haven't been processed
        remaining = []
        for idx, f in enumerate(self.enriched_findings):
            status = (f.get('status') or '').lower()
            if idx in processed_indices or status in ('applied', 'skipped'):
                continue
            item = dict(f)
            item['original_index'] = idx
            remaining.append(item)
        return remaining
    
    def get_applied_fixes(self) -> List[Dict[str, Any]]:
        return self.applied_fixes
    
    def get_fix_preview(self, finding_index: int) -> Dict[str, Any]:
        if finding_index >= len(self.enriched_findings):
            return {
                'success': False,
                'error': 'Invalid finding index'
            }
        
        finding = self.enriched_findings[finding_index]
        
        if not finding.get('auto_fixable', False):
            return {
                'success': False,
                'error': 'This finding cannot be auto-fixed',
                'auto_fixable': False
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
            
            original_code = ''
            replacement_code = finding.get('replacement_code', '')
            context_before = []
            context_after = []
            
            if finding['line'] > 0 and finding['line'] <= len(lines):
                original_code = lines[finding['line'] - 1].rstrip('\n')
                
                start_line = max(0, finding['line'] - 4)
                for i in range(start_line, finding['line'] - 1):
                    context_before.append({
                        'line_num': i + 1,
                        'code': lines[i].rstrip('\n')
                    })
                
                end_line = min(len(lines), finding['line'] + 3)
                for i in range(finding['line'], end_line):
                    context_after.append({
                        'line_num': i + 1,
                        'code': lines[i].rstrip('\n')
                    })
            
            return {
                'success': True,
                'auto_fixable': True,
                'finding': {
                    'description': finding.get('description', 'Unknown Issue'),
                    'file': finding.get('file', 'unknown'),
                    'line': finding.get('line', 0),
                    'severity': finding.get('severity', 'MEDIUM'),
                    'explanation': finding.get('explanation', ''),
                    'suggested_fix': finding.get('suggested_fix', '')
                },
                'original_code': original_code,
                'replacement_code': replacement_code,
                'context_before': context_before,
                'context_after': context_after
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_summary(self) -> Dict[str, Any]:
        if not self.scan_results:
            return {}
        
        applied_count = len([f for f in self.applied_fixes if f.get('status') == 'applied'])
        skipped_count = len([f for f in self.applied_fixes if f.get('status') == 'skipped'])
        failed_count = len([f for f in self.applied_fixes if f.get('status') == 'failed'])

        return {
            'total_findings': len(self.enriched_findings),
            'applied_fixes': applied_count,
            'skipped_fixes': skipped_count,
            'failed_fixes': failed_count,
            'remaining_issues': len(self.enriched_findings) - applied_count - skipped_count,
            'total_files_scanned': self.scan_results.get('total_files_scanned', 0),
            'summary': self.scan_results['summary']
        }
    
    def generate_ai_fix(self, finding_index: int) -> Dict[str, Any]:
        """Generate a fixed version of the file using Groq AI."""
        
        if finding_index >= len(self.enriched_findings):
            return {
                'success': False,
                'error': 'Invalid finding index'
            }
        
        finding = self.enriched_findings[finding_index]
        
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
                file_content = f.read()
            
            if not self.llm_engine:
                try:
                    self.llm_engine = LLMReasoningEngine()
                except ValueError as e:
                    return {
                        'success': False,
                        'error': 'Groq AI API key not configured. Please set GROQ_API_KEY environment variable.'
                    }
            
            result = self.llm_engine.generate_fixed_file(file_content, finding)
            
            if result.get('success'):
                explanation = self.llm_engine.generate_fix_explanation(
                    finding,
                    finding.get('snippet', ''),
                    result.get('fixed_content', '')[:500]
                )
                
                return {
                    'success': True,
                    'fixed_content': result.get('fixed_content', ''),
                    'original_content': file_content,
                    'filename': os.path.basename(finding['file']),
                    'file_path': finding['file'],
                    'finding': {
                        'description': finding.get('description', 'Unknown Issue'),
                        'file': finding.get('file', 'unknown'),
                        'line': finding.get('line', 0),
                        'severity': finding.get('severity', 'MEDIUM'),
                        'explanation': finding.get('explanation', ''),
                        'suggested_fix': finding.get('suggested_fix', '')
                    },
                    'fix_explanation': explanation
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Failed to generate fix')
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
