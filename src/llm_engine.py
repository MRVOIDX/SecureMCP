import os
import google.generativeai as genai
from typing import Dict, List, Any
import json

class LLMReasoningEngine:
    def __init__(self):
        api_key = os.getenv('GOOGLE_AI_API_KEY')
        if not api_key:
            raise ValueError("GOOGLE_AI_API_KEY environment variable is required")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
    
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
            response = self.model.generate_content(prompt)
            content = response.text or "{}"
            
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
            response = self.model.generate_content(prompt)
            content = response.text
            return content.strip() if content else "Your scan is complete."
        except:
            return "Your scan is complete. Review the findings above and apply the suggested fixes to improve your project's security posture."
    
    def _get_severity_breakdown(self, findings: List[Dict[str, Any]]) -> str:
        severity_counts = {}
        for finding in findings:
            severity = finding.get('risk_level', finding.get('severity', 'MEDIUM'))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return '\n'.join([f"- {severity}: {count}" for severity, count in severity_counts.items()])
