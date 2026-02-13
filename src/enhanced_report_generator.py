"""
Enhanced Report Generator for SecureMCP
========================================
Generates comprehensive security reports with visualizations, summaries, and recommendations.

Features:
- Project summary and overview
- Detailed findings with severity levels
- Applied fixes tracking
- Security recommendations
- Chart visualizations (severity breakdown, vulnerability types, fixes status)
- PDF and HTML export formats
- Robust error handling for edge cases
- Clean, maintainable, PEP8-compliant code
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import os
import json
from pathlib import Path
from io import BytesIO
import base64

# PDF generation
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
)

# Data visualization
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.figure import Figure
import numpy as np

# HTML templating
from jinja2 import Template


class EnhancedReportGenerator:
    """
    Professional report generator for security scans with visualizations and exports.
    
    Supports PDF and HTML formats with comprehensive sections:
    - Project Summary
    - Security Findings
    - Applied Fixes
    - Recommendations
    - Visualizations (charts and graphs)
    """
    
    # Severity color mapping for consistent styling
    SEVERITY_COLORS = {
        'CRITICAL': '#dc2626',  # Red
        'HIGH': '#ea580c',      # Orange
        'MEDIUM': '#f59e0b',    # Amber
        'LOW': '#10b981',       # Green
        'INFO': '#3b82f6'       # Blue
    }
    
    # Matplotlib color mapping
    MPLOT_COLORS = {
        'CRITICAL': '#dc2626',
        'HIGH': '#ea580c',
        'MEDIUM': '#f59e0b',
        'LOW': '#10b981',
        'INFO': '#3b82f6'
    }
    
    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ''
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))

    @staticmethod
    def _image_from_base64(image_b64: str, max_width: float = 6*inch) -> Optional[Image]:
        """Convert base64 PNG to ReportLab Image flowable with max width constraint."""
        if not image_b64:
            return None
        try:
            img_bytes = base64.b64decode(image_b64)
            img_buffer = BytesIO(img_bytes)
            img = Image(img_buffer)
            # Constrain width, preserve aspect ratio
            if img.drawWidth > max_width:
                ratio = max_width / float(img.drawWidth)
                img.drawWidth = max_width
                img.drawHeight = img.drawHeight * ratio
            img.hAlign = 'CENTER'
            return img
        except Exception:
            return None
    
    def __init__(
        self,
        project_path: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        applied_fixes: Optional[List[Dict[str, Any]]] = None,
        summary: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the report generator with scan data.
        
        Args:
            project_path: Path to the scanned project
            findings: List of security findings detected
            applied_fixes: List of applied fixes
            summary: Summary statistics from the scan
        """
        # Validate and set project path
        self.project_path = project_path or "Unknown Project"
        self.project_name = Path(self.project_path).name or "SecureMCP Scan"
        
        # Initialize findings and fixes with error handling
        self.findings = findings or []
        self.applied_fixes = applied_fixes or []
        self.summary = summary or {}
        
        # Generate timestamps
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_date_formatted = datetime.now().strftime("%B %d, %Y at %I:%M %p")
        
        # Normalize data
        self._normalize_findings()
        self._normalize_applied_fixes()
    
    def _normalize_findings(self) -> None:
        """
        Normalize findings data and ensure all required fields are present.
        Handles missing or malformed data gracefully.
        """
        for idx, finding in enumerate(self.findings):
            # Ensure severity/risk_level exists
            severity = (finding.get('risk_level') or 
                       finding.get('severity') or 
                       'MEDIUM').upper()
            finding['severity'] = severity
            finding['risk_level'] = severity
            
            # Set defaults for missing fields
            finding.setdefault('file', 'unknown')
            finding.setdefault('line', 0)
            finding.setdefault('category', 'unknown')
            finding.setdefault('description', 'Unknown Issue')
            finding.setdefault('explanation', 'No detailed explanation available.')
            finding.setdefault('suggested_fix', 'No suggested fix provided.')
            finding.setdefault('snippet', '')
            
            # Generate unique ID if missing
            if 'id' not in finding:
                base = (f"{finding.get('file', 'unknown')}|"
                       f"{finding.get('line', '')}|"
                       f"{finding.get('description', '')}")
                finding['id'] = f"finding-{idx}-{abs(hash(base))}"
    
    def _normalize_applied_fixes(self) -> None:
        """
        Normalize applied fixes data.
        Ensures consistent structure for all fix records.
        """
        for fix in self.applied_fixes:
            fix.setdefault('status', 'pending').lower()
            fix.setdefault('finding', {})
            fix.setdefault('original_code', '')
            fix.setdefault('replacement_code', '')
    
    def generate_statistics(self) -> Dict[str, Any]:
        """
        Calculate comprehensive statistics from findings and fixes.
        
        Returns:
            Dictionary with statistics including counts and percentages
        """
        # Determine remaining findings (exclude applied/skipped; keep failed)
        remaining_findings: List[Dict[str, Any]] = []
        processed = []
        for fix in self.applied_fixes:
            status = fix.get('status', '').lower()
            if status in ('applied', 'skipped'):
                finding_data = fix.get('finding', {})
                processed.append((finding_data.get('file'), finding_data.get('line')))

        for f in self.findings:
            key = (f.get('file'), f.get('line'))
            if key in processed:
                continue
            remaining_findings.append(f)

        # Initialize statistics dictionary based on remaining findings for risk
        stats = {
            'total_findings': len(remaining_findings),
            'total_files_scanned': self.summary.get('total_files_scanned', 0),
            'severity_breakdown': {},
            'category_breakdown': {},
            'applied_count': 0,
            'skipped_count': 0,
            'failed_count': 0,
            'remaining_count': len(remaining_findings),
        }

        # Count findings by severity/category on remaining only
        for finding in remaining_findings:
            severity = finding.get('severity', 'MEDIUM')
            stats['severity_breakdown'][severity] = (
                stats['severity_breakdown'].get(severity, 0) + 1
            )
            category = finding.get('category', 'unknown')
            stats['category_breakdown'][category] = (
                stats['category_breakdown'].get(category, 0) + 1
            )

        # Count fix statuses
        for fix in self.applied_fixes:
            status = fix.get('status', 'pending').lower()
            if status == 'applied':
                stats['applied_count'] += 1
            elif status == 'skipped':
                stats['skipped_count'] += 1
            elif status == 'failed':
                stats['failed_count'] += 1

        # Calculate risk score and rating based on remaining findings
        risk_data = self.calculate_risk_score(remaining_findings)
        stats['risk_score'] = risk_data['score']
        stats['risk_rating'] = risk_data['rating']
        stats['risk_level'] = risk_data['level']
        stats['risk_color'] = risk_data['color']

        return stats
    
    def calculate_risk_score(self, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Calculate overall security risk score based on findings.
        
        Returns:
            Dictionary with risk score, rating, and level
        """
        # Severity weights for risk calculation
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }
        
        findings = findings if findings is not None else self.findings

        # Calculate weighted risk score
        total_risk = 0
        max_possible_risk = 0
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            weight = severity_weights.get(severity, 1)
            total_risk += weight
        
        # Calculate max possible risk (if all findings were CRITICAL)
        max_possible_risk = len(findings) * severity_weights['CRITICAL']
        
        # Normalize to 0-100 scale
        if max_possible_risk > 0:
            risk_score = int((total_risk / max_possible_risk) * 100)
        else:
            risk_score = 0
        
        # Determine risk rating and level
        if risk_score >= 80:
            rating = 'CRITICAL'
            level = 'Immediate Action Required'
            color = '#dc2626'
        elif risk_score >= 60:
            rating = 'HIGH'
            level = 'Urgent Attention Needed'
            color = '#ea580c'
        elif risk_score >= 40:
            rating = 'MEDIUM'
            level = 'Action Recommended'
            color = '#f59e0b'
        elif risk_score >= 20:
            rating = 'LOW'
            level = 'Monitor and Review'
            color = '#10b981'
        else:
            rating = 'MINIMAL'
            level = 'Good Security Posture'
            color = '#3b82f6'
        
        return {
            'score': risk_score,
            'rating': rating,
            'level': level,
            'color': color
        }
    
    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate comprehensive security recommendations based on findings.
        
        Returns:
            List of recommendation dictionaries with priority, category, and action items
        """
        recommendations = []
        stats = self.generate_statistics()
        
        # CRITICAL: Immediate Actions
        if stats['severity_breakdown'].get('CRITICAL', 0) > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Immediate Action Required',
                'title': 'Address Critical Security Vulnerabilities',
                'description': f"Found {stats['severity_breakdown']['CRITICAL']} CRITICAL security issue(s) that require immediate attention.",
                'actions': [
                    'Stop deployment to production until critical issues are resolved',
                    'Assign dedicated security team to investigate and fix immediately',
                    'Implement emergency security patches within 24-48 hours',
                    'Conduct thorough security review of affected components',
                    'Notify stakeholders and security team about critical findings'
                ],
                'timeline': 'Within 24-48 hours',
                'impact': 'HIGH - Critical vulnerabilities can lead to data breaches, system compromise, or service disruption'
            })
        
        # HIGH: Urgent Priorities
        if stats['severity_breakdown'].get('HIGH', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Urgent Security Issues',
                'title': 'Resolve High-Priority Security Findings',
                'description': f"Identified {stats['severity_breakdown']['HIGH']} HIGH severity issue(s) requiring urgent attention.",
                'actions': [
                    'Prioritize fixes in current sprint or next release cycle',
                    'Conduct security code review for affected areas',
                    'Implement security controls and defensive measures',
                    'Update security documentation and threat models',
                    'Test fixes thoroughly before deployment'
                ],
                'timeline': 'Within 1-2 weeks',
                'impact': 'MEDIUM-HIGH - May expose sensitive data or allow unauthorized access'
            })
        
        # MEDIUM: Important Actions
        if stats['severity_breakdown'].get('MEDIUM', 0) > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Security Improvements',
                'title': 'Address Medium-Priority Security Issues',
                'description': f"Found {stats['severity_breakdown']['MEDIUM']} MEDIUM severity issue(s) that should be addressed.",
                'actions': [
                    'Schedule fixes in upcoming development cycles',
                    'Review and update security policies',
                    'Implement additional security layers',
                    'Conduct peer code reviews for affected code',
                    'Add security tests to prevent regression'
                ],
                'timeline': 'Within 2-4 weeks',
                'impact': 'MEDIUM - Could potentially be exploited under specific conditions'
            })
        
        # Unapplied Fixes
        if stats['remaining_count'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Fix Implementation',
                'title': 'Apply Pending Security Fixes',
                'description': f"{stats['remaining_count']} security fix(es) have been identified but not yet applied.",
                'actions': [
                    f"Review and test all {stats['remaining_count']} pending fixes",
                    'Prioritize fixes based on severity and business impact',
                    'Create implementation plan with clear timelines',
                    'Assign responsibility for each fix to team members',
                    'Track progress and verify successful implementation'
                ],
                'timeline': 'Based on severity - Critical: 24-48hrs, High: 1-2 weeks, Medium: 2-4 weeks',
                'impact': 'VARIES - Depends on severity of unresolved issues'
            })
        
        # Security Best Practices
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Security Best Practices',
            'title': 'Implement Comprehensive Security Measures',
            'description': 'Strengthen overall security posture with industry best practices.',
            'actions': [
                'Integrate automated security scanning in CI/CD pipeline',
                'Conduct regular security training for development team',
                'Implement secure coding standards and guidelines',
                'Perform quarterly security audits and penetration testing',
                'Establish security incident response procedures',
                'Maintain security documentation and threat models',
                'Use dependency scanning for third-party libraries',
                'Implement code signing and secure deployment practices'
            ],
            'timeline': 'Ongoing - Implement progressively over 3-6 months',
            'impact': 'HIGH - Proactive security measures prevent future vulnerabilities'
        })
        
        # Code Quality & Security
        recommendations.append({
            'priority': 'LOW',
            'category': 'Long-term Security Strategy',
            'title': 'Establish Security-First Development Culture',
            'description': 'Build sustainable security practices into development workflow.',
            'actions': [
                'Create security champions program within teams',
                'Implement security gates in release process',
                'Conduct regular threat modeling sessions',
                'Establish bug bounty or responsible disclosure program',
                'Monitor and respond to security advisories',
                'Participate in security community and conferences',
                'Regular security architecture reviews',
                'Implement zero-trust security principles'
            ],
            'timeline': '6-12 months',
            'impact': 'HIGH - Long-term reduction in security incidents and vulnerabilities'
        })
        
        return recommendations
    
    def create_severity_chart(self) -> str:
        """
        Create a bar chart showing findings by severity level.
        
        Returns:
            Base64-encoded PNG image string for embedding in reports
        """
        stats = self.generate_statistics()
        severity_data = stats['severity_breakdown']
        
        # Return empty string if no findings
        if not severity_data:
            return ""
        
        # Create figure
        fig = Figure(figsize=(10, 6), dpi=100)
        ax = fig.subplots()
        
        # Prepare data in correct order
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        counts = [severity_data.get(s, 0) for s in severities]
        colors = [self.MPLOT_COLORS.get(s, '#gray') for s in severities]
        
        # Filter out zero values
        severities_filtered = [s for s, c in zip(severities, counts) if c > 0]
        counts_filtered = [c for c in counts if c > 0]
        colors_filtered = [self.MPLOT_COLORS.get(s, '#gray') 
                          for s in severities_filtered]
        
        # Create bar chart
        bars = ax.bar(severities_filtered, counts_filtered, color=colors_filtered)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontweight='bold')
        
        ax.set_ylabel('Number of Findings', fontweight='bold')
        ax.set_title('Security Findings by Severity Level', fontweight='bold', fontsize=14)
        ax.set_ylim(0, max(counts_filtered) * 1.1 if counts_filtered else 1)
        
        # Save to bytes buffer
        buf = BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight', dpi=100)
        buf.seek(0)
        plt.close(fig)
        
        # Convert to base64
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    
    def create_fixes_status_chart(self) -> str:
        """
        Create a pie chart showing fixes applied vs. remaining.
        
        Returns:
            Base64-encoded PNG image string for embedding in reports
        """
        stats = self.generate_statistics()
        
        # Prepare data
        labels = []
        sizes = []
        colors_list = []
        
        if stats['applied_count'] > 0:
            labels.append(f"Applied ({stats['applied_count']})")
            sizes.append(stats['applied_count'])
            colors_list.append('#10b981')  # Green
        
        if stats['remaining_count'] > 0:
            labels.append(f"Remaining ({stats['remaining_count']})")
            sizes.append(stats['remaining_count'])
            colors_list.append('#f59e0b')  # Amber
        
        if stats['skipped_count'] > 0:
            labels.append(f"Skipped ({stats['skipped_count']})")
            sizes.append(stats['skipped_count'])
            colors_list.append('#6b7280')  # Gray

        if stats['failed_count'] > 0:
            labels.append(f"Failed ({stats['failed_count']})")
            sizes.append(stats['failed_count'])
            colors_list.append('#ef4444')  # Red
        
        # Return empty string if no fixes
        if not sizes:
            return ""
        
        # Create figure
        fig = Figure(figsize=(8, 6), dpi=100)
        ax = fig.subplots()
        
        # Create pie chart
        ax.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%',
              startangle=90, textprops={'fontweight': 'bold'})
        ax.set_title('Fix Status Overview', fontweight='bold', fontsize=14)
        
        # Save to bytes buffer
        buf = BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight', dpi=100)
        buf.seek(0)
        plt.close(fig)
        
        # Convert to base64
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    
    def create_category_chart(self) -> str:
        """
        Create a horizontal bar chart showing findings by category.
        
        Returns:
            Base64-encoded PNG image string for embedding in reports
        """
        stats = self.generate_statistics()
        category_data = stats['category_breakdown']
        
        # Return empty string if no findings
        if not category_data:
            return ""
        
        # Sort by count (descending) and limit to top 10
        sorted_categories = sorted(
            category_data.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        categories = [cat[0].replace('_', ' ').title() for cat in sorted_categories]
        counts = [cat[1] for cat in sorted_categories]
        
        # Create figure
        fig = Figure(figsize=(10, 6), dpi=100)
        ax = fig.subplots()
        
        # Create horizontal bar chart
        bars = ax.barh(categories, counts, color='#3b82f6')
        
        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f'{int(width)}',
                   ha='left', va='center', fontweight='bold', fontsize=9)
        
        ax.set_xlabel('Number of Findings', fontweight='bold')
        ax.set_title('Vulnerability Types', fontweight='bold', fontsize=14)
        ax.set_xlim(0, max(counts) * 1.15 if counts else 1)
        
        # Save to bytes buffer
        buf = BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight', dpi=100)
        buf.seek(0)
        plt.close(fig)
        
        # Convert to base64
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    
    def create_risk_gauge_chart(self) -> str:
        """
        Create a risk gauge visualization showing overall security risk score.
        
        Returns:
            Base64-encoded PNG image string for embedding in reports
        """
        stats = self.generate_statistics()
        risk_score = stats['risk_score']
        risk_rating = stats['risk_rating']
        risk_level = stats['risk_level']
        
        # Create figure with gauge
        fig = Figure(figsize=(10, 5), dpi=100)
        ax = fig.subplots()
        
        # Create gauge segments
        segments = [
            {'range': (0, 20), 'color': '#3b82f6', 'label': 'MINIMAL'},
            {'range': (20, 40), 'color': '#10b981', 'label': 'LOW'},
            {'range': (40, 60), 'color': '#f59e0b', 'label': 'MEDIUM'},
            {'range': (60, 80), 'color': '#ea580c', 'label': 'HIGH'},
            {'range': (80, 100), 'color': '#dc2626', 'label': 'CRITICAL'}
        ]
        
        # Draw gauge background
        for segment in segments:
            start, end = segment['range']
            theta = np.linspace(np.pi * (1 - start/100), np.pi * (1 - end/100), 100)
            r = 1
            x = r * np.cos(theta)
            y = r * np.sin(theta)
            ax.fill_between(x, 0, y, color=segment['color'], alpha=0.3, label=segment['label'])
        
        # Draw needle pointing to risk score
        angle = np.pi * (1 - risk_score/100)
        needle_x = [0, 0.9 * np.cos(angle)]
        needle_y = [0, 0.9 * np.sin(angle)]
        ax.plot(needle_x, needle_y, color='black', linewidth=4, zorder=10)
        ax.plot(0, 0, 'ko', markersize=12, zorder=11)
        
        # Add risk score text
        ax.text(0, -0.3, f'{risk_score}', fontsize=48, fontweight='bold', 
                ha='center', va='center', color=stats['risk_color'])
        ax.text(0, -0.5, risk_rating, fontsize=20, fontweight='bold',
                ha='center', va='center', color=stats['risk_color'])
        ax.text(0, -0.65, risk_level, fontsize=12, ha='center', va='center')
        
        # Configure axes
        ax.set_xlim(-1.3, 1.3)
        ax.set_ylim(-0.8, 1.1)
        ax.set_aspect('equal')
        ax.axis('off')
        ax.set_title('Overall Security Risk Score', fontweight='bold', fontsize=16, pad=20)
        
        # Add legend
        ax.legend(loc='upper right', fontsize=9, framealpha=0.9)
        
        # Save to bytes buffer
        buf = BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight', dpi=100, facecolor='white')
        buf.seek(0)
        plt.close(fig)
        
        # Convert to base64
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    
    def generate_html(self) -> str:
        """
        Generate a comprehensive HTML report with embedded charts.
        
        Returns:
            HTML string ready for export
        """
        # Generate statistics and visualizations
        stats = self.generate_statistics()
        severity_chart = self.create_severity_chart()
        fixes_chart = self.create_fixes_status_chart()
        category_chart = self.create_category_chart()
        risk_gauge_chart = self.create_risk_gauge_chart()
        recommendations = self.generate_recommendations()
        
        # Build findings HTML
        findings_html = self._build_findings_html()
        
        # Build applied fixes HTML
        fixes_html = self._build_applied_fixes_html()

        # Build manual remediation HTML
        manual_fixes_html = self._build_manual_fixes_html()
        
        # Build recommendations HTML
        recommendations_html = self._build_recommendations_html(recommendations)
        
        # HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMCP Security Report - {{ project_name }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f3f4f6;
            color: #1f2937;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 40px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .metadata {
            background-color: #f9fafb;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
        }
        
        .metadata p {
            margin: 8px 0;
        }
        
        .metadata strong {
            color: #667eea;
        }
        
        section {
            margin-bottom: 40px;
        }
        
        h2 {
            color: #667eea;
            font-size: 2em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        
        h3 {
            color: #764ba2;
            font-size: 1.5em;
            margin-top: 25px;
            margin-bottom: 15px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .stat-card h3 {
            color: white;
            font-size: 2.5em;
            margin: 0;
            border: none;
        }
        
        .stat-card p {
            font-size: 1em;
            opacity: 0.9;
            margin-top: 5px;
        }
        
        .chart-container {
            background-color: #f9fafb;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .chart-container img {
            max-width: 100%;
            height: auto;
        }
        
        .finding-card {
            border-left: 5px solid;
            padding: 20px;
            margin-bottom: 20px;
            background-color: #f9fafb;
            border-radius: 4px;
        }
        
        .finding-card.critical { border-left-color: #dc2626; }
        .finding-card.high { border-left-color: #ea580c; }
        .finding-card.medium { border-left-color: #f59e0b; }
        .finding-card.low { border-left-color: #10b981; }
        .finding-card.info { border-left-color: #3b82f6; }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .finding-header h4 {
            margin: 0;
            font-size: 1.3em;
            color: #1f2937;
        }
        
        .badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            white-space: nowrap;
        }
        
        .badge-critical { background-color: #dc2626; color: white; }
        .badge-high { background-color: #ea580c; color: white; }
        .badge-medium { background-color: #f59e0b; color: white; }
        .badge-low { background-color: #10b981; color: white; }
        .badge-info { background-color: #3b82f6; color: white; }
        
        .finding-meta {
            display: flex;
            gap: 20px;
            margin: 10px 0;
            flex-wrap: wrap;
            font-size: 0.95em;
            color: #6b7280;
        }
        
        .finding-meta span {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .finding-description {
            margin: 15px 0;
            padding: 15px;
            background-color: white;
            border-radius: 4px;
        }
        
        .finding-description strong {
            color: #667eea;
        }
        
        .code-block {
            background-color: #0f172a;
            color: #e5e7eb;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'SFMono-Regular', Consolas, 'Courier New', monospace;
            font-size: 0.88em;
            white-space: pre-wrap;
            line-height: 1.4;
            border: 1px solid #1f2937;
        }
        
        .recommendations-list {
            list-style: none;
            padding: 0;
        }
        
        .recommendations-list li {
            background-color: #f9fafb;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
            border-left: 4px solid #667eea;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .recommendations-list li:before {
            content: "✓";
            font-weight: bold;
            color: #10b981;
            font-size: 1.3em;
        }
        
        .recommendation-card {
            background-color: #ffffff;
            border-left: 6px solid;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .recommendation-card.critical {
            border-left-color: #dc2626;
            background-color: #fef2f2;
        }
        
        .recommendation-card.high {
            border-left-color: #ea580c;
            background-color: #fff7ed;
        }
        
        .recommendation-card.medium {
            border-left-color: #f59e0b;
            background-color: #fffbeb;
        }
        
        .recommendation-card.low {
            border-left-color: #10b981;
            background-color: #f0fdf4;
        }
        
        .recommendation-header {
            margin-bottom: 15px;
        }
        
        .recommendation-title {
            color: #1f2937;
            font-size: 1.3em;
            margin: 10px 0;
            border: none;
            padding: 0;
        }
        
        .recommendation-category {
            background-color: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            margin-left: 10px;
        }
        
        .recommendation-body {
            color: #374151;
        }
        
        .recommendation-description {
            font-size: 1.05em;
            margin-bottom: 15px;
            line-height: 1.6;
        }
        
        .recommendation-actions {
            background-color: rgba(102, 126, 234, 0.05);
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
        }
        
        .recommendation-actions ul {
            margin: 10px 0 0 20px;
            padding: 0;
        }
        
        .recommendation-actions li {
            margin: 8px 0;
            color: #374151;
            line-height: 1.5;
        }
        
        .recommendation-meta {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .recommendation-meta p {
            margin: 6px 0;
            color: #6b7280;
            font-size: 0.95em;
        }
        
        .fix-card {
            background-color: #f0fdf4;
            border-left: 5px solid #10b981;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }

        .manual-card {
            background-color: #fff7ed;
            border-left: 5px solid #ea580c;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .fix-status {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .fix-status.applied {
            background-color: #10b981;
            color: white;
        }
        
        .fix-status.skipped {
            background-color: #6b7280;
            color: white;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #6b7280;
            border-top: 1px solid #e5e7eb;
            margin-top: 40px;
            font-size: 0.9em;
        }
        
        @media print {
            body {
                background-color: white;
            }
            
            .container {
                padding: 0;
            }
            
            section {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 SecureMCP Security Report</h1>
            <p>{{ project_name }}</p>
        </header>
        
        <div class="metadata">
            <p><strong>Scan Date:</strong> {{ scan_date_formatted }}</p>
            <p><strong>Project Path:</strong> {{ project_path }}</p>
            <p><strong>Total Files Scanned:</strong> {{ total_files_scanned }}</p>
        </div>
        
        <!-- Project Summary Section -->
        <section>
            <h2>📋 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{{ total_findings }}</h3>
                    <p>Total Findings</p>
                </div>
                <div class="stat-card">
                    <h3>{{ applied_count }}</h3>
                    <p>Fixes Applied</p>
                </div>
                <div class="stat-card">
                    <h3>{{ remaining_count }}</h3>
                    <p>Remaining Issues</p>
                </div>
                <div class="stat-card">
                    <h3>{{ skipped_count }}</h3>
                    <p>Skipped</p>
                </div>
                <div class="stat-card">
                    <h3>{{ failed_count }}</h3>
                    <p>Failed Applies</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, {{ risk_color }} 0%, {{ risk_color }}dd 100%);">
                    <h3>{{ risk_score }}</h3>
                    <p>Risk Score</p>
                </div>
            </div>
        </section>
        
        <!-- Risk Assessment Section -->
        <section>
            <h2>⚠️ Security Risk Assessment</h2>
            {% if risk_gauge_chart %}
            <div class="chart-container">
                <img src="data:image/png;base64,{{ risk_gauge_chart }}" alt="Risk Gauge">
            </div>
            {% endif %}
            <div class="metadata" style="border-left-color: {{ risk_color }};">
                <h3>Risk Rating: <span style="color: {{ risk_color }};">{{ risk_rating }}</span></h3>
                <p><strong>Security Level:</strong> {{ risk_level }}</p>
                <p><strong>Risk Score:</strong> {{ risk_score }}/100</p>
                {% if risk_rating == 'CRITICAL' %}
                <p style="color: #dc2626; font-weight: bold;">🚨 IMMEDIATE ACTION REQUIRED - This project has critical security vulnerabilities that must be addressed before production deployment.</p>
                {% elif risk_rating == 'HIGH' %}
                <p style="color: #ea580c; font-weight: bold;">⚠️ URGENT ATTENTION NEEDED - High-severity security issues detected. Prioritize fixes immediately.</p>
                {% elif risk_rating == 'MEDIUM' %}
                <p style="color: #f59e0b; font-weight: bold;">⚡ ACTION RECOMMENDED - Moderate security concerns. Address in upcoming sprint.</p>
                {% elif risk_rating == 'LOW' %}
                <p style="color: #10b981; font-weight: bold;">✓ MONITOR AND REVIEW - Low security risk. Continue monitoring.</p>
                {% else %}
                <p style="color: #3b82f6; font-weight: bold;">✅ GOOD SECURITY POSTURE - Minimal security risks detected.</p>
                {% endif %}
            </div>
        </section>
        
        <!-- Visualizations Section -->
        <section>
            <h2>📊 Security Analytics</h2>
            
            {% if severity_chart %}
            <div class="chart-container">
                <img src="data:image/png;base64,{{ severity_chart }}" alt="Severity Breakdown">
            </div>
            {% endif %}
            
            {% if category_chart %}
            <div class="chart-container">
                <img src="data:image/png;base64,{{ category_chart }}" alt="Vulnerability Types">
            </div>
            {% endif %}
            
            {% if fixes_chart %}
            <div class="chart-container">
                <img src="data:image/png;base64,{{ fixes_chart }}" alt="Fixes Status">
            </div>
            {% endif %}
        </section>
        
        <!-- Findings Section -->
        <section>
            <h2>🔍 Security Findings</h2>
            {% if findings_html %}
                {{ findings_html | safe }}
            {% else %}
                <p style="text-align: center; color: #10b981; font-size: 1.1em; margin: 30px 0;">
                    ✅ No security issues found!
                </p>
            {% endif %}
        </section>
        
        <!-- Applied Fixes Section -->
        {% if applied_fixes_html %}
        <section>
            <h2>✅ Applied Fixes (Before/After)</h2>
            {{ applied_fixes_html | safe }}
        </section>
        {% endif %}

        <!-- Manual Remediation Section -->
        {% if manual_fixes_html %}
        <section>
            <h2>🛠️ Manual Remediation Required</h2>
            {{ manual_fixes_html | safe }}
        </section>
        {% endif %}
        
        <!-- Recommendations Section -->
        <section>
            <h2>💡 Security Recommendations & Action Plan</h2>
            {% if recommendations_html %}
                {{ recommendations_html | safe }}
            {% else %}
                <p style="text-align: center; color: #10b981; font-size: 1.1em; margin: 30px 0;">
                    ✅ No specific recommendations at this time.
                </p>
            {% endif %}
        </section>
        
        <footer>
            <p>Generated by SecureMCP on {{ timestamp }}</p>
            <p>For more information, visit: https://github.com/securemcp</p>
        </footer>
    </div>
</body>
</html>
        """
        
        # Render template
        template = Template(html_template)
        html_content = template.render(
            project_name=self.project_name,
            project_path=self.project_path,
            scan_date_formatted=self.scan_date_formatted,
            timestamp=self.timestamp,
            total_files_scanned=stats['total_files_scanned'],
            total_findings=stats['total_findings'],
            applied_count=stats['applied_count'],
            remaining_count=stats['remaining_count'],
            skipped_count=stats['skipped_count'],
            failed_count=stats['failed_count'],
            risk_score=stats['risk_score'],
            risk_rating=stats['risk_rating'],
            risk_level=stats['risk_level'],
            risk_color=stats['risk_color'],
            severity_chart=severity_chart,
            category_chart=category_chart,
            fixes_chart=fixes_chart,
            risk_gauge_chart=risk_gauge_chart,
            recommendations_html=recommendations_html,
            findings_html=findings_html,
            applied_fixes_html=fixes_html,
            manual_fixes_html=manual_fixes_html,
        )
        
        return html_content
    
    def _build_findings_html(self) -> str:
        """
        Build HTML for findings section.
        
        Returns:
            HTML string with formatted findings
        """
        if not self.findings:
            return ""
        
        html_parts = []
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in self.findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Render findings grouped by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        for severity in severity_order:
            if severity not in findings_by_severity:
                continue
            
            html_parts.append(f'<h3>{severity} Severity ({len(findings_by_severity[severity])})</h3>')
            
            for finding in findings_by_severity[severity]:
                severity_lower = severity.lower()
                file_path = self._escape_html(finding.get('file', 'unknown'))
                line_num = finding.get('line', 'N/A')
                category = self._escape_html(finding.get('category', 'unknown').replace('_', ' ').title())
                description = self._escape_html(finding.get('description', 'Unknown Issue'))
                explanation = self._escape_html(finding.get('explanation', 'No detailed explanation.'))
                suggested_fix = self._escape_html(finding.get('suggested_fix', 'No fix suggested.'))
                snippet = self._escape_html(finding.get('snippet', ''))
                
                html_parts.append(f'''
                <div class="finding-card {severity_lower}">
                    <div class="finding-header">
                        <h4>{description}</h4>
                        <span class="badge badge-{severity_lower}">{severity}</span>
                    </div>
                    <div class="finding-meta">
                        <span>📄 {file_path}</span>
                        <span>📍 Line {line_num}</span>
                        <span>🏷️ {category}</span>
                    </div>
                    <div class="finding-description">
                        <strong>Description:</strong><br/>
                        {explanation}
                    </div>
                    <div class="finding-description">
                        <strong>💡 Suggested Fix:</strong><br/>
                        {suggested_fix}
                    </div>
                    {f'<div class="code-block">{snippet[:500]}</div>' if snippet else ''}
                </div>
                ''')
        
        return ''.join(html_parts)
    
    def _build_applied_fixes_html(self) -> str:
        """
        Build HTML for applied fixes section.
        
        Returns:
            HTML string with formatted applied fixes
        """
        if not self.applied_fixes:
            return ""
        
        html_parts = []
        applied = [f for f in self.applied_fixes if f.get('status', '').lower() == 'applied']
        
        if not applied:
            return ""
        
        for fix in applied:
            finding = fix.get('finding', {})
            file_path = finding.get('file', 'unknown')
            line_num = finding.get('line', 'N/A')
            description = finding.get('description', 'Unknown Fix')
            original_raw = fix.get('original_code') or finding.get('snippet') or ''
            replacement_raw = fix.get('replacement_code') or finding.get('replacement_code') or finding.get('suggested_fix') or ''
            original = self._escape_html(original_raw)
            replacement = self._escape_html(replacement_raw)
            suggested_fix = self._escape_html(finding.get('suggested_fix', ''))
            explanation = self._escape_html(finding.get('explanation', ''))
            
            html_parts.append(f'''
            <div class="fix-card">
                <div class="finding-header">
                    <h4>{description}</h4>
                    <span class="fix-status applied">✓ Applied</span>
                </div>
                <div class="finding-meta">
                    <span>📄 {file_path}</span>
                    <span>📍 Line {line_num}</span>
                </div>
                {f'<p><strong>What changed:</strong><br/>{explanation}</p>' if explanation else ''}
                {f'<p><strong>Before:</strong><br/><div class="code-block">{original[:1200]}</div></p>' if original else ''}
                {f'<p><strong>After:</strong><br/><div class="code-block">{replacement[:1200]}</div></p>' if replacement else ''}
                {f'<p><strong>Suggested Fix Rationale:</strong><br/>{suggested_fix}</p>' if suggested_fix else ''}
                {'' if (original or replacement) else '<p><em>No code snapshot captured for this fix.</em></p>'}
            </div>
            ''')
        
        return ''.join(html_parts)

    def _collect_manual_fix_items(self) -> List[Dict[str, Any]]:
        """
        Gather findings that require manual remediation (non-auto-fixable or failed applies).
        """
        manual_items = []
        seen = set()

        # Non-auto-fixable findings
        for finding in self.findings:
            if finding.get('auto_fixable', True):
                continue
            key = (finding.get('file'), finding.get('line'), 'non_auto')
            if key in seen:
                continue
            seen.add(key)
            manual_items.append({
                'reason': 'Not auto-fixable safely; review and patch manually.',
                'finding': finding,
                'suggested_fix': finding.get('suggested_fix', ''),
                'snippet': finding.get('snippet', ''),
                'category': finding.get('category', 'unknown')
            })

        # Failed auto-fix attempts
        for fix in self.applied_fixes:
            if fix.get('status', '').lower() != 'failed':
                continue
            finding = fix.get('finding', {})
            key = (finding.get('file'), finding.get('line'), 'failed')
            if key in seen:
                continue
            seen.add(key)
            manual_items.append({
                'reason': f"Auto-fix attempt failed: {fix.get('error', 'unknown error')}",
                'finding': finding,
                'suggested_fix': finding.get('suggested_fix', ''),
                'snippet': fix.get('original_code') or finding.get('snippet', ''),
                'category': finding.get('category', 'unknown')
            })

        return manual_items

    def _build_manual_fixes_html(self) -> str:
        """
        Build HTML for manual remediation section.
        """
        manual_items = self._collect_manual_fix_items()
        if not manual_items:
            return ''

        html_parts = []
        for item in manual_items:
            finding = item.get('finding', {})
            severity = (finding.get('severity', 'MEDIUM') or 'MEDIUM').upper()
            severity_lower = severity.lower()
            description = self._escape_html(finding.get('description', 'Manual remediation required'))
            file_path = self._escape_html(finding.get('file', 'unknown'))
            line_num = finding.get('line', 'N/A')
            reason = self._escape_html(item.get('reason', 'Manual review needed'))
            suggested_fix = self._escape_html(item.get('suggested_fix', ''))
            snippet = self._escape_html(item.get('snippet', ''))

            html_parts.append(f'''
            <div class="manual-card {severity_lower}">
                <div class="finding-header">
                    <h4>{description}</h4>
                    <span class="badge badge-{severity_lower}">{severity}</span>
                </div>
                <div class="finding-meta">
                    <span>📄 {file_path}</span>
                    <span>📍 Line {line_num}</span>
                </div>
                <p><strong>Why manual:</strong> {reason}</p>
                {f'<p><strong>Suggested remediation:</strong><br/>{suggested_fix}</p>' if suggested_fix else ''}
                {f'<div class="code-block">{snippet[:800]}</div>' if snippet else ''}
            </div>
            ''')

        return ''.join(html_parts)
    
    def _build_recommendations_html(self, recommendations: List[Dict[str, Any]]) -> str:
        """
        Build HTML for enhanced recommendations section.
        
        Args:
            recommendations: List of recommendation dictionaries
            
        Returns:
            HTML string with formatted recommendations
        """
        if not recommendations:
            return ""
        
        html_parts = []
        
        # Priority badges colors
        priority_colors = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        
        for rec in recommendations:
            priority = rec.get('priority', 'MEDIUM')
            priority_class = priority_colors.get(priority, 'medium')
            category = self._escape_html(rec.get('category', 'General'))
            title = self._escape_html(rec.get('title', 'Recommendation'))
            description = self._escape_html(rec.get('description', ''))
            actions = rec.get('actions', [])
            timeline = self._escape_html(rec.get('timeline', 'Not specified'))
            impact = self._escape_html(rec.get('impact', 'Not specified'))
            
            # Build actions list
            actions_html = ''
            if actions:
                actions_items = ''.join([f'<li>{self._escape_html(action)}</li>' for action in actions])
                actions_html = f'''
                <div class="recommendation-actions">
                    <strong>📋 Action Items:</strong>
                    <ul>{actions_items}</ul>
                </div>
                '''
            
            html_parts.append(f'''
            <div class="recommendation-card {priority_class}">
                <div class="recommendation-header">
                    <div>
                        <span class="badge badge-{priority_class}">{priority} Priority</span>
                        <span class="recommendation-category">{category}</span>
                    </div>
                    <h3 class="recommendation-title">{title}</h3>
                </div>
                <div class="recommendation-body">
                    <p class="recommendation-description">{description}</p>
                    {actions_html}
                    <div class="recommendation-meta">
                        <p><strong>⏱️ Timeline:</strong> {timeline}</p>
                        <p><strong>💥 Business Impact:</strong> {impact}</p>
                    </div>
                </div>
            </div>
            ''')
        
        return ''.join(html_parts)
    
    def generate_pdf(self) -> bytes:
        """
        Generate a comprehensive PDF report.
        
        Returns:
            PDF content as bytes
        """
        # Create PDF buffer
        pdf_buffer = BytesIO()
        
        # Initialize PDF document
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
            title='SecureMCP Security Report',
        )
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=10,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )

        code_style = ParagraphStyle(
            'Code',
            parent=styles['Code'] if 'Code' in styles else styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.whitesmoke,
            backColor=colors.HexColor('#0f172a')
        )
        
        # Build PDF content
        story = []
        
        # Title
        story.append(Paragraph("🔐 SecureMCP Security Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Metadata
        story.append(Paragraph(f"<b>Project:</b> {self.project_name}", styles['Normal']))
        story.append(Paragraph(f"<b>Path:</b> {self.project_path}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan Date:</b> {self.scan_date_formatted}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Statistics
        story.append(Paragraph("Project Summary", heading_style))
        stats = self.generate_statistics()
        
        summary_data = [
            ['Total Findings', f"{stats['total_findings']}"],
            ['Files Scanned', f"{stats['total_files_scanned']}"],
            ['Fixes Applied', f"{stats['applied_count']}"],
            ['Remaining', f"{stats['remaining_count']}"],
            ['Skipped', f"{stats['skipped_count']}"],
            ['Failed Applies', f"{stats['failed_count']}"],
            ['Risk Score', f"{stats['risk_score']} ({stats['risk_rating']})"],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')])
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Analytics (charts)
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("📊 Security Analytics", heading_style))

        # Generate chart images
        severity_chart = self.create_severity_chart()
        category_chart = self.create_category_chart()
        fixes_chart = self.create_fixes_status_chart()
        risk_gauge_chart = self.create_risk_gauge_chart()

        charts = [
            ("Severity Breakdown", severity_chart),
            ("Vulnerability Types", category_chart),
            ("Fix Status", fixes_chart),
            ("Overall Risk Gauge", risk_gauge_chart),
        ]

        for title, chart_b64 in charts:
            img = self._image_from_base64(chart_b64)
            if not img:
                continue
            story.append(Paragraph(title, styles['Heading3']))
            story.append(img)
            story.append(Spacer(1, 0.15*inch))

        # Applied fixes with before/after snapshots
        applied = [f for f in self.applied_fixes if f.get('status', '').lower() == 'applied']
        if applied:
            story.append(PageBreak())
            story.append(Paragraph("✅ Applied Fixes (Before/After)", heading_style))
            for fix in applied:
                finding = fix.get('finding', {})
                desc = finding.get('description', 'Applied Fix')
                file_path = finding.get('file', 'unknown')
                line_num = finding.get('line', 'N/A')
                explanation = self._escape_html(finding.get('explanation', ''))

                story.append(Paragraph(f"{desc}", styles['Heading3']))
                story.append(Paragraph(f"File: {file_path} | Line: {line_num}", styles['Normal']))
                if explanation:
                    story.append(Paragraph(explanation, styles['Normal']))

                original_raw = (fix.get('original_code') or finding.get('snippet') or '')
                replacement_raw = (fix.get('replacement_code') or finding.get('replacement_code') or finding.get('suggested_fix') or '')
                original = self._escape_html(original_raw[:1500]).replace('\n', '<br/>')
                replacement = self._escape_html(replacement_raw[:1500]).replace('\n', '<br/>')

                if original:
                    story.append(Paragraph("<b>Before:</b><br/>" + original, code_style))
                if replacement:
                    story.append(Paragraph("<b>After:</b><br/>" + replacement, code_style))
                if not original and not replacement:
                    story.append(Paragraph("No code snapshot captured for this fix.", styles['Italic']))
                story.append(Spacer(1, 0.15*inch))

        # Manual remediation section
        manual_items = self._collect_manual_fix_items()
        if manual_items:
            story.append(PageBreak())
            story.append(Paragraph("🛠️ Manual Remediation Required", heading_style))
            for item in manual_items:
                finding = item.get('finding', {})
                desc = finding.get('description', 'Manual Fix Needed')
                file_path = finding.get('file', 'unknown')
                line_num = finding.get('line', 'N/A')
                reason = self._escape_html(item.get('reason', 'Manual review needed'))
                suggested = self._escape_html(item.get('suggested_fix', '')).replace('\n', '<br/>')
                snippet = self._escape_html((item.get('snippet', '') or '')[:1500]).replace('\n', '<br/>')

                story.append(Paragraph(desc, styles['Heading3']))
                story.append(Paragraph(f"File: {file_path} | Line: {line_num}", styles['Normal']))
                story.append(Paragraph(f"Why manual: {reason}", styles['Normal']))
                if suggested:
                    story.append(Paragraph(f"Suggested remediation:<br/>{suggested}", styles['Normal']))
                if snippet:
                    story.append(Paragraph("Code context:", styles['Normal']))
                    story.append(Paragraph(snippet, code_style))
                story.append(Spacer(1, 0.15*inch))

        # Findings section
        if self.findings:
            story.append(PageBreak())
            story.append(Paragraph("🔍 Security Findings", heading_style))
            
            # Group findings by severity
            findings_by_severity = {}
            for finding in self.findings:
                severity = finding.get('severity', 'MEDIUM')
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)
            
            # Render findings
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            for severity in severity_order:
                if severity not in findings_by_severity:
                    continue
                
                story.append(Paragraph(
                    f"{severity} ({len(findings_by_severity[severity])})",
                    styles['Heading3']
                ))
                
                for finding in findings_by_severity[severity]:
                    finding_text = (
                        f"<b>{finding.get('description', 'Unknown')}</b><br/>"
                        f"File: {finding.get('file', 'unknown')} | "
                        f"Line: {finding.get('line', 'N/A')}<br/>"
                        f"{finding.get('explanation', 'No description.')}"
                    )
                    story.append(Paragraph(finding_text, styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
        
        # Recommendations section
        story.append(PageBreak())
        story.append(Paragraph("💡 Security Recommendations & Action Plan", heading_style))

        recommendations = self.generate_recommendations()
        for rec in recommendations:
            priority = rec.get('priority', 'MEDIUM')
            title_text = f"{priority} - {rec.get('title', 'Recommendation')}"
            story.append(Paragraph(title_text, styles['Heading3']))
            story.append(Paragraph(rec.get('description', ''), styles['Normal']))

            actions = rec.get('actions', [])
            if actions:
                bullet_items = '<br/>'.join([f"• {self._escape_html(a)}" for a in actions])
                story.append(Paragraph(f"<b>Action Items:</b><br/>{bullet_items}", styles['Normal']))

            meta_parts = []
            if rec.get('timeline'):
                meta_parts.append(f"⏱️ Timeline: {self._escape_html(rec['timeline'])}")
            if rec.get('impact'):
                meta_parts.append(f"💥 Impact: {self._escape_html(rec['impact'])}")
            if meta_parts:
                story.append(Paragraph('<br/>'.join(meta_parts), styles['Normal']))

            story.append(Spacer(1, 0.15*inch))
        
        # Footer
        story.append(Spacer(1, 0.3*inch))
        footer_text = f"Generated by SecureMCP on {self.timestamp}"
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        return pdf_buffer.getvalue()
    
    def save_html(self, filepath: str) -> bool:
        """
        Save HTML report to file.
        
        Args:
            filepath: Path where to save the HTML file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            html_content = self.generate_html()
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except Exception as e:
            print(f"Error saving HTML report: {e}")
            return False
    
    def save_pdf(self, filepath: str) -> bool:
        """
        Save PDF report to file.
        
        Args:
            filepath: Path where to save the PDF file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            pdf_content = self.generate_pdf()
            with open(filepath, 'wb') as f:
                f.write(pdf_content)
            return True
        except Exception as e:
            print(f"Error saving PDF report: {e}")
            return False
    
    def export(self, directory: str = 'reports', formats: List[str] = None) -> Dict[str, str]:
        """
        Export report in multiple formats.
        
        Args:
            directory: Directory to save reports
            formats: List of formats ('pdf', 'html', 'json')
            
        Returns:
            Dictionary with format -> filepath mappings
        """
        if formats is None:
            formats = ['pdf', 'html']
        
        # Create directory if it doesn't exist
        Path(directory).mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp for filename
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = f"security_report_{timestamp_str}"
        
        exported_files = {}
        
        try:
            if 'html' in formats:
                filepath = os.path.join(directory, f"{basename}.html")
                if self.save_html(filepath):
                    exported_files['html'] = filepath
            
            if 'pdf' in formats:
                filepath = os.path.join(directory, f"{basename}.pdf")
                if self.save_pdf(filepath):
                    exported_files['pdf'] = filepath
            
            if 'json' in formats:
                filepath = os.path.join(directory, f"{basename}.json")
                stats = self.generate_statistics()
                json_data = {
                    'project_name': self.project_name,
                    'project_path': self.project_path,
                    'scan_date': self.timestamp,
                    'statistics': stats,
                    'findings': self.findings,
                    'applied_fixes': self.applied_fixes,
                }
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2)
                exported_files['json'] = filepath
        
        except Exception as e:
            print(f"Error exporting reports: {e}")
        
        return exported_files
