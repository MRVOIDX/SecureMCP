from flask import Flask, render_template, request, jsonify, send_file
from src.controller import SecurityController
from src.enhanced_report_generator import EnhancedReportGenerator
import os
import json
import zipfile
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from werkzeug.utils import secure_filename
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SESSION_SECRET', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

controller = SecurityController()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scanner')
def scanner():
    return render_template('scanner.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file.filename or file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.zip'):
            return jsonify({'success': False, 'error': 'Only ZIP files are supported'}), 400
        
        filename = secure_filename(file.filename) or 'project.zip'
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, filename)
        
        file.save(zip_path)
        
        extract_dir = os.path.join(temp_dir, 'extracted')
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        return jsonify({
            'success': True,
            'project_path': extract_dir
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def scan_project():
    try:
        data = request.json or {}
        project_path = data.get('project_path', '.')
        
        if not project_path or project_path == '':
            project_path = '.'
        
        result = controller.initialize_scan(project_path)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/findings', methods=['GET'])
def get_findings():
    try:
        # Return only remaining findings (exclude applied/skipped)
        findings = controller.get_remaining_findings()
        return jsonify({
            'success': True,
            'findings': findings
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/apply-fix/<int:finding_index>', methods=['POST'])
def apply_fix(finding_index):
    try:
        result = controller.apply_fix(finding_index)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/skip-fix/<int:finding_index>', methods=['POST'])
def skip_fix(finding_index):
    try:
        result = controller.skip_fix(finding_index)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fix-preview/<int:finding_index>', methods=['GET'])
def get_fix_preview(finding_index):
    try:
        result = controller.get_fix_preview(finding_index)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/summary', methods=['GET'])
def get_summary():
    try:
        summary = controller.get_summary()
        return jsonify({
            'success': True,
            'summary': summary
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    try:
        data = request.json or {}
        format_type = data.get('format', 'pdf')
        
        # Use original findings for accurate reporting (before any modifications from apply/skip)
        findings = controller.get_original_findings()
        applied_fixes = controller.get_applied_fixes()
        summary = controller.get_summary()
        project_path = controller.scan_results.get('project_path', '.') if controller.scan_results else '.'
        
        # Create enhanced report generator
        report_gen = EnhancedReportGenerator(project_path, findings, applied_fixes, summary)
        
        # Create reports directory
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        # Generate report based on format
        if format_type == 'pdf':
            try:
                content = report_gen.generate_pdf()
                filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
                is_binary = True
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'PDF generation failed: {str(e)}. Falling back to HTML.'
                }), 500
        elif format_type == 'html':
            content = report_gen.generate_html()
            filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
            is_binary = False
        else:
            # Default to PDF
            content = report_gen.generate_pdf()
            filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            is_binary = True
        
        # Save report file
        report_path = reports_dir / filename
        if is_binary:
            with open(report_path, 'wb') as f:
                f.write(content if isinstance(content, bytes) else content.encode('utf-8'))
        else:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(content if isinstance(content, str) else content.decode('utf-8'))
        
        return jsonify({
            'success': True,
            'report_path': str(report_path),
            'filename': filename,
            'format': format_type
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/download-report/<filename>')
def download_report(filename):
    try:
        report_path = Path('reports') / filename
        if report_path.exists():
            if filename.endswith('.pdf'):
                return send_file(report_path, mimetype='application/pdf', as_attachment=True, download_name=filename)
            elif filename.endswith('.html'):
                return send_file(report_path, mimetype='text/html', as_attachment=True, download_name=filename)
            else:
                return send_file(report_path, mimetype='text/markdown', as_attachment=True, download_name=filename)
        else:
            return jsonify({
                'success': False,
                'error': 'Report not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/generate-ai-fix/<int:finding_index>', methods=['POST'])
def generate_ai_fix(finding_index):
    """Generate a fixed version of the file using Groq AI."""
    try:
        result = controller.generate_ai_fix(finding_index)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/download-fixed-file/<int:finding_index>', methods=['POST'])
def download_fixed_file(finding_index):
    """Download the AI-generated fixed file."""
    try:
        data = request.json or {}
        fixed_content = data.get('fixed_content', '')
        filename = data.get('filename', 'fixed_file.txt')
        
        if not fixed_content:
            return jsonify({
                'success': False,
                'error': 'No fixed content provided'
            }), 400
        
        buffer = BytesIO()
        buffer.write(fixed_content.encode('utf-8'))
        buffer.seek(0)
        
        fixed_filename = f"fixed_{filename}"
        
        return send_file(
            buffer,
            mimetype='text/plain',
            as_attachment=True,
            download_name=fixed_filename
        )
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)