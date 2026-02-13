let currentFindings = [];
let currentReportFilename = null;
let currentFixIndex = null; // index in currentFindings array (UI list)
let currentFixOriginalIndex = null; // original index in backend list
let currentFixData = null;

// Upload functionality
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const scanBtn = document.getElementById('scanBtn');

uploadBtn.addEventListener('click', () => fileInput.click());

uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('drag-over');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('drag-over');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('drag-over');
    handleFileUpload(e.dataTransfer.files);
});

fileInput.addEventListener('change', (e) => {
    handleFileUpload(e.target.files);
});

scanBtn.addEventListener('click', startDirScan);
document.getElementById('generateReportBtn').addEventListener('click', generateReport);

async function handleFileUpload(files) {
    if (files.length === 0) return;
    
    const file = files[0];
    if (!file.name.endsWith('.zip')) {
        showToast('Please upload a ZIP file', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    const uploadProgress = document.getElementById('uploadProgress');
    uploadProgress.style.display = 'block';
    uploadBtn.disabled = true;
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            await startScan(data.project_path);
        } else {
            showToast(`Upload failed: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        uploadBtn.disabled = false;
        uploadProgress.style.display = 'none';
        fileInput.value = '';
    }
}

async function startDirScan() {
    const projectPath = document.getElementById('projectPath').value.trim() || '.';
    await startScan(projectPath);
}

async function startScan(projectPath) {
    const scanBtn = document.getElementById('scanBtn');
    const uploadArea = document.getElementById('uploadArea');
    const uploadProgress = document.getElementById('uploadProgress');
    
    scanBtn.disabled = true;
    uploadArea.style.opacity = '0.5';
    uploadProgress.style.display = 'block';
    
    document.getElementById('summarySection').style.display = 'none';
    document.getElementById('findingsSection').style.display = 'none';
    document.getElementById('reportSection').style.display = 'none';
    document.getElementById('emptyState').style.display = 'none';
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ project_path: projectPath })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentFindings = data.findings;
            displaySummary(data);
            displayFindings(data.findings);
            showToast('✅ Scan completed successfully!', 'success');
        } else {
            showToast(`Scan failed: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        scanBtn.disabled = false;
        uploadArea.style.opacity = '1';
        uploadProgress.style.display = 'none';
    }
}

function displaySummary(data) {
    document.getElementById('totalFindings').textContent = data.summary.total_findings;
    document.getElementById('filesScanned').textContent = data.total_files_scanned;
    
    const severity = data.summary.by_severity || {};
    document.getElementById('criticalCount').textContent = severity.CRITICAL || 0;
    document.getElementById('highCount').textContent = severity.HIGH || 0;
    document.getElementById('mediumCount').textContent = severity.MEDIUM || 0;
    
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('summarySection').style.display = 'block';
}

function displayFindings(findings) {
    const findingsList = document.getElementById('findingsList');
    findingsList.innerHTML = '';
    
    if (!findings || findings.length === 0) {
        findingsList.innerHTML = '<p style="text-align: center; color: #10b981; font-weight: 600;">✅ No security issues found!</p>';
        document.getElementById('findingsSection').style.display = 'block';
        return;
    }
    
    findings.forEach((finding, index) => {
        const severity = finding.severity || 'MEDIUM';
        const severityClass = `severity-${severity.toLowerCase()}`;
        const badgeClass = `badge-${severity.toLowerCase()}`;
        
        const card = document.createElement('div');
        card.className = `finding-card ${severityClass}`;
        
        card.innerHTML = `
            <div class="finding-title">
                <h3>${finding.description || 'Unknown Issue'}</h3>
            </div>
            <div class="finding-meta">
                <span class="finding-badge ${badgeClass}">${severity}</span>
                <span>📄 ${finding.file || 'unknown'}</span>
                <span>📍 Line ${finding.line || 'N/A'}</span>
            </div>
            <div class="finding-explanation">
                <strong>Description:</strong> ${finding.explanation || 'No detailed explanation available.'}
            </div>
            ${finding.snippet ? `
                <div class="finding-code">
                    <strong>Code:</strong><br/>${escapeHtml(finding.snippet.substring(0, 300))}
                </div>
            ` : ''}
            ${finding.suggested_fix ? `
                <div class="finding-suggestion">
                    <strong>💡 Suggested Fix:</strong> ${finding.suggested_fix}
                </div>
            ` : ''}
            <div class="finding-actions">
                <button class="btn btn-primary" onclick="applyFix(${index})">✅ Apply Fix</button>
                <button class="btn btn-secondary" onclick="skipFix(${index})">⏭️ Skip</button>
            </div>
        `;
        
        findingsList.appendChild(card);
    });
    
    document.getElementById('findingsSection').style.display = 'block';
}

async function applyFix(index) {
    currentFixIndex = index;
    currentFixOriginalIndex = currentFindings[index]?.original_index ?? index;
    currentFixData = null;
    const targetIndex = currentFixOriginalIndex ?? index;
    
    const modal = document.getElementById('fixPreviewModal');
    const fixNotAvailable = document.getElementById('fixNotAvailable');
    const fixPreviewContent = document.getElementById('fixPreviewContent');
    const finding = currentFindings[index];
    
    document.getElementById('modalTitle').textContent = 'Generating AI Fix...';
    fixNotAvailable.style.display = 'none';
    fixPreviewContent.style.display = 'none';
    
    const loadingHtml = `
        <div class="ai-loading">
            <div class="loading-spinner"></div>
            <p>Groq AI is analyzing and fixing the security issue...</p>
        </div>
    `;
    fixPreviewContent.innerHTML = loadingHtml;
    fixPreviewContent.style.display = 'block';
    modal.style.display = 'flex';
    
    document.getElementById('modalApplyBtn').style.display = 'none';
    
    try {
        const response = await fetch(`/api/generate-ai-fix/${targetIndex}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        
        if (data.success) {
            currentFixData = data;
            showAIFixPreviewModal(data);
        } else {
            showManualFixModal(index, data.error);
        }
    } catch (error) {
        showManualFixModal(index, error.message);
    }
}

function showAIFixPreviewModal(data) {
    const modal = document.getElementById('fixPreviewModal');
    const fixNotAvailable = document.getElementById('fixNotAvailable');
    const fixPreviewContent = document.getElementById('fixPreviewContent');
    
    fixNotAvailable.style.display = 'none';
    
    document.getElementById('modalTitle').textContent = 'AI-Generated Fix: ' + (data.finding.description || 'Security Issue');
    
    const previewHtml = `
        <div class="fix-info">
            <div class="fix-file-info">
                <span id="previewFile">📄 ${escapeHtml(data.finding.file)}</span>
                <span id="previewLine">📍 Line ${data.finding.line}</span>
            </div>
            <span class="finding-badge badge-${data.finding.severity.toLowerCase()}">${data.finding.severity}</span>
        </div>
        <div class="fix-description">
            <strong>🤖 AI Fix Explanation:</strong> ${escapeHtml(data.fix_explanation || data.finding.suggested_fix || 'Security fix applied.')}
        </div>
        
        <div class="code-comparison-full">
            <div class="code-panel-full before-panel">
                <div class="code-panel-header">
                    <span class="panel-icon">❌</span> Original File (with issue)
                </div>
                <pre class="code-block-full">${escapeHtml(data.original_content.substring(0, 3000))}${data.original_content.length > 3000 ? '\n... (truncated)' : ''}</pre>
            </div>
            <div class="code-arrow-down">⬇️</div>
            <div class="code-panel-full after-panel">
                <div class="code-panel-header">
                    <span class="panel-icon">✅</span> Fixed File (by Groq AI)
                </div>
                <pre class="code-block-full">${escapeHtml(data.fixed_content.substring(0, 3000))}${data.fixed_content.length > 3000 ? '\n... (truncated)' : ''}</pre>
            </div>
        </div>
        
        <div class="download-info">
            <p>📥 Click <strong>"Apply & Download"</strong> to download the fixed file.</p>
        </div>
    `;
    
    fixPreviewContent.innerHTML = previewHtml;
    fixPreviewContent.style.display = 'block';
    
    const applyBtn = document.getElementById('modalApplyBtn');
    applyBtn.innerHTML = '<span class="btn-icon">📥</span> Apply & Download';
    applyBtn.style.display = 'inline-flex';
    
    modal.style.display = 'flex';
}

function showFixPreviewModal(data) {
    const modal = document.getElementById('fixPreviewModal');
    const fixNotAvailable = document.getElementById('fixNotAvailable');
    const fixPreviewContent = document.getElementById('fixPreviewContent');
    
    fixNotAvailable.style.display = 'none';
    fixPreviewContent.style.display = 'block';
    
    document.getElementById('modalTitle').textContent = 'Fix Preview: ' + (data.finding.description || 'Security Issue');
    document.getElementById('previewFile').innerHTML = '📄 ' + data.finding.file;
    document.getElementById('previewLine').innerHTML = '📍 Line ' + data.finding.line;
    
    const severityBadge = document.getElementById('previewSeverity');
    severityBadge.textContent = data.finding.severity;
    severityBadge.className = 'finding-badge badge-' + data.finding.severity.toLowerCase();
    
    document.getElementById('previewDescription').textContent = data.finding.explanation || data.finding.suggested_fix || 'This fix will update the vulnerable code.';
    
    document.getElementById('beforeCode').textContent = data.original_code || '(no code)';
    document.getElementById('afterCode').textContent = data.replacement_code || '(no replacement)';
    
    const contextSection = document.getElementById('contextSection');
    const codeContext = document.getElementById('codeContext');
    
    if (data.context_before.length > 0 || data.context_after.length > 0) {
        contextSection.style.display = 'block';
        codeContext.innerHTML = '';
        
        data.context_before.forEach(line => {
            codeContext.innerHTML += `
                <div class="context-line">
                    <span class="line-number">${line.line_num}</span>
                    <span class="line-code">${escapeHtml(line.code)}</span>
                </div>
            `;
        });
        
        codeContext.innerHTML += `
            <div class="context-line highlight">
                <span class="line-number">${data.finding.line}</span>
                <span class="line-code">${escapeHtml(data.original_code)}</span>
            </div>
        `;
        
        codeContext.innerHTML += `
            <div class="context-line new-code">
                <span class="line-number">${data.finding.line}</span>
                <span class="line-code">${escapeHtml(data.replacement_code)}</span>
            </div>
        `;
        
        data.context_after.forEach(line => {
            codeContext.innerHTML += `
                <div class="context-line">
                    <span class="line-number">${line.line_num}</span>
                    <span class="line-code">${escapeHtml(line.code)}</span>
                </div>
            `;
        });
    } else {
        contextSection.style.display = 'none';
    }
    
    document.getElementById('modalApplyBtn').style.display = 'inline-flex';
    modal.style.display = 'flex';
}

function showManualFixModal(index, errorMessage = null) {
    const modal = document.getElementById('fixPreviewModal');
    const fixNotAvailable = document.getElementById('fixNotAvailable');
    const fixPreviewContent = document.getElementById('fixPreviewContent');
    const finding = currentFindings[index];
    
    fixPreviewContent.innerHTML = '';
    fixPreviewContent.style.display = 'none';
    fixNotAvailable.style.display = 'block';
    
    document.getElementById('modalTitle').textContent = 'Manual Fix Required';
    
    const manualFixSuggestion = document.getElementById('manualFixSuggestion');
    let content = '';
    
    if (errorMessage) {
        content += `<div class="error-msg"><strong>⚠️ AI Fix Unavailable:</strong> ${escapeHtml(errorMessage)}</div>`;
        content += `<p class="error-help">The AI could not generate a fix automatically. Please review the suggestion below and apply it manually.</p>`;
    }
    
    if (finding) {
        content += `
            <div class="manual-fix-details">
                <p><strong>File:</strong> ${escapeHtml(finding.file || 'Unknown')}</p>
                <p><strong>Line:</strong> ${finding.line || 'N/A'}</p>
                <p><strong>Issue:</strong> ${escapeHtml(finding.description || 'Security issue')}</p>
            </div>
        `;
        
        if (finding.suggested_fix) {
            content += `
                <div class="suggested-fix-box">
                    <h4>💡 Suggested Fix:</h4>
                    <p>${escapeHtml(finding.suggested_fix)}</p>
                </div>
            `;
        }
        
        if (finding.snippet) {
            content += `
                <div class="code-snippet-box">
                    <h4>📝 Problematic Code:</h4>
                    <pre class="code-snippet">${escapeHtml(finding.snippet)}</pre>
                </div>
            `;
        }
    } else {
        content += '<p>Please review the code and apply the fix manually based on the security issue description.</p>';
    }
    
    manualFixSuggestion.innerHTML = content;
    
    const applyBtn = document.getElementById('modalApplyBtn');
    applyBtn.innerHTML = '<span class="btn-icon">✅</span> Mark as Reviewed';
    applyBtn.style.display = 'inline-flex';
    applyBtn.disabled = false;
    
    modal.style.display = 'flex';
}

function closeFixModal() {
    document.getElementById('fixPreviewModal').style.display = 'none';
    currentFixIndex = null;
    currentFixOriginalIndex = null;
    currentFixData = null;
    
    const applyBtn = document.getElementById('modalApplyBtn');
    applyBtn.innerHTML = '<span class="btn-icon">✅</span> Apply Fix';
}

async function confirmApplyFix() {
    if (currentFixIndex === null) return;
    const targetIndex = currentFixOriginalIndex ?? currentFixIndex;
    
    const applyBtn = document.getElementById('modalApplyBtn');
    
    if (currentFixData && currentFixData.fixed_content) {
        applyBtn.disabled = true;
        applyBtn.innerHTML = '<span class="btn-icon">⏳</span> Downloading...';
        
        try {
            const filename = currentFixData.filename || 'fixed_file.txt';
            const mimeType = getMimeType(filename);
            
            const blob = new Blob([currentFixData.fixed_content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `fixed_${filename}`;
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
            
            showToast('📥 Fixed file downloaded successfully!', 'success');
            
            const applyResp = await fetch(`/api/apply-fix/${targetIndex}`, { method: 'POST' });
            const applyData = await applyResp.json();

            if (!applyData.success) {
                showToast(`Error applying fix: ${applyData.error || 'Unknown error'}`, 'error');
                return;
            }
            
            closeFixModal();
            refreshFindings();
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        } finally {
            applyBtn.disabled = false;
            applyBtn.innerHTML = '<span class="btn-icon">📥</span> Apply & Download';
        }
    } else {
        applyBtn.disabled = true;
        applyBtn.innerHTML = '<span class="btn-icon">⏳</span> Applying...';
        
        try {
            const response = await fetch(`/api/apply-fix/${targetIndex}`, { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                showToast('✅ Fix applied successfully!', 'success');
                closeFixModal();
                refreshFindings();
            } else {
                showToast(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        } finally {
            applyBtn.disabled = false;
            applyBtn.innerHTML = '<span class="btn-icon">✅</span> Apply Fix';
        }
    }
}

async function confirmSkipFix() {
    if (currentFixIndex === null) return;
    const targetIndex = currentFixOriginalIndex ?? currentFixIndex;
    
    try {
        const response = await fetch(`/api/skip-fix/${targetIndex}`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showToast('⏭️ Fix skipped', 'success');
            closeFixModal();
            refreshFindings();
        } else {
            showToast(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    }
}

async function skipFix(index) {
    currentFixIndex = index;
    currentFixOriginalIndex = currentFindings[index]?.original_index ?? index;
    
    try {
        const response = await fetch(`/api/skip-fix/${currentFixOriginalIndex ?? index}`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showToast('⏭️ Fix skipped', 'success');
            refreshFindings();
        } else {
            showToast(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    }
}

async function refreshFindings() {
    try {
        const response = await fetch('/api/findings');
        const data = await response.json();
        
        if (data.success) {
            currentFindings = data.findings;
            displayFindings(data.findings);
        }
    } catch (error) {
        console.error('Error refreshing findings:', error);
    }
}

async function generateReport() {
    try {
        const response = await fetch('/api/generate-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ format: 'pdf' })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentReportFilename = data.filename;
            document.getElementById('reportSection').style.display = 'block';
            
            document.getElementById('viewReportBtn').onclick = () => downloadReport(data.filename);
            document.getElementById('downloadReportBtn').onclick = () => downloadReport(data.filename);
            
            document.getElementById('viewReportBtn').textContent = '📥 Download & View PDF';
            document.getElementById('downloadReportBtn').textContent = '⬇️ Download PDF';
            
            showToast('📄 PDF Report generated successfully!', 'success');
        } else {
            showToast(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    }
}

function viewReport(content) {
    const reportPreview = document.getElementById('reportPreview');
    reportPreview.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${escapeHtml(content)}</pre>`;
    reportPreview.style.display = 'block';
}

function downloadReport(filename) {
    window.location.href = `/api/download-report/${filename}`;
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getMimeType(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const mimeTypes = {
        'js': 'text/javascript',
        'jsx': 'text/javascript',
        'ts': 'text/typescript',
        'tsx': 'text/typescript',
        'py': 'text/x-python',
        'java': 'text/x-java',
        'c': 'text/x-c',
        'cpp': 'text/x-c++',
        'h': 'text/x-c',
        'hpp': 'text/x-c++',
        'cs': 'text/x-csharp',
        'php': 'text/x-php',
        'rb': 'text/x-ruby',
        'go': 'text/x-go',
        'rs': 'text/x-rust',
        'swift': 'text/x-swift',
        'kt': 'text/x-kotlin',
        'html': 'text/html',
        'htm': 'text/html',
        'css': 'text/css',
        'json': 'application/json',
        'xml': 'application/xml',
        'yaml': 'text/yaml',
        'yml': 'text/yaml',
        'md': 'text/markdown',
        'txt': 'text/plain',
        'sql': 'text/x-sql',
        'sh': 'text/x-sh',
        'bash': 'text/x-sh',
        'env': 'text/plain',
        'ini': 'text/plain',
        'cfg': 'text/plain',
        'toml': 'text/x-toml'
    };
    return mimeTypes[ext] || 'text/plain';
}
