let currentFindings = [];
let currentReportFilename = null;

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
    try {
        const response = await fetch(`/api/apply-fix/${index}`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showToast('✅ Fix applied successfully!', 'success');
            refreshFindings();
        } else {
            showToast(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    }
}

async function skipFix(index) {
    try {
        const response = await fetch(`/api/skip-fix/${index}`, { method: 'POST' });
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
            body: JSON.stringify({ format: 'markdown' })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentReportFilename = data.filename;
            document.getElementById('reportSection').style.display = 'block';
            
            document.getElementById('viewReportBtn').onclick = () => viewReport(data.content);
            document.getElementById('downloadReportBtn').onclick = () => downloadReport(data.filename);
            
            showToast('📄 Report generated successfully!', 'success');
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

