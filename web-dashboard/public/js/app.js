/**
 * CodeGuardian Dashboard - Frontend Logic
 */

// Initialize Socket.IO connection
const socket = io();

// State
let selectedFile = null;
let currentTab = 'scanner';

// ============================================================
// INITIALIZATION
// ============================================================

// Configure marked.js for better markdown rendering
if (typeof marked !== 'undefined') {
    marked.setOptions({
        breaks: true,
        gfm: true,
        headerIds: false,
        mangle: false
    });
}

document.addEventListener('DOMContentLoaded', () => {
    checkServerHealth();
    setupEventListeners();
    setupSocketListeners();
    loadReports();
});

// ============================================================
// SERVER HEALTH CHECK
// ============================================================

async function checkServerHealth() {
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');

    try {
        const response = await fetch('/api/health');
        const data = await response.json();

        if (data.status === 'healthy') {
            statusIndicator.style.background = '#43e97b';
            statusText.textContent = data.geminiApiKey ? 'Connected ✓' : 'No API Key';
        } else {
            statusIndicator.style.background = '#ffdd44';
            statusText.textContent = 'Degraded';
        }
    } catch (error) {
        statusIndicator.style.background = '#ff4444';
        statusText.textContent = 'Offline';
    }
}

// ============================================================
// EVENT LISTENERS
// ============================================================

function setupEventListeners() {
    // Tab navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = e.currentTarget.dataset.tab;
            switchTab(tab);
        });
    });

    // File upload
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');

    uploadZone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            selectedFile = e.target.files[0];
            uploadZone.innerHTML = `
                <i class="fas fa-file-code"></i>
                <p><strong>${selectedFile.name}</strong></p>
                <p class="text-sm">${(selectedFile.size / 1024).toFixed(2)} KB</p>
            `;
            document.getElementById('scan-file-btn').disabled = false;
        }
    });

    // Drag and drop
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('drag-over');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');

        if (e.dataTransfer.files.length > 0) {
            selectedFile = e.dataTransfer.files[0];
            fileInput.files = e.dataTransfer.files;
            uploadZone.innerHTML = `
                <i class="fas fa-file-code"></i>
                <p><strong>${selectedFile.name}</strong></p>
                <p class="text-sm">${(selectedFile.size / 1024).toFixed(2)} KB</p>
            `;
            document.getElementById('scan-file-btn').disabled = false;
        }
    });

    // Scan buttons
    document.getElementById('scan-file-btn').addEventListener('click', scanFile);
    document.getElementById('scan-project-btn').addEventListener('click', scanProject);

    // Close results
    document.getElementById('close-results').addEventListener('click', () => {
        document.getElementById('results-section').style.display = 'none';
    });

    // Chat
    document.getElementById('send-chat').addEventListener('click', sendChatMessage);
    document.getElementById('chat-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendChatMessage();
    });

    // Chat examples
    document.querySelectorAll('.example-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.getElementById('chat-input').value = btn.textContent;
            sendChatMessage();
        });
    });
}

// ============================================================
// SOCKET.IO LISTENERS
// ============================================================

function setupSocketListeners() {
    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('scan-progress', (data) => {
        const outputBox = document.getElementById('scan-output');
        outputBox.textContent += data.data;
        outputBox.scrollTop = outputBox.scrollHeight;
    });

    socket.on('scan-complete', (data) => {
        document.getElementById('scan-progress').style.display = 'none';
        if (data.success) {
            showNotification('Scan completed successfully!', 'success');
        } else {
            showNotification('Scan failed. Check output for details.', 'error');
        }
    });
}

// ============================================================
// TAB SWITCHING
// ============================================================

function switchTab(tabName) {
    currentTab = tabName;

    // Update nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.tab === tabName) {
            link.classList.add('active');
        }
    });

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');

    // Load reports if on reports tab
    if (tabName === 'reports') {
        loadReports();
    }
}

// ============================================================
// FILE SCANNING
// ============================================================

async function scanFile() {
    if (!selectedFile) {
        showNotification('Please select a file first', 'error');
        return;
    }

    const scanType = document.querySelector('input[name="scanType"]:checked').value;
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('scanType', scanType);

    // Show results section
    const resultsSection = document.getElementById('results-section');
    resultsSection.style.display = 'block';
    
    const progressDiv = document.getElementById('scan-progress');
    progressDiv.style.display = 'block';
    
    const outputBox = document.getElementById('scan-output');
    outputBox.textContent = '';
    outputBox.style.display = 'none';

    try {
        const response = await fetch('/api/scan/file', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        progressDiv.style.display = 'none';
        outputBox.style.display = 'block';
        outputBox.textContent = data.output || 'Scan completed. Check summary below.';

        if (data.report) {
            displayScanSummary(data.report);
        }

        showNotification('File scan completed!', 'success');
    } catch (error) {
        progressDiv.style.display = 'none';
        showNotification('Scan failed: ' + error.message, 'error');
    }
}

// ============================================================
// PROJECT SCANNING
// ============================================================

async function scanProject() {
    const projectPath = document.getElementById('project-path').value.trim();
    
    if (!projectPath) {
        showNotification('Please enter a project path', 'error');
        return;
    }

    const enableBattle = document.getElementById('enable-battle').checked;

    // Show results section
    const resultsSection = document.getElementById('results-section');
    resultsSection.style.display = 'block';
    
    const progressDiv = document.getElementById('scan-progress');
    progressDiv.style.display = 'block';
    
    const outputBox = document.getElementById('scan-output');
    outputBox.textContent = '';
    outputBox.style.display = 'block';

    try {
        const response = await fetch('/api/scan/project', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                projectPath,
                enableBattle,
                socketId: socket.id
            })
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Project scan started!', 'success');
        } else {
            showNotification('Failed to start scan', 'error');
        }
    } catch (error) {
        progressDiv.style.display = 'none';
        showNotification('Scan failed: ' + error.message, 'error');
    }
}

// ============================================================
// DISPLAY SCAN SUMMARY
// ============================================================

function displayScanSummary(report) {
    const summaryDiv = document.getElementById('scan-summary');
    
    const vulnerabilities = report.vulnerabilities || [];
    const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
    const high = vulnerabilities.filter(v => v.severity === 'high').length;
    const medium = vulnerabilities.filter(v => v.severity === 'medium').length;
    const low = vulnerabilities.filter(v => v.severity === 'low').length;
    
    const score = report.security_score || report.overall_score || 0;
    const grade = report.grade || 'N/A';

    summaryDiv.innerHTML = `
        <div style="padding: 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 15px; color: white; margin-top: 2rem;">
            <h3 style="margin: 0 0 1.5rem 0; font-size: 1.5rem;">📊 Scan Summary</h3>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
                <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 10px; text-align: center;">
                    <div style="font-size: 2rem; font-weight: 800;">${score.toFixed(1)}</div>
                    <div style="opacity: 0.9;">Security Score (${grade})</div>
                </div>
                <div style="background: rgba(255,68,68,0.3); padding: 1rem; border-radius: 10px; text-align: center;">
                    <div style="font-size: 2rem; font-weight: 800;">${critical}</div>
                    <div style="opacity: 0.9;">Critical</div>
                </div>
                <div style="background: rgba(255,153,68,0.3); padding: 1rem; border-radius: 10px; text-align: center;">
                    <div style="font-size: 2rem; font-weight: 800;">${high}</div>
                    <div style="opacity: 0.9;">High</div>
                </div>
                <div style="background: rgba(255,221,68,0.3); padding: 1rem; border-radius: 10px; text-align: center;">
                    <div style="font-size: 2rem; font-weight: 800;">${medium}</div>
                    <div style="opacity: 0.9;">Medium</div>
                </div>
                <div style="background: rgba(67,233,123,0.3); padding: 1rem; border-radius: 10px; text-align: center;">
                    <div style="font-size: 2rem; font-weight: 800;">${low}</div>
                    <div style="opacity: 0.9;">Low</div>
                </div>
            </div>

            <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 10px;">
                <strong>Total Vulnerabilities:</strong> ${vulnerabilities.length}
            </div>
        </div>
    `;
}

// ============================================================
// CHAT
// ============================================================

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();

    if (!message) return;

    const messagesContainer = document.getElementById('chat-messages');

    // Add user message
    const userMessage = document.createElement('div');
    userMessage.className = 'chat-message user';
    userMessage.innerHTML = `
        <div class="message-avatar">
            <i class="fas fa-user"></i>
        </div>
        <div class="message-content">
            <p>${escapeHtml(message)}</p>
        </div>
    `;
    messagesContainer.appendChild(userMessage);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    input.value = '';

    // Show typing indicator
    const typingDiv = document.createElement('div');
    typingDiv.className = 'chat-message bot typing-indicator';
    typingDiv.id = 'typing-indicator';
    typingDiv.innerHTML = `
        <div class="message-avatar">
            <i class="fas fa-robot"></i>
        </div>
        <div class="message-content">
            <p>Thinking...</p>
        </div>
    `;
    messagesContainer.appendChild(typingDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });

        const data = await response.json();

        // Remove typing indicator
        document.getElementById('typing-indicator').remove();

        // Add bot response with markdown rendering
        const botMessage = document.createElement('div');
        botMessage.className = 'chat-message bot';
        const responseText = data.response || 'Sorry, I could not process that.';
        const htmlContent = marked.parse(responseText);
        
        botMessage.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-robot"></i>
            </div>
            <div class="message-content markdown-content">
                ${htmlContent}
            </div>
        `;
        messagesContainer.appendChild(botMessage);
        
        // Apply syntax highlighting to code blocks
        botMessage.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
            
            // Add copy button
            const pre = block.parentElement;
            const copyBtn = document.createElement('button');
            copyBtn.className = 'copy-code-btn';
            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
            copyBtn.onclick = () => {
                navigator.clipboard.writeText(block.textContent);
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
                }, 2000);
            };
            pre.style.position = 'relative';
            pre.appendChild(copyBtn);
        });
        
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

    } catch (error) {
        document.getElementById('typing-indicator').remove();
        showNotification('Chat failed: ' + error.message, 'error');
    }
}

// ============================================================
// LOAD REPORTS
// ============================================================

async function loadReports() {
    const reportsList = document.getElementById('reports-list');
    reportsList.innerHTML = '<p class="text-center">Loading reports...</p>';

    try {
        const response = await fetch('/api/reports');
        const data = await response.json();

        if (data.reports.length === 0) {
            reportsList.innerHTML = '<p class="text-center">No reports found. Run a scan first!</p>';
            return;
        }

        reportsList.innerHTML = '';

        data.reports.forEach((report, index) => {
            const reportDiv = document.createElement('div');
            reportDiv.className = 'report-item';
            
            const reportData = report.data;
            const timestamp = reportData.scan_timestamp || 'Unknown';
            const vulnerabilities = (reportData.vulnerabilities || []).length;
            const score = reportData.security_score || reportData.overall_score || 0;

            reportDiv.innerHTML = `
                <h4>📄 Report #${index + 1}</h4>
                <p><strong>Date:</strong> ${timestamp}</p>
                <p><strong>Vulnerabilities:</strong> ${vulnerabilities}</p>
                <p><strong>Security Score:</strong> ${score.toFixed(1)}/100</p>
                <p><small>${report.filename}</small></p>
            `;

            reportsList.appendChild(reportDiv);
        });

    } catch (error) {
        reportsList.innerHTML = '<p class="text-center">Failed to load reports</p>';
    }
}

// ============================================================
// UTILITIES
// ============================================================

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? '#43e97b' : type === 'error' ? '#ff4444' : '#667eea'};
        color: white;
        border-radius: 10px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);
