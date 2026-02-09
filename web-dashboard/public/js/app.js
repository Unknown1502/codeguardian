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

    // Terminal output handler
    socket.on('terminal-output', (data) => {
        if (term) {
            term.write(data.data);
            
            // Write new prompt when command finishes
            if (data.exitCode !== undefined) {
                writePrompt();
            }
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

        if (data.success && data.report) {
            displayScanSummary(data.report);
        } else if (!data.success) {
            showNotification('Scan failed: ' + (data.error || 'Unknown error'), 'error');
        }

        showNotification('File scan completed!', 'success');
    } catch (error) {
        progressDiv.style.display = 'none';
        showNotification('Scan failed: ' + error.message, 'error');
        console.error('Scan error:', error);
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
    
    // Handle different report structures
    let vulnerabilities = [];
    if (report && report.vulnerabilities) {
        // New format: vulnerabilities.list
        if (report.vulnerabilities.list && Array.isArray(report.vulnerabilities.list)) {
            vulnerabilities = report.vulnerabilities.list;
        } 
        // Old format: vulnerabilities is array directly
        else if (Array.isArray(report.vulnerabilities)) {
            vulnerabilities = report.vulnerabilities;
        } else {
            console.warn('Unexpected vulnerabilities format:', report.vulnerabilities);
        }
    }
    
    // Get counts from by_severity if available, otherwise count from list
    let critical, high, medium, low;
    if (report.vulnerabilities && report.vulnerabilities.by_severity) {
        critical = report.vulnerabilities.by_severity.critical || 0;
        high = report.vulnerabilities.by_severity.high || 0;
        medium = report.vulnerabilities.by_severity.medium || 0;
        low = report.vulnerabilities.by_severity.low || 0;
    } else {
        critical = vulnerabilities.filter(v => v && v.severity === 'critical').length;
        high = vulnerabilities.filter(v => v && v.severity === 'high').length;
        medium = vulnerabilities.filter(v => v && v.severity === 'medium').length;
        low = vulnerabilities.filter(v => v && v.severity === 'low').length;
    }
    
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

            <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 10px; margin-bottom: 1rem;">
                <strong>Total Vulnerabilities:</strong> ${report.vulnerabilities && report.vulnerabilities.total ? report.vulnerabilities.total : vulnerabilities.length}
            </div>
            
            <div style="display: flex; gap: 1rem; justify-content: center;">
                <button onclick="viewFullReport()" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: 2px solid rgba(255,255,255,0.3); padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 1rem; transition: all 0.3s ease;">
                    <i class="fas fa-file-alt"></i> View Full Report
                </button>
                <button onclick="downloadReport()" style="background: rgba(255,255,255,0.1); color: white; border: 2px solid rgba(255,255,255,0.3); padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 1rem; transition: all 0.3s ease;">
                    <i class="fas fa-download"></i> Download Report
                </button>
            </div>
        </div>
    `;
}

function viewFullReport() {
    window.open('/api/report/latest', '_blank');
}

function downloadReport() {
    window.location.href = '/api/report/download';
}

function viewSpecificReport(timestamp) {
    window.open(`/api/report/view/${timestamp}`, '_blank');
}

function downloadSpecificReport(timestamp) {
    window.location.href = `/api/report/download/${timestamp}`;
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
            const metadata = reportData.metadata || {};
            const timestamp = metadata.generated_at || reportData.scan_timestamp || 'Unknown';
            
            // Extract timestamp from filename (report_YYYYMMDD_HHMMSS.json)
            const timestampMatch = report.filename.match(/report_(\d{8}_\d{6})\.json/);
            const reportTimestamp = timestampMatch ? timestampMatch[1] : null;
            
            // Get vulnerability count
            let vulnerabilities = 0;
            if (reportData.vulnerabilities) {
                if (reportData.vulnerabilities.total !== undefined) {
                    vulnerabilities = reportData.vulnerabilities.total;
                } else if (Array.isArray(reportData.vulnerabilities)) {
                    vulnerabilities = reportData.vulnerabilities.length;
                } else if (reportData.vulnerabilities.list) {
                    vulnerabilities = reportData.vulnerabilities.list.length;
                }
            }
            
            const score = reportData.security_score || reportData.overall_score || 0;
            const grade = reportData.grade || 'N/A';

            reportDiv.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div>
                        <h4 style="margin: 0 0 0.5rem 0;">📄 Report #${index + 1}</h4>
                        <p style="margin: 0.25rem 0;"><strong>Date:</strong> ${new Date(timestamp).toLocaleString()}</p>
                        <p style="margin: 0.25rem 0;"><strong>Vulnerabilities:</strong> ${vulnerabilities}</p>
                        <p style="margin: 0.25rem 0;"><strong>Security Score:</strong> ${score.toFixed(1)}/100 (${grade})</p>
                        <p style="margin: 0.25rem 0; font-size: 0.85rem; opacity: 0.7;">${report.filename}</p>
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                        ${reportTimestamp ? `
                            <button onclick="viewSpecificReport('${reportTimestamp}')" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; white-space: nowrap;">
                                <i class="fas fa-eye"></i> View
                            </button>
                            <button onclick="downloadSpecificReport('${reportTimestamp}')" style="background: #2d3748; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; white-space: nowrap;">
                                <i class="fas fa-download"></i> Download
                            </button>
                        ` : ''}
                    </div>
                </div>
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
// ============================================================
// TERMINAL
// ============================================================

let term = null;
let fitAddon = null;
let commandHistory = [];
let historyIndex = -1;
let currentCommand = '';

function initTerminal() {
    if (!window.Terminal || term) return;

    // Initialize terminal
    term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'Courier New, monospace',
        theme: {
            background: '#1e1e1e',
            foreground: '#d4d4d4',
            cursor: '#d4d4d4',
            selection: '#264f78',
            black: '#000000',
            red: '#cd3131',
            green: '#0dbc79',
            yellow: '#e5e510',
            blue: '#2472c8',
            magenta: '#bc3fbc',
            cyan: '#11a8cd',
            white: '#e5e5e5',
            brightBlack: '#666666',
            brightRed: '#f14c4c',
            brightGreen: '#23d18b',
            brightYellow: '#f5f543',
            brightBlue: '#3b8eea',
            brightMagenta: '#d670d6',
            brightCyan: '#29b8db',
            brightWhite: '#e5e5e5'
        },
        scrollback: 1000
    });

    // Initialize fit addon
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);

    // Mount terminal
    const terminalElement = document.getElementById('terminal');
    if (terminalElement) {
        term.open(terminalElement);
        fitAddon.fit();

        // Welcome message
        term.writeln('\\x1b[1;32m╔═══════════════════════════════════════════════════════════╗\\x1b[0m');
        term.writeln('\\x1b[1;32m║         CodeGuardian CLI Terminal - Web Interface        ║\\x1b[0m');
        term.writeln('\\x1b[1;32m╚═══════════════════════════════════════════════════════════╝\\x1b[0m');
        term.writeln('');
        term.writeln('\\x1b[1;36mℹ Type commands or use Quick Commands buttons below\\x1b[0m');
        term.writeln('\\x1b[1;36mℹ Commands execute in project root directory\\x1b[0m');
        term.writeln('');
        writePrompt();

        // Handle keyboard input
        term.onData(data => handleTerminalInput(data));

        // Handle window resize
        window.addEventListener('resize', () => {
            if (fitAddon && term) {
                fitAddon.fit();
            }
        });
    }
}

function writePrompt() {
    term.write('\\x1b[1;33mCodeGuardian>\\x1b[0m ');
}

function handleTerminalInput(data) {
    const code = data.charCodeAt(0);

    // Handle Enter
    if (code === 13) {
        term.writeln('');
        if (currentCommand.trim()) {
            executeTerminalCommand(currentCommand.trim());
            commandHistory.push(currentCommand.trim());
            historyIndex = commandHistory.length;
        } else {
            writePrompt();
        }
        currentCommand = '';
    }
    // Handle Backspace
    else if (code === 127) {
        if (currentCommand.length > 0) {
            currentCommand = currentCommand.slice(0, -1);
            term.write('\\b \\b');
        }
    }
    // Handle Up Arrow (history)
    else if (data === '\\x1b[A') {
        if (historyIndex > 0) {
            // Clear current line
            term.write('\\r\\x1b[K');
            writePrompt();
            
            historyIndex--;
            currentCommand = commandHistory[historyIndex];
            term.write(currentCommand);
        }
    }
    // Handle Down Arrow (history)
    else if (data === '\\x1b[B') {
        if (historyIndex < commandHistory.length - 1) {
            // Clear current line
            term.write('\\r\\x1b[K');
            writePrompt();
            
            historyIndex++;
            currentCommand = commandHistory[historyIndex];
            term.write(currentCommand);
        } else {
            // Clear current line
            term.write('\\r\\x1b[K');
            writePrompt();
            currentCommand = '';
            historyIndex = commandHistory.length;
        }
    }
    // Ignore other control characters
    else if (code < 32 && code !== 9) {
        return;
    }
    // Regular character
    else {
        currentCommand += data;
        term.write(data);
    }
}

function executeTerminalCommand(command) {
    term.writeln(command);
    term.writeln('\\x1b[2;37m[Executing...]\\x1b[0m');

    // Emit command to server via socket
    socket.emit('terminal-command', { command });
}

function clearTerminal() {
    if (term) {
        term.clear();
        term.writeln('\\x1b[1;32mTerminal cleared!\\x1b[0m');
        term.writeln('');
        writePrompt();
    }
}

function runQuickCommand(command) {
    if (term) {
        // Clear current input
        term.write('\\r\\x1b[K');
        writePrompt();
        term.write(command);
        currentCommand = command;
        
        // Simulate Enter key
        setTimeout(() => {
            term.writeln('');
            executeTerminalCommand(command);
            commandHistory.push(command);
            historyIndex = commandHistory.length;
            currentCommand = '';
        }, 100);
    }
}

// Initialize terminal when terminal tab is clicked
document.addEventListener('click', (e) => {
    if (e.target.closest('[data-tab="terminal"]')) {
        setTimeout(initTerminal, 100);
    }
});