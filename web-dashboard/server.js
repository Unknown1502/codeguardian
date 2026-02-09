/**
 * CodeGuardian Web Dashboard - Node.js/Express Server
 * Modern, fast, and secure web interface
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer');
const { spawn } = require('child_process');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// File upload configuration
const upload = multer({
    dest: path.join(__dirname, 'uploads'),
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// ============================================================
// API ROUTES
// ============================================================

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        geminiApiKey: !!process.env.GEMINI_API_KEY
    });
});

// Scan uploaded file
app.post('/api/scan/file', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const { scanType } = req.body;
    const filePath = req.file.path;
    
    try {
        const pythonPath = path.join(__dirname, '..', 'venv', 'Scripts', 'python.exe');
        const mainPath = path.join(__dirname, '..', 'src', 'main.py');
        
        // Execute scan
        const scanProcess = spawn(pythonPath, [
            '-m', 'src.main',
            '--scan', filePath,
            '--max-time', scanType === 'quick' ? '60' : '300'
        ], {
            cwd: path.join(__dirname, '..')
        });

        let output = '';
        let errorOutput = '';

        scanProcess.stdout.on('data', (data) => {
            output += data.toString();
            io.emit('scan-progress', { data: data.toString() });
        });

        scanProcess.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });

        scanProcess.on('close', (code) => {
            // Clean up uploaded file
            fs.unlinkSync(filePath);

            if (code !== 0) {
                return res.status(500).json({
                    error: 'Scan failed',
                    details: errorOutput
                });
            }

            // Parse scan results
            try {
                const reportsDir = path.join(__dirname, '..', 'reports');
                const files = fs.readdirSync(reportsDir)
                    .filter(f => f.startsWith('report_') && f.endsWith('.json'))
                    .sort()
                    .reverse();

                if (files.length > 0) {
                    const latestReport = fs.readFileSync(
                        path.join(reportsDir, files[0]),
                        'utf8'
                    );
                    res.json({
                        success: true,
                        report: JSON.parse(latestReport),
                        output: output
                    });
                } else {
                    res.json({
                        success: true,
                        output: output
                    });
                }
            } catch (parseError) {
                res.json({
                    success: true,
                    output: output
                });
            }
        });

    } catch (error) {
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// Scan project directory
app.post('/api/scan/project', async (req, res) => {
    const { projectPath, enableBattle } = req.body;

    if (!projectPath) {
        return res.status(400).json({ error: 'Project path required' });
    }

    try {
        const pythonPath = path.join(__dirname, '..', 'venv', 'Scripts', 'python.exe');
        
        const args = [
            '-m', 'src.main',
            '--scan', projectPath,
            '--max-time', '600'
        ];

        if (enableBattle) {
            args.push('--simulate-attacks');
        }

        const scanProcess = spawn(pythonPath, args, {
            cwd: path.join(__dirname, '..')
        });

        let output = '';

        scanProcess.stdout.on('data', (data) => {
            output += data.toString();
            io.emit('scan-progress', { 
                data: data.toString(),
                socketId: req.body.socketId 
            });
        });

        scanProcess.on('close', (code) => {
            io.emit('scan-complete', {
                success: code === 0,
                socketId: req.body.socketId
            });
        });

        res.json({ 
            success: true, 
            message: 'Scan started',
            socketId: req.body.socketId
        });

    } catch (error) {
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

// Get recent reports
app.get('/api/reports', (req, res) => {
    try {
        const reportsDir = path.join(__dirname, '..', 'reports');
        const files = fs.readdirSync(reportsDir)
            .filter(f => f.startsWith('report_') && f.endsWith('.json'))
            .sort()
            .reverse()
            .slice(0, 10);

        const reports = files.map(file => {
            const content = fs.readFileSync(path.join(reportsDir, file), 'utf8');
            return {
                filename: file,
                data: JSON.parse(content)
            };
        });

        res.json({ reports });
    } catch (error) {
        res.status(500).json({
            error: 'Failed to load reports',
            message: error.message
        });
    }
});

// Chat with AI
app.post('/api/chat', async (req, res) => {
    const { message } = req.body;

    if (!message) {
        return res.status(400).json({ error: 'Message required' });
    }

    try {
        const pythonPath = path.join(__dirname, '..', 'venv', 'Scripts', 'python.exe');
        const workingDir = path.join(__dirname, '..');
        
        // Escape message for JSON
        const escapedMessage = JSON.stringify(message);
        
        const chatScript = `
import sys
import os
import json
import asyncio

# Add project to path
sys.path.insert(0, r'${workingDir.replace(/\\/g, '\\\\')}')

try:
    from src.core.gemini_client import GeminiClient
    
    async def chat():
        try:
            api_key = os.getenv('GEMINI_API_KEY', '${process.env.GEMINI_API_KEY || ''}')
            if not api_key:
                print("ERROR: No Gemini API key configured")
                return
            
            client = GeminiClient(api_key=api_key)
            
            user_message = ${escapedMessage}
            
            prompt = f"""You are CodeGuardian AI, an expert security assistant powered by Gemini 3 Flash & Pro.

User question: {user_message}

Instructions:
- Provide clear, actionable security advice
- Use **markdown formatting** for better readability:
  * Use **bold** for important terms
  * Use ### headings for sections
  * Use code blocks with \`\`\`language syntax for code examples
  * Use bullet points or numbered lists for steps
  * Use > blockquotes for key warnings or tips
- Be thorough but concise
- Include practical code examples when relevant
- Explain vulnerabilities with context and real-world impact
- Always suggest secure alternatives

Respond in well-formatted markdown."""
            
            response = await client.analyze_with_extended_reasoning(prompt=prompt, thinking_level=2)
            
            # Get response text from the result
            if response.get('success') and 'response' in response:
                content = response['response']
            elif 'error' in response:
                content = f"I apologize, but I encountered an error: {response['error']}"
            else:
                content = 'I apologize, but I could not generate a response. Please try rephrasing your question.'
            
            print(content)
            
        except Exception as e:
            print(f"ERROR: {str(e)}")
    
    asyncio.run(chat())
    
except Exception as e:
    print(f"ERROR: {str(e)}")
`;

        const tempScript = path.join(__dirname, 'temp_chat.py');
        fs.writeFileSync(tempScript, chatScript, 'utf8');

        const chatProcess = spawn(pythonPath, [tempScript], {
            cwd: workingDir,
            env: { ...process.env }
        });

        let output = '';
        let errorOutput = '';

        chatProcess.stdout.on('data', (data) => {
            output += data.toString();
        });

        chatProcess.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });

        chatProcess.on('close', (code) => {
            try {
                fs.unlinkSync(tempScript);
            } catch (e) {
                // Ignore cleanup errors
            }

            const trimmedOutput = output.trim();
            const trimmedError = errorOutput.trim();

            if (trimmedOutput && !trimmedOutput.startsWith('ERROR:')) {
                res.json({
                    success: true,
                    response: trimmedOutput
                });
            } else {
                console.error('Chat error:', trimmedError || trimmedOutput);
                res.json({
                    success: false,
                    response: 'I apologize, but I encountered an issue. Please ensure your GEMINI_API_KEY is configured in the .env file.'
                });
            }
        });

        // Timeout after 30 seconds
        setTimeout(() => {
            chatProcess.kill();
            try {
                fs.unlinkSync(tempScript);
            } catch (e) {
                // Ignore
            }
            if (!res.headersSent) {
                res.json({
                    success: false,
                    response: 'Request timed out. Please try a simpler question.'
                });
            }
        }, 30000);

    } catch (error) {
        res.status(500).json({
            error: 'Chat failed',
            message: error.message,
            response: 'An unexpected error occurred. Please try again.'
        });
    }
});

// ============================================================
// SOCKET.IO
// ============================================================

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// ============================================================
// START SERVER
// ============================================================

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║         🛡️  CodeGuardian Dashboard                   ║
║         Modern Node.js Web Interface                  ║
║                                                       ║
║         🌐 Server: http://localhost:${PORT}             ║
║         ⚡ Status: Running                            ║
║         🤖 Gemini API: ${process.env.GEMINI_API_KEY ? 'Connected' : 'Not configured'}               ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
    `);
});

module.exports = { app, server, io };
