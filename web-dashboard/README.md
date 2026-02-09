# CodeGuardian Web Dashboard

Modern Node.js/Express-based web interface for CodeGuardian AI Security Scanner

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd web-dashboard
npm install
```

### 2. Start the Server

```bash
npm start
```

Or with auto-reload during development:

```bash
npm run dev
```

### 3. Access Dashboard

Open your browser and navigate to:
```
http://localhost:3000
```

## ✨ Features

### 🔍 File Scanner
- Drag & drop file upload
- Quick scan (60s) or Deep scan (300s)
- Real-time progress updates
- Detailed vulnerability reports

### 📂 Project Scanner
- Scan entire project directories
- Optional Red Team vs Blue Team battles
- Live progress streaming via WebSocket
- Comprehensive security analysis

### 💬 AI Security Assistant
- Chat with Gemini 3 AI
- Ask about vulnerabilities
- Get code reviews
- Learn security best practices

### 📊 Reports Dashboard
- View scan history
- Analyze past vulnerabilities
- Track security improvements

## 🛠️ Technology Stack

- **Backend**: Node.js, Express.js
- **Real-time**: Socket.IO
- **Frontend**: Vanilla JavaScript (no framework overhead)
- **Styling**: Modern CSS with gradients and animations
- **AI**: Gemini 3 Flash & Pro integration

## 📁 Project Structure

```
web-dashboard/
├── server.js              # Express server & API routes
├── package.json           # Dependencies
├── public/
│   ├── index.html        # Main UI
│   ├── css/
│   │   └── style.css     # Modern styling
│   └── js/
│       └── app.js        # Frontend logic
└── uploads/              # Temporary file storage
```

## 🔧 Configuration

The dashboard automatically reads your `.env` file from the parent directory:

```env
GEMINI_API_KEY=your_api_key_here
PORT=3000  # Optional, defaults to 3000
```

## 🎨 UI/UX Features

- **Modern Gradient Design**: Beautiful purple-to-violet gradient theme
- **Responsive Layout**: Works on desktop, tablet, and mobile
- **Real-time Updates**: Socket.IO for live progress streaming
- **Smooth Animations**: Fade-ins, slides, and hover effects
- **Intuitive Navigation**: Tab-based interface
- **Drag & Drop**: Easy file uploads
- **Accessibility**: ARIA labels and keyboard navigation

## 📡 API Endpoints

### GET `/api/health`
Check server health and Gemini API connection

### POST `/api/scan/file`
Scan an uploaded file
- Body: `multipart/form-data` with `file` and `scanType`
- Returns: Scan results and report JSON

### POST `/api/scan/project`
Scan a project directory
- Body: `{ projectPath, enableBattle, socketId }`
- Returns: Scan started confirmation

### GET `/api/reports`
Get recent scan reports
- Returns: List of recent reports with data

### POST `/api/chat`
Chat with AI assistant
- Body: `{ message }`
- Returns: AI response

## 🔌 WebSocket Events

### Client → Server
- None currently (uses HTTP for actions)

### Server → Client
- `scan-progress`: Real-time scan output
- `scan-complete`: Scan completion notification

## 🚀 Deployment

### Local Development
```bash
npm run dev
```

### Production
```bash
npm start
```

### Environment Variables
```
PORT=3000
GEMINI_API_KEY=your_api_key
NODE_ENV=production
```

## 🎯 Performance

- **Fast**: Vanilla JS, no heavy frameworks
- **Lightweight**: Minimal dependencies
- **Real-time**: WebSocket for instant updates
- **Efficient**: Async/await for non-blocking operations

## 🔒 Security

- File size limits (10MB)
- Temporary file cleanup
- Input sanitization
- CORS configuration
- Error handling

## 📝 Notes

- Uploaded files are stored temporarily in `uploads/` and deleted after scanning
- Reports are stored in parent directory's `reports/` folder
- Python scanner must be accessible via `../venv/Scripts/python.exe`
- Requires CodeGuardian core scanner to be installed in parent directory

## 🐛 Troubleshooting

### Server won't start
- Check if port 3000 is available
- Verify `npm install` completed successfully
- Ensure `.env` file exists in parent directory

### Scans fail
- Verify Python virtual environment is activated
- Check GEMINI_API_KEY is set correctly
- Ensure CodeGuardian core is installed properly

### WebSocket not connecting
- Check firewall settings
- Verify Socket.IO client version matches server
- Try refreshing the page

## 📦 Dependencies

```json
{
  "express": "^4.18.2",
  "socket.io": "^4.6.1",
  "cors": "^2.8.5",
  "dotenv": "^16.3.1",
  "body-parser": "^1.20.2",
  "multer": "^1.4.5-lts.1"
}
```

## 🎓 Development

### Adding New Features

1. **New API Endpoint**: Add route in `server.js`
2. **New UI Section**: Add tab in `index.html`
3. **New Styling**: Add CSS in `style.css`
4. **New Logic**: Add functions in `app.js`

### Code Style

- Use async/await for promises
- ES6+ features
- Consistent naming conventions
- Comment complex logic

## 📄 License

MIT License - Same as CodeGuardian core

## 🙋 Support

For issues or questions:
1. Check this README
2. Review console logs
3. Check server terminal output
4. Open an issue on GitHub

---

**Enjoy using CodeGuardian Web Dashboard!** 🛡️✨
