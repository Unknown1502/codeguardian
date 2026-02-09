# CodeGuardian - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Prerequisites
- Python 3.10 or higher
- Gemini API key (free tier available)

### Step 1: Get Your API Key
1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Sign in with your Google account
3. Click "Get API Key"
4. Copy your API key

### Step 2: Install Dependencies
```bash
# Navigate to project directory
cd CodeGuardian

# Install Python dependencies
pip install -r requirements.txt
```

### Step 3: Configure API Key
```bash
# Copy the example environment file
copy .env.example .env

# Edit .env and add your API key
# GEMINI_API_KEY=your_actual_api_key_here
```

### Step 4: Run Your First Scan
```bash
# Scan a sample project
python src/main.py --scan ./examples/vulnerable_app

# Or scan your own codebase
python src/main.py --scan C:\path\to\your\project
```

### Step 5: View the Report
The scan will generate an HTML report in the `reports/` directory.
Open it in your browser to see:
- Detected vulnerabilities
- Severity rankings
- Fix recommendations
- Code snippets

## 🎯 Common Commands

### Basic Scan
```bash
python src/main.py --scan /path/to/code
```

### Scan with Auto-Fix
```bash
python src/main.py --scan /path/to/code --auto-fix
```

### Focus on Specific Vulnerabilities
```bash
python src/main.py --scan /path/to/code --focus sql-injection,xss
```

### Set Custom Time Limit
```bash
python src/main.py --scan /path/to/code --max-time 7200
```

## 🔍 What CodeGuardian Checks

- ✅ SQL Injection (CWE-89)
- ✅ Cross-Site Scripting / XSS (CWE-79)
- ✅ Command Injection (CWE-78)
- ✅ Path Traversal (CWE-22)
- ✅ Insecure Deserialization (CWE-502)
- ✅ Broken Authentication (CWE-287)
- ✅ Sensitive Data Exposure (CWE-200)
- ✅ XML External Entities / XXE (CWE-611)
- ✅ Broken Access Control (CWE-639)
- ✅ Security Misconfiguration (CWE-16)

## 📊 Understanding the Report

### Severity Levels
- **Critical**: Immediate action required. Actively exploitable.
- **High**: Serious security risk. Should be fixed soon.
- **Medium**: Moderate risk. Fix when possible.
- **Low**: Minor issue. Consider fixing.

### Vulnerability Details
Each finding includes:
1. **Type**: What kind of vulnerability (SQL injection, XSS, etc.)
2. **Location**: Exact file and line number
3. **Description**: What's wrong and why it's dangerous
4. **Exploit**: How an attacker could exploit it
5. **Fix**: Concrete steps to remediate

## 🛠️ Troubleshooting

### "API Key not configured"
- Make sure you copied `.env.example` to `.env`
- Check that your API key is correct
- Verify no extra spaces or quotes around the key

### "Rate limit exceeded"
- The free tier has limits on requests per minute
- Wait a few minutes and try again
- Consider using `--max-time` to spread out requests

### "Failed to parse file"
- CodeGuardian may not support that file type yet
- Check if the file has syntax errors
- The scan will continue with other files

## 🎓 Next Steps

1. **Run on Your Codebase**: Try scanning your actual project
2. **Enable Auto-Fix**: Add `--auto-fix` to generate patches
3. **Review Output**: Check the HTML report carefully
4. **Customize**: Edit scan types, time limits, etc.

## 📚 Learn More

- [Full Documentation](docs/DOCUMENTATION.md)
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Contributing Guide](CONTRIBUTING.md)

## 💡 Tips for Best Results

1. **Start Small**: Test on a small project first
2. **Review Findings**: Not all detections are true vulnerabilities
3. **Test Fixes**: Always test auto-generated fixes before deploying
4. **Iterate**: Run multiple scans as you fix issues

## ❓ Need Help?

- Check the [FAQ](docs/FAQ.md)
- Open an issue on GitHub
- Review example scans in `examples/`

---

**Ready to secure your code? Let's go! 🛡️**
