# CodeGuardian Example Vulnerable Applications

This directory contains **intentionally vulnerable code** for testing CodeGuardian's security scanning capabilities. These files demonstrate common security vulnerabilities across multiple programming languages.

⚠️ **WARNING**: These files contain deliberately insecure code. **NEVER use these patterns in production applications!**

## 📁 Files Overview

### 🐍 Python - `vulnerable_app.py`
Flask web application with 10+ vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Hardcoded Secrets
- Insecure Deserialization
- Weak Cryptography (MD5)
- Missing Authentication
- Dangerous `eval()` usage
- Unrestricted File Upload

### 🟨 JavaScript/Node.js - `vulnerable_api.js`
Express.js API with 17 vulnerabilities:
- SQL Injection & NoSQL Injection
- Command Injection
- Path Traversal
- Hardcoded AWS/JWT Secrets
- Insecure Deserialization
- Weak Cryptography (MD5, DES)
- SSRF (Server-Side Request Forgery)
- ReDoS (Regular Expression DoS)
- XXE (XML External Entity)
- Prototype Pollution
- Insecure CORS
- Memory Leaks
- Open Redirects

### ☕ Java - `VulnerableApp.java`
Java Servlet application with 20 vulnerabilities:
- SQL Injection
- Command Injection
- Path Traversal
- XXE (XML External Entity)
- Insecure Deserialization
- Weak Cryptography
- LDAP Injection
- SSRF
- XSS
- Race Conditions
- Memory Leaks
- Unsafe Reflection
- Resource Leaks
- Null Pointer Dereference

### 🐘 PHP - `vulnerable_web.php`
PHP web application with 24 vulnerabilities:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Remote Code Execution (RCE)
- Local/Remote File Inclusion
- Insecure Deserialization
- CSRF (Cross-Site Request Forgery)
- XXE
- LDAP Injection
- SSRF
- IDOR (Insecure Direct Object Reference)
- Type Juggling
- Mass Assignment
- Header Injection
- TOCTOU Race Conditions

### 🔷 Go - `vulnerable_code.go`
Go web server with 24 vulnerabilities:
- SQL Injection
- Command Injection
- Path Traversal
- XXE
- Weak Cryptography (MD5)
- Insecure Random Generation
- SSRF
- Open Redirects
- Race Conditions
- TOCTOU
- Insecure File Permissions
- Memory Disclosure
- DoS (Denial of Service)
- ReDoS
- Template Injection
- Integer Overflow
- Insecure TLS Configuration

## 🎯 Testing with CodeGuardian

### Quick Start

**1. Scan a single file:**
```bash
python -m src.main --scan examples/vulnerable_app.py
```

**2. Scan all examples:**
```bash
python -m src.main --scan examples/
```

**3. Scan with auto-fix:**
```bash
python -m src.main --scan examples/vulnerable_app.py --auto-fix
```

**4. Enable attack simulation (Battle Mode):**
```bash
python -m src.main --scan examples/ --simulate-attacks
```

### Via Web Dashboard

1. **Start the dashboard:**
   ```bash
   cd web-dashboard
   npm start
   ```

2. **Upload & Scan:**
   - Navigate to `http://localhost:3000`
   - Go to "File Scanner" tab
   - Upload any example file
   - Click "Scan File"

3. **Project Scan:**
   - Go to "Project Scanner" tab
   - Enter path: `C:\Users\...\CodeGuardian\examples`
   - Click "Scan Project"

## 🔍 What CodeGuardian Should Detect

For each file, CodeGuardian should identify:

| Language | Expected Vulnerabilities | Severity |
|----------|-------------------------|----------|
| **Python** | 10+ vulnerabilities | Critical/High |
| **JavaScript** | 17+ vulnerabilities | Critical/High |
| **Java** | 20+ vulnerabilities | Critical/High |
| **PHP** | 24+ vulnerabilities | Critical/High |
| **Go** | 24+ vulnerabilities | Critical/High |

### Expected Output Example:
```
✨ Scan Complete!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡ Critical: 15
🔴 High: 25
🟡 Medium: 12
🟢 Low: 5
Total: 57 vulnerabilities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 📊 Vulnerability Categories Covered

### OWASP Top 10 (2021)
- ✅ A01: Broken Access Control
- ✅ A02: Cryptographic Failures
- ✅ A03: Injection
- ✅ A04: Insecure Design
- ✅ A05: Security Misconfiguration
- ✅ A06: Vulnerable Components
- ✅ A07: Authentication Failures
- ✅ A08: Software & Data Integrity
- ✅ A09: Logging & Monitoring
- ✅ A10: SSRF

### CWE Top 25
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- XSS (CWE-79)
- Path Traversal (CWE-22)
- Deserialization (CWE-502)
- Hardcoded Credentials (CWE-798)
- Weak Crypto (CWE-327)
- Race Conditions (CWE-362)
- Memory Leaks (CWE-401)
- And 15+ more...

## 🛡️ Learning Objectives

These examples demonstrate:

1. **Common Attack Vectors**: How attackers exploit vulnerabilities
2. **Insecure Patterns**: Code patterns to avoid
3. **Security Best Practices**: What NOT to do
4. **Multi-Language Coverage**: Vulnerabilities across tech stacks
5. **Real-World Scenarios**: Practical security issues

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [CodeGuardian Documentation](../README.md)

## ⚠️ Disclaimer

**DO NOT deploy these files to any production environment!**

These files are for **educational and testing purposes only**. They contain deliberately vulnerable code designed to demonstrate security flaws. Using these patterns in real applications will result in serious security breaches.

## 🤝 Contributing

Want to add more examples?

1. Create a new vulnerable file in a supported language
2. Document the vulnerabilities in comments
3. Update this README with the new file
4. Test with CodeGuardian to verify detection
5. Submit a pull request

---

**Happy Testing! 🚀**

*Remember: The best way to learn security is to understand how things can go wrong.*
