# Example: Vulnerable Python Application
# This file contains intentional vulnerabilities for testing CodeGuardian

import sqlite3
import os
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)


# VULNERABILITY 1: SQL Injection
@app.route('/user')
def get_user():
    """Vulnerable to SQL injection - user input directly in query"""
    user_id = request.args.get('id')
    
    # BAD: No input validation or parameterization
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # SQL Injection vulnerability!
    
    user = cursor.fetchone()
    conn.close()
    
    return f"User: {user}"


# VULNERABILITY 2: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    """Vulnerable to XSS - unescaped user input in HTML"""
    search_term = request.args.get('q', '')
    
    # BAD: User input rendered directly without escaping
    html = f"""
    <html>
        <body>
            <h1>Search Results for: {search_term}</h1>
        </body>
    </html>
    """
    
    return render_template_string(html)  # XSS vulnerability!


# VULNERABILITY 3: Command Injection
@app.route('/ping')
def ping_server():
    """Vulnerable to command injection - unsanitized shell execution"""
    hostname = request.args.get('host', 'localhost')
    
    # BAD: User input passed directly to shell
    result = subprocess.check_output(f'ping -c 1 {hostname}', shell=True)
    
    return f"Ping result: {result.decode()}"


# VULNERABILITY 4: Path Traversal
@app.route('/download')
def download_file():
    """Vulnerable to path traversal - no path validation"""
    filename = request.args.get('file')
    
    # BAD: No validation of file path
    file_path = os.path.join('/var/www/files', filename)
    
    # Attacker could use: file=../../../../etc/passwd
    with open(file_path, 'r') as f:
        content = f.read()
    
    return content


# VULNERABILITY 5: Hardcoded Secrets
DATABASE_PASSWORD = "super_secret_password123"  # BAD: Hardcoded secret
API_KEY = "sk_live_abc123xyz789"  # BAD: Hardcoded API key


# VULNERABILITY 6: Insecure Deserialization
import pickle

@app.route('/load_data')
def load_user_data():
    """Vulnerable to insecure deserialization"""
    user_data = request.args.get('data')
    
    # BAD: Deserializing untrusted data
    obj = pickle.loads(user_data.encode())  # Insecure deserialization!
    
    return f"Loaded: {obj}"


# VULNERABILITY 7: Weak Cryptography
import hashlib

def hash_password(password):
    """Weak password hashing - using MD5"""
    # BAD: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY 8: Missing Authentication
@app.route('/admin/delete_user')
def admin_delete_user():
    """No authentication check for admin endpoint"""
    user_id = request.args.get('id')
    
    # BAD: No authentication or authorization check
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    
    return "User deleted"


# VULNERABILITY 9: Eval Usage
@app.route('/calculate')
def calculate():
    """Dangerous use of eval with user input"""
    expression = request.args.get('expr')
    
    # BAD: eval() with user input = code execution
    result = eval(expression)  # Arbitrary code execution!
    
    return f"Result: {result}"


# VULNERABILITY 10: Unrestricted File Upload
@app.route('/upload', methods=['POST'])
def upload_file():
    """No validation on uploaded files"""
    file = request.files['file']
    
    # BAD: No file type validation or size limits
    file.save(f'/var/www/uploads/{file.filename}')
    
    return "File uploaded successfully"


if __name__ == '__main__':
    # BAD: Debug mode in production, exposed to all interfaces
    app.run(debug=True, host='0.0.0.0', port=5000)
