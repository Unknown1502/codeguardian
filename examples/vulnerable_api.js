// Example: Vulnerable Node.js/Express API
// This file contains intentional vulnerabilities for testing CodeGuardian

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

app.use(express.json());


// VULNERABILITY 1: SQL Injection
app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    
    // BAD: String concatenation in SQL query
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password123',  // ALSO BAD: Hardcoded credentials
        database: 'mydb'
    });
    
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (error, results) => {  // SQL Injection!
        if (error) throw error;
        res.json(results);
    });
});


// VULNERABILITY 2: NoSQL Injection
const mongoose = require('mongoose');

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // BAD: Direct object injection in MongoDB query
    User.find({ 
        username: username,  // NoSQL Injection possible
        password: password   // Also storing plaintext password!
    }, (err, user) => {
        if (user) {
            res.json({ success: true });
        }
    });
});


// VULNERABILITY 3: Command Injection
app.post('/api/convert', (req, res) => {
    const filename = req.body.filename;
    
    // BAD: User input in shell command
    exec(`convert ${filename} output.pdf`, (error, stdout, stderr) => {
        if (error) {
            console.error(error);
            return;
        }
        res.send('Conversion complete');
    });
});


// VULNERABILITY 4: Path Traversal
app.get('/api/files/:filename', (req, res) => {
    const filename = req.params.filename;
    
    // BAD: No path validation
    const filePath = '/var/www/uploads/' + filename;
    // Attack: GET /api/files/../../etc/passwd
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(404).send('File not found');
        }
        res.send(data);
    });
});


// VULNERABILITY 5: Hardcoded Secrets
const JWT_SECRET = 'my_super_secret_key_12345';  // BAD: Hardcoded secret
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';   // BAD: Hardcoded AWS key
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';  // BAD!


// VULNERABILITY 6: Insecure Deserialization
const serialize = require('node-serialize');

app.post('/api/profile', (req, res) => {
    const userData = req.body.data;
    
    // BAD: Deserializing untrusted data
    const profile = serialize.unserialize(userData);  // Remote code execution!
    
    res.json(profile);
});


// VULNERABILITY 7: Weak Cryptography
function encryptPassword(password) {
    // BAD: MD5 is cryptographically broken
    return crypto.createHash('md5').update(password).digest('hex');
}

function weakEncryption(data) {
    // BAD: DES is deprecated and insecure
    const cipher = crypto.createCipher('des', 'weak_key');
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}


// VULNERABILITY 8: Missing Authentication
app.delete('/api/admin/users/:id', (req, res) => {
    const userId = req.params.id;
    
    // BAD: No authentication or authorization check
    connection.query(`DELETE FROM users WHERE id = ${userId}`, (err, result) => {
        if (err) throw err;
        res.send('User deleted');
    });
});


// VULNERABILITY 9: Insecure Random Number Generation
function generateToken() {
    // BAD: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

function generateSessionId() {
    // BAD: Predictable session IDs
    return new Date().getTime().toString();
}


// VULNERABILITY 10: SSRF (Server-Side Request Forgery)
const axios = require('axios');

app.post('/api/fetch', async (req, res) => {
    const url = req.body.url;
    
    // BAD: No URL validation - can access internal services
    try {
        const response = await axios.get(url);  // SSRF vulnerability!
        res.json(response.data);
    } catch (error) {
        res.status(500).send('Error fetching URL');
    }
});


// VULNERABILITY 11: Regular Expression DoS (ReDoS)
app.post('/api/validate', (req, res) => {
    const input = req.body.text;
    
    // BAD: Catastrophic backtracking pattern
    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    
    if (emailRegex.test(input)) {  // ReDoS possible!
        res.send('Valid email');
    } else {
        res.send('Invalid email');
    }
});


// VULNERABILITY 12: XML External Entity (XXE)
const xml2js = require('xml2js');

app.post('/api/parse-xml', (req, res) => {
    const xmlData = req.body.xml;
    
    // BAD: XXE vulnerability - external entities not disabled
    const parser = new xml2js.Parser();
    parser.parseString(xmlData, (err, result) => {
        res.json(result);
    });
});


// VULNERABILITY 13: Prototype Pollution
app.post('/api/merge', (req, res) => {
    const userInput = req.body;
    let config = {};
    
    // BAD: Recursive merge without protection
    function merge(target, source) {
        for (let key in source) {
            if (typeof source[key] === 'object') {
                target[key] = merge(target[key] || {}, source[key]);
            } else {
                target[key] = source[key];  // Prototype pollution!
            }
        }
        return target;
    }
    
    merge(config, userInput);
    res.json(config);
});


// VULNERABILITY 14: Insecure CORS Configuration
const cors = require('cors');

// BAD: Allow all origins with credentials
app.use(cors({
    origin: '*',
    credentials: true  // Dangerous combination!
}));


// VULNERABILITY 15: Memory Leak
let userSessions = {};  // BAD: Never cleaned up

app.post('/api/session', (req, res) => {
    const sessionId = Math.random().toString();
    
    // BAD: Sessions never expire or get cleaned up
    userSessions[sessionId] = {
        user: req.body.username,
        data: new Array(10000).fill('memory leak'),
        timestamp: Date.now()
    };
    
    res.json({ sessionId });
});


// VULNERABILITY 16: Information Disclosure
app.use((err, req, res, next) => {
    // BAD: Exposing stack traces to users
    res.status(500).json({
        error: err.message,
        stack: err.stack,  // Never expose stack traces!
        env: process.env   // Never expose environment variables!
    });
});


// VULNERABILITY 17: Unvalidated Redirects
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    // BAD: No whitelist validation
    res.redirect(url);  // Open redirect vulnerability!
});


// BAD: Running on all interfaces with default settings
app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on port 3000');
    console.log(`Database password: ${AWS_SECRET_KEY}`);  // BAD: Logging secrets!
});
