// JWT Weakness Test Case — CWE-347, OWASP A07:2021
// This file contains INTENTIONAL vulnerabilities for testing the security scanner.

const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

// VULNERABILITY: JWT with 'none' algorithm allowed
app.get('/verify-weak', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    // VULNERABLE: Allows 'none' algorithm — attacker can forge tokens
    const decoded = jwt.verify(token, 'secret', { algorithms: ['none', 'HS256'] });
    res.json(decoded);
});

// VULNERABILITY: Weak JWT secret
const JWT_SECRET = 'secret123';  // Too short, easily brute-forced

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABILITY: No expiration set on token
    const token = jwt.sign({ user: username, role: 'admin' }, JWT_SECRET);
    res.json({ token });
});

// VULNERABILITY: JWT decoded without verification
app.get('/profile', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    // VULNERABLE: decode() doesn't verify signature
    const decoded = jwt.decode(token);
    // Using unverified claims for authorization
    if (decoded.role === 'admin') {
        return res.json({ data: 'admin_sensitive_data' });
    }
    res.json({ data: 'user_data' });
});

// VULNERABILITY: Token not checked for expiration
app.get('/data', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
    res.json(decoded);
});

// SAFE EXAMPLE:
// jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'], maxAge: '1h' });
