// Open CORS Test Case — OWASP A05 + CERT-IN Violation
// This file contains INTENTIONAL vulnerabilities for testing the security scanner.

const express = require('express');
const cors = require('cors');
const app = express();

// VULNERABILITY: Wildcard CORS — allows any origin
app.use(cors({
    origin: '*',                    // VIOLATION: Any website can make requests
    credentials: true,              // VIOLATION: Credentials with wildcard = browser blocks, but misconfiguration
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['*']           // VIOLATION: All headers allowed
}));

// VULNERABILITY: Manual CORS headers — also wildcard
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');           // VIOLATION
    res.setHeader('Access-Control-Allow-Methods', '*');          // VIOLATION
    res.setHeader('Access-Control-Allow-Headers', '*');          // VIOLATION
    res.setHeader('Access-Control-Allow-Credentials', 'true');  // VIOLATION with wildcard
    next();
});

// VULNERABILITY: Reflecting origin without validation
app.use((req, res, next) => {
    // VIOLATION: Reflecting any origin back — equivalent to wildcard
    const origin = req.headers.origin;
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});

// VULNERABILITY: Missing security headers
// No X-Content-Type-Options
// No X-Frame-Options
// No Strict-Transport-Security
// No Content-Security-Policy
// No X-XSS-Protection

app.get('/api/sensitive-data', (req, res) => {
    // This endpoint returns sensitive data but has wildcard CORS
    res.json({ users: getAllUsers(), tokens: getActiveTokens() });
});

// SAFE EXAMPLE:
// app.use(cors({
//     origin: ['https://myapp.com', 'https://admin.myapp.com'],
//     credentials: true,
//     methods: ['GET', 'POST'],
//     allowedHeaders: ['Content-Type', 'Authorization']
// }));
