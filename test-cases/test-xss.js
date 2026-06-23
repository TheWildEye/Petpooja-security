// XSS Test Case — CWE-79, OWASP A03:2021
// This file contains INTENTIONAL vulnerabilities for testing the security scanner.

const express = require('express');
const app = express();

// VULNERABILITY: Reflected XSS via innerHTML
app.get('/search', (req, res) => {
    const name = req.query.name;
    res.send(`
        <html>
        <body>
            <div id="result"></div>
            <script>
                // VULNERABLE: User input directly in innerHTML
                document.getElementById('result').innerHTML = '${name}';
            </script>
        </body>
        </html>
    `);
});

// VULNERABILITY: Stored XSS via dangerouslySetInnerHTML (React pattern)
function UserComment({ comment }) {
    // VULNERABLE: Rendering user content without sanitization
    return <div dangerouslySetInnerHTML={{__html: comment.body}} />;
}

// VULNERABILITY: DOM-based XSS via document.write
app.get('/profile', (req, res) => {
    res.send(`
        <script>
            var username = new URLSearchParams(window.location.search).get('user');
            document.write('<h1>Welcome ' + username + '</h1>');
        </script>
    `);
});

// SAFE EXAMPLE:
// const sanitized = DOMPurify.sanitize(userInput);
// element.textContent = userInput; // textContent is safe
