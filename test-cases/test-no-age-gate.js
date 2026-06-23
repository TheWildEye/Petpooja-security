// No Age Gate Test Case — DPDP Act Sec 9 Violation
// This file contains an INTENTIONAL compliance violation for testing.

const express = require('express');
const app = express();
app.use(express.json());

// VIOLATION: Signup endpoint with NO age verification
// DPDP Act Section 9 requires verifiable parental consent for children's data
app.post('/api/signup', (req, res) => {
    const { name, email, phone, school, grade } = req.body;
    
    // VIOLATION: Collecting school and grade (likely children's data)
    // but no age gate, no date of birth check, no parental consent
    
    const user = {
        name: name,
        email: email,
        phone: phone,
        school: school,       // Children-specific data
        grade: grade,         // Children-specific data
        created: new Date()
    };
    
    // No age verification before saving
    saveUser(user);
    
    res.json({ status: 'created', user_id: user.id });
});

// VIOLATION: Profile update without age check
app.put('/api/profile/:id', (req, res) => {
    const { hobbies, favorite_game, parent_email } = req.body;
    // Collecting children's interest data without parental consent
    updateProfile(req.params.id, req.body);
    res.json({ status: 'updated' });
});

// VIOLATION: No age-restricted content check
app.get('/api/content', (req, res) => {
    // Serving all content regardless of user age
    // No content filtering for minors
    res.json(getAllContent());
});

// SAFE EXAMPLE:
// 1. Add date_of_birth to signup
// 2. Calculate age: if (age < 18) requireParentalConsent()
// 3. If age < 13, block or require verifiable parental consent
// 4. Store age verification record
