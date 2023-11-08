// Import required modules
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');
const Registration = require('./models/Registration'); // You should have a Registration model defined
const conn = require('./db/conn'); // Make sure the MongoDB connection is correctly established

// Create an Express application
const app = express();
const port = process.env.PORT || 5000;
const secretKey = process.env.SECRET_KEY || 'default-secret-key'; // Use a strong and unique secret key in production
const backendUrl = process.env.REACT_APP_BACKEND_URL || `http://localhost:${port}`;

// Middleware setup
app.use(bodyParser.json());
app.use(cors({
    origin: "*"
}));

// Login endpoint
app.post('/login', async (req, res) => {
    const { companyEmail, password } = req.body;

    try {
        // Check if the user with the provided companyEmail exists in the Registration model
        const user = await Registration.findOne({ companyEmail });
        console.log('User from the database:', user);

        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, companyEmail: user.companyEmail }, secretKey, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Registration endpoint
app.post('/register', async (req, res) => {
    const {
        salutation,
        name,
        companyEmail,
        password,
        companyName,
        designation,
        personalEmail,
        country,
        mobileNumber,
    } = req.body;

    try {
        // Check if the user with the provided companyEmail exists in the Registration model
        const existingUser = await Registration.findOne({ companyEmail });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password before storing it (use bcrypt for secure hashing)
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Create a new user in the Registration model
        const newUser = new Registration({
            salutation,
            name,
            companyEmail,
            password: hashedPassword,
            companyName,
            designation,
            personalEmail,
            country,
            mobileNumber,
        });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Protected route
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'You have access to this protected route!', user: req.user });
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden' });
        }

        req.user = user;
        next();
    }
}

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log(`Backend server URL: ${backendUrl}`);
});
