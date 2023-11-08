
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');
require("./db/conn");



const Registration = require('./models/Registration');
const User = require('./models/User'); 
const conn = require('./db/conn'); 



const app = express();
const port = process.env.PORT || 5000;
const secretKey = process.env.SECRET_KEY || 'default-secret-key';
const backendUrl = process.env.REACT_APP_BACKEND_URL || `http://localhost:${port}`;


app.use(bodyParser.json());

app.use(cors({
    origin: "*"
}));


app.post('/login', async (req, res) => {
    const { companyEmail, password } = req.body;

    try {
        // Check if the user with the provided companyEmail exists in the Registration schema
        const user = await Registration.findOne({ companyEmail });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        // Verify the provided password against the stored hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        // At this point, the login is successful.
        // You can generate and return a JSON Web Token (JWT) for authentication here.
        // For simplicity, you can return a success message along with user details.
        res.status(200).json({
            message: 'Login successful',
            user: {
                _id: user._id,
                name: user.name,
                companyEmail: user.companyEmail,
                // Include any other user details you want to return
            },
        });
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
        // Check if the user with the provided companyEmail exists in the Registration schema
        const existingUser = await Registration.findOne({ companyEmail });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password before storing it (use bcrypt for secure hashing)
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user in the Registration schema
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




// protected route
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'You have access to this protected route!', user: req.user });
});



// middleware to verify JWT token
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
    });
}


// start the server

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log(`Backend server URL: ${backendUrl}`);
});
