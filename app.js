

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');
require("./db/conn");



const Registration = require('./models/Registration');
const conn = require('./db/conn'); 



const app = express();
const port = process.env.PORT || 5000;
const secretKey = process.env.SECRET_KEY || 'default-secret-key';
const backendUrl = process.env.REACT_APP_BACKEND_URL || `http://localhost:${port}`;


app.use(bodyParser.json());

app.use(cors({
    origin: "*"
}));


// login 
app.post('/login', async (req, res) => {
    const { companyEmail, password } = req.body;

    try {

        const user = await Registration.findOne({ companyEmail });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, companyEmail: user.companyEmail }, secretKey, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});





// Registration 
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
       
        const existingUser = await Registration.findOne({ companyEmail });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }        

       
        const newUser = new Registration({
            salutation,
            name,
            companyEmail,
            password,
            companyName,
            designation,
            personalEmail,
            country,
            mobileNumber,
        });

        
       newUser.password = bcrypt.hashSync(password, 10);
        
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



//JWT token
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


// start server

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log(`Backend server URL: ${backendUrl}`);
});
