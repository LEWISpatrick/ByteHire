
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const authenticateToken = require('./middleware');  // Import the authentication middleware


const app = express();
const port = 3000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

app.use(express.json()); // Allows Express to parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parses form-encoded data


const bitcoin = require('bitcoinjs-lib');
const crypto = require('crypto');
const { ECPairFactory } = require('ecpair');
const tinysecp = require('tiny-secp256k1');

const ECPair = ECPairFactory(tinysecp);


const JWT_SECRET = process.env.JWT_SECRET;  // Make sure you have this in your .env file

// Middleware
app.use(cookieParser());
app.use(express.json());






// encrypting private keys functionnn

function encryptPrivateKey(privateKey, password) {
    const salt = crypto.randomBytes(16); // Generate a random salt
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256'); // Derive key
    const iv = crypto.randomBytes(12); // AES-GCM IV

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return {
        encryptedData: encrypted,
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag
    };
}

// end







//signup shit


app.post('/signup', async (req, res) => {
    const { username, password } = req.body


    if (!username || !password) {
        return res.status(400).json({message: 'Username and password were not filled dumbass'})
    }


    try {
        const hashedPassword = await bcrypt.hash(password, 10) 

        const existingUser = await prisma.user.findUnique({
            where: { username }
        })

        if (existingUser) {
            return res.status(400).json({message: 'bro you already signup stupid!'})

        }

        const keypair = ECPair.makeRandom();


        const { address } = bitcoin.payments.p2pkh({
            pubkey: Buffer.from(keypair.publicKey)
        });

        const privateKey = keypair.toWIF();


        // encrypt private key
        const encrypted = encryptPrivateKey(privateKey, password);


        // saving data


        const user = await prisma.user.create({
            data: {
                username,
                password: hashedPassword,
                publicKey: address,
                privateKey: encrypted.encryptedData,
                privateKeySalt: encrypted.salt,
                privateKeyIV: encrypted.iv,
                privateKeyAuthTag: encrypted.authTag

            }
        })





        res.status(201).json({
            message: 'user created W',

            user : {
                id: user.id,
                username: user.username,
                createAt: user.createdAt
            },
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});



app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        // Check if username exists
        const user = await prisma.user.findUnique({ where: { username } });
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        // Check if password matches
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        // Create a JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Send token in an HttpOnly cookie
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 3600000,
        });
        
        // Respond with success
        return res.redirect('/road')
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Logout route
app.post('/logout', (req, res) => {
    res.clearCookie('auth_token');  // Remove the token cookie
    res.status(200).json({ message: 'Logged out successfully' });
});



// shit



